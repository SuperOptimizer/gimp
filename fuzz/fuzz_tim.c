/*
 * TIM (PlayStation Texture) Format Fuzzer
 *
 * Tests parsing of PlayStation 1 texture files:
 * - 4-bit indexed (16 colors with CLUT)
 * - 8-bit indexed (256 colors with CLUT)
 * - 16-bit direct color (A1R5G5B5)
 * - 24-bit direct color (RGB)
 * - CLUT (Color Look-Up Table) parsing
 *
 * AFL++ persistent mode with libFuzzer-compatible entry point.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* TIM file type indicators */
typedef enum {
    PSX_16BPP = 2,   /* 16-bit direct color (A1R5G5B5) */
    PSX_24BPP = 3,   /* 24-bit direct color (RGB) */
    PSX_4BPP  = 8,   /* 4-bit indexed (16 colors) */
    PSX_8BPP  = 9    /* 8-bit indexed (256 colors) */
} TimType;

/* TIM file header structure */
typedef struct {
    uint8_t  magic[4];     /* 0x10 0x00 0x00 0x00 */
    uint8_t  type[4];      /* Format type (low byte) */
} TimHeader;

/* CLUT (palette) header */
typedef struct {
    uint32_t data_size;    /* Size of CLUT data */
    uint16_t x;            /* X coordinate in VRAM */
    uint16_t y;            /* Y coordinate in VRAM */
    uint16_t num_colors;   /* Colors per CLUT */
    uint16_t num_cluts;    /* Number of CLUTs */
} ClutHeader;

/* Image data header */
typedef struct {
    uint32_t data_size;    /* Size of image data */
    uint16_t x;            /* X coordinate in VRAM */
    uint16_t y;            /* Y coordinate in VRAM */
    uint16_t width;        /* Width in bytes (varies by type) */
    uint16_t height;       /* Height in pixels */
} ImageHeader;

/* Size limits */
#define MAX_WIDTH       2048
#define MAX_HEIGHT      2048
#define MAX_COLORS      65536
#define MAX_CLUTS       256
#define MAX_FILE_SIZE   (64 * 1024 * 1024)

static const uint8_t *fuzz_data;
static size_t fuzz_size;
static size_t fuzz_pos;

static inline int read_bytes(void *buf, size_t len)
{
    if (fuzz_pos + len > fuzz_size) {
        return 0;
    }
    memcpy(buf, fuzz_data + fuzz_pos, len);
    fuzz_pos += len;
    return 1;
}

static inline int skip_bytes(size_t len)
{
    if (fuzz_pos + len > fuzz_size) {
        return 0;
    }
    fuzz_pos += len;
    return 1;
}

static inline uint16_t read_u16_le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Convert A1R5G5B5 to RGBA */
static void convert_a1r5g5b5(uint16_t pixel, uint8_t *rgba)
{
    /* Red: bits 0-4, Green: bits 5-9, Blue: bits 10-14, Alpha: bit 15 */
    rgba[0] = (pixel & 0x1F) << 3;           /* Red */
    rgba[1] = ((pixel >> 5) & 0x1F) << 3;    /* Green */
    rgba[2] = ((pixel >> 10) & 0x1F) << 3;   /* Blue */
    rgba[3] = (pixel & 0x8000) ? 255 : 0;    /* Alpha from bit 15 */
}

/* Parse and validate CLUT data */
static uint8_t *parse_clut(int *num_colors_out, int *num_cluts_out)
{
    ClutHeader clut;
    uint8_t raw[12];

    if (!read_bytes(raw, 12)) {
        return NULL;
    }

    clut.data_size = read_u32_le(raw);
    clut.x = read_u16_le(raw + 4);
    clut.y = read_u16_le(raw + 6);
    clut.num_colors = read_u16_le(raw + 8);
    clut.num_cluts = read_u16_le(raw + 10);

    if (clut.num_colors == 0 || clut.num_colors > MAX_COLORS) {
        return NULL;
    }
    if (clut.num_cluts == 0 || clut.num_cluts > MAX_CLUTS) {
        return NULL;
    }

    /* CLUT data is 16-bit A1R5G5B5 entries */
    size_t clut_data_size = (size_t)clut.num_colors * clut.num_cluts * 2;
    if (clut.data_size < clut_data_size + 12) {
        return NULL;
    }

    /* Read and convert CLUT to RGBA */
    size_t palette_entries = (size_t)clut.num_colors * clut.num_cluts;
    if (palette_entries > MAX_COLORS) {
        return NULL;
    }

    uint8_t *palette = malloc(palette_entries * 4);
    if (!palette) {
        return NULL;
    }

    for (size_t i = 0; i < palette_entries; i++) {
        uint8_t entry[2];
        if (!read_bytes(entry, 2)) {
            free(palette);
            return NULL;
        }
        uint16_t color = read_u16_le(entry);
        convert_a1r5g5b5(color, palette + i * 4);
    }

    *num_colors_out = clut.num_colors;
    *num_cluts_out = clut.num_cluts;

    return palette;
}

/* Parse indexed (4-bit or 8-bit) TIM image */
static int parse_indexed(int bpp)
{
    int num_colors = 0;
    int num_cluts = 0;

    /* Parse CLUT first */
    uint8_t *palette = parse_clut(&num_colors, &num_cluts);
    if (!palette) {
        return 0;
    }

    /* Parse image header */
    uint8_t raw[12];
    if (!read_bytes(raw, 12)) {
        free(palette);
        return 0;
    }

    ImageHeader img;
    img.data_size = read_u32_le(raw);
    img.x = read_u16_le(raw + 4);
    img.y = read_u16_le(raw + 6);
    img.width = read_u16_le(raw + 8);
    img.height = read_u16_le(raw + 10);

    /* Calculate real dimensions based on bit depth */
    uint32_t real_width;
    size_t bytes_per_row;

    if (bpp == 4) {
        /* 4-bit: width is in 16-bit units, 4 pixels per 16-bit word */
        real_width = (uint32_t)img.width * 4;
        bytes_per_row = (real_width + 1) / 2;
    } else {
        /* 8-bit: width is in 16-bit units, 2 pixels per 16-bit word */
        real_width = (uint32_t)img.width * 2;
        bytes_per_row = real_width;
    }

    if (real_width == 0 || real_width > MAX_WIDTH) {
        free(palette);
        return 0;
    }
    if (img.height == 0 || img.height > MAX_HEIGHT) {
        free(palette);
        return 0;
    }

    /* Allocate output buffer */
    size_t output_size = real_width * img.height * 4;
    if (output_size > MAX_FILE_SIZE) {
        free(palette);
        return 0;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(palette);
        return 0;
    }

    /* Parse and decode image data */
    for (uint32_t y = 0; y < img.height; y++) {
        uint8_t *row = output + y * real_width * 4;

        if (bpp == 4) {
            /* 4-bit indexed */
            for (uint32_t x = 0; x < real_width; x += 2) {
                uint8_t byte;
                if (!read_bytes(&byte, 1)) {
                    free(output);
                    free(palette);
                    return 0;
                }

                /* Low nibble = first pixel, high nibble = second */
                int idx1 = byte & 0x0F;
                int idx2 = (byte >> 4) & 0x0F;

                idx1 %= num_colors;
                idx2 %= num_colors;

                memcpy(row + x * 4, palette + idx1 * 4, 4);
                if (x + 1 < real_width) {
                    memcpy(row + (x + 1) * 4, palette + idx2 * 4, 4);
                }
            }
        } else {
            /* 8-bit indexed */
            for (uint32_t x = 0; x < real_width; x++) {
                uint8_t idx;
                if (!read_bytes(&idx, 1)) {
                    free(output);
                    free(palette);
                    return 0;
                }

                idx %= num_colors;
                memcpy(row + x * 4, palette + idx * 4, 4);
            }
        }
    }

    free(output);
    free(palette);
    return 1;
}

/* Parse 16-bit direct color TIM image */
static int parse_16bit(void)
{
    uint8_t raw[12];
    if (!read_bytes(raw, 12)) {
        return 0;
    }

    ImageHeader img;
    img.data_size = read_u32_le(raw);
    img.x = read_u16_le(raw + 4);
    img.y = read_u16_le(raw + 6);
    img.width = read_u16_le(raw + 8);
    img.height = read_u16_le(raw + 10);

    /* Width is in pixels for 16-bit mode */
    if (img.width == 0 || img.width > MAX_WIDTH) {
        return 0;
    }
    if (img.height == 0 || img.height > MAX_HEIGHT) {
        return 0;
    }

    size_t output_size = (size_t)img.width * img.height * 4;
    if (output_size > MAX_FILE_SIZE) {
        return 0;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        return 0;
    }

    /* Parse pixel data */
    for (uint32_t y = 0; y < img.height; y++) {
        for (uint32_t x = 0; x < img.width; x++) {
            uint8_t pixel[2];
            if (!read_bytes(pixel, 2)) {
                free(output);
                return 0;
            }

            uint16_t color = read_u16_le(pixel);
            size_t idx = (y * img.width + x) * 4;
            convert_a1r5g5b5(color, output + idx);
        }
    }

    free(output);
    return 1;
}

/* Parse 24-bit direct color TIM image */
static int parse_24bit(void)
{
    uint8_t raw[12];
    if (!read_bytes(raw, 12)) {
        return 0;
    }

    ImageHeader img;
    img.data_size = read_u32_le(raw);
    img.x = read_u16_le(raw + 4);
    img.y = read_u16_le(raw + 6);
    img.width = read_u16_le(raw + 8);
    img.height = read_u16_le(raw + 10);

    /* For 24-bit, width is stored as width * 1.5 in 16-bit units */
    uint32_t real_width = (uint32_t)img.width * 2 / 3;
    if (real_width == 0 || real_width > MAX_WIDTH) {
        return 0;
    }
    if (img.height == 0 || img.height > MAX_HEIGHT) {
        return 0;
    }

    size_t output_size = real_width * img.height * 3;
    if (output_size > MAX_FILE_SIZE) {
        return 0;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        return 0;
    }

    /* Parse RGB pixel data */
    for (uint32_t y = 0; y < img.height; y++) {
        for (uint32_t x = 0; x < real_width; x++) {
            uint8_t rgb[3];
            if (!read_bytes(rgb, 3)) {
                free(output);
                return 0;
            }

            size_t idx = (y * real_width + x) * 3;
            output[idx] = rgb[0];
            output[idx + 1] = rgb[1];
            output[idx + 2] = rgb[2];
        }
    }

    free(output);
    return 1;
}

/* Main TIM parser */
static int parse_tim(void)
{
    TimHeader header;

    if (!read_bytes(&header, 8)) {
        return 0;
    }

    /* Validate magic bytes: 0x10 0x00 0x00 0x00 */
    if (header.magic[0] != 0x10 || header.magic[1] != 0x00 ||
        header.magic[2] != 0x00 || header.magic[3] != 0x00) {
        return 0;
    }

    /* Get format type from low byte of type field */
    int type = header.type[0];

    switch (type) {
        case PSX_4BPP:
            return parse_indexed(4);
        case PSX_8BPP:
            return parse_indexed(8);
        case PSX_16BPP:
            return parse_16bit();
        case PSX_24BPP:
            return parse_24bit();
        default:
            return 0;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8 || size > MAX_FILE_SIZE) {
        return 0;
    }

    fuzz_data = data;
    fuzz_size = size;
    fuzz_pos = 0;

    parse_tim();

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}
#else
/* Standalone mode for testing */
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <tim_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }

    if (fread(data, 1, size, f) != size) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    LLVMFuzzerTestOneInput(data, size);
    free(data);

    return 0;
}
#endif
