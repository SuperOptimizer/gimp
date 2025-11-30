/*
 * CEL (KISS) Image Format Fuzzer
 *
 * Standalone harness for fuzzing KISS CEL image parsing.
 * Based on GIMP's file-cel plugin.
 *
 * KISS CEL format:
 * - Used in Kisekae Set System (paper doll program)
 * - Simple palette-based format
 * - Header contains width, height, offset, bits per pixel
 * - Palette can be separate or embedded
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* CEL constants */
#define CEL_MAGIC     0x04  /* KiSS cell mark */
#define CEL_MAX_WIDTH  4096
#define CEL_MAX_HEIGHT 4096
#define CEL_MAX_IMAGE_SIZE (32 * 1024 * 1024)

/* CEL header structure */
typedef struct {
    uint8_t  mark;        /* File mark (0x04) */
    uint8_t  bpp;         /* Bits per pixel (4 or 8) */
    uint16_t reserved;    /* Reserved */
    uint16_t width;       /* Image width */
    uint16_t height;      /* Image height */
    uint16_t x_offset;    /* X offset */
    uint16_t y_offset;    /* Y offset */
} cel_header_t;

/* KCF (KiSS Color File) palette header */
typedef struct {
    uint8_t  mark;        /* File mark (0x10) */
    uint8_t  bpp;         /* Bits per color (12 or 24) */
    uint16_t reserved;    /* Reserved */
    uint16_t ncolors;     /* Number of colors */
    uint16_t ngroups;     /* Number of palette groups */
} kcf_header_t;

/* Read little-endian 16-bit */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* Parse CEL header */
static int parse_cel_header(const uint8_t *data, size_t size, cel_header_t *hdr) {
    if (size < 32) return -1;

    hdr->mark = data[0];
    hdr->bpp = data[1];
    hdr->reserved = read_u16_le(data + 2);
    hdr->width = read_u16_le(data + 4);
    hdr->height = read_u16_le(data + 6);
    hdr->x_offset = read_u16_le(data + 8);
    hdr->y_offset = read_u16_le(data + 10);

    /* Validate */
    if (hdr->mark != CEL_MAGIC) return -1;
    if (hdr->bpp != 4 && hdr->bpp != 8 && hdr->bpp != 32) return -1;
    if (hdr->width == 0 || hdr->width > CEL_MAX_WIDTH) return -1;
    if (hdr->height == 0 || hdr->height > CEL_MAX_HEIGHT) return -1;

    return 0;
}

/* Parse optional KCF palette embedded in CEL */
static int parse_kcf_palette(const uint8_t *data, size_t size, size_t pos,
                             uint8_t *palette, int *num_colors) {
    if (pos + 8 > size) return -1;

    kcf_header_t hdr;
    hdr.mark = data[pos];
    hdr.bpp = data[pos + 1];
    hdr.reserved = read_u16_le(data + pos + 2);
    hdr.ncolors = read_u16_le(data + pos + 4);
    hdr.ngroups = read_u16_le(data + pos + 6);

    if (hdr.mark != 0x10) return -1;
    if (hdr.ncolors == 0 || hdr.ncolors > 256) return -1;

    pos += 8;

    /* Read palette entries */
    *num_colors = hdr.ncolors;
    int bytes_per_color = (hdr.bpp == 12) ? 2 : 3;

    for (int i = 0; i < hdr.ncolors && pos + bytes_per_color <= size; i++) {
        if (hdr.bpp == 12) {
            /* 12-bit color (4 bits per channel packed into 2 bytes) */
            uint16_t val = read_u16_le(data + pos);
            palette[i * 3 + 0] = ((val >> 8) & 0x0F) * 17;  /* R */
            palette[i * 3 + 1] = ((val >> 4) & 0x0F) * 17;  /* G */
            palette[i * 3 + 2] = (val & 0x0F) * 17;          /* B */
            pos += 2;
        } else {
            /* 24-bit color */
            palette[i * 3 + 0] = data[pos + 0];
            palette[i * 3 + 1] = data[pos + 1];
            palette[i * 3 + 2] = data[pos + 2];
            pos += 3;
        }
    }

    return 0;
}

/* Load 4-bit CEL image */
static void load_4bpp(const uint8_t *data, size_t size, size_t pos,
                      int width, int height, uint8_t *output) {
    /* Each byte contains 2 pixels */
    int bytes_per_row = (width + 1) / 2;

    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            size_t byte_pos = pos + (size_t)y * bytes_per_row + x / 2;
            if (byte_pos >= size) break;

            uint8_t byte = data[byte_pos];
            uint8_t pixel;

            if (x & 1) {
                pixel = byte & 0x0F;
            } else {
                pixel = (byte >> 4) & 0x0F;
            }

            output[y * width + x] = pixel;
        }
    }
}

/* Load 8-bit CEL image */
static void load_8bpp(const uint8_t *data, size_t size, size_t pos,
                      int width, int height, uint8_t *output) {
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            size_t byte_pos = pos + (size_t)y * width + x;
            if (byte_pos >= size) {
                output[y * width + x] = 0;
            } else {
                output[y * width + x] = data[byte_pos];
            }
        }
    }
}

/* Load 32-bit RGBA CEL image */
static void load_32bpp(const uint8_t *data, size_t size, size_t pos,
                       int width, int height, uint8_t *output) {
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            size_t pixel_pos = pos + ((size_t)y * width + x) * 4;
            size_t out_pos = ((size_t)y * width + x) * 4;

            if (pixel_pos + 3 < size) {
                output[out_pos + 0] = data[pixel_pos + 0];  /* B */
                output[out_pos + 1] = data[pixel_pos + 1];  /* G */
                output[out_pos + 2] = data[pixel_pos + 2];  /* R */
                output[out_pos + 3] = data[pixel_pos + 3];  /* A */
            } else {
                output[out_pos + 0] = 0;
                output[out_pos + 1] = 0;
                output[out_pos + 2] = 0;
                output[out_pos + 3] = 0;
            }
        }
    }
}

/* Apply palette to indexed image */
static void apply_palette(const uint8_t *indexed, int width, int height,
                          const uint8_t *palette, int transparent_idx,
                          uint8_t *rgba) {
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            size_t idx = (size_t)y * width + x;
            uint8_t color_idx = indexed[idx];
            size_t out_pos = idx * 4;

            if (color_idx == transparent_idx) {
                rgba[out_pos + 0] = 0;
                rgba[out_pos + 1] = 0;
                rgba[out_pos + 2] = 0;
                rgba[out_pos + 3] = 0;
            } else {
                rgba[out_pos + 0] = palette[color_idx * 3 + 0];
                rgba[out_pos + 1] = palette[color_idx * 3 + 1];
                rgba[out_pos + 2] = palette[color_idx * 3 + 2];
                rgba[out_pos + 3] = 255;
            }
        }
    }
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cel_header_t hdr;

    if (parse_cel_header(data, size, &hdr) != 0) {
        return 0;
    }

    /* Check image size limit */
    size_t pixel_count = (size_t)hdr.width * hdr.height;
    size_t image_size = pixel_count * 4;  /* RGBA output */

    if (image_size > CEL_MAX_IMAGE_SIZE) {
        return 0;
    }

    /* Data starts after 32-byte header */
    size_t data_pos = 32;

    /* Default grayscale palette */
    uint8_t palette[768];
    int num_colors = 256;
    for (int i = 0; i < 256; i++) {
        palette[i * 3 + 0] = i;
        palette[i * 3 + 1] = i;
        palette[i * 3 + 2] = i;
    }

    if (hdr.bpp == 32) {
        /* 32-bit RGBA - no palette needed */
        uint8_t *output = malloc(image_size);
        if (!output) return 0;

        load_32bpp(data, size, data_pos, hdr.width, hdr.height, output);
        free(output);
    } else {
        /* Indexed image - need palette */
        uint8_t *indexed = malloc(pixel_count);
        if (!indexed) return 0;

        if (hdr.bpp == 4) {
            load_4bpp(data, size, data_pos, hdr.width, hdr.height, indexed);
            num_colors = 16;
        } else {
            load_8bpp(data, size, data_pos, hdr.width, hdr.height, indexed);
            num_colors = 256;
        }

        /* Try to load embedded KCF palette after image data */
        size_t palette_pos;
        if (hdr.bpp == 4) {
            palette_pos = data_pos + ((size_t)(hdr.width + 1) / 2) * hdr.height;
        } else {
            palette_pos = data_pos + pixel_count;
        }

        if (palette_pos < size) {
            int pal_colors;
            parse_kcf_palette(data, size, palette_pos, palette, &pal_colors);
        }

        /* Apply palette to create RGBA output */
        uint8_t *output = malloc(image_size);
        if (output) {
            apply_palette(indexed, hdr.width, hdr.height, palette, 0, output);
            free(output);
        }

        free(indexed);
    }

    return 0;
}

/* AFL++ persistent mode */
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}
#else
/* Standalone mode */
int main(int argc, char **argv) {
    uint8_t *data = NULL;
    size_t size = 0;
    size_t capacity = 0;

    FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) {
        perror("fopen");
        return 1;
    }

    while (1) {
        if (size >= capacity) {
            capacity = capacity ? capacity * 2 : 4096;
            data = realloc(data, capacity);
            if (!data) {
                perror("realloc");
                if (argc > 1) fclose(f);
                return 1;
            }
        }
        size_t n = fread(data + size, 1, capacity - size, f);
        if (n == 0) break;
        size += n;
    }

    if (argc > 1) fclose(f);

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    return 0;
}
#endif
