/*
 * PVR (PowerVR) Texture Format Fuzzer
 *
 * Standalone harness for fuzzing Sega Dreamcast PVR texture parsing.
 * Based on GIMP's file-pvr plugin.
 *
 * PVR format features:
 * - Multiple pixel formats (ARGB1555, RGB565, ARGB4444, ARGB8888)
 * - Twiddle (Morton code) pixel ordering
 * - VQ (Vector Quantization) compression
 * - Palette/CLUT modes (4-bit and 8-bit)
 * - Mipmaps
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* PVR constants */
#define PVR_MAGIC 0x50565254  /* "PVRT" */
#define GBIX_MAGIC 0x47424958 /* "GBIX" */

#define PVR_MAX_WIDTH  2048
#define PVR_MAX_HEIGHT 2048
#define PVR_MAX_IMAGE_SIZE (32 * 1024 * 1024)

/* Pixel modes */
#define PVR_ARGB1555  0
#define PVR_RGB565    1
#define PVR_ARGB4444  2
#define PVR_YUV422    3
#define PVR_BUMPMAP   4
#define PVR_RGB555    5
#define PVR_ARGB8888  6

/* Texture modes */
#define PVR_TWIDDLE            1
#define PVR_TWIDDLE_MIPMAP     2
#define PVR_COMPRESSED         3
#define PVR_COMPRESSED_MIPMAP  4
#define PVR_CLUT4              5
#define PVR_CLUT4_MIPMAP       6
#define PVR_CLUT8              7
#define PVR_CLUT8_MIPMAP       8
#define PVR_RECTANGLE          9
#define PVR_STRIDE             11
#define PVR_TWIDDLED_RECT      13
#define PVR_SMALL_VQ           16
#define PVR_SMALL_VQ_MIPMAP    17

/* PVR header */
typedef struct {
    uint32_t magic;        /* "PVRT" */
    uint32_t data_size;    /* Size of texture data */
    uint8_t  pixel_mode;   /* Pixel format */
    uint8_t  texture_mode; /* Texture type */
    uint16_t dummy;
    uint16_t width;
    uint16_t height;
} pvr_header_t;

/* Read little-endian integers */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Create twiddle (Morton code) lookup table */
static void create_twiddle_table(int *twiddle, int max_dim) {
    for (int i = 0; i < max_dim; i++) {
        twiddle[i] = 0;
        for (int j = 0; j < 16; j++) {
            if (i & (1 << j)) {
                twiddle[i] |= (1 << (j * 2));
            }
        }
    }
}

/* Decode a 16-bit color based on pixel mode */
static void decode_color16(int pixel_mode, uint16_t color,
                           uint8_t *r, uint8_t *g, uint8_t *b, uint8_t *a) {
    switch (pixel_mode) {
        case PVR_ARGB1555:
            *a = (color & 0x8000) ? 255 : 0;
            *r = ((color >> 10) & 0x1F) * 255 / 31;
            *g = ((color >> 5) & 0x1F) * 255 / 31;
            *b = (color & 0x1F) * 255 / 31;
            break;

        case PVR_RGB565:
            *a = 255;
            *r = ((color >> 11) & 0x1F) * 255 / 31;
            *g = ((color >> 5) & 0x3F) * 255 / 63;
            *b = (color & 0x1F) * 255 / 31;
            break;

        case PVR_ARGB4444:
            *a = ((color >> 12) & 0x0F) * 255 / 15;
            *r = ((color >> 8) & 0x0F) * 255 / 15;
            *g = ((color >> 4) & 0x0F) * 255 / 15;
            *b = (color & 0x0F) * 255 / 15;
            break;

        case PVR_RGB555:
            *a = 255;
            *r = ((color >> 10) & 0x1F) * 255 / 31;
            *g = ((color >> 5) & 0x1F) * 255 / 31;
            *b = (color & 0x1F) * 255 / 31;
            break;

        default:
            *r = *g = *b = 128;
            *a = 255;
            break;
    }
}

/* Decode rectangle format */
static void decode_rectangle(const uint8_t *data, size_t size, size_t offset,
                             int width, int height, int pixel_mode,
                             uint8_t *output) {
    int bpp = (pixel_mode == PVR_ARGB8888) ? 4 : 2;

    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            size_t src = offset + ((size_t)y * width + x) * bpp;
            size_t dst = ((size_t)y * width + x) * 4;

            if (src + bpp > size) continue;

            if (pixel_mode == PVR_ARGB8888) {
                output[dst + 0] = data[src + 2];  /* R */
                output[dst + 1] = data[src + 1];  /* G */
                output[dst + 2] = data[src + 0];  /* B */
                output[dst + 3] = data[src + 3];  /* A */
            } else {
                uint16_t color = read_u16_le(data + src);
                decode_color16(pixel_mode, color,
                               &output[dst], &output[dst + 1],
                               &output[dst + 2], &output[dst + 3]);
            }
        }
    }
}

/* Decode twiddled format */
static void decode_twiddle(const uint8_t *data, size_t size, size_t offset,
                           int width, int height, int pixel_mode,
                           uint8_t *output) {
    int *twiddle_x = malloc(width * sizeof(int));
    int *twiddle_y = malloc(height * sizeof(int));

    if (!twiddle_x || !twiddle_y) {
        free(twiddle_x);
        free(twiddle_y);
        return;
    }

    create_twiddle_table(twiddle_x, width);
    create_twiddle_table(twiddle_y, height);

    int bpp = (pixel_mode == PVR_ARGB8888) ? 4 : 2;
    int min_dim = (width < height) ? width : height;

    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            /* Calculate twiddled index */
            size_t twiddle_idx;
            if (width == height) {
                twiddle_idx = (twiddle_y[y] << 1) | twiddle_x[x];
            } else if (width > height) {
                twiddle_idx = (twiddle_y[y % min_dim] << 1) | twiddle_x[x % min_dim];
                twiddle_idx += (x / min_dim) * min_dim * min_dim;
            } else {
                twiddle_idx = (twiddle_y[y % min_dim] << 1) | twiddle_x[x % min_dim];
                twiddle_idx += (y / min_dim) * min_dim * min_dim;
            }

            size_t src = offset + twiddle_idx * bpp;
            size_t dst = ((size_t)y * width + x) * 4;

            if (src + bpp > size) continue;

            if (pixel_mode == PVR_ARGB8888) {
                output[dst + 0] = data[src + 2];
                output[dst + 1] = data[src + 1];
                output[dst + 2] = data[src + 0];
                output[dst + 3] = data[src + 3];
            } else {
                uint16_t color = read_u16_le(data + src);
                decode_color16(pixel_mode, color,
                               &output[dst], &output[dst + 1],
                               &output[dst + 2], &output[dst + 3]);
            }
        }
    }

    free(twiddle_x);
    free(twiddle_y);
}

/* Decode VQ compressed format */
static void decode_vq(const uint8_t *data, size_t size, size_t offset,
                      int width, int height, int pixel_mode, int small_vq,
                      uint8_t *output) {
    /* VQ uses a codebook of 256 or 16 entries, each with 4 pixels (2x2) */
    int codebook_size = small_vq ? 16 : 256;
    int codebook_bytes = codebook_size * 4 * 2;  /* 4 pixels * 2 bytes each */

    if (offset + codebook_bytes > size) return;

    /* Read codebook (decode colors) */
    uint8_t codebook[256][4][4];  /* [entry][pixel][RGBA] */

    for (int i = 0; i < codebook_size; i++) {
        for (int p = 0; p < 4; p++) {
            size_t cb_off = offset + i * 8 + p * 2;
            if (cb_off + 2 > size) break;

            uint16_t color = read_u16_le(data + cb_off);
            decode_color16(pixel_mode, color,
                           &codebook[i][p][0], &codebook[i][p][1],
                           &codebook[i][p][2], &codebook[i][p][3]);
        }
    }

    /* VQ indices start after codebook */
    size_t indices_offset = offset + codebook_bytes;
    int block_width = (width + 1) / 2;
    int block_height = (height + 1) / 2;

    /* Create twiddle tables for block indices */
    int *twiddle_x = malloc(block_width * sizeof(int));
    int *twiddle_y = malloc(block_height * sizeof(int));

    if (!twiddle_x || !twiddle_y) {
        free(twiddle_x);
        free(twiddle_y);
        return;
    }

    create_twiddle_table(twiddle_x, block_width);
    create_twiddle_table(twiddle_y, block_height);

    /* Decode blocks */
    for (int by = 0; by < block_height; by++) {
        for (int bx = 0; bx < block_width; bx++) {
            size_t twiddle_idx = (twiddle_y[by] << 1) | twiddle_x[bx];
            size_t idx_off = indices_offset + twiddle_idx;

            if (idx_off >= size) continue;

            uint8_t cb_idx = data[idx_off];
            if (cb_idx >= codebook_size) cb_idx = 0;

            /* Write 2x2 block */
            for (int py = 0; py < 2; py++) {
                for (int px = 0; px < 2; px++) {
                    int x = bx * 2 + px;
                    int y = by * 2 + py;
                    if (x >= width || y >= height) continue;

                    size_t dst = ((size_t)y * width + x) * 4;
                    int p = py * 2 + px;

                    output[dst + 0] = codebook[cb_idx][p][0];
                    output[dst + 1] = codebook[cb_idx][p][1];
                    output[dst + 2] = codebook[cb_idx][p][2];
                    output[dst + 3] = codebook[cb_idx][p][3];
                }
            }
        }
    }

    free(twiddle_x);
    free(twiddle_y);
}

/* Parse PVR header */
static int parse_pvr_header(const uint8_t *data, size_t size,
                            pvr_header_t *hdr, size_t *data_offset) {
    size_t offset = 0;

    /* Check for GBIX header (global index) */
    if (size >= 8 && read_u32_le(data) == GBIX_MAGIC) {
        uint32_t gbix_size = read_u32_le(data + 4);
        offset = 8 + gbix_size;
        if (offset > size) return -1;
    }

    if (offset + 16 > size) return -1;

    /* Check PVR magic */
    hdr->magic = read_u32_le(data + offset);
    if (hdr->magic != PVR_MAGIC) return -1;

    hdr->data_size = read_u32_le(data + offset + 4);
    hdr->pixel_mode = data[offset + 8];
    hdr->texture_mode = data[offset + 9];
    hdr->dummy = read_u16_le(data + offset + 10);
    hdr->width = read_u16_le(data + offset + 12);
    hdr->height = read_u16_le(data + offset + 14);

    *data_offset = offset + 16;

    /* Validate */
    if (hdr->width == 0 || hdr->width > PVR_MAX_WIDTH) return -1;
    if (hdr->height == 0 || hdr->height > PVR_MAX_HEIGHT) return -1;
    if (hdr->pixel_mode > PVR_ARGB8888) return -1;

    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pvr_header_t hdr;
    size_t data_offset;

    if (parse_pvr_header(data, size, &hdr, &data_offset) != 0) {
        return 0;
    }

    /* Check output size */
    size_t output_size = (size_t)hdr.width * hdr.height * 4;
    if (output_size > PVR_MAX_IMAGE_SIZE) {
        return 0;
    }

    /* Allocate output buffer */
    uint8_t *output = malloc(output_size);
    if (!output) return 0;

    memset(output, 0, output_size);

    /* Decode based on texture mode */
    switch (hdr.texture_mode) {
        case PVR_RECTANGLE:
        case PVR_STRIDE:
            decode_rectangle(data, size, data_offset,
                             hdr.width, hdr.height, hdr.pixel_mode, output);
            break;

        case PVR_TWIDDLE:
        case PVR_TWIDDLE_MIPMAP:
        case PVR_TWIDDLED_RECT:
            decode_twiddle(data, size, data_offset,
                           hdr.width, hdr.height, hdr.pixel_mode, output);
            break;

        case PVR_COMPRESSED:
        case PVR_COMPRESSED_MIPMAP:
            decode_vq(data, size, data_offset,
                      hdr.width, hdr.height, hdr.pixel_mode, 0, output);
            break;

        case PVR_SMALL_VQ:
        case PVR_SMALL_VQ_MIPMAP:
            decode_vq(data, size, data_offset,
                      hdr.width, hdr.height, hdr.pixel_mode, 1, output);
            break;

        case PVR_CLUT4:
        case PVR_CLUT4_MIPMAP:
        case PVR_CLUT8:
        case PVR_CLUT8_MIPMAP:
            /* Palette modes - would need palette data */
            break;
    }

    free(output);
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
