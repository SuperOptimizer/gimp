/*
 * QOI (Quite OK Image) Format Fuzzer
 *
 * Standalone harness for fuzzing QOI image parsing.
 * Based on the QOI specification: https://qoiformat.org/
 *
 * QOI is a simple, fast, lossless image format with:
 * - 14-byte header (magic, width, height, channels, colorspace)
 * - Run-length encoding with 4 op types
 * - 64-entry running hash table
 * - 8-byte end marker
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* QOI constants */
#define QOI_MAGIC 0x716F6966  /* "qoif" */
#define QOI_HEADER_SIZE 14
#define QOI_END_MARKER_SIZE 8

#define QOI_OP_INDEX  0x00  /* 00xxxxxx */
#define QOI_OP_DIFF   0x40  /* 01xxxxxx */
#define QOI_OP_LUMA   0x80  /* 10xxxxxx */
#define QOI_OP_RUN    0xC0  /* 11xxxxxx */
#define QOI_OP_RGB    0xFE  /* 11111110 */
#define QOI_OP_RGBA   0xFF  /* 11111111 */

#define QOI_MASK_2    0xC0  /* Top 2 bits */

#define QOI_MAX_WIDTH  65536
#define QOI_MAX_HEIGHT 65536
#define QOI_MAX_PIXELS (256 * 1024 * 1024)

/* QOI header structure */
typedef struct {
    uint32_t magic;      /* "qoif" */
    uint32_t width;      /* Image width in pixels */
    uint32_t height;     /* Image height in pixels */
    uint8_t  channels;   /* 3 = RGB, 4 = RGBA */
    uint8_t  colorspace; /* 0 = sRGB with linear alpha, 1 = all linear */
} qoi_header_t;

/* RGBA pixel */
typedef struct {
    uint8_t r, g, b, a;
} qoi_rgba_t;

/* Hash function for pixel index */
static inline int qoi_color_hash(qoi_rgba_t c) {
    return (c.r * 3 + c.g * 5 + c.b * 7 + c.a * 11) % 64;
}

/* Read big-endian 32-bit integer */
static uint32_t read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* Parse QOI header */
static int parse_qoi_header(const uint8_t *data, size_t size, qoi_header_t *hdr) {
    if (size < QOI_HEADER_SIZE) return -1;

    hdr->magic = read_u32_be(data);
    hdr->width = read_u32_be(data + 4);
    hdr->height = read_u32_be(data + 8);
    hdr->channels = data[12];
    hdr->colorspace = data[13];

    /* Validate */
    if (hdr->magic != QOI_MAGIC) return -1;
    if (hdr->width == 0 || hdr->width > QOI_MAX_WIDTH) return -1;
    if (hdr->height == 0 || hdr->height > QOI_MAX_HEIGHT) return -1;
    if (hdr->channels != 3 && hdr->channels != 4) return -1;
    if (hdr->colorspace > 1) return -1;

    return 0;
}

/* Decode QOI image data */
static int decode_qoi(const uint8_t *data, size_t size, qoi_header_t *hdr,
                      uint8_t *output, size_t max_pixels) {
    /* Hash table of recently seen pixels */
    qoi_rgba_t index[64] = {0};

    /* Current pixel (starts as opaque black) */
    qoi_rgba_t px = {0, 0, 0, 255};

    size_t pos = QOI_HEADER_SIZE;
    size_t pixel_count = 0;
    size_t total_pixels = (size_t)hdr->width * hdr->height;
    int channels = hdr->channels;

    if (total_pixels > max_pixels) {
        total_pixels = max_pixels;
    }

    int run = 0;

    while (pixel_count < total_pixels) {
        if (run > 0) {
            /* Continue a run of identical pixels */
            run--;
        } else if (pos < size) {
            uint8_t b1 = data[pos++];

            if (b1 == QOI_OP_RGB) {
                /* RGB literal */
                if (pos + 2 >= size) break;
                px.r = data[pos++];
                px.g = data[pos++];
                px.b = data[pos++];
            } else if (b1 == QOI_OP_RGBA) {
                /* RGBA literal */
                if (pos + 3 >= size) break;
                px.r = data[pos++];
                px.g = data[pos++];
                px.b = data[pos++];
                px.a = data[pos++];
            } else if ((b1 & QOI_MASK_2) == QOI_OP_INDEX) {
                /* Index into hash table */
                px = index[b1 & 0x3F];
            } else if ((b1 & QOI_MASK_2) == QOI_OP_DIFF) {
                /* Small difference from previous pixel */
                px.r += ((b1 >> 4) & 0x03) - 2;
                px.g += ((b1 >> 2) & 0x03) - 2;
                px.b += (b1 & 0x03) - 2;
            } else if ((b1 & QOI_MASK_2) == QOI_OP_LUMA) {
                /* Larger difference with luma */
                if (pos >= size) break;
                uint8_t b2 = data[pos++];
                int vg = (b1 & 0x3F) - 32;
                px.r += vg - 8 + ((b2 >> 4) & 0x0F);
                px.g += vg;
                px.b += vg - 8 + (b2 & 0x0F);
            } else if ((b1 & QOI_MASK_2) == QOI_OP_RUN) {
                /* Run of identical pixels */
                run = (b1 & 0x3F);  /* 0-61 means 1-62 pixels */
            }

            /* Update hash table */
            index[qoi_color_hash(px)] = px;
        } else {
            /* Out of input data */
            break;
        }

        /* Write pixel to output */
        size_t out_pos = pixel_count * channels;
        output[out_pos + 0] = px.r;
        output[out_pos + 1] = px.g;
        output[out_pos + 2] = px.b;
        if (channels == 4) {
            output[out_pos + 3] = px.a;
        }

        pixel_count++;
    }

    return pixel_count;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    qoi_header_t hdr;

    if (parse_qoi_header(data, size, &hdr) != 0) {
        return 0;
    }

    /* Check total pixel count */
    size_t total_pixels = (size_t)hdr.width * hdr.height;
    if (total_pixels > QOI_MAX_PIXELS) {
        return 0;
    }

    /* Allocate output buffer */
    size_t output_size = total_pixels * hdr.channels;
    uint8_t *output = malloc(output_size);
    if (!output) {
        return 0;
    }

    /* Decode image */
    decode_qoi(data, size, &hdr, output, total_pixels);

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
