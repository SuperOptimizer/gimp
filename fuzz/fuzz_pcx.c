/*
 * PCX (ZSoft Paintbrush) Image Format Fuzzer
 *
 * Standalone harness for fuzzing PCX image file parsing.
 * Based on GIMP's file-pcx plugin.
 *
 * PCX supports:
 * - 1, 2, 4, 8, 24-bit color depths
 * - RLE compression
 * - Multiple planes (planar format)
 * - Palette (EGA header palette or VGA 256-color)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* PCX constants */
#define PCX_MANUFACTURER 0x0A
#define PCX_MAX_WIDTH    32768
#define PCX_MAX_HEIGHT   32768
#define PCX_MAX_IMAGE_SIZE (64 * 1024 * 1024)

/* PCX header structure (128 bytes) */
typedef struct {
    uint8_t  manufacturer;  /* Always 0x0A */
    uint8_t  version;       /* 0=2.5, 2=2.8 w/palette, 3=2.8 w/o palette, 5=3.0 */
    uint8_t  compression;   /* 0=none, 1=RLE */
    uint8_t  bpp;           /* Bits per pixel per plane */
    uint16_t x1, y1;        /* Window coordinates */
    uint16_t x2, y2;
    uint16_t hdpi, vdpi;    /* Resolution */
    uint8_t  colormap[48];  /* 16-color EGA palette */
    uint8_t  reserved;
    uint8_t  planes;        /* Number of color planes */
    uint16_t bytesperline;  /* Bytes per scanline per plane */
    uint16_t color;         /* 1=color, 2=grayscale */
    uint8_t  filler[58];    /* Padding to 128 bytes */
} pcx_header_t;

/* Read little-endian integers */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* RLE decompression state */
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
    uint8_t count;
    uint8_t value;
} rle_state_t;

/* Initialize RLE decoder */
static void rle_init(rle_state_t *state, const uint8_t *data, size_t size, size_t offset) {
    state->data = data;
    state->size = size;
    state->offset = offset;
    state->count = 0;
    state->value = 0;
}

/* Read one byte from RLE stream */
static int rle_read(rle_state_t *state) {
    if (state->count > 0) {
        state->count--;
        return state->value;
    }

    if (state->offset >= state->size) {
        return -1;
    }

    uint8_t byte = state->data[state->offset++];

    if ((byte & 0xC0) == 0xC0) {
        /* RLE run */
        state->count = byte & 0x3F;
        if (state->count == 0 || state->offset >= state->size) {
            return -1;
        }
        state->value = state->data[state->offset++];
        state->count--;
        return state->value;
    }

    return byte;
}

/* Read a scanline */
static int read_scanline(rle_state_t *state, uint8_t *line, int bytes, int compressed) {
    if (!compressed) {
        if (state->offset + bytes > state->size) {
            return -1;
        }
        memcpy(line, state->data + state->offset, bytes);
        state->offset += bytes;
        return 0;
    }

    for (int i = 0; i < bytes; i++) {
        int b = rle_read(state);
        if (b < 0) {
            /* Fill rest with zeros */
            memset(line + i, 0, bytes - i);
            return 0;
        }
        line[i] = (uint8_t)b;
    }

    return 0;
}

/* Parse PCX header */
static int parse_pcx_header(const uint8_t *data, size_t size, pcx_header_t *hdr) {
    if (size < 128) return -1;

    hdr->manufacturer = data[0];
    hdr->version = data[1];
    hdr->compression = data[2];
    hdr->bpp = data[3];
    hdr->x1 = read_u16_le(data + 4);
    hdr->y1 = read_u16_le(data + 6);
    hdr->x2 = read_u16_le(data + 8);
    hdr->y2 = read_u16_le(data + 10);
    hdr->hdpi = read_u16_le(data + 12);
    hdr->vdpi = read_u16_le(data + 14);
    memcpy(hdr->colormap, data + 16, 48);
    hdr->reserved = data[64];
    hdr->planes = data[65];
    hdr->bytesperline = read_u16_le(data + 66);
    hdr->color = read_u16_le(data + 68);

    /* Validate */
    if (hdr->manufacturer != PCX_MANUFACTURER) return -1;
    if (hdr->compression > 1) return -1;
    if (hdr->bpp == 0 || hdr->bpp > 8) return -1;
    if (hdr->planes == 0 || hdr->planes > 4) return -1;

    return 0;
}

/* Load 1-bit monochrome PCX */
static void load_1bpp(rle_state_t *state, int width, int height,
                      uint8_t *buf, uint16_t bytesperline, int compressed) {
    uint8_t *line = malloc(bytesperline);
    if (!line) return;

    for (int y = 0; y < height; y++) {
        read_scanline(state, line, bytesperline, compressed);

        for (int x = 0; x < width; x++) {
            buf[y * width + x] = (line[x / 8] & (128 >> (x % 8))) ? 1 : 0;
        }
    }

    free(line);
}

/* Load 4-bit (4 planes) PCX */
static void load_4bpp_planar(rle_state_t *state, int width, int height,
                             uint8_t *buf, uint16_t bytesperline, int compressed) {
    uint8_t *line = malloc(bytesperline);
    if (!line) return;

    for (int y = 0; y < height; y++) {
        memset(buf + y * width, 0, width);

        for (int c = 0; c < 4; c++) {
            read_scanline(state, line, bytesperline, compressed);

            for (int x = 0; x < width; x++) {
                if (line[x / 8] & (128 >> (x % 8))) {
                    buf[y * width + x] |= (1 << c);
                }
            }
        }
    }

    free(line);
}

/* Load 8-bit indexed PCX */
static void load_8bpp(rle_state_t *state, int width, int height,
                      uint8_t *buf, uint16_t bytesperline, int compressed) {
    uint8_t *line = malloc(bytesperline);
    if (!line) return;

    for (int y = 0; y < height; y++) {
        read_scanline(state, line, bytesperline, compressed);
        memcpy(buf + y * width, line, width);
    }

    free(line);
}

/* Load 24-bit RGB PCX */
static void load_24bpp(rle_state_t *state, int width, int height,
                       uint8_t *buf, uint16_t bytesperline, uint8_t planes,
                       int compressed) {
    uint8_t *line = malloc(bytesperline);
    if (!line) return;

    for (int y = 0; y < height; y++) {
        for (int c = 0; c < planes; c++) {
            read_scanline(state, line, bytesperline, compressed);

            for (int x = 0; x < width; x++) {
                buf[(y * width + x) * planes + c] = line[x];
            }
        }
    }

    free(line);
}

/* Load sub-8-bit formats (2-bit, etc.) */
static void load_sub_8bpp(rle_state_t *state, int width, int height,
                          int bpp, int planes, uint8_t *buf,
                          uint16_t bytesperline, int compressed) {
    uint8_t *line = malloc(bytesperline);
    if (!line) return;

    int real_bpp = bpp - 1;

    for (int y = 0; y < height; y++) {
        memset(buf + y * width, 0, width);

        for (int c = 0; c < planes; c++) {
            read_scanline(state, line, bytesperline, compressed);

            for (int x = 0; x < width; x++) {
                for (int b = 0; b < bpp; b++) {
                    int current_bit = bpp * x + b;
                    if (line[current_bit / 8] & (128 >> (current_bit % 8))) {
                        buf[y * width + x] |= (1 << (real_bpp - b + c));
                    }
                }
            }
        }
    }

    free(line);
}

/* Read VGA palette at end of file */
static int read_vga_palette(const uint8_t *data, size_t size, uint8_t *palette) {
    if (size < 769) return -1;

    /* Look for palette marker 0x0C */
    if (data[size - 769] != 0x0C) return -1;

    memcpy(palette, data + size - 768, 768);
    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pcx_header_t hdr;

    if (parse_pcx_header(data, size, &hdr) != 0) {
        return 0;
    }

    /* Calculate dimensions */
    int width = hdr.x2 - hdr.x1 + 1;
    int height = hdr.y2 - hdr.y1 + 1;

    if (width <= 0 || width > PCX_MAX_WIDTH) return 0;
    if (height <= 0 || height > PCX_MAX_HEIGHT) return 0;

    /* Validate bytesperline */
    int min_bytes = (width * hdr.bpp + 7) / 8;
    if (hdr.bytesperline < min_bytes || hdr.bytesperline == 0) {
        return 0;
    }

    /* Check for overflow */
    size_t image_size;
    if (hdr.planes == 3 || hdr.planes == 4) {
        /* RGB/RGBA */
        image_size = (size_t)width * height * hdr.planes;
    } else {
        /* Indexed */
        image_size = (size_t)width * height;
    }

    if (image_size > PCX_MAX_IMAGE_SIZE) {
        return 0;
    }

    /* Allocate output buffer */
    uint8_t *buf = malloc(image_size);
    if (!buf) return 0;

    memset(buf, 0, image_size);

    /* Initialize RLE decoder */
    rle_state_t state;
    rle_init(&state, data, size, 128);

    int compressed = hdr.compression;

    /* Decode based on format */
    if (hdr.planes == 1 && hdr.bpp == 1) {
        /* 1-bit monochrome */
        load_1bpp(&state, width, height, buf, hdr.bytesperline, compressed);
    } else if (hdr.planes == 4 && hdr.bpp == 1) {
        /* 4-bit planar (16 colors) */
        load_4bpp_planar(&state, width, height, buf, hdr.bytesperline, compressed);
    } else if (hdr.planes == 1 && hdr.bpp == 8) {
        /* 8-bit indexed */
        load_8bpp(&state, width, height, buf, hdr.bytesperline, compressed);

        /* Try to read VGA palette */
        uint8_t palette[768];
        read_vga_palette(data, size, palette);
    } else if ((hdr.planes == 3 || hdr.planes == 4) && hdr.bpp == 8) {
        /* 24-bit or 32-bit RGB(A) */
        load_24bpp(&state, width, height, buf, hdr.bytesperline, hdr.planes, compressed);
    } else if (hdr.bpp < 8) {
        /* Other sub-8-bit formats (2-bit, 4-bit) */
        load_sub_8bpp(&state, width, height, hdr.bpp, hdr.planes,
                     buf, hdr.bytesperline, compressed);
    }

    free(buf);
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
