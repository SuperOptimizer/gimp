/*
 * SGI (Silicon Graphics) Image Format Fuzzer
 *
 * Standalone harness for fuzzing SGI RGB image file parsing.
 * Based on GIMP's file-sgi plugin.
 *
 * SGI format supports:
 * - 8-bit and 16-bit per channel
 * - 1-4 channels (grayscale, RGB, RGBA)
 * - RLE compression with offset tables
 * - Both big-endian and little-endian variants
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* SGI constants */
#define SGI_MAGIC    0x01DA
#define SGI_MAGIC_LE 0xDA01  /* Little-endian magic */

/* Compression types */
#define SGI_COMP_NONE 0
#define SGI_COMP_RLE  1

/* Maximum dimensions */
#define SGI_MAX_WIDTH  32768
#define SGI_MAX_HEIGHT 32768
#define SGI_MAX_CHANNELS 4
#define SGI_MAX_IMAGE_SIZE (128 * 1024 * 1024)

/* SGI header structure */
typedef struct {
    uint16_t magic;
    uint8_t  compression;
    uint8_t  bpp;          /* 1 or 2 bytes per pixel */
    uint16_t dimension;    /* 1, 2, or 3 */
    uint16_t xsize;
    uint16_t ysize;
    uint16_t zsize;        /* Number of channels */
    uint32_t min_pixel;
    uint32_t max_pixel;
    int      swap_bytes;   /* 1 if little-endian file */
} sgi_header_t;

/* Read big-endian 16-bit integer */
static uint16_t read_u16_be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

/* Read big-endian 32-bit integer */
static uint32_t read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* Read little-endian 16-bit integer */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* Read little-endian 32-bit integer */
static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Read 16-bit based on endianness */
static uint16_t read_u16(const uint8_t *p, int swap) {
    return swap ? read_u16_le(p) : read_u16_be(p);
}

/* Read 32-bit based on endianness */
static uint32_t read_u32(const uint8_t *p, int swap) {
    return swap ? read_u32_le(p) : read_u32_be(p);
}

/* Parse SGI header */
static int parse_sgi_header(const uint8_t *data, size_t size, sgi_header_t *hdr) {
    if (size < 512) return -1;

    /* Check magic - try big-endian first */
    uint16_t magic = read_u16_be(data);
    if (magic == SGI_MAGIC) {
        hdr->swap_bytes = 0;
    } else if (magic == SGI_MAGIC_LE) {
        hdr->swap_bytes = 1;
    } else {
        return -1;
    }

    hdr->magic = SGI_MAGIC;
    hdr->compression = data[2];
    hdr->bpp = data[3];
    hdr->dimension = read_u16(data + 4, hdr->swap_bytes);
    hdr->xsize = read_u16(data + 6, hdr->swap_bytes);
    hdr->ysize = read_u16(data + 8, hdr->swap_bytes);
    hdr->zsize = read_u16(data + 10, hdr->swap_bytes);
    hdr->min_pixel = read_u32(data + 12, hdr->swap_bytes);
    hdr->max_pixel = read_u32(data + 16, hdr->swap_bytes);

    /* Validate */
    if (hdr->compression > 1) return -1;
    if (hdr->bpp < 1 || hdr->bpp > 2) return -1;
    if (hdr->xsize == 0 || hdr->xsize > SGI_MAX_WIDTH) return -1;
    if (hdr->ysize == 0 || hdr->ysize > SGI_MAX_HEIGHT) return -1;
    if (hdr->zsize == 0 || hdr->zsize > SGI_MAX_CHANNELS) return -1;

    return 0;
}

/* Read 8-bit RLE compressed data */
static int read_rle8(const uint8_t *data, size_t size, size_t offset,
                     uint16_t *row, int xsize) {
    int length = 0;

    while (xsize > 0 && offset < size) {
        uint8_t ch = data[offset++];
        length++;

        int count = ch & 0x7F;
        if (count == 0) break;
        if (count > xsize) count = xsize;

        if (ch & 0x80) {
            /* Literal run */
            for (int i = 0; i < count && offset < size; i++, length++) {
                *row++ = data[offset++];
                xsize--;
            }
        } else {
            /* Repeat run */
            if (offset >= size) break;
            uint8_t val = data[offset++];
            length++;
            for (int i = 0; i < count; i++) {
                *row++ = val;
                xsize--;
            }
        }
    }

    return (xsize > 0) ? -1 : length;
}

/* Read 16-bit RLE compressed data */
static int read_rle16(const uint8_t *data, size_t size, size_t offset,
                      uint16_t *row, int xsize, int swap) {
    int length = 0;

    while (xsize > 0 && offset + 1 < size) {
        uint16_t ch = read_u16(data + offset, swap);
        offset += 2;
        length++;

        int count = ch & 0x7F;
        if (count == 0) break;
        if (count > xsize) count = xsize;

        if (ch & 0x80) {
            /* Literal run */
            for (int i = 0; i < count && offset + 1 < size; i++, length++) {
                *row++ = read_u16(data + offset, swap);
                offset += 2;
                xsize--;
            }
        } else {
            /* Repeat run */
            if (offset + 1 >= size) break;
            uint16_t val = read_u16(data + offset, swap);
            offset += 2;
            length++;
            for (int i = 0; i < count; i++) {
                *row++ = val;
                xsize--;
            }
        }
    }

    return (xsize > 0) ? -1 : length * 2;
}

/* Read uncompressed row */
static int read_raw(const uint8_t *data, size_t size, size_t offset,
                    uint16_t *row, int xsize, int bpp, int swap) {
    if (bpp == 1) {
        if (offset + xsize > size) return -1;
        for (int x = 0; x < xsize; x++) {
            row[x] = data[offset + x];
        }
    } else {
        if (offset + xsize * 2 > size) return -1;
        for (int x = 0; x < xsize; x++) {
            row[x] = read_u16(data + offset + x * 2, swap);
        }
    }
    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sgi_header_t hdr;

    if (parse_sgi_header(data, size, &hdr) != 0) {
        return 0;
    }

    /* Calculate image size */
    size_t row_size = (size_t)hdr.xsize * sizeof(uint16_t);
    size_t image_pixels = (size_t)hdr.xsize * hdr.ysize * hdr.zsize;
    size_t image_size = image_pixels * sizeof(uint16_t);

    if (image_size > SGI_MAX_IMAGE_SIZE) {
        return 0;
    }

    /* Allocate row buffer */
    uint16_t *row = malloc(row_size);
    if (!row) return 0;

    /* Allocate offset table for RLE */
    uint32_t *offset_table = NULL;
    size_t table_entries = (size_t)hdr.ysize * hdr.zsize;

    if (hdr.compression == SGI_COMP_RLE) {
        /* Read offset table from header (starts at byte 512) */
        offset_table = malloc(table_entries * sizeof(uint32_t));
        if (!offset_table) {
            free(row);
            return 0;
        }

        size_t table_offset = 512;
        if (table_offset + table_entries * 4 > size) {
            free(offset_table);
            free(row);
            return 0;
        }

        for (size_t i = 0; i < table_entries; i++) {
            offset_table[i] = read_u32(data + table_offset + i * 4, hdr.swap_bytes);
        }
    }

    /* Allocate output buffer */
    uint16_t *output = malloc(image_size);
    if (!output) {
        free(offset_table);
        free(row);
        return 0;
    }

    /* Read all scanlines */
    for (int z = 0; z < hdr.zsize; z++) {
        for (int y = 0; y < hdr.ysize; y++) {
            size_t offset;

            if (hdr.compression == SGI_COMP_NONE) {
                /* Uncompressed: data starts at 512 */
                offset = 512 + ((size_t)y + z * hdr.ysize) * hdr.xsize * hdr.bpp;
                read_raw(data, size, offset, row, hdr.xsize, hdr.bpp, hdr.swap_bytes);
            } else {
                /* RLE: use offset table */
                size_t table_idx = (size_t)z * hdr.ysize + y;
                offset = offset_table[table_idx];

                if (offset >= size) {
                    memset(row, 0, row_size);
                } else {
                    if (hdr.bpp == 1) {
                        read_rle8(data, size, offset, row, hdr.xsize);
                    } else {
                        read_rle16(data, size, offset, row, hdr.xsize, hdr.swap_bytes);
                    }
                }
            }

            /* Copy row to output */
            size_t out_offset = ((size_t)z * hdr.ysize + y) * hdr.xsize;
            if (out_offset + hdr.xsize <= image_pixels) {
                memcpy(output + out_offset, row, row_size);
            }
        }
    }

    free(output);
    free(offset_table);
    free(row);
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
