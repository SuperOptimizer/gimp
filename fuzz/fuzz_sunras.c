/*
 * AFL++ fuzzing harness for GIMP Sun Raster (RAS) file parser
 * Based on plug-ins/common/file-sunras.c
 *
 * Targets: Buffer overflows in RLE decoding and colormap handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#define RAS_MAGIC       0x59a66a95
#define RT_OLD          0
#define RT_STANDARD     1
#define RT_BYTE_ENCODED 2
#define RT_FORMAT_RGB   3

#define RMT_NONE        0
#define RMT_EQUAL_RGB   1
#define RMT_RAW         2

#define MAX_IMAGE_SIZE  262144
#define MAX_COLORMAP    768  /* 256 * 3 */

typedef struct {
    uint32_t magic;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t length;
    uint32_t type;
    uint32_t maptype;
    uint32_t maplength;
} SunRasHeader;

static int read_sunras_header(FILE *fp, SunRasHeader *hdr) {
    uint32_t buf[8];

    if (fread(buf, sizeof(uint32_t), 8, fp) != 8)
        return -1;

    /* Sun Raster is big-endian */
    hdr->magic = ntohl(buf[0]);
    hdr->width = ntohl(buf[1]);
    hdr->height = ntohl(buf[2]);
    hdr->depth = ntohl(buf[3]);
    hdr->length = ntohl(buf[4]);
    hdr->type = ntohl(buf[5]);
    hdr->maptype = ntohl(buf[6]);
    hdr->maplength = ntohl(buf[7]);

    return 0;
}

static int decode_rle(FILE *fp, uint8_t *output, size_t output_size) {
    size_t pos = 0;

    while (pos < output_size) {
        int byte = fgetc(fp);
        if (byte == EOF)
            return -1;

        if (byte == 0x80) {
            int count_byte = fgetc(fp);
            if (count_byte == EOF)
                return -1;

            if (count_byte == 0) {
                /* Literal 0x80 */
                if (pos >= output_size)
                    return -1;
                output[pos++] = 0x80;
            } else {
                /* Run of count+1 copies of next byte */
                int value = fgetc(fp);
                if (value == EOF)
                    return -1;

                uint32_t count = (uint32_t)count_byte + 1;
                if (pos + count > output_size)
                    return -1;

                memset(output + pos, value, count);
                pos += count;
            }
        } else {
            if (pos >= output_size)
                return -1;
            output[pos++] = byte;
        }
    }

    return 0;
}

static int load_sunras_image(FILE *fp, SunRasHeader *hdr, uint8_t *colormap) {
    /* Validate dimensions */
    if (hdr->width == 0 || hdr->height == 0)
        return -1;
    if (hdr->width > MAX_IMAGE_SIZE || hdr->height > MAX_IMAGE_SIZE)
        return -1;

    /* Validate depth */
    if (hdr->depth != 1 && hdr->depth != 8 && hdr->depth != 24 && hdr->depth != 32)
        return -1;

    /* Calculate scanline size (padded to 16-bit boundary) */
    uint32_t bytes_per_pixel = (hdr->depth + 7) / 8;
    uint32_t scanline_size = hdr->width * bytes_per_pixel;
    scanline_size = (scanline_size + 1) & ~1;  /* Pad to even */

    size_t raw_size = (size_t)scanline_size * hdr->height;

    /* Check for overflow */
    if (raw_size / hdr->height != scanline_size)
        return -1;

    if (raw_size > 256 * 1024 * 1024)
        return -1;

    uint8_t *raw_data = malloc(raw_size);
    if (!raw_data)
        return -1;

    int result = 0;

    if (hdr->type == RT_BYTE_ENCODED) {
        result = decode_rle(fp, raw_data, raw_size);
    } else {
        if (fread(raw_data, 1, raw_size, fp) != raw_size)
            result = -1;
    }

    if (result != 0) {
        free(raw_data);
        return -1;
    }

    /* Convert to RGB output (simulating GIMP conversion) */
    size_t pixel_count = (size_t)hdr->width * hdr->height;
    size_t output_size = pixel_count * 3;

    if (output_size > 256 * 1024 * 1024) {
        free(raw_data);
        return -1;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(raw_data);
        return -1;
    }

    for (uint32_t y = 0; y < hdr->height; y++) {
        uint8_t *row = raw_data + y * scanline_size;
        for (uint32_t x = 0; x < hdr->width; x++) {
            size_t out_idx = ((size_t)y * hdr->width + x) * 3;
            size_t in_idx = x * bytes_per_pixel;

            switch (hdr->depth) {
                case 8:
                    if (colormap && row[in_idx] < 256) {
                        uint8_t idx = row[in_idx];
                        output[out_idx + 0] = colormap[idx];
                        output[out_idx + 1] = colormap[idx + 256];
                        output[out_idx + 2] = colormap[idx + 512];
                    }
                    break;
                case 24:
                    output[out_idx + 0] = row[in_idx + 2];  /* R */
                    output[out_idx + 1] = row[in_idx + 1];  /* G */
                    output[out_idx + 2] = row[in_idx + 0];  /* B */
                    break;
                case 32:
                    output[out_idx + 0] = row[in_idx + 3];  /* R */
                    output[out_idx + 1] = row[in_idx + 2];  /* G */
                    output[out_idx + 2] = row[in_idx + 1];  /* B */
                    break;
            }
        }
    }

    free(output);
    free(raw_data);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32)  /* Minimum header size */
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    SunRasHeader hdr;
    if (read_sunras_header(fp, &hdr) != 0) {
        fclose(fp);
        return 0;
    }

    /* Validate magic */
    if (hdr.magic != RAS_MAGIC) {
        fclose(fp);
        return 0;
    }

    /* Read colormap if present */
    uint8_t *colormap = NULL;
    if (hdr.maptype == RMT_EQUAL_RGB && hdr.maplength > 0) {
        if (hdr.maplength > MAX_COLORMAP) {
            fclose(fp);
            return 0;
        }
        colormap = malloc(hdr.maplength);
        if (colormap) {
            if (fread(colormap, 1, hdr.maplength, fp) != hdr.maplength) {
                free(colormap);
                fclose(fp);
                return 0;
            }
        }
    }

    load_sunras_image(fp, &hdr, colormap);

    if (colormap)
        free(colormap);
    fclose(fp);
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
