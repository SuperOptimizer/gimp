/*
 * AFL++ fuzzing harness for GIMP TGA (Targa) file parser
 * Based on plug-ins/common/file-tga.c
 *
 * Targets: Heap-based buffer overflows in TGA parsing (similar to Krita CVE)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define TGA_TYPE_MAPPED     1
#define TGA_TYPE_COLOR      2
#define TGA_TYPE_GRAY       3
#define TGA_COMP_NONE       0
#define TGA_COMP_RLE        1

#define MAX_IMAGE_SIZE      262144
#define MAX_COLORMAP_SIZE   256

typedef struct {
    uint8_t id_length;
    uint8_t colormap_type;
    uint8_t image_type;
    uint16_t colormap_index;
    uint16_t colormap_length;
    uint8_t colormap_size;
    uint16_t x_origin;
    uint16_t y_origin;
    uint16_t width;
    uint16_t height;
    uint8_t bpp;
    uint8_t descriptor;
    /* Derived fields */
    uint8_t bytes_per_pixel;
    uint8_t alpha_bits;
    uint8_t flip_horiz;
    uint8_t flip_vert;
    uint8_t compression;
    uint8_t mapped_type;
} TGAHeader;

static int read_tga_header(FILE *fp, TGAHeader *hdr) {
    uint8_t buf[18];

    if (fread(buf, 1, 18, fp) != 18)
        return -1;

    hdr->id_length = buf[0];
    hdr->colormap_type = buf[1];

    /* Image type encodes both type and compression */
    uint8_t raw_type = buf[2];
    hdr->compression = (raw_type & 0x08) ? TGA_COMP_RLE : TGA_COMP_NONE;
    hdr->mapped_type = raw_type & 0x07;

    switch (hdr->mapped_type) {
        case 1: hdr->image_type = TGA_TYPE_MAPPED; break;
        case 2: hdr->image_type = TGA_TYPE_COLOR; break;
        case 3: hdr->image_type = TGA_TYPE_GRAY; break;
        default: hdr->image_type = 0; break;
    }

    /* Colormap specification (little-endian) */
    hdr->colormap_index = buf[3] | (buf[4] << 8);
    hdr->colormap_length = buf[5] | (buf[6] << 8);
    hdr->colormap_size = buf[7];

    /* Image specification */
    hdr->x_origin = buf[8] | (buf[9] << 8);
    hdr->y_origin = buf[10] | (buf[11] << 8);
    hdr->width = buf[12] | (buf[13] << 8);
    hdr->height = buf[14] | (buf[15] << 8);
    hdr->bpp = buf[16];
    hdr->descriptor = buf[17];

    /* Derived fields */
    hdr->bytes_per_pixel = (hdr->bpp + 7) / 8;
    hdr->alpha_bits = hdr->descriptor & 0x0f;
    hdr->flip_horiz = (hdr->descriptor & 0x10) ? 1 : 0;
    hdr->flip_vert = (hdr->descriptor & 0x20) ? 0 : 1;  /* Default is bottom-up */

    return 0;
}

static int validate_tga_header(TGAHeader *hdr) {
    /* Validate dimensions */
    if (hdr->width == 0 || hdr->height == 0)
        return -1;
    if (hdr->width > MAX_IMAGE_SIZE || hdr->height > MAX_IMAGE_SIZE)
        return -1;

    /* Validate image type */
    if (hdr->image_type == 0)
        return -1;

    /* Validate bits per pixel */
    switch (hdr->image_type) {
        case TGA_TYPE_MAPPED:
            if (hdr->bpp != 8)
                return -1;
            if (hdr->colormap_type != 1)
                return -1;
            if (hdr->colormap_length == 0 || hdr->colormap_length > MAX_COLORMAP_SIZE)
                return -1;
            break;
        case TGA_TYPE_COLOR:
            if (hdr->bpp != 15 && hdr->bpp != 16 && hdr->bpp != 24 && hdr->bpp != 32)
                return -1;
            break;
        case TGA_TYPE_GRAY:
            if (hdr->bpp != 8 && hdr->bpp != 16)
                return -1;
            break;
    }

    return 0;
}

static int read_colormap(FILE *fp, TGAHeader *hdr, uint8_t **colormap) {
    if (hdr->colormap_type != 1 || hdr->colormap_length == 0)
        return 0;

    uint32_t entry_size = (hdr->colormap_size + 7) / 8;
    size_t colormap_bytes = (size_t)hdr->colormap_length * entry_size;

    if (colormap_bytes > 256 * 4)  /* Max 256 entries * 4 bytes */
        return -1;

    *colormap = malloc(colormap_bytes);
    if (!*colormap)
        return -1;

    if (fread(*colormap, 1, colormap_bytes, fp) != colormap_bytes) {
        free(*colormap);
        *colormap = NULL;
        return -1;
    }

    return 0;
}

static int decode_rle(FILE *fp, uint8_t *output, size_t output_size, uint32_t bytes_per_pixel) {
    size_t pos = 0;

    while (pos < output_size) {
        int packet_header = fgetc(fp);
        if (packet_header == EOF)
            return -1;

        uint32_t count = (packet_header & 0x7f) + 1;
        size_t bytes_needed = (size_t)count * bytes_per_pixel;

        if (pos + bytes_needed > output_size)
            return -1;  /* Would overflow buffer */

        if (packet_header & 0x80) {
            /* RLE packet - read one pixel, repeat count times */
            uint8_t pixel[4];
            if (fread(pixel, 1, bytes_per_pixel, fp) != bytes_per_pixel)
                return -1;

            for (uint32_t i = 0; i < count; i++) {
                memcpy(output + pos, pixel, bytes_per_pixel);
                pos += bytes_per_pixel;
            }
        } else {
            /* Raw packet - read count pixels */
            if (fread(output + pos, 1, bytes_needed, fp) != bytes_needed)
                return -1;
            pos += bytes_needed;
        }
    }

    return 0;
}

static int load_tga_image(FILE *fp, TGAHeader *hdr, uint8_t *colormap) {
    size_t pixel_count = (size_t)hdr->width * hdr->height;
    size_t raw_size = pixel_count * hdr->bytes_per_pixel;

    /* Limit memory allocation */
    if (raw_size > 256 * 1024 * 1024)
        return -1;

    uint8_t *raw_data = malloc(raw_size);
    if (!raw_data)
        return -1;

    int result = 0;

    if (hdr->compression == TGA_COMP_RLE) {
        result = decode_rle(fp, raw_data, raw_size, hdr->bytes_per_pixel);
    } else {
        if (fread(raw_data, 1, raw_size, fp) != raw_size)
            result = -1;
    }

    if (result != 0) {
        free(raw_data);
        return -1;
    }

    /* Simulate pixel conversion (where many bugs occur) */
    size_t output_channels = 3;  /* RGB */
    if (hdr->alpha_bits > 0)
        output_channels = 4;  /* RGBA */

    size_t output_size = pixel_count * output_channels;
    if (output_size > 256 * 1024 * 1024) {
        free(raw_data);
        return -1;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(raw_data);
        return -1;
    }

    /* Convert pixels based on type */
    for (size_t i = 0; i < pixel_count; i++) {
        uint8_t *src = raw_data + i * hdr->bytes_per_pixel;
        uint8_t *dst = output + i * output_channels;

        switch (hdr->image_type) {
            case TGA_TYPE_MAPPED:
                if (colormap && src[0] < hdr->colormap_length) {
                    uint32_t entry_size = (hdr->colormap_size + 7) / 8;
                    uint8_t *cmap_entry = colormap + src[0] * entry_size;
                    if (entry_size >= 3) {
                        dst[0] = cmap_entry[2];  /* R */
                        dst[1] = cmap_entry[1];  /* G */
                        dst[2] = cmap_entry[0];  /* B */
                    }
                    if (output_channels == 4 && entry_size >= 4)
                        dst[3] = cmap_entry[3];  /* A */
                }
                break;

            case TGA_TYPE_COLOR:
                if (hdr->bpp == 24 || hdr->bpp == 32) {
                    dst[0] = src[2];  /* R */
                    dst[1] = src[1];  /* G */
                    dst[2] = src[0];  /* B */
                    if (output_channels == 4 && hdr->bpp == 32)
                        dst[3] = src[3];  /* A */
                } else if (hdr->bpp == 15 || hdr->bpp == 16) {
                    uint16_t pixel = src[0] | (src[1] << 8);
                    dst[0] = ((pixel >> 10) & 0x1f) << 3;  /* R */
                    dst[1] = ((pixel >> 5) & 0x1f) << 3;   /* G */
                    dst[2] = (pixel & 0x1f) << 3;          /* B */
                }
                break;

            case TGA_TYPE_GRAY:
                dst[0] = dst[1] = dst[2] = src[0];
                if (output_channels == 4 && hdr->bpp == 16)
                    dst[3] = src[1];
                break;
        }
    }

    free(output);
    free(raw_data);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 18)  /* Minimum TGA header size */
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    TGAHeader hdr;
    if (read_tga_header(fp, &hdr) != 0) {
        fclose(fp);
        return 0;
    }

    if (validate_tga_header(&hdr) != 0) {
        fclose(fp);
        return 0;
    }

    /* Skip ID field */
    if (hdr.id_length > 0) {
        if (fseek(fp, hdr.id_length, SEEK_CUR) != 0) {
            fclose(fp);
            return 0;
        }
    }

    /* Read colormap */
    uint8_t *colormap = NULL;
    if (read_colormap(fp, &hdr, &colormap) != 0) {
        fclose(fp);
        return 0;
    }

    /* Load image data */
    load_tga_image(fp, &hdr, colormap);

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
