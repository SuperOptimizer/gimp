/*
 * AFL++ fuzzing harness for GIMP XWD file parser
 * Based on plug-ins/common/file-xwd.c
 *
 * Targets: ZDI-25-909 and related XWD parsing vulnerabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

/* XWD header structure (big-endian on disk) */
typedef struct {
    uint32_t header_size;
    uint32_t file_version;
    uint32_t pixmap_format;
    uint32_t pixmap_depth;
    uint32_t pixmap_width;
    uint32_t pixmap_height;
    uint32_t xoffset;
    uint32_t byte_order;
    uint32_t bitmap_unit;
    uint32_t bitmap_bit_order;
    uint32_t bitmap_pad;
    uint32_t bits_per_pixel;
    uint32_t bytes_per_line;
    uint32_t visual_class;
    uint32_t red_mask;
    uint32_t green_mask;
    uint32_t blue_mask;
    uint32_t bits_per_rgb;
    uint32_t colormap_entries;
    uint32_t ncolors;
    uint32_t window_width;
    uint32_t window_height;
    uint32_t window_x;
    uint32_t window_y;
    uint32_t window_bdrwidth;
} XWDFileHeader;

typedef struct {
    uint32_t pixel;
    uint16_t red, green, blue;
    uint8_t flags, pad;
} XWDColor;

#define MAX_IMAGE_SIZE 262144  /* 256K pixels max per dimension */
#define MAX_COLORS 256

/* Simulate GIMP's pixel map structure */
#define MAPPERBITS 12
#define MAPPERMASK ((1 << MAPPERBITS) - 1)

typedef struct {
    uint32_t pixel_val;
    uint8_t red, green, blue;
} PixelMapEntry;

typedef struct {
    int npixel;
    uint8_t pixel_in_map[1 << MAPPERBITS];
    PixelMapEntry pmap[256];
} PixelMap;

static int read_xwd_header(FILE *fp, XWDFileHeader *hdr) {
    uint32_t buf[25];

    if (fread(buf, sizeof(uint32_t), 25, fp) != 25)
        return -1;

    /* Convert from big-endian */
    hdr->header_size = ntohl(buf[0]);
    hdr->file_version = ntohl(buf[1]);
    hdr->pixmap_format = ntohl(buf[2]);
    hdr->pixmap_depth = ntohl(buf[3]);
    hdr->pixmap_width = ntohl(buf[4]);
    hdr->pixmap_height = ntohl(buf[5]);
    hdr->xoffset = ntohl(buf[6]);
    hdr->byte_order = ntohl(buf[7]);
    hdr->bitmap_unit = ntohl(buf[8]);
    hdr->bitmap_bit_order = ntohl(buf[9]);
    hdr->bitmap_pad = ntohl(buf[10]);
    hdr->bits_per_pixel = ntohl(buf[11]);
    hdr->bytes_per_line = ntohl(buf[12]);
    hdr->visual_class = ntohl(buf[13]);
    hdr->red_mask = ntohl(buf[14]);
    hdr->green_mask = ntohl(buf[15]);
    hdr->blue_mask = ntohl(buf[16]);
    hdr->bits_per_rgb = ntohl(buf[17]);
    hdr->colormap_entries = ntohl(buf[18]);
    hdr->ncolors = ntohl(buf[19]);
    hdr->window_width = ntohl(buf[20]);
    hdr->window_height = ntohl(buf[21]);
    hdr->window_x = ntohl(buf[22]);
    hdr->window_y = ntohl(buf[23]);
    hdr->window_bdrwidth = ntohl(buf[24]);

    return 0;
}

static int read_xwd_colors(FILE *fp, XWDFileHeader *hdr, XWDColor *colors) {
    for (uint32_t i = 0; i < hdr->colormap_entries; i++) {
        uint32_t pixel;
        uint16_t rgb[3];
        uint8_t flags_pad[2];

        if (fread(&pixel, sizeof(uint32_t), 1, fp) != 1)
            return -1;
        if (fread(rgb, sizeof(uint16_t), 3, fp) != 3)
            return -1;
        if (fread(flags_pad, sizeof(uint8_t), 2, fp) != 2)
            return -1;

        colors[i].pixel = ntohl(pixel);
        colors[i].red = ntohs(rgb[0]);
        colors[i].green = ntohs(rgb[1]);
        colors[i].blue = ntohs(rgb[2]);
        colors[i].flags = flags_pad[0];
        colors[i].pad = flags_pad[1];
    }
    return 0;
}

static int set_pixelmap(int ncols, XWDColor *xwdcol, PixelMap *pixelmap) {
    memset(pixelmap->pixel_in_map, 0, sizeof(pixelmap->pixel_in_map));
    pixelmap->npixel = 0;

    for (int i = 0; i < ncols; i++) {
        uint32_t idx = xwdcol[i].pixel & MAPPERMASK;

        if (pixelmap->pixel_in_map[idx] == 0) {
            if (pixelmap->npixel >= 256)
                return -1;

            pixelmap->pixel_in_map[idx] = pixelmap->npixel + 1;
            pixelmap->pmap[pixelmap->npixel].pixel_val = xwdcol[i].pixel;
            pixelmap->pmap[pixelmap->npixel].red = xwdcol[i].red >> 8;
            pixelmap->pmap[pixelmap->npixel].green = xwdcol[i].green >> 8;
            pixelmap->pmap[pixelmap->npixel].blue = xwdcol[i].blue >> 8;
            pixelmap->npixel++;
        }
    }
    return 0;
}

/* Simulate reading pixel data for different formats */
static int load_xwd_f2_d8_b8(FILE *fp, XWDFileHeader *hdr, XWDColor *colors) {
    uint32_t width = hdr->pixmap_width;
    uint32_t height = hdr->pixmap_height;
    uint32_t bytes_per_line = hdr->bytes_per_line;

    /* Sanity checks similar to GIMP */
    if (width == 0 || height == 0)
        return -1;
    if (width > MAX_IMAGE_SIZE || height > MAX_IMAGE_SIZE)
        return -1;
    if (bytes_per_line > MAX_IMAGE_SIZE * 4)
        return -1;

    /* Allocate scanline buffer */
    uint8_t *scanline = malloc(bytes_per_line);
    if (!scanline)
        return -1;

    /* Allocate output buffer (simulating GIMP tile) */
    size_t output_size = (size_t)width * height * 3;
    if (output_size > 256 * 1024 * 1024) {  /* 256MB limit */
        free(scanline);
        return -1;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(scanline);
        return -1;
    }

    /* Read and process each scanline */
    for (uint32_t y = 0; y < height; y++) {
        if (fread(scanline, 1, bytes_per_line, fp) != bytes_per_line) {
            free(scanline);
            free(output);
            return -1;
        }

        /* Process pixels - this is where overflows could occur */
        for (uint32_t x = 0; x < width; x++) {
            uint8_t pixel = scanline[x];
            size_t out_idx = ((size_t)y * width + x) * 3;

            if (pixel < hdr->colormap_entries && colors) {
                output[out_idx] = colors[pixel].red >> 8;
                output[out_idx + 1] = colors[pixel].green >> 8;
                output[out_idx + 2] = colors[pixel].blue >> 8;
            }
        }
    }

    free(scanline);
    free(output);
    return 0;
}

static int load_xwd_f2_d24_b32(FILE *fp, XWDFileHeader *hdr) {
    uint32_t width = hdr->pixmap_width;
    uint32_t height = hdr->pixmap_height;
    uint32_t bytes_per_line = hdr->bytes_per_line;

    if (width == 0 || height == 0)
        return -1;
    if (width > MAX_IMAGE_SIZE || height > MAX_IMAGE_SIZE)
        return -1;
    if (bytes_per_line > MAX_IMAGE_SIZE * 4)
        return -1;

    uint8_t *scanline = malloc(bytes_per_line);
    if (!scanline)
        return -1;

    size_t output_size = (size_t)width * height * 3;
    if (output_size > 256 * 1024 * 1024) {
        free(scanline);
        return -1;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(scanline);
        return -1;
    }

    /* Calculate bit shifts for RGB extraction */
    uint32_t red_mask = hdr->red_mask;
    uint32_t green_mask = hdr->green_mask;
    uint32_t blue_mask = hdr->blue_mask;

    int red_shift = 0, green_shift = 0, blue_shift = 0;

    if (red_mask) {
        while ((red_mask & 1) == 0) { red_shift++; red_mask >>= 1; }
    }
    if (green_mask) {
        while ((green_mask & 1) == 0) { green_shift++; green_mask >>= 1; }
    }
    if (blue_mask) {
        while ((blue_mask & 1) == 0) { blue_shift++; blue_mask >>= 1; }
    }

    for (uint32_t y = 0; y < height; y++) {
        if (fread(scanline, 1, bytes_per_line, fp) != bytes_per_line) {
            free(scanline);
            free(output);
            return -1;
        }

        for (uint32_t x = 0; x < width; x++) {
            uint32_t pixel;
            size_t src_idx = x * 4;

            if (src_idx + 3 >= bytes_per_line)
                break;

            /* Handle byte order */
            if (hdr->byte_order == 0) {  /* LSBFirst */
                pixel = scanline[src_idx] |
                        (scanline[src_idx + 1] << 8) |
                        (scanline[src_idx + 2] << 16) |
                        (scanline[src_idx + 3] << 24);
            } else {  /* MSBFirst */
                pixel = (scanline[src_idx] << 24) |
                        (scanline[src_idx + 1] << 16) |
                        (scanline[src_idx + 2] << 8) |
                        scanline[src_idx + 3];
            }

            size_t out_idx = ((size_t)y * width + x) * 3;
            output[out_idx] = (pixel & hdr->red_mask) >> red_shift;
            output[out_idx + 1] = (pixel & hdr->green_mask) >> green_shift;
            output[out_idx + 2] = (pixel & hdr->blue_mask) >> blue_shift;
        }
    }

    free(scanline);
    free(output);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(XWDFileHeader))
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    XWDFileHeader hdr;
    if (read_xwd_header(fp, &hdr) != 0) {
        fclose(fp);
        return 0;
    }

    /* Validate file version */
    if (hdr.file_version != 7) {
        fclose(fp);
        return 0;
    }

    /* Seek to colormap position */
    if (fseek(fp, hdr.header_size, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }

    /* Read colormap if present */
    XWDColor *colors = NULL;
    if (hdr.colormap_entries > 0 && hdr.colormap_entries <= MAX_COLORS) {
        colors = malloc(hdr.colormap_entries * sizeof(XWDColor));
        if (colors) {
            if (read_xwd_colors(fp, &hdr, colors) != 0) {
                free(colors);
                fclose(fp);
                return 0;
            }
        }
    }

    /* Try different load paths based on format */
    uint32_t depth = hdr.pixmap_depth;
    uint32_t bpp = hdr.bits_per_pixel;

    switch (hdr.pixmap_format) {
        case 2:  /* Multiplane pixmaps */
            if (depth <= 8 && bpp == 8) {
                load_xwd_f2_d8_b8(fp, &hdr, colors);
            } else if (depth <= 24 && (bpp == 24 || bpp == 32)) {
                load_xwd_f2_d24_b32(fp, &hdr);
            }
            break;
    }

    if (colors)
        free(colors);
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
