/*
 * AFL++ fuzzing harness for BMP file parser
 * Based on GIMP plug-ins/file-bmp/
 *
 * Targets: RLE decompression, Huffman decoding, colormap handling,
 *          integer overflows in dimension calculations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_IMAGE_DIMENSION 32768
#define MAX_IMAGE_PIXELS (32768ULL * 32768ULL)
#define MAX_COLORMAP_SIZE 256

/* BMP compression types */
#define BI_RGB       0
#define BI_RLE8      1
#define BI_RLE4      2
#define BI_BITFIELDS 3
#define BI_JPEG      4
#define BI_PNG       5

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;         /* 'BM' */
    uint32_t file_size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t data_offset;
} BmpFileHeader;

typedef struct {
    uint32_t header_size;
    int32_t  width;
    int32_t  height;
    uint16_t planes;
    uint16_t bpp;
    uint32_t compression;
    uint32_t image_size;
    int32_t  x_ppm;
    int32_t  y_ppm;
    uint32_t colors_used;
    uint32_t colors_important;
} BmpInfoHeader;

typedef struct {
    uint32_t red_mask;
    uint32_t green_mask;
    uint32_t blue_mask;
    uint32_t alpha_mask;
} BmpBitfields;
#pragma pack(pop)

typedef struct {
    uint32_t mask;
    int shift;
    int bits;
} ChannelMask;

static int count_bits(uint32_t mask) {
    int count = 0;
    while (mask) {
        count += mask & 1;
        mask >>= 1;
    }
    return count;
}

static int find_shift(uint32_t mask) {
    if (mask == 0) return 0;
    int shift = 0;
    while ((mask & 1) == 0) {
        mask >>= 1;
        shift++;
    }
    return shift;
}

static void setup_channel(ChannelMask *ch, uint32_t mask) {
    ch->mask = mask;
    ch->shift = find_shift(mask);
    ch->bits = count_bits(mask);
}

static uint8_t extract_channel(uint32_t pixel, ChannelMask *ch) {
    if (ch->bits == 0) return 255;
    uint32_t val = (pixel & ch->mask) >> ch->shift;
    /* Scale to 8-bit */
    if (ch->bits < 8)
        val = (val * 255) / ((1 << ch->bits) - 1);
    else if (ch->bits > 8)
        val >>= (ch->bits - 8);
    return (uint8_t)val;
}

/* Decode RLE8 compressed data */
static int decode_rle8(const uint8_t *src, size_t src_size,
                       uint8_t *dst, int width, int height) {
    size_t src_pos = 0;
    int x = 0, y = 0;
    size_t dst_size = (size_t)width * height;

    while (src_pos + 1 < src_size && y < height) {
        uint8_t count = src[src_pos++];
        uint8_t value = src[src_pos++];

        if (count == 0) {
            /* Escape code */
            switch (value) {
                case 0: /* End of line */
                    x = 0;
                    y++;
                    break;
                case 1: /* End of bitmap */
                    return 0;
                case 2: /* Delta */
                    if (src_pos + 1 >= src_size) return -1;
                    x += src[src_pos++];
                    y += src[src_pos++];
                    break;
                default: /* Absolute mode */
                    {
                        int abs_count = value;
                        int padding = abs_count & 1;  /* Pad to word boundary */
                        if (src_pos + abs_count + padding > src_size)
                            return -1;
                        for (int i = 0; i < abs_count && y < height; i++) {
                            size_t dst_idx = (size_t)(height - 1 - y) * width + x;
                            if (dst_idx < dst_size)
                                dst[dst_idx] = src[src_pos];
                            src_pos++;
                            x++;
                            if (x >= width) { x = 0; y++; }
                        }
                        src_pos += padding;
                    }
                    break;
            }
        } else {
            /* Run of pixels */
            for (int i = 0; i < count && y < height; i++) {
                size_t dst_idx = (size_t)(height - 1 - y) * width + x;
                if (dst_idx < dst_size)
                    dst[dst_idx] = value;
                x++;
                if (x >= width) { x = 0; y++; }
            }
        }
    }
    return 0;
}

/* Decode RLE4 compressed data */
static int decode_rle4(const uint8_t *src, size_t src_size,
                       uint8_t *dst, int width, int height) {
    size_t src_pos = 0;
    int x = 0, y = 0;
    size_t dst_size = (size_t)width * height;

    while (src_pos + 1 < src_size && y < height) {
        uint8_t count = src[src_pos++];
        uint8_t value = src[src_pos++];

        if (count == 0) {
            switch (value) {
                case 0: x = 0; y++; break;
                case 1: return 0;
                case 2:
                    if (src_pos + 1 >= src_size) return -1;
                    x += src[src_pos++];
                    y += src[src_pos++];
                    break;
                default:
                    {
                        int abs_count = value;
                        int bytes_needed = (abs_count + 1) / 2;
                        int padding = bytes_needed & 1;
                        if (src_pos + bytes_needed + padding > src_size)
                            return -1;
                        for (int i = 0; i < abs_count && y < height; i++) {
                            uint8_t nibble;
                            if (i & 1)
                                nibble = src[src_pos++] & 0x0f;
                            else
                                nibble = src[src_pos] >> 4;
                            size_t dst_idx = (size_t)(height - 1 - y) * width + x;
                            if (dst_idx < dst_size)
                                dst[dst_idx] = nibble;
                            x++;
                            if (x >= width) { x = 0; y++; }
                        }
                        if (abs_count & 1) src_pos++;  /* Skip remaining nibble */
                        src_pos += padding;
                    }
                    break;
            }
        } else {
            uint8_t hi = value >> 4;
            uint8_t lo = value & 0x0f;
            for (int i = 0; i < count && y < height; i++) {
                size_t dst_idx = (size_t)(height - 1 - y) * width + x;
                if (dst_idx < dst_size)
                    dst[dst_idx] = (i & 1) ? lo : hi;
                x++;
                if (x >= width) { x = 0; y++; }
            }
        }
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(BmpFileHeader) + sizeof(BmpInfoHeader))
        return 0;

    const BmpFileHeader *file_hdr = (const BmpFileHeader *)data;
    const BmpInfoHeader *info_hdr = (const BmpInfoHeader *)(data + sizeof(BmpFileHeader));

    /* Check magic */
    if (file_hdr->magic != 0x4D42)  /* 'BM' little-endian */
        return 0;

    /* Validate dimensions */
    int32_t width = info_hdr->width;
    int32_t height = info_hdr->height;
    int top_down = 0;

    if (height < 0) {
        height = -height;
        top_down = 1;
    }

    if (width <= 0 || width > MAX_IMAGE_DIMENSION ||
        height <= 0 || height > MAX_IMAGE_DIMENSION)
        return 0;

    uint64_t pixel_count = (uint64_t)width * height;
    if (pixel_count > MAX_IMAGE_PIXELS)
        return 0;

    /* Validate header size */
    if (info_hdr->header_size < 40)
        return 0;

    uint16_t bpp = info_hdr->bpp;
    uint32_t compression = info_hdr->compression;

    /* Validate bpp */
    if (bpp != 1 && bpp != 4 && bpp != 8 && bpp != 16 &&
        bpp != 24 && bpp != 32)
        return 0;

    /* Calculate row size (padded to 4-byte boundary) */
    size_t row_size = ((size_t)width * bpp + 31) / 32 * 4;

    /* Find colormap if present */
    size_t colormap_offset = sizeof(BmpFileHeader) + info_hdr->header_size;
    int colormap_entries = 0;
    const uint8_t *colormap = NULL;

    if (bpp <= 8) {
        colormap_entries = info_hdr->colors_used;
        if (colormap_entries == 0)
            colormap_entries = 1 << bpp;
        if (colormap_entries > MAX_COLORMAP_SIZE)
            colormap_entries = MAX_COLORMAP_SIZE;

        if (colormap_offset + colormap_entries * 4 <= size) {
            colormap = data + colormap_offset;
        }
    }

    /* Find pixel data */
    if (file_hdr->data_offset >= size)
        return 0;

    const uint8_t *pixel_data = data + file_hdr->data_offset;
    size_t pixel_data_size = size - file_hdr->data_offset;

    /* Allocate output buffer */
    uint8_t *output = malloc(pixel_count * 4);  /* RGBA */
    if (!output)
        return 0;

    /* Handle bitfields for 16/32-bit images */
    ChannelMask masks[4] = {0};
    if (compression == BI_BITFIELDS && bpp >= 16) {
        size_t bf_offset = sizeof(BmpFileHeader) + info_hdr->header_size;
        if (info_hdr->header_size >= 52) {
            /* V4/V5 header includes masks */
            bf_offset = sizeof(BmpFileHeader) + 40;
        }
        if (bf_offset + sizeof(BmpBitfields) <= size) {
            const BmpBitfields *bf = (const BmpBitfields *)(data + bf_offset);
            setup_channel(&masks[0], bf->red_mask);
            setup_channel(&masks[1], bf->green_mask);
            setup_channel(&masks[2], bf->blue_mask);
            setup_channel(&masks[3], bf->alpha_mask);
        }
    } else if (bpp == 16) {
        /* Default 555 */
        setup_channel(&masks[0], 0x7C00);
        setup_channel(&masks[1], 0x03E0);
        setup_channel(&masks[2], 0x001F);
        setup_channel(&masks[3], 0x0000);
    } else if (bpp == 32) {
        /* Default BGRX */
        setup_channel(&masks[0], 0x00FF0000);
        setup_channel(&masks[1], 0x0000FF00);
        setup_channel(&masks[2], 0x000000FF);
        setup_channel(&masks[3], 0x00000000);
    }

    /* Decode based on compression type */
    switch (compression) {
        case BI_RGB:
        case BI_BITFIELDS:
            if (bpp == 24 || bpp == 32) {
                int bytes_per_pixel = bpp / 8;
                for (int y = 0; y < height; y++) {
                    int src_y = top_down ? y : (height - 1 - y);
                    if ((size_t)src_y * row_size + (size_t)width * bytes_per_pixel > pixel_data_size)
                        break;
                    const uint8_t *row = pixel_data + (size_t)src_y * row_size;
                    for (int x = 0; x < width; x++) {
                        size_t dst_idx = (size_t)y * width + x;
                        if (bpp == 24) {
                            output[dst_idx * 4 + 0] = row[x * 3 + 2];  /* R */
                            output[dst_idx * 4 + 1] = row[x * 3 + 1];  /* G */
                            output[dst_idx * 4 + 2] = row[x * 3 + 0];  /* B */
                            output[dst_idx * 4 + 3] = 255;
                        } else {
                            uint32_t pixel = *(uint32_t *)(row + x * 4);
                            output[dst_idx * 4 + 0] = extract_channel(pixel, &masks[0]);
                            output[dst_idx * 4 + 1] = extract_channel(pixel, &masks[1]);
                            output[dst_idx * 4 + 2] = extract_channel(pixel, &masks[2]);
                            output[dst_idx * 4 + 3] = extract_channel(pixel, &masks[3]);
                        }
                    }
                }
            } else if (bpp == 16) {
                for (int y = 0; y < height; y++) {
                    int src_y = top_down ? y : (height - 1 - y);
                    if ((size_t)src_y * row_size + (size_t)width * 2 > pixel_data_size)
                        break;
                    const uint8_t *row = pixel_data + (size_t)src_y * row_size;
                    for (int x = 0; x < width; x++) {
                        size_t dst_idx = (size_t)y * width + x;
                        uint16_t pixel = *(uint16_t *)(row + x * 2);
                        output[dst_idx * 4 + 0] = extract_channel(pixel, &masks[0]);
                        output[dst_idx * 4 + 1] = extract_channel(pixel, &masks[1]);
                        output[dst_idx * 4 + 2] = extract_channel(pixel, &masks[2]);
                        output[dst_idx * 4 + 3] = 255;
                    }
                }
            } else if (bpp <= 8 && colormap) {
                /* Indexed color */
                uint8_t *indexed = malloc(pixel_count);
                if (indexed) {
                    memset(indexed, 0, pixel_count);
                    for (int y = 0; y < height; y++) {
                        int src_y = top_down ? y : (height - 1 - y);
                        if ((size_t)src_y * row_size >= pixel_data_size)
                            break;
                        const uint8_t *row = pixel_data + (size_t)src_y * row_size;
                        for (int x = 0; x < width; x++) {
                            size_t dst_idx = (size_t)y * width + x;
                            uint8_t idx;
                            if (bpp == 8) {
                                if ((size_t)x < row_size)
                                    idx = row[x];
                                else
                                    idx = 0;
                            } else if (bpp == 4) {
                                size_t byte_idx = x / 2;
                                if (byte_idx < row_size) {
                                    if (x & 1)
                                        idx = row[byte_idx] & 0x0f;
                                    else
                                        idx = row[byte_idx] >> 4;
                                } else {
                                    idx = 0;
                                }
                            } else { /* bpp == 1 */
                                size_t byte_idx = x / 8;
                                if (byte_idx < row_size) {
                                    int bit = 7 - (x % 8);
                                    idx = (row[byte_idx] >> bit) & 1;
                                } else {
                                    idx = 0;
                                }
                            }
                            indexed[dst_idx] = idx;
                        }
                    }
                    /* Apply colormap */
                    for (size_t i = 0; i < pixel_count; i++) {
                        int idx = indexed[i];
                        if (idx < colormap_entries) {
                            output[i * 4 + 0] = colormap[idx * 4 + 2];
                            output[i * 4 + 1] = colormap[idx * 4 + 1];
                            output[i * 4 + 2] = colormap[idx * 4 + 0];
                            output[i * 4 + 3] = 255;
                        }
                    }
                    free(indexed);
                }
            }
            break;

        case BI_RLE8:
            if (bpp == 8 && colormap) {
                uint8_t *indexed = malloc(pixel_count);
                if (indexed) {
                    memset(indexed, 0, pixel_count);
                    decode_rle8(pixel_data, pixel_data_size, indexed, width, height);
                    for (size_t i = 0; i < pixel_count; i++) {
                        int idx = indexed[i];
                        if (idx < colormap_entries) {
                            output[i * 4 + 0] = colormap[idx * 4 + 2];
                            output[i * 4 + 1] = colormap[idx * 4 + 1];
                            output[i * 4 + 2] = colormap[idx * 4 + 0];
                            output[i * 4 + 3] = 255;
                        }
                    }
                    free(indexed);
                }
            }
            break;

        case BI_RLE4:
            if (bpp == 4 && colormap) {
                uint8_t *indexed = malloc(pixel_count);
                if (indexed) {
                    memset(indexed, 0, pixel_count);
                    decode_rle4(pixel_data, pixel_data_size, indexed, width, height);
                    for (size_t i = 0; i < pixel_count; i++) {
                        int idx = indexed[i];
                        if (idx < colormap_entries) {
                            output[i * 4 + 0] = colormap[idx * 4 + 2];
                            output[i * 4 + 1] = colormap[idx * 4 + 1];
                            output[i * 4 + 2] = colormap[idx * 4 + 0];
                            output[i * 4 + 3] = 255;
                        }
                    }
                    free(indexed);
                }
            }
            break;

        default:
            /* Unknown compression - skip */
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
/* Standalone mode - read from file */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bmp_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        fclose(fp);
        return 1;
    }

    if (fread(data, 1, size, fp) != size) {
        free(data);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}
#endif
