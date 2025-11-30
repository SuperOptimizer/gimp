/*
 * PAA (Bohemia Interactive) Texture Format Fuzzer
 *
 * Standalone harness for fuzzing Bohemia PAA texture parsing.
 * Based on GIMP's file-paa plugin.
 *
 * PAA format features (used in ARMA games):
 * - Multiple pixel formats (ARGB4444, ARGB1555, ARGB8888)
 * - DXT1-5 compression support
 * - LZSS compression for mipmap data
 * - Mipmap chain storage
 * - Tagged file structure
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* PAA constants */
#define PAA_MAX_WIDTH  8192
#define PAA_MAX_HEIGHT 8192
#define PAA_MAX_IMAGE_SIZE (64 * 1024 * 1024)
#define PAA_MAX_MIPMAPS 16

/* PAA pixel types */
#define PAA_RGBA_4444   0x4444
#define PAA_RGBA_5551   0x1555
#define PAA_GRAY_ALPHA  0x8080
#define PAA_RGBA_8888   0x8888
#define PAA_DXT1        0xFF01
#define PAA_DXT2        0xFF02
#define PAA_DXT3        0xFF03
#define PAA_DXT4        0xFF04
#define PAA_DXT5        0xFF05

/* PAA tag types */
#define PAA_TAG_AVGC    0x01  /* Average color */
#define PAA_TAG_MAXC    0x02  /* Max color */
#define PAA_TAG_FLAG    0x03  /* Flags */
#define PAA_TAG_SWIZ    0x04  /* Swizzle */
#define PAA_TAG_PROC    0x05  /* Procedure */
#define PAA_TAG_OFFS    0xFF  /* Offset table */

/* Mipmap entry */
typedef struct {
    uint16_t width;
    uint16_t height;
    uint32_t data_size;
    uint32_t offset;
} paa_mipmap_t;

/* PAA header info */
typedef struct {
    uint16_t type;
    int num_mipmaps;
    paa_mipmap_t mipmaps[PAA_MAX_MIPMAPS];
} paa_header_t;

/* Read little-endian integers */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* LZSS decompression */
static int decode_lzss(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_len) {
    size_t src_pos = 0;
    size_t dst_pos = 0;

    /* LZSS uses a ring buffer */
    uint8_t ring[4096];
    int ring_pos = 0;
    memset(ring, 0, sizeof(ring));

    while (src_pos < src_len && dst_pos < dst_len) {
        /* Read flags byte */
        if (src_pos >= src_len) break;
        uint8_t flags = src[src_pos++];

        for (int bit = 0; bit < 8 && dst_pos < dst_len; bit++) {
            if (flags & (1 << bit)) {
                /* Literal byte */
                if (src_pos >= src_len) break;
                uint8_t byte = src[src_pos++];
                dst[dst_pos++] = byte;
                ring[ring_pos] = byte;
                ring_pos = (ring_pos + 1) & 0xFFF;
            } else {
                /* Back reference */
                if (src_pos + 1 >= src_len) break;
                uint16_t ref = read_u16_le(src + src_pos);
                src_pos += 2;

                int offset = ref & 0xFFF;
                int length = ((ref >> 12) & 0x0F) + 3;

                for (int i = 0; i < length && dst_pos < dst_len; i++) {
                    uint8_t byte = ring[(offset + i) & 0xFFF];
                    dst[dst_pos++] = byte;
                    ring[ring_pos] = byte;
                    ring_pos = (ring_pos + 1) & 0xFFF;
                }
            }
        }
    }

    return dst_pos;
}

/* Convert ARGB1555 to RGBA8888 */
static void convert_argb1555(uint16_t color, uint8_t *rgba) {
    rgba[0] = ((color >> 10) & 0x1F) * 255 / 31;  /* R */
    rgba[1] = ((color >> 5) & 0x1F) * 255 / 31;   /* G */
    rgba[2] = (color & 0x1F) * 255 / 31;          /* B */
    rgba[3] = (color & 0x8000) ? 255 : 0;         /* A */
}

/* Convert ARGB4444 to RGBA8888 */
static void convert_argb4444(uint16_t color, uint8_t *rgba) {
    rgba[0] = ((color >> 8) & 0x0F) * 255 / 15;   /* R */
    rgba[1] = ((color >> 4) & 0x0F) * 255 / 15;   /* G */
    rgba[2] = (color & 0x0F) * 255 / 15;          /* B */
    rgba[3] = ((color >> 12) & 0x0F) * 255 / 15;  /* A */
}

/* Decode DXT1 block */
static void decode_dxt1_block(const uint8_t *src, uint8_t *dst,
                              int stride, int has_alpha) {
    uint16_t c0 = read_u16_le(src);
    uint16_t c1 = read_u16_le(src + 2);
    uint32_t bits = read_u32_le(src + 4);

    /* Decode endpoint colors */
    uint8_t colors[4][4];

    colors[0][0] = ((c0 >> 11) & 0x1F) * 255 / 31;
    colors[0][1] = ((c0 >> 5) & 0x3F) * 255 / 63;
    colors[0][2] = (c0 & 0x1F) * 255 / 31;
    colors[0][3] = 255;

    colors[1][0] = ((c1 >> 11) & 0x1F) * 255 / 31;
    colors[1][1] = ((c1 >> 5) & 0x3F) * 255 / 63;
    colors[1][2] = (c1 & 0x1F) * 255 / 31;
    colors[1][3] = 255;

    if (c0 > c1) {
        /* 4-color mode */
        for (int i = 0; i < 3; i++) {
            colors[2][i] = (2 * colors[0][i] + colors[1][i]) / 3;
            colors[3][i] = (colors[0][i] + 2 * colors[1][i]) / 3;
        }
        colors[2][3] = colors[3][3] = 255;
    } else {
        /* 3-color + transparent mode */
        for (int i = 0; i < 3; i++) {
            colors[2][i] = (colors[0][i] + colors[1][i]) / 2;
            colors[3][i] = 0;
        }
        colors[2][3] = 255;
        colors[3][3] = has_alpha ? 0 : 255;
    }

    /* Write pixels */
    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; x++) {
            int idx = (bits >> (2 * (y * 4 + x))) & 0x03;
            uint8_t *p = dst + y * stride + x * 4;
            p[0] = colors[idx][0];
            p[1] = colors[idx][1];
            p[2] = colors[idx][2];
            p[3] = colors[idx][3];
        }
    }
}

/* Decode DXT5 block (DXT3/4/5 alpha) */
static void decode_dxt5_block(const uint8_t *src, uint8_t *dst, int stride) {
    /* Alpha endpoints */
    uint8_t a0 = src[0];
    uint8_t a1 = src[1];

    /* Alpha lookup table */
    uint8_t alphas[8];
    alphas[0] = a0;
    alphas[1] = a1;

    if (a0 > a1) {
        for (int i = 1; i < 7; i++) {
            alphas[i + 1] = ((7 - i) * a0 + i * a1) / 7;
        }
    } else {
        for (int i = 1; i < 5; i++) {
            alphas[i + 1] = ((5 - i) * a0 + i * a1) / 5;
        }
        alphas[6] = 0;
        alphas[7] = 255;
    }

    /* Extract 3-bit alpha indices */
    uint64_t alpha_bits = 0;
    for (int i = 0; i < 6; i++) {
        alpha_bits |= ((uint64_t)src[2 + i]) << (i * 8);
    }

    /* Apply alpha values */
    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; x++) {
            int idx = (alpha_bits >> (3 * (y * 4 + x))) & 0x07;
            uint8_t *p = dst + y * stride + x * 4;
            p[3] = alphas[idx];
        }
    }

    /* Decode color part (same as DXT1 but starts at offset 8) */
    decode_dxt1_block(src + 8, dst, stride, 0);
}

/* Decode mipmap data based on format */
static int decode_mipmap(const uint8_t *data, size_t size, size_t offset,
                         int width, int height, uint16_t type,
                         uint32_t compressed_size, uint8_t *output) {
    if (offset + compressed_size > size) return -1;

    size_t pixel_count = (size_t)width * height;
    size_t output_size = pixel_count * 4;

    /* Check if data needs LZSS decompression */
    uint8_t *decoded = NULL;
    const uint8_t *src_data;
    size_t src_size;

    /* Estimate decompressed size based on format */
    size_t expected_size;
    int bytes_per_pixel;

    switch (type) {
        case PAA_RGBA_4444:
        case PAA_RGBA_5551:
        case PAA_GRAY_ALPHA:
            bytes_per_pixel = 2;
            expected_size = pixel_count * bytes_per_pixel;
            break;
        case PAA_RGBA_8888:
            bytes_per_pixel = 4;
            expected_size = pixel_count * bytes_per_pixel;
            break;
        case PAA_DXT1:
            expected_size = ((width + 3) / 4) * ((height + 3) / 4) * 8;
            break;
        case PAA_DXT3:
        case PAA_DXT5:
            expected_size = ((width + 3) / 4) * ((height + 3) / 4) * 16;
            break;
        default:
            return -1;
    }

    /* Check if LZSS compressed (compressed_size < expected) */
    if (compressed_size < expected_size && compressed_size > 0) {
        decoded = malloc(expected_size);
        if (!decoded) return -1;

        int dec_len = decode_lzss(data + offset, compressed_size,
                                  decoded, expected_size);
        if (dec_len < 0) {
            free(decoded);
            return -1;
        }
        src_data = decoded;
        src_size = dec_len;
    } else {
        src_data = data + offset;
        src_size = compressed_size;
    }

    /* Decode based on format */
    switch (type) {
        case PAA_RGBA_5551:
            for (size_t i = 0; i < pixel_count && i * 2 + 1 < src_size; i++) {
                uint16_t color = read_u16_le(src_data + i * 2);
                convert_argb1555(color, output + i * 4);
            }
            break;

        case PAA_RGBA_4444:
            for (size_t i = 0; i < pixel_count && i * 2 + 1 < src_size; i++) {
                uint16_t color = read_u16_le(src_data + i * 2);
                convert_argb4444(color, output + i * 4);
            }
            break;

        case PAA_RGBA_8888:
            for (size_t i = 0; i < pixel_count && i * 4 + 3 < src_size; i++) {
                output[i * 4 + 0] = src_data[i * 4 + 2];  /* R */
                output[i * 4 + 1] = src_data[i * 4 + 1];  /* G */
                output[i * 4 + 2] = src_data[i * 4 + 0];  /* B */
                output[i * 4 + 3] = src_data[i * 4 + 3];  /* A */
            }
            break;

        case PAA_DXT1: {
            int blocks_x = (width + 3) / 4;
            int blocks_y = (height + 3) / 4;
            size_t block_offset = 0;

            for (int by = 0; by < blocks_y; by++) {
                for (int bx = 0; bx < blocks_x; bx++) {
                    if (block_offset + 8 > src_size) break;

                    /* Decode into temporary 4x4 block */
                    uint8_t block[4 * 4 * 4];
                    decode_dxt1_block(src_data + block_offset, block, 16, 1);

                    /* Copy to output */
                    for (int y = 0; y < 4 && by * 4 + y < height; y++) {
                        for (int x = 0; x < 4 && bx * 4 + x < width; x++) {
                            size_t dst = ((by * 4 + y) * width + bx * 4 + x) * 4;
                            memcpy(output + dst, block + (y * 4 + x) * 4, 4);
                        }
                    }

                    block_offset += 8;
                }
            }
            break;
        }

        case PAA_DXT5: {
            int blocks_x = (width + 3) / 4;
            int blocks_y = (height + 3) / 4;
            size_t block_offset = 0;

            for (int by = 0; by < blocks_y; by++) {
                for (int bx = 0; bx < blocks_x; bx++) {
                    if (block_offset + 16 > src_size) break;

                    uint8_t block[4 * 4 * 4];
                    decode_dxt5_block(src_data + block_offset, block, 16);

                    for (int y = 0; y < 4 && by * 4 + y < height; y++) {
                        for (int x = 0; x < 4 && bx * 4 + x < width; x++) {
                            size_t dst = ((by * 4 + y) * width + bx * 4 + x) * 4;
                            memcpy(output + dst, block + (y * 4 + x) * 4, 4);
                        }
                    }

                    block_offset += 16;
                }
            }
            break;
        }
    }

    if (decoded) free(decoded);
    return 0;
}

/* Parse PAA header and mipmap table */
static int parse_paa_header(const uint8_t *data, size_t size,
                            paa_header_t *hdr) {
    if (size < 6) return -1;

    hdr->type = read_u16_le(data);

    /* Validate type */
    if (hdr->type != PAA_RGBA_4444 && hdr->type != PAA_RGBA_5551 &&
        hdr->type != PAA_GRAY_ALPHA && hdr->type != PAA_RGBA_8888 &&
        hdr->type != PAA_DXT1 && hdr->type != PAA_DXT2 &&
        hdr->type != PAA_DXT3 && hdr->type != PAA_DXT4 &&
        hdr->type != PAA_DXT5) {
        return -1;
    }

    size_t pos = 2;

    /* Read tags until OFFS tag */
    while (pos + 2 < size) {
        uint8_t tag = data[pos++];

        if (tag == PAA_TAG_OFFS) {
            /* Offset table follows */
            break;
        }

        /* Skip tag data based on tag type */
        if (pos + 4 > size) return -1;

        uint32_t tag_size = read_u32_le(data + pos);
        pos += 4;

        if (pos + tag_size > size) return -1;
        pos += tag_size;
    }

    /* Read mipmap offsets */
    hdr->num_mipmaps = 0;
    while (pos + 4 <= size && hdr->num_mipmaps < PAA_MAX_MIPMAPS) {
        uint32_t mip_offset = read_u32_le(data + pos);
        pos += 4;

        if (mip_offset == 0) break;
        if (mip_offset >= size) continue;

        /* Read mipmap header at offset */
        if (mip_offset + 6 > size) continue;

        hdr->mipmaps[hdr->num_mipmaps].width = read_u16_le(data + mip_offset);
        hdr->mipmaps[hdr->num_mipmaps].height = read_u16_le(data + mip_offset + 2);
        hdr->mipmaps[hdr->num_mipmaps].data_size = read_u16_le(data + mip_offset + 4);

        /* Handle 3-byte size for larger textures */
        if (hdr->mipmaps[hdr->num_mipmaps].data_size == 0 && mip_offset + 7 <= size) {
            hdr->mipmaps[hdr->num_mipmaps].data_size =
                data[mip_offset + 4] |
                (data[mip_offset + 5] << 8) |
                (data[mip_offset + 6] << 16);
            hdr->mipmaps[hdr->num_mipmaps].offset = mip_offset + 7;
        } else {
            hdr->mipmaps[hdr->num_mipmaps].offset = mip_offset + 6;
        }

        /* Validate dimensions */
        if (hdr->mipmaps[hdr->num_mipmaps].width > PAA_MAX_WIDTH ||
            hdr->mipmaps[hdr->num_mipmaps].height > PAA_MAX_HEIGHT) {
            continue;
        }

        hdr->num_mipmaps++;
    }

    return (hdr->num_mipmaps > 0) ? 0 : -1;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    paa_header_t hdr;

    if (parse_paa_header(data, size, &hdr) != 0) {
        return 0;
    }

    /* Decode largest mipmap (first one) */
    if (hdr.num_mipmaps > 0) {
        paa_mipmap_t *mip = &hdr.mipmaps[0];

        size_t output_size = (size_t)mip->width * mip->height * 4;
        if (output_size > PAA_MAX_IMAGE_SIZE) {
            return 0;
        }

        uint8_t *output = malloc(output_size);
        if (output) {
            decode_mipmap(data, size, mip->offset,
                          mip->width, mip->height, hdr.type,
                          mip->data_size, output);
            free(output);
        }
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
