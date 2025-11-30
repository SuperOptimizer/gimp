/*
 * DDS (DirectDraw Surface) Texture Format Fuzzer
 *
 * Standalone harness for fuzzing DDS texture file parsing.
 * Based on GIMP's file-dds plugin.
 *
 * DDS is a Microsoft texture format supporting:
 * - Multiple compression formats (DXT1-5, BC4-7)
 * - Mipmaps and cubemaps
 * - Volume textures
 * - DX10 extended header
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* DDS Magic number */
#define DDS_MAGIC 0x20534444  /* "DDS " */

/* DDS Header flags */
#define DDSD_CAPS        0x00000001
#define DDSD_HEIGHT      0x00000002
#define DDSD_WIDTH       0x00000004
#define DDSD_PITCH       0x00000008
#define DDSD_PIXELFORMAT 0x00001000
#define DDSD_MIPMAPCOUNT 0x00020000
#define DDSD_LINEARSIZE  0x00080000
#define DDSD_DEPTH       0x00800000

/* Pixel format flags */
#define DDPF_ALPHAPIXELS 0x00000001
#define DDPF_ALPHA       0x00000002
#define DDPF_FOURCC      0x00000004
#define DDPF_RGB         0x00000040
#define DDPF_YUV         0x00000200
#define DDPF_LUMINANCE   0x00020000
#define DDPF_BUMPDUDV    0x00080000

/* Caps flags */
#define DDSCAPS_COMPLEX  0x00000008
#define DDSCAPS_TEXTURE  0x00001000
#define DDSCAPS_MIPMAP   0x00400000

/* Caps2 flags */
#define DDSCAPS2_CUBEMAP           0x00000200
#define DDSCAPS2_CUBEMAP_POSITIVEX 0x00000400
#define DDSCAPS2_CUBEMAP_NEGATIVEX 0x00000800
#define DDSCAPS2_CUBEMAP_POSITIVEY 0x00001000
#define DDSCAPS2_CUBEMAP_NEGATIVEY 0x00002000
#define DDSCAPS2_CUBEMAP_POSITIVEZ 0x00004000
#define DDSCAPS2_CUBEMAP_NEGATIVEZ 0x00008000
#define DDSCAPS2_VOLUME            0x00200000

/* FOURCC codes */
#define FOURCC_DXT1 0x31545844  /* "DXT1" */
#define FOURCC_DXT2 0x32545844  /* "DXT2" */
#define FOURCC_DXT3 0x33545844  /* "DXT3" */
#define FOURCC_DXT4 0x34545844  /* "DXT4" */
#define FOURCC_DXT5 0x35545844  /* "DXT5" */
#define FOURCC_DX10 0x30315844  /* "DX10" */
#define FOURCC_ATI1 0x31495441  /* "ATI1" */
#define FOURCC_ATI2 0x32495441  /* "ATI2" */
#define FOURCC_BC4U 0x55344342  /* "BC4U" */
#define FOURCC_BC4S 0x53344342  /* "BC4S" */
#define FOURCC_BC5U 0x55354342  /* "BC5U" */
#define FOURCC_BC5S 0x53354342  /* "BC5S" */
#define FOURCC_RXGB 0x42475852  /* "RXGB" */

/* DDS Pixel Format structure */
typedef struct {
    uint32_t size;
    uint32_t flags;
    uint32_t fourcc;
    uint32_t rgb_bitcount;
    uint32_t r_mask;
    uint32_t g_mask;
    uint32_t b_mask;
    uint32_t a_mask;
} dds_pixelformat_t;

/* DDS Header structure */
typedef struct {
    uint32_t magic;
    uint32_t size;
    uint32_t flags;
    uint32_t height;
    uint32_t width;
    uint32_t pitch_or_linsize;
    uint32_t depth;
    uint32_t mipmap_count;
    uint32_t reserved[11];
    dds_pixelformat_t pixelfmt;
    uint32_t caps;
    uint32_t caps2;
    uint32_t caps3;
    uint32_t caps4;
    uint32_t reserved2;
} dds_header_t;

/* DX10 Header extension */
typedef struct {
    uint32_t dxgi_format;
    uint32_t resource_dimension;
    uint32_t misc_flag;
    uint32_t array_size;
    uint32_t misc_flags2;
} dds_header_dx10_t;

/* Maximum dimensions to prevent excessive memory allocation */
#define MAX_WIDTH  16384
#define MAX_HEIGHT 16384
#define MAX_DEPTH  2048
#define MAX_MIPMAPS 16
#define MAX_IMAGE_SIZE (256 * 1024 * 1024)  /* 256MB */

/* Read little-endian integers */
static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* Calculate the size of a block-compressed image */
static size_t calc_compressed_size(uint32_t width, uint32_t height,
                                   uint32_t block_size) {
    uint32_t blocks_x = (width + 3) / 4;
    uint32_t blocks_y = (height + 3) / 4;
    return (size_t)blocks_x * blocks_y * block_size;
}

/* Decode DXT1 block (simplified) */
static void decode_dxt1_block(const uint8_t *src, uint8_t *dst,
                              int dst_pitch, int alpha) {
    uint16_t c0 = read_u16_le(src);
    uint16_t c1 = read_u16_le(src + 2);
    uint32_t indices = read_u32_le(src + 4);

    /* Extract RGB565 colors */
    uint8_t colors[4][4];

    colors[0][0] = ((c0 >> 11) & 0x1F) << 3;
    colors[0][1] = ((c0 >> 5) & 0x3F) << 2;
    colors[0][2] = (c0 & 0x1F) << 3;
    colors[0][3] = 255;

    colors[1][0] = ((c1 >> 11) & 0x1F) << 3;
    colors[1][1] = ((c1 >> 5) & 0x3F) << 2;
    colors[1][2] = (c1 & 0x1F) << 3;
    colors[1][3] = 255;

    if (c0 > c1) {
        colors[2][0] = (2 * colors[0][0] + colors[1][0] + 1) / 3;
        colors[2][1] = (2 * colors[0][1] + colors[1][1] + 1) / 3;
        colors[2][2] = (2 * colors[0][2] + colors[1][2] + 1) / 3;
        colors[2][3] = 255;

        colors[3][0] = (colors[0][0] + 2 * colors[1][0] + 1) / 3;
        colors[3][1] = (colors[0][1] + 2 * colors[1][1] + 1) / 3;
        colors[3][2] = (colors[0][2] + 2 * colors[1][2] + 1) / 3;
        colors[3][3] = 255;
    } else {
        colors[2][0] = (colors[0][0] + colors[1][0]) / 2;
        colors[2][1] = (colors[0][1] + colors[1][1]) / 2;
        colors[2][2] = (colors[0][2] + colors[1][2]) / 2;
        colors[2][3] = 255;

        colors[3][0] = 0;
        colors[3][1] = 0;
        colors[3][2] = 0;
        colors[3][3] = alpha ? 0 : 255;
    }

    /* Decode 4x4 block */
    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; x++) {
            int idx = (indices >> (2 * (y * 4 + x))) & 0x3;
            uint8_t *pixel = dst + y * dst_pitch + x * 4;
            pixel[0] = colors[idx][0];
            pixel[1] = colors[idx][1];
            pixel[2] = colors[idx][2];
            pixel[3] = colors[idx][3];
        }
    }
}

/* Decode DXT3 block (simplified) */
static void decode_dxt3_block(const uint8_t *src, uint8_t *dst, int dst_pitch) {
    /* Alpha is stored as 4-bit values in first 8 bytes */
    uint64_t alpha_data;
    memcpy(&alpha_data, src, 8);

    /* Decode color part (same as DXT1) */
    decode_dxt1_block(src + 8, dst, dst_pitch, 0);

    /* Apply alpha values */
    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; x++) {
            int idx = y * 4 + x;
            uint8_t a = (alpha_data >> (4 * idx)) & 0xF;
            dst[y * dst_pitch + x * 4 + 3] = (a << 4) | a;
        }
    }
}

/* Decode DXT5 block (simplified) */
static void decode_dxt5_block(const uint8_t *src, uint8_t *dst, int dst_pitch) {
    uint8_t a0 = src[0];
    uint8_t a1 = src[1];
    uint8_t alphas[8];

    alphas[0] = a0;
    alphas[1] = a1;

    if (a0 > a1) {
        for (int i = 0; i < 6; i++) {
            alphas[2 + i] = ((6 - i) * a0 + (1 + i) * a1 + 3) / 7;
        }
    } else {
        for (int i = 0; i < 4; i++) {
            alphas[2 + i] = ((4 - i) * a0 + (1 + i) * a1 + 2) / 5;
        }
        alphas[6] = 0;
        alphas[7] = 255;
    }

    /* Decode color part */
    decode_dxt1_block(src + 8, dst, dst_pitch, 0);

    /* Decode alpha indices (3-bit each, 48 bits total) */
    uint64_t alpha_indices = 0;
    for (int i = 0; i < 6; i++) {
        alpha_indices |= (uint64_t)src[2 + i] << (8 * i);
    }

    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; x++) {
            int idx = y * 4 + x;
            int a_idx = (alpha_indices >> (3 * idx)) & 0x7;
            dst[y * dst_pitch + x * 4 + 3] = alphas[a_idx];
        }
    }
}

/* Parse and validate DDS header */
static int parse_dds_header(const uint8_t *data, size_t size,
                            dds_header_t *header, dds_header_dx10_t *dx10) {
    if (size < 128) return -1;

    /* Parse header */
    header->magic = read_u32_le(data);
    header->size = read_u32_le(data + 4);
    header->flags = read_u32_le(data + 8);
    header->height = read_u32_le(data + 12);
    header->width = read_u32_le(data + 16);
    header->pitch_or_linsize = read_u32_le(data + 20);
    header->depth = read_u32_le(data + 24);
    header->mipmap_count = read_u32_le(data + 28);

    /* Pixel format at offset 76 */
    header->pixelfmt.size = read_u32_le(data + 76);
    header->pixelfmt.flags = read_u32_le(data + 80);
    header->pixelfmt.fourcc = read_u32_le(data + 84);
    header->pixelfmt.rgb_bitcount = read_u32_le(data + 88);
    header->pixelfmt.r_mask = read_u32_le(data + 92);
    header->pixelfmt.g_mask = read_u32_le(data + 96);
    header->pixelfmt.b_mask = read_u32_le(data + 100);
    header->pixelfmt.a_mask = read_u32_le(data + 104);

    /* Caps at offset 108 */
    header->caps = read_u32_le(data + 108);
    header->caps2 = read_u32_le(data + 112);

    /* Validate magic */
    if (header->magic != DDS_MAGIC) return -1;

    /* Validate header size */
    if (header->size != 124) return -1;

    /* Validate dimensions */
    if (header->width == 0 || header->width > MAX_WIDTH) return -1;
    if (header->height == 0 || header->height > MAX_HEIGHT) return -1;

    /* Handle depth for volume textures */
    if (header->flags & DDSD_DEPTH) {
        if (header->depth == 0 || header->depth > MAX_DEPTH) return -1;
    } else {
        header->depth = 1;
    }

    /* Handle mipmap count */
    if (header->flags & DDSD_MIPMAPCOUNT) {
        if (header->mipmap_count > MAX_MIPMAPS) {
            header->mipmap_count = MAX_MIPMAPS;
        }
    } else {
        header->mipmap_count = 1;
    }

    /* Parse DX10 header if present */
    if (header->pixelfmt.fourcc == FOURCC_DX10) {
        if (size < 148) return -1;

        dx10->dxgi_format = read_u32_le(data + 128);
        dx10->resource_dimension = read_u32_le(data + 132);
        dx10->misc_flag = read_u32_le(data + 136);
        dx10->array_size = read_u32_le(data + 140);
        dx10->misc_flags2 = read_u32_le(data + 144);
    }

    return 0;
}

/* Get the block size for compressed formats */
static int get_block_size(uint32_t fourcc) {
    switch (fourcc) {
        case FOURCC_DXT1:
        case FOURCC_ATI1:
        case FOURCC_BC4U:
        case FOURCC_BC4S:
            return 8;
        case FOURCC_DXT2:
        case FOURCC_DXT3:
        case FOURCC_DXT4:
        case FOURCC_DXT5:
        case FOURCC_ATI2:
        case FOURCC_BC5U:
        case FOURCC_BC5S:
        case FOURCC_RXGB:
            return 16;
        default:
            return 0;
    }
}

/* Decode a compressed DDS image */
static int decode_compressed(const uint8_t *data, size_t size,
                             const dds_header_t *header,
                             uint8_t *output, size_t output_size) {
    uint32_t width = header->width;
    uint32_t height = header->height;
    uint32_t fourcc = header->pixelfmt.fourcc;
    int block_size = get_block_size(fourcc);

    if (block_size == 0) return -1;

    size_t compressed_size = calc_compressed_size(width, height, block_size);
    size_t header_size = (fourcc == FOURCC_DX10) ? 148 : 128;

    if (size < header_size + compressed_size) return -1;

    const uint8_t *src = data + header_size;
    int dst_pitch = width * 4;

    uint32_t blocks_x = (width + 3) / 4;
    uint32_t blocks_y = (height + 3) / 4;

    for (uint32_t by = 0; by < blocks_y; by++) {
        for (uint32_t bx = 0; bx < blocks_x; bx++) {
            uint8_t block[64];  /* 4x4 RGBA */

            switch (fourcc) {
                case FOURCC_DXT1:
                    decode_dxt1_block(src, block, 16, 1);
                    break;
                case FOURCC_DXT2:
                case FOURCC_DXT3:
                    decode_dxt3_block(src, block, 16);
                    break;
                case FOURCC_DXT4:
                case FOURCC_DXT5:
                case FOURCC_RXGB:
                    decode_dxt5_block(src, block, 16);
                    break;
                default:
                    /* Just process the bytes for coverage */
                    memset(block, 0, sizeof(block));
                    break;
            }

            /* Copy block to output */
            int x_start = bx * 4;
            int y_start = by * 4;

            for (int y = 0; y < 4 && y_start + y < height; y++) {
                for (int x = 0; x < 4 && x_start + x < width; x++) {
                    size_t out_offset = (y_start + y) * dst_pitch + (x_start + x) * 4;
                    if (out_offset + 4 <= output_size) {
                        memcpy(output + out_offset, block + y * 16 + x * 4, 4);
                    }
                }
            }

            src += block_size;
        }
    }

    return 0;
}

/* Decode an uncompressed DDS image */
static int decode_uncompressed(const uint8_t *data, size_t size,
                               const dds_header_t *header,
                               uint8_t *output, size_t output_size) {
    uint32_t width = header->width;
    uint32_t height = header->height;
    uint32_t bpp = header->pixelfmt.rgb_bitcount;
    size_t header_size = 128;

    if (bpp == 0 || bpp > 128) return -1;

    size_t bytes_per_pixel = (bpp + 7) / 8;
    size_t row_size = width * bytes_per_pixel;
    size_t image_size = row_size * height;

    if (size < header_size + image_size) return -1;

    const uint8_t *src = data + header_size;

    uint32_t r_mask = header->pixelfmt.r_mask;
    uint32_t g_mask = header->pixelfmt.g_mask;
    uint32_t b_mask = header->pixelfmt.b_mask;
    uint32_t a_mask = header->pixelfmt.a_mask;

    /* Calculate shifts */
    int r_shift = 0, g_shift = 0, b_shift = 0, a_shift = 0;
    while (r_mask && !(r_mask & 1)) { r_shift++; r_mask >>= 1; }
    while (g_mask && !(g_mask & 1)) { g_shift++; g_mask >>= 1; }
    while (b_mask && !(b_mask & 1)) { b_shift++; b_mask >>= 1; }
    while (a_mask && !(a_mask & 1)) { a_shift++; a_mask >>= 1; }

    /* Reset masks */
    r_mask = header->pixelfmt.r_mask;
    g_mask = header->pixelfmt.g_mask;
    b_mask = header->pixelfmt.b_mask;
    a_mask = header->pixelfmt.a_mask;

    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < width; x++) {
            uint32_t pixel = 0;
            const uint8_t *p = src + y * row_size + x * bytes_per_pixel;

            for (size_t i = 0; i < bytes_per_pixel; i++) {
                pixel |= (uint32_t)p[i] << (8 * i);
            }

            size_t out_offset = (y * width + x) * 4;
            if (out_offset + 4 <= output_size) {
                if (r_mask) output[out_offset + 0] = ((pixel & r_mask) >> r_shift) * 255 / (r_mask >> r_shift);
                else output[out_offset + 0] = 0;

                if (g_mask) output[out_offset + 1] = ((pixel & g_mask) >> g_shift) * 255 / (g_mask >> g_shift);
                else output[out_offset + 1] = 0;

                if (b_mask) output[out_offset + 2] = ((pixel & b_mask) >> b_shift) * 255 / (b_mask >> b_shift);
                else output[out_offset + 2] = 0;

                if (a_mask) output[out_offset + 3] = ((pixel & a_mask) >> a_shift) * 255 / (a_mask >> a_shift);
                else output[out_offset + 3] = 255;
            }
        }
    }

    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    dds_header_t header;
    dds_header_dx10_t dx10;

    memset(&header, 0, sizeof(header));
    memset(&dx10, 0, sizeof(dx10));

    /* Parse header */
    if (parse_dds_header(data, size, &header, &dx10) != 0) {
        return 0;
    }

    /* Calculate output size */
    size_t output_size = (size_t)header.width * header.height * 4;
    if (output_size > MAX_IMAGE_SIZE) {
        return 0;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        return 0;
    }

    /* Decode based on format */
    if (header.pixelfmt.flags & DDPF_FOURCC) {
        decode_compressed(data, size, &header, output, output_size);
    } else if (header.pixelfmt.flags & DDPF_RGB) {
        decode_uncompressed(data, size, &header, output, output_size);
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
