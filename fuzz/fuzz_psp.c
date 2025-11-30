/*
 * PSP (Paint Shop Pro) Image Format Fuzzer
 *
 * Standalone harness for fuzzing Paint Shop Pro PSP/TUB image parsing.
 * Based on GIMP's file-psp plugin.
 *
 * PSP format features:
 * - Block-based structure with various block types
 * - Multiple compression methods (None, RLE, LZ77/zlib)
 * - Multiple layers, channels, and alpha masks
 * - Versions 3-8+ supported
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <zlib.h>

/* PSP constants */
#define PSP_MAGIC "Paint Shop Pro Image File\n\032\0\0\0\0\0"
#define PSP_MAGIC_LEN 32

#define PSP_MAX_WIDTH  65536
#define PSP_MAX_HEIGHT 65536
#define PSP_MAX_IMAGE_SIZE (128 * 1024 * 1024)
#define PSP_MAX_LAYERS 1000

/* Block identifiers */
#define PSP_IMAGE_BLOCK           0
#define PSP_CREATOR_BLOCK         1
#define PSP_COLOR_BLOCK           2
#define PSP_LAYER_START_BLOCK     3
#define PSP_LAYER_BLOCK           4
#define PSP_CHANNEL_BLOCK         5
#define PSP_SELECTION_BLOCK       6
#define PSP_ALPHA_BANK_BLOCK      7
#define PSP_ALPHA_CHANNEL_BLOCK   8
#define PSP_THUMBNAIL_BLOCK       9
#define PSP_EXTENDED_DATA_BLOCK   10
#define PSP_TUBE_BLOCK            11

/* Compression types */
#define PSP_COMP_NONE   0
#define PSP_COMP_RLE    1
#define PSP_COMP_LZ77   2
#define PSP_COMP_JPEG   3

/* Channel types */
#define PSP_CHANNEL_COMPOSITE 0
#define PSP_CHANNEL_RED       1
#define PSP_CHANNEL_GREEN     2
#define PSP_CHANNEL_BLUE      3

/* DIB types */
#define PSP_DIB_IMAGE       0
#define PSP_DIB_TRANS_MASK  1
#define PSP_DIB_USER_MASK   2

/* PSP file header info */
typedef struct {
    uint16_t major_version;
    uint16_t minor_version;
} psp_file_header_t;

/* Image attributes */
typedef struct {
    uint32_t width;
    uint32_t height;
    double   resolution;
    uint8_t  metric;
    uint16_t compression;
    uint16_t depth;
    uint8_t  grayscale;
    uint32_t active_layer;
    uint16_t layer_count;
    uint16_t bytes_per_sample;
} psp_image_t;

/* Layer info */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t layer_offset_x;
    uint32_t layer_offset_y;
    uint8_t  opacity;
    uint8_t  blend_mode;
    uint8_t  visible;
    uint8_t  linked;
    uint8_t  mask_linked;
    uint8_t  mask_disabled;
} psp_layer_t;

/* Channel info */
typedef struct {
    uint32_t compressed_len;
    uint32_t uncompressed_len;
    uint16_t bitmap_type;
    uint16_t channel_type;
} psp_channel_t;

/* Read little-endian integers */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* RLE decompression */
static int decompress_rle(const uint8_t *src, size_t src_len,
                          uint8_t *dst, size_t dst_len) {
    size_t src_pos = 0;
    size_t dst_pos = 0;

    while (src_pos < src_len && dst_pos < dst_len) {
        uint8_t run_type = src[src_pos++];

        if (run_type > 128) {
            /* Run of repeated byte */
            int run_len = 256 - run_type + 1;
            if (src_pos >= src_len) break;
            uint8_t run_val = src[src_pos++];

            for (int i = 0; i < run_len && dst_pos < dst_len; i++) {
                dst[dst_pos++] = run_val;
            }
        } else if (run_type > 0) {
            /* Run of literal bytes */
            int run_len = run_type;
            for (int i = 0; i < run_len && src_pos < src_len && dst_pos < dst_len; i++) {
                dst[dst_pos++] = src[src_pos++];
            }
        }
        /* run_type == 0 is end marker */
    }

    return dst_pos;
}

/* LZ77/zlib decompression */
static int decompress_lz77(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_len) {
    z_stream strm = {0};
    strm.next_in = (Bytef *)src;
    strm.avail_in = src_len;
    strm.next_out = dst;
    strm.avail_out = dst_len;

    if (inflateInit(&strm) != Z_OK) {
        return -1;
    }

    int ret = inflate(&strm, Z_FINISH);
    size_t decompressed = dst_len - strm.avail_out;
    inflateEnd(&strm);

    if (ret != Z_STREAM_END && ret != Z_OK) {
        return -1;
    }

    return decompressed;
}

/* Parse PSP header */
static int parse_psp_header(const uint8_t *data, size_t size,
                            psp_file_header_t *hdr, size_t *pos) {
    if (size < PSP_MAGIC_LEN + 4) return -1;

    /* Check magic */
    if (memcmp(data, PSP_MAGIC, PSP_MAGIC_LEN) != 0) {
        return -1;
    }

    *pos = PSP_MAGIC_LEN;

    /* Read version */
    hdr->major_version = read_u16_le(data + *pos);
    hdr->minor_version = read_u16_le(data + *pos + 2);
    *pos += 4;

    /* Validate version (3.0 to 12.0 roughly) */
    if (hdr->major_version < 3 || hdr->major_version > 20) {
        return -1;
    }

    return 0;
}

/* Read block header */
static int read_block_header(const uint8_t *data, size_t size, size_t pos,
                             uint16_t *block_id, uint32_t *init_len,
                             uint32_t *total_len, int major_version) {
    /* Block header format varies by version */
    if (major_version >= 4) {
        /* Version 4+: 4-byte signature + 2-byte ID + 4-byte init_len + 4-byte total_len */
        if (pos + 14 > size) return -1;

        /* Check block signature "~BK\0" */
        if (data[pos] != '~' || data[pos + 1] != 'B' ||
            data[pos + 2] != 'K' || data[pos + 3] != 0) {
            return -1;
        }

        *block_id = read_u16_le(data + pos + 4);
        *init_len = read_u32_le(data + pos + 6);
        *total_len = read_u32_le(data + pos + 10);
        return 14;
    } else {
        /* Version 3: 2-byte ID + 4-byte total_len */
        if (pos + 6 > size) return -1;

        *block_id = read_u16_le(data + pos);
        *total_len = read_u32_le(data + pos + 2);
        *init_len = *total_len;
        return 6;
    }
}

/* Parse image block */
static int parse_image_block(const uint8_t *data, size_t size, size_t pos,
                             uint32_t block_len, psp_image_t *img,
                             int major_version) {
    if (block_len < 38) return -1;
    if (pos + block_len > size) return -1;

    const uint8_t *p = data + pos;

    if (major_version >= 4) {
        /* Skip chunk length for v4+ */
        if (block_len < 42) return -1;
        p += 4;
    }

    img->width = read_u32_le(p + 0);
    img->height = read_u32_le(p + 4);

    /* Resolution is a double - read as 8 bytes */
    uint64_t res_bits = 0;
    for (int i = 0; i < 8; i++) {
        res_bits |= ((uint64_t)p[8 + i]) << (i * 8);
    }
    memcpy(&img->resolution, &res_bits, 8);

    img->metric = p[16];
    img->compression = read_u16_le(p + 17);
    img->depth = read_u16_le(p + 19);
    /* Skip plane count at offset 21-22 */
    /* Skip color count at offset 23-26 */
    img->grayscale = p[27];
    /* Skip total image size at offset 28-31 */
    img->active_layer = read_u32_le(p + 32);
    img->layer_count = read_u16_le(p + 36);

    if (major_version >= 4) {
        /* GraphicContents field at offset 38 for v4+ */
    }

    /* Validate */
    if (img->width == 0 || img->width > PSP_MAX_WIDTH) return -1;
    if (img->height == 0 || img->height > PSP_MAX_HEIGHT) return -1;
    if (img->depth != 1 && img->depth != 4 && img->depth != 8 &&
        img->depth != 24 && img->depth != 48) return -1;
    if (img->compression > PSP_COMP_JPEG) return -1;
    if (img->layer_count > PSP_MAX_LAYERS) return -1;

    return 0;
}

/* Parse layer block */
static int parse_layer_block(const uint8_t *data, size_t size, size_t pos,
                             uint32_t block_len, psp_layer_t *layer,
                             int major_version) {
    if (pos + block_len > size) return -1;

    const uint8_t *p = data + pos;
    size_t offset = 0;

    if (major_version >= 4) {
        if (block_len < 4) return -1;
        offset = 4;  /* Skip chunk length */
    }

    if (offset + 40 > block_len) return -1;

    /* Skip name length and name */
    uint16_t name_len = read_u16_le(p + offset);
    offset += 2 + name_len;

    if (offset + 30 > block_len) return -1;

    layer->layer_offset_x = read_u32_le(p + offset + 4);
    layer->layer_offset_y = read_u32_le(p + offset + 8);
    layer->opacity = p[offset + 12];
    layer->blend_mode = p[offset + 13];
    layer->visible = p[offset + 14];
    layer->linked = p[offset + 16];
    layer->mask_linked = p[offset + 18];
    layer->mask_disabled = p[offset + 20];

    /* Width and height */
    layer->width = read_u32_le(p + offset + 22);
    layer->height = read_u32_le(p + offset + 26);

    return 0;
}

/* Parse and decompress channel data */
static int parse_channel_block(const uint8_t *data, size_t size, size_t pos,
                               uint32_t block_len, psp_channel_t *channel,
                               uint8_t **output, int compression,
                               int major_version) {
    if (pos + block_len > size) return -1;

    const uint8_t *p = data + pos;
    size_t offset = 0;

    if (major_version >= 4) {
        if (block_len < 4) return -1;
        offset = 4;
    }

    if (offset + 12 > block_len) return -1;

    channel->compressed_len = read_u32_le(p + offset);
    channel->uncompressed_len = read_u32_le(p + offset + 4);
    channel->bitmap_type = read_u16_le(p + offset + 8);
    channel->channel_type = read_u16_le(p + offset + 10);

    offset += 12;

    /* Validate sizes */
    if (channel->uncompressed_len > PSP_MAX_IMAGE_SIZE) return -1;
    if (channel->compressed_len > block_len - offset) return -1;

    /* Allocate output buffer */
    *output = malloc(channel->uncompressed_len);
    if (!*output) return -1;

    const uint8_t *compressed = p + offset;

    /* Decompress based on compression type */
    int result;
    switch (compression) {
        case PSP_COMP_NONE:
            if (channel->compressed_len > channel->uncompressed_len) {
                free(*output);
                *output = NULL;
                return -1;
            }
            memcpy(*output, compressed, channel->compressed_len);
            result = channel->compressed_len;
            break;

        case PSP_COMP_RLE:
            result = decompress_rle(compressed, channel->compressed_len,
                                    *output, channel->uncompressed_len);
            break;

        case PSP_COMP_LZ77:
            result = decompress_lz77(compressed, channel->compressed_len,
                                     *output, channel->uncompressed_len);
            break;

        default:
            free(*output);
            *output = NULL;
            return -1;
    }

    if (result < 0) {
        free(*output);
        *output = NULL;
        return -1;
    }

    return result;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    psp_file_header_t file_hdr;
    psp_image_t image = {0};
    size_t pos;

    if (parse_psp_header(data, size, &file_hdr, &pos) != 0) {
        return 0;
    }

    int major_version = file_hdr.major_version;

    /* Parse blocks */
    int found_image_block = 0;
    int layer_count = 0;

    while (pos < size) {
        uint16_t block_id;
        uint32_t init_len, total_len;

        int hdr_size = read_block_header(data, size, pos, &block_id,
                                         &init_len, &total_len, major_version);
        if (hdr_size < 0) break;

        pos += hdr_size;

        /* Validate block length */
        if (total_len > size - pos) {
            total_len = size - pos;
        }

        switch (block_id) {
            case PSP_IMAGE_BLOCK:
                if (parse_image_block(data, size, pos, init_len, &image,
                                      major_version) == 0) {
                    found_image_block = 1;
                }
                break;

            case PSP_LAYER_BLOCK:
                if (found_image_block && layer_count < PSP_MAX_LAYERS) {
                    psp_layer_t layer = {0};
                    parse_layer_block(data, size, pos, init_len, &layer,
                                      major_version);
                    layer_count++;
                }
                break;

            case PSP_CHANNEL_BLOCK:
                if (found_image_block) {
                    psp_channel_t channel = {0};
                    uint8_t *channel_data = NULL;
                    parse_channel_block(data, size, pos, init_len, &channel,
                                        &channel_data, image.compression,
                                        major_version);
                    if (channel_data) {
                        free(channel_data);
                    }
                }
                break;

            case PSP_COLOR_BLOCK:
            case PSP_CREATOR_BLOCK:
            case PSP_LAYER_START_BLOCK:
            case PSP_SELECTION_BLOCK:
            case PSP_ALPHA_BANK_BLOCK:
            case PSP_ALPHA_CHANNEL_BLOCK:
            case PSP_THUMBNAIL_BLOCK:
            case PSP_EXTENDED_DATA_BLOCK:
            case PSP_TUBE_BLOCK:
                /* Skip these blocks */
                break;

            default:
                /* Unknown block - skip */
                break;
        }

        pos += total_len;
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
