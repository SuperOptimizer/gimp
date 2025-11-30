/*
 * AFL++ fuzzing harness for PSD (Photoshop Document) file parser
 * Based on GIMP plug-ins/file-psd/
 *
 * Targets: Layer parsing, RLE decompression, image resources,
 *          integer overflows, out-of-bounds reads
 *
 * PSD Format Structure:
 *  1. File Header (26 bytes)
 *  2. Color Mode Data
 *  3. Image Resources
 *  4. Layer and Mask Information
 *  5. Image Data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PSD_SIGNATURE 0x38425053  /* "8BPS" */
#define PSB_SIGNATURE 0x38425053  /* Same, but version=2 */

#define MAX_IMAGE_DIMENSION 300000  /* PSB supports up to 300k */
#define MAX_IMAGE_PIXELS (100ULL * 1024 * 1024)  /* 100 megapixels */
#define MAX_CHANNELS 99
#define MAX_LAYERS 1000

/* Color modes */
#define PSD_BITMAP       0
#define PSD_GRAYSCALE    1
#define PSD_INDEXED      2
#define PSD_RGB          3
#define PSD_CMYK         4
#define PSD_MULTICHANNEL 7
#define PSD_DUOTONE      8
#define PSD_LAB          9

/* Compression types */
#define PSD_COMP_RAW     0
#define PSD_COMP_RLE     1
#define PSD_COMP_ZIP     2
#define PSD_COMP_ZIP_PRED 3

#pragma pack(push, 1)
typedef struct {
    uint32_t signature;   /* "8BPS" */
    uint16_t version;     /* 1 = PSD, 2 = PSB */
    uint8_t  reserved[6];
    uint16_t channels;    /* 1-56 (up to 99 in some versions) */
    uint32_t height;
    uint32_t width;
    uint16_t depth;       /* bits per channel: 1, 8, 16, 32 */
    uint16_t color_mode;
} PsdHeader;
#pragma pack(pop)

typedef struct {
    int32_t  top, left, bottom, right;
    uint16_t channels;
    uint16_t *channel_ids;
    uint64_t *channel_lengths;  /* uint32 for PSD, uint64 for PSB */
    char     blend_mode[4];
    uint8_t  opacity;
    uint8_t  clipping;
    uint8_t  flags;
    uint32_t extra_len;
    /* Layer mask data */
    uint32_t mask_top, mask_left, mask_bottom, mask_right;
    uint8_t  mask_default_color;
    uint8_t  mask_flags;
} PsdLayer;

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    int is_psb;  /* PSB uses 64-bit lengths in some places */
} PsdReader;

static int read_u8(PsdReader *r, uint8_t *out) {
    if (r->pos + 1 > r->size) return -1;
    *out = r->data[r->pos++];
    return 0;
}

static int read_u16(PsdReader *r, uint16_t *out) {
    if (r->pos + 2 > r->size) return -1;
    *out = ((uint16_t)r->data[r->pos] << 8) | r->data[r->pos + 1];
    r->pos += 2;
    return 0;
}

static int read_u32(PsdReader *r, uint32_t *out) {
    if (r->pos + 4 > r->size) return -1;
    *out = ((uint32_t)r->data[r->pos] << 24) |
           ((uint32_t)r->data[r->pos + 1] << 16) |
           ((uint32_t)r->data[r->pos + 2] << 8) |
           r->data[r->pos + 3];
    r->pos += 4;
    return 0;
}

static int read_u64(PsdReader *r, uint64_t *out) {
    if (r->pos + 8 > r->size) return -1;
    *out = ((uint64_t)r->data[r->pos] << 56) |
           ((uint64_t)r->data[r->pos + 1] << 48) |
           ((uint64_t)r->data[r->pos + 2] << 40) |
           ((uint64_t)r->data[r->pos + 3] << 32) |
           ((uint64_t)r->data[r->pos + 4] << 24) |
           ((uint64_t)r->data[r->pos + 5] << 16) |
           ((uint64_t)r->data[r->pos + 6] << 8) |
           r->data[r->pos + 7];
    r->pos += 8;
    return 0;
}

static int read_bytes(PsdReader *r, void *out, size_t len) {
    if (r->pos + len > r->size) return -1;
    memcpy(out, r->data + r->pos, len);
    r->pos += len;
    return 0;
}

static int skip_bytes(PsdReader *r, size_t len) {
    if (r->pos + len > r->size) return -1;
    r->pos += len;
    return 0;
}

/* Read length field (32-bit for PSD, 64-bit for PSB in some contexts) */
static int read_length(PsdReader *r, uint64_t *out, int use_psb) {
    if (use_psb) {
        return read_u64(r, out);
    } else {
        uint32_t val;
        if (read_u32(r, &val) != 0) return -1;
        *out = val;
        return 0;
    }
}

/* Decompress PackBits RLE data */
static int decompress_rle(const uint8_t *src, size_t src_len,
                          uint8_t *dst, size_t dst_len) {
    size_t src_pos = 0;
    size_t dst_pos = 0;

    while (src_pos < src_len && dst_pos < dst_len) {
        int8_t header = (int8_t)src[src_pos++];

        if (header >= 0) {
            /* Literal run: 1 to 128 bytes */
            size_t count = header + 1;
            if (src_pos + count > src_len) break;
            if (dst_pos + count > dst_len) count = dst_len - dst_pos;
            memcpy(dst + dst_pos, src + src_pos, count);
            src_pos += count;
            dst_pos += count;
        } else if (header != -128) {
            /* Repeat run: 2 to 128 copies */
            size_t count = -header + 1;
            if (src_pos >= src_len) break;
            uint8_t value = src[src_pos++];
            if (dst_pos + count > dst_len) count = dst_len - dst_pos;
            memset(dst + dst_pos, value, count);
            dst_pos += count;
        }
        /* header == -128 is a no-op */
    }

    return 0;
}

/* Parse image resource block */
static int parse_image_resource(PsdReader *r) {
    /* Resource block: "8BIM" signature, ID, name, data */
    uint32_t signature;
    uint16_t resource_id;
    uint8_t name_len;

    if (read_u32(r, &signature) != 0) return -1;
    if (signature != 0x3842494D)  /* "8BIM" */
        return -1;

    if (read_u16(r, &resource_id) != 0) return -1;

    /* Pascal string name (padded to even) */
    if (read_u8(r, &name_len) != 0) return -1;
    size_t name_pad = (name_len + 1) & 1;  /* Pad to even */
    if (skip_bytes(r, name_len + name_pad) != 0) return -1;

    /* Resource data (padded to even) */
    uint32_t data_len;
    if (read_u32(r, &data_len) != 0) return -1;
    size_t data_pad = data_len & 1;
    if (skip_bytes(r, data_len + data_pad) != 0) return -1;

    return 0;
}

/* Parse layer record */
static int parse_layer(PsdReader *r, PsdLayer *layer, int is_psb) {
    /* Layer bounds */
    uint32_t top, left, bottom, right;
    if (read_u32(r, (uint32_t*)&top) != 0) return -1;
    if (read_u32(r, (uint32_t*)&left) != 0) return -1;
    if (read_u32(r, (uint32_t*)&bottom) != 0) return -1;
    if (read_u32(r, (uint32_t*)&right) != 0) return -1;

    layer->top = (int32_t)top;
    layer->left = (int32_t)left;
    layer->bottom = (int32_t)bottom;
    layer->right = (int32_t)right;

    /* Number of channels */
    if (read_u16(r, &layer->channels) != 0) return -1;
    if (layer->channels > MAX_CHANNELS) return -1;

    /* Channel info */
    for (int i = 0; i < layer->channels; i++) {
        uint16_t channel_id;
        uint64_t channel_length;

        if (read_u16(r, &channel_id) != 0) return -1;
        if (read_length(r, &channel_length, is_psb) != 0) return -1;
    }

    /* Blend mode signature */
    uint32_t blend_sig;
    if (read_u32(r, &blend_sig) != 0) return -1;
    if (blend_sig != 0x3842494D)  /* "8BIM" */
        return -1;

    /* Blend mode key */
    if (read_bytes(r, layer->blend_mode, 4) != 0) return -1;

    /* Opacity, clipping, flags, padding */
    if (read_u8(r, &layer->opacity) != 0) return -1;
    if (read_u8(r, &layer->clipping) != 0) return -1;
    if (read_u8(r, &layer->flags) != 0) return -1;
    if (skip_bytes(r, 1) != 0) return -1;  /* Filler */

    /* Extra data length */
    if (read_u32(r, &layer->extra_len) != 0) return -1;

    /* Skip extra data (mask, blending ranges, name, additional info) */
    if (skip_bytes(r, layer->extra_len) != 0) return -1;

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(PsdHeader))
        return 0;

    PsdReader reader = { .data = data, .size = size, .pos = 0 };

    /* Parse header */
    PsdHeader header;
    if (read_u32(&reader, &header.signature) != 0) return 0;
    if (header.signature != PSD_SIGNATURE) return 0;

    if (read_u16(&reader, &header.version) != 0) return 0;
    if (header.version != 1 && header.version != 2) return 0;
    reader.is_psb = (header.version == 2);

    if (skip_bytes(&reader, 6) != 0) return 0;  /* Reserved */

    if (read_u16(&reader, &header.channels) != 0) return 0;
    if (header.channels == 0 || header.channels > MAX_CHANNELS) return 0;

    if (read_u32(&reader, &header.height) != 0) return 0;
    if (read_u32(&reader, &header.width) != 0) return 0;

    /* Validate dimensions */
    if (header.width == 0 || header.height == 0) return 0;
    if (header.width > MAX_IMAGE_DIMENSION || header.height > MAX_IMAGE_DIMENSION) return 0;
    uint64_t pixels = (uint64_t)header.width * header.height;
    if (pixels > MAX_IMAGE_PIXELS) return 0;

    if (read_u16(&reader, &header.depth) != 0) return 0;
    if (header.depth != 1 && header.depth != 8 &&
        header.depth != 16 && header.depth != 32) return 0;

    if (read_u16(&reader, &header.color_mode) != 0) return 0;

    /* Color Mode Data Section */
    uint32_t color_mode_len;
    if (read_u32(&reader, &color_mode_len) != 0) return 0;

    if (header.color_mode == PSD_INDEXED || header.color_mode == PSD_DUOTONE) {
        /* Indexed: 768 bytes (256 * RGB) */
        /* Duotone: variable */
        if (color_mode_len > 0 && color_mode_len < 10 * 1024 * 1024) {
            if (skip_bytes(&reader, color_mode_len) != 0) return 0;
        }
    } else {
        if (color_mode_len > 0) {
            if (skip_bytes(&reader, color_mode_len) != 0) return 0;
        }
    }

    /* Image Resources Section */
    uint32_t resources_len;
    if (read_u32(&reader, &resources_len) != 0) return 0;

    if (resources_len > 0 && resources_len < size - reader.pos) {
        size_t resources_end = reader.pos + resources_len;
        int resource_count = 0;

        while (reader.pos < resources_end && resource_count < 1000) {
            if (parse_image_resource(&reader) != 0)
                break;
            resource_count++;
        }

        /* Ensure we're at the end of resources section */
        reader.pos = resources_end;
    }

    /* Layer and Mask Information Section */
    uint64_t layer_info_len;
    if (read_length(&reader, &layer_info_len, reader.is_psb) != 0) return 0;

    if (layer_info_len > 0 && layer_info_len < size - reader.pos) {
        size_t layer_section_end = reader.pos + layer_info_len;

        /* Layer info */
        uint64_t layer_len;
        if (read_length(&reader, &layer_len, reader.is_psb) != 0) return 0;

        if (layer_len > 0 && layer_len < size - reader.pos) {
            /* Layer count (can be negative for merged alpha) */
            int16_t layer_count_raw;
            if (read_u16(&reader, (uint16_t*)&layer_count_raw) != 0) return 0;

            int layer_count = layer_count_raw;
            if (layer_count < 0) layer_count = -layer_count;
            if (layer_count > MAX_LAYERS) layer_count = MAX_LAYERS;

            /* Parse layer records */
            PsdLayer *layers = calloc(layer_count, sizeof(PsdLayer));
            if (layers) {
                for (int i = 0; i < layer_count; i++) {
                    if (parse_layer(&reader, &layers[i], reader.is_psb) != 0)
                        break;
                }

                /* Channel image data follows, but we'll skip detailed parsing */
                free(layers);
            }
        }

        /* Skip to end of layer section */
        reader.pos = layer_section_end;
    }

    /* Image Data Section */
    if (reader.pos < size) {
        uint16_t compression;
        if (read_u16(&reader, &compression) != 0) return 0;

        size_t remaining = size - reader.pos;
        size_t expected_size = (size_t)header.width * header.height *
                               header.channels * (header.depth / 8);

        if (compression == PSD_COMP_RAW) {
            /* Just validate we have enough data */
            if (remaining >= expected_size && expected_size < 100 * 1024 * 1024) {
                uint8_t *output = malloc(expected_size);
                if (output) {
                    memcpy(output, data + reader.pos, expected_size);
                    free(output);
                }
            }
        } else if (compression == PSD_COMP_RLE) {
            /* RLE compressed: first comes row byte counts */
            size_t row_count = (size_t)header.height * header.channels;

            /* For PSB, byte counts are 32-bit; for PSD, 16-bit */
            size_t counts_size = row_count * (reader.is_psb ? 4 : 2);
            if (reader.pos + counts_size > size) return 0;

            uint64_t *row_lengths = malloc(row_count * sizeof(uint64_t));
            if (row_lengths) {
                for (size_t i = 0; i < row_count; i++) {
                    if (reader.is_psb) {
                        uint32_t len;
                        if (read_u32(&reader, &len) != 0) break;
                        row_lengths[i] = len;
                    } else {
                        uint16_t len;
                        if (read_u16(&reader, &len) != 0) break;
                        row_lengths[i] = len;
                    }
                }

                /* Decompress each row */
                size_t row_size = (size_t)header.width * (header.depth / 8);
                uint8_t *row_output = malloc(row_size);
                if (row_output) {
                    for (size_t i = 0; i < row_count && reader.pos < size; i++) {
                        size_t comp_len = row_lengths[i];
                        if (comp_len > remaining) break;
                        if (reader.pos + comp_len > size) break;

                        decompress_rle(data + reader.pos, comp_len,
                                      row_output, row_size);
                        reader.pos += comp_len;
                    }
                    free(row_output);
                }

                free(row_lengths);
            }
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
/* Standalone mode - read from file */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <psd_file>\n", argv[0]);
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
