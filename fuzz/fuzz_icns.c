/*
 * AFL++ fuzzing harness for GIMP ICNS (Apple Icon) file parser
 * Based on plug-ins/file-icns/
 *
 * Targets: Buffer overflows in icon parsing (ZDI-25-xxx)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#define ICNS_MAGIC "icns"
#define MAX_IMAGE_SIZE 262144
#define MAX_ICON_SIZE (1024 * 1024)  /* 1MB per icon */

typedef struct {
    char type[4];
    uint32_t size;
} IcnsBlockHeader;

typedef struct {
    char magic[4];
    uint32_t file_size;
} IcnsHeader;

/* Known icon types with their sizes */
typedef struct {
    const char *type;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    int has_mask;
} IcnsIconInfo;

static const IcnsIconInfo known_icons[] = {
    {"ICON", 32, 32, 1, 0},
    {"ICN#", 32, 32, 1, 1},
    {"icm#", 16, 12, 1, 1},
    {"icm4", 16, 12, 4, 0},
    {"icm8", 16, 12, 8, 0},
    {"ics#", 16, 16, 1, 1},
    {"ics4", 16, 16, 4, 0},
    {"ics8", 16, 16, 8, 0},
    {"is32", 16, 16, 32, 0},
    {"s8mk", 16, 16, 8, 0},
    {"icl4", 32, 32, 4, 0},
    {"icl8", 32, 32, 8, 0},
    {"il32", 32, 32, 32, 0},
    {"l8mk", 32, 32, 8, 0},
    {"ich#", 48, 48, 1, 1},
    {"ich4", 48, 48, 4, 0},
    {"ich8", 48, 48, 8, 0},
    {"ih32", 48, 48, 32, 0},
    {"h8mk", 48, 48, 8, 0},
    {"it32", 128, 128, 32, 0},
    {"t8mk", 128, 128, 8, 0},
    {"ic08", 256, 256, 32, 0},
    {"ic09", 512, 512, 32, 0},
    {"ic10", 1024, 1024, 32, 0},
    {"ic11", 32, 32, 32, 0},
    {"ic12", 64, 64, 32, 0},
    {"ic13", 256, 256, 32, 0},
    {"ic14", 512, 512, 32, 0},
    {NULL, 0, 0, 0, 0}
};

static const IcnsIconInfo *find_icon_info(const char *type) {
    for (int i = 0; known_icons[i].type != NULL; i++) {
        if (memcmp(type, known_icons[i].type, 4) == 0)
            return &known_icons[i];
    }
    return NULL;
}

static int read_icns_header(FILE *fp, IcnsHeader *hdr) {
    if (fread(hdr->magic, 1, 4, fp) != 4)
        return -1;
    if (memcmp(hdr->magic, ICNS_MAGIC, 4) != 0)
        return -1;

    uint32_t size;
    if (fread(&size, sizeof(uint32_t), 1, fp) != 1)
        return -1;

    hdr->file_size = ntohl(size);
    return 0;
}

static int read_block_header(FILE *fp, IcnsBlockHeader *block) {
    if (fread(block->type, 1, 4, fp) != 4)
        return -1;

    uint32_t size;
    if (fread(&size, sizeof(uint32_t), 1, fp) != 1)
        return -1;

    block->size = ntohl(size);
    return 0;
}

/* Simple RLE decompression for 32-bit icons */
static int decompress_rle(const uint8_t *src, size_t src_size,
                          uint8_t *dst, size_t dst_size) {
    size_t src_pos = 0;
    size_t dst_pos = 0;

    while (src_pos < src_size && dst_pos < dst_size) {
        uint8_t control = src[src_pos++];

        if (control & 0x80) {
            /* Run of repeated bytes */
            uint32_t count = (control & 0x7f) + 3;
            if (src_pos >= src_size)
                return -1;
            uint8_t value = src[src_pos++];

            if (dst_pos + count > dst_size)
                count = dst_size - dst_pos;

            memset(dst + dst_pos, value, count);
            dst_pos += count;
        } else {
            /* Run of literal bytes */
            uint32_t count = control + 1;
            if (src_pos + count > src_size)
                return -1;
            if (dst_pos + count > dst_size)
                count = dst_size - dst_pos;

            memcpy(dst + dst_pos, src + src_pos, count);
            src_pos += count;
            dst_pos += count;
        }
    }

    return 0;
}

static int decode_icon(const uint8_t *data, size_t size, const IcnsIconInfo *info) {
    if (info->width > MAX_IMAGE_SIZE || info->height > MAX_IMAGE_SIZE)
        return -1;

    size_t pixel_count = (size_t)info->width * info->height;
    size_t expected_size;

    switch (info->bpp) {
        case 1:
            expected_size = pixel_count / 8;
            if (info->has_mask)
                expected_size *= 2;
            break;
        case 4:
            expected_size = pixel_count / 2;
            break;
        case 8:
            expected_size = pixel_count;
            break;
        case 32:
            expected_size = pixel_count * 4;
            break;
        default:
            return -1;
    }

    uint8_t *output = malloc(pixel_count * 4);  /* Always RGBA output */
    if (!output)
        return -1;

    if (info->bpp == 32 && size < expected_size) {
        /* Compressed 32-bit icon */
        uint8_t *decompressed = malloc(expected_size);
        if (!decompressed) {
            free(output);
            return -1;
        }

        /* Decompress each channel separately */
        size_t channel_size = pixel_count;
        size_t src_offset = 0;

        for (int channel = 0; channel < 3; channel++) {
            if (decompress_rle(data + src_offset, size - src_offset,
                             decompressed + channel * channel_size,
                             channel_size) != 0) {
                break;
            }
            /* Estimate consumed bytes - simplified */
            src_offset += channel_size / 2;
            if (src_offset > size)
                src_offset = size;
        }

        /* Convert planar to RGBA */
        for (size_t i = 0; i < pixel_count; i++) {
            output[i * 4 + 0] = decompressed[i];                    /* R */
            output[i * 4 + 1] = decompressed[pixel_count + i];      /* G */
            output[i * 4 + 2] = decompressed[pixel_count * 2 + i];  /* B */
            output[i * 4 + 3] = 255;                                /* A */
        }

        free(decompressed);
    } else if (info->bpp == 32) {
        /* Uncompressed 32-bit ARGB */
        for (size_t i = 0; i < pixel_count && i * 4 + 3 < size; i++) {
            output[i * 4 + 0] = data[i * 4 + 1];  /* R */
            output[i * 4 + 1] = data[i * 4 + 2];  /* G */
            output[i * 4 + 2] = data[i * 4 + 3];  /* B */
            output[i * 4 + 3] = data[i * 4 + 0];  /* A */
        }
    } else if (info->bpp == 8) {
        /* 8-bit indexed - just copy as grayscale */
        for (size_t i = 0; i < pixel_count && i < size; i++) {
            output[i * 4 + 0] = data[i];
            output[i * 4 + 1] = data[i];
            output[i * 4 + 2] = data[i];
            output[i * 4 + 3] = 255;
        }
    } else if (info->bpp == 4) {
        /* 4-bit indexed */
        for (size_t i = 0; i < pixel_count; i++) {
            size_t byte_idx = i / 2;
            if (byte_idx >= size)
                break;
            uint8_t nibble = (i % 2 == 0) ? (data[byte_idx] >> 4) : (data[byte_idx] & 0x0f);
            uint8_t gray = nibble * 17;  /* Scale 0-15 to 0-255 */
            output[i * 4 + 0] = gray;
            output[i * 4 + 1] = gray;
            output[i * 4 + 2] = gray;
            output[i * 4 + 3] = 255;
        }
    } else if (info->bpp == 1) {
        /* 1-bit bitmap */
        for (size_t i = 0; i < pixel_count; i++) {
            size_t byte_idx = i / 8;
            if (byte_idx >= size)
                break;
            int bit_idx = 7 - (i % 8);
            uint8_t bit = (data[byte_idx] >> bit_idx) & 1;
            uint8_t gray = bit ? 255 : 0;
            output[i * 4 + 0] = gray;
            output[i * 4 + 1] = gray;
            output[i * 4 + 2] = gray;
            output[i * 4 + 3] = 255;
        }
    }

    free(output);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8)  /* Minimum: 4 magic + 4 size */
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    IcnsHeader hdr;
    if (read_icns_header(fp, &hdr) != 0) {
        fclose(fp);
        return 0;
    }

    /* Parse icon blocks */
    int block_count = 0;
    while (block_count < 100) {  /* Limit iterations */
        IcnsBlockHeader block;
        long block_start = ftell(fp);

        if (read_block_header(fp, &block) != 0)
            break;

        block_count++;

        /* Validate block size */
        if (block.size < 8 || block.size > MAX_ICON_SIZE)
            break;

        uint32_t data_size = block.size - 8;

        /* Find icon info */
        const IcnsIconInfo *info = find_icon_info(block.type);
        if (info != NULL) {
            uint8_t *icon_data = malloc(data_size);
            if (icon_data) {
                if (fread(icon_data, 1, data_size, fp) == data_size) {
                    decode_icon(icon_data, data_size, info);
                }
                free(icon_data);
            }
        }

        /* Skip to next block */
        if (fseek(fp, block_start + block.size, SEEK_SET) != 0)
            break;
    }

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
