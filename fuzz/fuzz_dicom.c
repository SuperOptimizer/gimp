/*
 * AFL++ fuzzing harness for GIMP DICOM file parser
 * Based on plug-ins/common/file-dicom.c
 *
 * Targets: Buffer overflows in DICOM tag parsing (ZDI-25-xxx)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_IMAGE_SIZE 262144
#define DICOM_MAGIC "DICM"

/* DICOM uses little-endian by default */
typedef struct {
    uint16_t group;
    uint16_t element;
    uint32_t length;
} DicomTag;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint16_t bits_allocated;
    uint16_t bits_stored;
    uint16_t high_bit;
    uint16_t samples_per_pixel;
    uint16_t pixel_representation;
    int found_pixel_data;
    long pixel_data_offset;
    uint32_t pixel_data_length;
} DicomInfo;

static uint16_t read_le16(FILE *fp) {
    uint8_t buf[2];
    if (fread(buf, 1, 2, fp) != 2)
        return 0;
    return buf[0] | (buf[1] << 8);
}

static uint32_t read_le32(FILE *fp) {
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4)
        return 0;
    return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static int is_implicit_vr(uint16_t group, uint16_t element) {
    /* Simplified check - real DICOM is more complex */
    return 0;
}

static int read_dicom_tag(FILE *fp, DicomTag *tag, int explicit_vr) {
    tag->group = read_le16(fp);
    tag->element = read_le16(fp);

    if (feof(fp))
        return -1;

    if (explicit_vr) {
        char vr[2];
        if (fread(vr, 1, 2, fp) != 2)
            return -1;

        /* Check if this VR type has 4-byte length */
        if ((vr[0] == 'O' && (vr[1] == 'B' || vr[1] == 'W' || vr[1] == 'F')) ||
            (vr[0] == 'S' && vr[1] == 'Q') ||
            (vr[0] == 'U' && (vr[1] == 'C' || vr[1] == 'N' || vr[1] == 'R'))) {
            /* Skip 2 reserved bytes, read 4-byte length */
            uint16_t reserved = read_le16(fp);
            (void)reserved;
            tag->length = read_le32(fp);
        } else {
            /* 2-byte length */
            tag->length = read_le16(fp);
        }
    } else {
        tag->length = read_le32(fp);
    }

    return 0;
}

static int parse_dicom_metadata(FILE *fp, DicomInfo *info) {
    /* Check for DICM prefix at offset 128 */
    if (fseek(fp, 128, SEEK_SET) != 0)
        return -1;

    char magic[4];
    if (fread(magic, 1, 4, fp) != 4)
        return -1;

    if (memcmp(magic, DICOM_MAGIC, 4) != 0) {
        /* Try reading from beginning (old DICOM without preamble) */
        if (fseek(fp, 0, SEEK_SET) != 0)
            return -1;
    }

    memset(info, 0, sizeof(*info));
    info->bits_allocated = 8;
    info->samples_per_pixel = 1;

    int tag_count = 0;
    int explicit_vr = 1;

    while (tag_count < 1000) {  /* Limit iterations */
        DicomTag tag;
        if (read_dicom_tag(fp, &tag, explicit_vr) != 0)
            break;

        tag_count++;

        /* Handle specific tags */
        if (tag.group == 0x0028) {
            switch (tag.element) {
                case 0x0010:  /* Rows (height) */
                    if (tag.length == 2)
                        info->height = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;

                case 0x0011:  /* Columns (width) */
                    if (tag.length == 2)
                        info->width = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;

                case 0x0100:  /* Bits Allocated */
                    if (tag.length == 2)
                        info->bits_allocated = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;

                case 0x0101:  /* Bits Stored */
                    if (tag.length == 2)
                        info->bits_stored = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;

                case 0x0102:  /* High Bit */
                    if (tag.length == 2)
                        info->high_bit = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;

                case 0x0002:  /* Samples per Pixel */
                    if (tag.length == 2)
                        info->samples_per_pixel = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;

                case 0x0103:  /* Pixel Representation */
                    if (tag.length == 2)
                        info->pixel_representation = read_le16(fp);
                    else if (tag.length > 0)
                        fseek(fp, tag.length, SEEK_CUR);
                    continue;
            }
        }

        /* Pixel Data tag */
        if (tag.group == 0x7fe0 && tag.element == 0x0010) {
            info->found_pixel_data = 1;
            info->pixel_data_offset = ftell(fp);
            info->pixel_data_length = tag.length;
            break;
        }

        /* Skip tag data */
        if (tag.length > 0 && tag.length != 0xFFFFFFFF) {
            if (fseek(fp, tag.length, SEEK_CUR) != 0)
                break;
        }
    }

    return info->found_pixel_data ? 0 : -1;
}

static int load_dicom_image(FILE *fp, DicomInfo *info) {
    if (info->width == 0 || info->height == 0)
        return -1;
    if (info->width > MAX_IMAGE_SIZE || info->height > MAX_IMAGE_SIZE)
        return -1;

    uint32_t bytes_per_sample = (info->bits_allocated + 7) / 8;
    if (bytes_per_sample == 0 || bytes_per_sample > 4)
        return -1;

    size_t pixel_count = (size_t)info->width * info->height;
    size_t raw_size = pixel_count * bytes_per_sample * info->samples_per_pixel;

    if (raw_size > 256 * 1024 * 1024)
        return -1;

    if (fseek(fp, info->pixel_data_offset, SEEK_SET) != 0)
        return -1;

    uint8_t *raw_data = malloc(raw_size);
    if (!raw_data)
        return -1;

    size_t to_read = raw_size;
    if (info->pixel_data_length > 0 && info->pixel_data_length < raw_size)
        to_read = info->pixel_data_length;

    if (fread(raw_data, 1, to_read, fp) != to_read) {
        free(raw_data);
        return -1;
    }

    /* Convert to 8-bit grayscale or RGB */
    size_t output_channels = (info->samples_per_pixel >= 3) ? 3 : 1;
    size_t output_size = pixel_count * output_channels;

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(raw_data);
        return -1;
    }

    for (size_t i = 0; i < pixel_count; i++) {
        if (bytes_per_sample == 1) {
            if (output_channels == 1) {
                output[i] = raw_data[i * info->samples_per_pixel];
            } else {
                size_t src_idx = i * info->samples_per_pixel;
                output[i * 3 + 0] = raw_data[src_idx + 0];
                output[i * 3 + 1] = raw_data[src_idx + 1];
                output[i * 3 + 2] = raw_data[src_idx + 2];
            }
        } else if (bytes_per_sample == 2) {
            size_t src_idx = i * bytes_per_sample * info->samples_per_pixel;
            uint16_t val = raw_data[src_idx] | (raw_data[src_idx + 1] << 8);
            if (output_channels == 1) {
                output[i] = val >> (info->bits_stored - 8);
            }
        }
    }

    free(output);
    free(raw_data);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 132)  /* Minimum: 128 preamble + 4 DICM + some tags */
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    DicomInfo info;
    if (parse_dicom_metadata(fp, &info) != 0) {
        fclose(fp);
        return 0;
    }

    load_dicom_image(fp, &info);

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
