/*
 * ANI (Windows Animated Cursor) Format Fuzzer
 *
 * Standalone harness for fuzzing Windows ANI file parsing.
 * Based on GIMP's file-ani plugin.
 *
 * ANI format features:
 * - RIFF container format
 * - Contains multiple ICO/CUR frames
 * - Animation sequence and timing info
 * - Can include rate and sequence chunks
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* ANI constants */
#define ANI_RIFF_MAGIC  0x46464952  /* "RIFF" */
#define ANI_ACON_MAGIC  0x4E4F4341  /* "ACON" */
#define ANI_LIST_MAGIC  0x5453494C  /* "LIST" */
#define ANI_ANIH_MAGIC  0x68696E61  /* "anih" */
#define ANI_RATE_MAGIC  0x65746172  /* "rate" */
#define ANI_SEQ_MAGIC   0x20716573  /* "seq " */
#define ANI_ICON_MAGIC  0x6E6F6369  /* "icon" */
#define ANI_FRAM_MAGIC  0x6D617266  /* "fram" */

#define ANI_MAX_FRAMES  1000
#define ANI_MAX_SIZE    (64 * 1024 * 1024)
#define ANI_MAX_WIDTH   256
#define ANI_MAX_HEIGHT  256

/* ANI header structure */
typedef struct {
    uint32_t size;        /* Size of this struct (36 bytes) */
    uint32_t num_frames;  /* Number of frames */
    uint32_t num_steps;   /* Number of animation steps */
    uint32_t width;       /* Icon width (0 = use default) */
    uint32_t height;      /* Icon height */
    uint32_t bit_count;   /* Bits per pixel */
    uint32_t num_planes;  /* Number of planes */
    uint32_t display_rate;/* Default display rate (jiffies) */
    uint32_t flags;       /* ANI_FLAG_ICON = 1, ANI_FLAG_SEQUENCE = 2 */
} ani_header_t;

/* ICO/CUR header embedded in ANI frame */
typedef struct {
    uint16_t reserved;
    uint16_t type;        /* 1 = ICO, 2 = CUR */
    uint16_t count;       /* Number of images */
} ico_header_t;

/* ICO directory entry */
typedef struct {
    uint8_t  width;
    uint8_t  height;
    uint8_t  color_count;
    uint8_t  reserved;
    uint16_t planes;      /* Or hotspot_x for CUR */
    uint16_t bit_count;   /* Or hotspot_y for CUR */
    uint32_t bytes;
    uint32_t offset;
} ico_dir_entry_t;

/* BITMAPINFOHEADER */
typedef struct {
    uint32_t size;
    int32_t  width;
    int32_t  height;
    uint16_t planes;
    uint16_t bit_count;
    uint32_t compression;
    uint32_t image_size;
    int32_t  x_ppm;
    int32_t  y_ppm;
    uint32_t colors_used;
    uint32_t colors_important;
} bmp_info_header_t;

/* Read little-endian integers */
static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int32_t read_i32_le(const uint8_t *p) {
    return (int32_t)read_u32_le(p);
}

/* Decode a single ICO frame */
static int decode_ico_frame(const uint8_t *data, size_t size) {
    if (size < 6) return -1;

    ico_header_t hdr;
    hdr.reserved = read_u16_le(data);
    hdr.type = read_u16_le(data + 2);
    hdr.count = read_u16_le(data + 4);

    if (hdr.type != 1 && hdr.type != 2) return -1;
    if (hdr.count == 0 || hdr.count > 256) return -1;

    size_t pos = 6;

    /* Process each image in the ICO */
    for (int i = 0; i < hdr.count && pos + 16 <= size; i++) {
        ico_dir_entry_t entry;
        entry.width = data[pos];
        entry.height = data[pos + 1];
        entry.color_count = data[pos + 2];
        entry.reserved = data[pos + 3];
        entry.planes = read_u16_le(data + pos + 4);
        entry.bit_count = read_u16_le(data + pos + 6);
        entry.bytes = read_u32_le(data + pos + 8);
        entry.offset = read_u32_le(data + pos + 12);
        pos += 16;

        /* Width/height of 0 means 256 */
        int width = entry.width ? entry.width : 256;
        int height = entry.height ? entry.height : 256;

        if (width > ANI_MAX_WIDTH || height > ANI_MAX_HEIGHT) continue;
        if (entry.offset + entry.bytes > size) continue;
        if (entry.bytes < 40) continue;

        /* Check for PNG frame (starts with PNG signature) */
        if (entry.bytes >= 8 && entry.offset + 8 <= size) {
            const uint8_t png_sig[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
            if (memcmp(data + entry.offset, png_sig, 8) == 0) {
                /* PNG frame - would need PNG decoder */
                continue;
            }
        }

        /* Parse BITMAPINFOHEADER */
        const uint8_t *bmp = data + entry.offset;
        bmp_info_header_t bih;
        bih.size = read_u32_le(bmp);
        bih.width = read_i32_le(bmp + 4);
        bih.height = read_i32_le(bmp + 8);
        bih.planes = read_u16_le(bmp + 12);
        bih.bit_count = read_u16_le(bmp + 14);
        bih.compression = read_u32_le(bmp + 16);

        if (bih.size < 40) continue;
        if (bih.width <= 0 || bih.width > ANI_MAX_WIDTH) continue;

        /* Height is doubled (includes mask) */
        int img_height = bih.height / 2;
        if (img_height <= 0 || img_height > ANI_MAX_HEIGHT) continue;

        /* Calculate palette size */
        int palette_colors = 0;
        if (bih.bit_count <= 8) {
            palette_colors = 1 << bih.bit_count;
        }

        size_t palette_offset = entry.offset + bih.size;
        size_t palette_size = palette_colors * 4;

        /* Skip palette */
        if (palette_offset + palette_size > size) continue;

        /* Calculate pixel data size */
        int row_stride = ((bih.width * bih.bit_count + 31) / 32) * 4;
        size_t pixel_size = (size_t)row_stride * img_height;

        size_t pixel_offset = palette_offset + palette_size;
        if (pixel_offset + pixel_size > size) continue;

        /* Allocate and decode pixel data */
        size_t output_size = (size_t)bih.width * img_height * 4;
        if (output_size > ANI_MAX_SIZE) continue;

        uint8_t *output = malloc(output_size);
        if (!output) continue;

        const uint8_t *palette = data + palette_offset;
        const uint8_t *pixels = data + pixel_offset;

        /* Decode based on bit depth */
        for (int y = 0; y < img_height; y++) {
            const uint8_t *row = pixels + (size_t)(img_height - 1 - y) * row_stride;

            for (int x = 0; x < bih.width; x++) {
                size_t out_idx = ((size_t)y * bih.width + x) * 4;
                uint8_t r = 0, g = 0, b = 0, a = 255;

                if (bih.bit_count == 1) {
                    int idx = (row[x / 8] >> (7 - (x % 8))) & 1;
                    if (idx < palette_colors) {
                        b = palette[idx * 4 + 0];
                        g = palette[idx * 4 + 1];
                        r = palette[idx * 4 + 2];
                    }
                } else if (bih.bit_count == 4) {
                    int idx;
                    if (x & 1) {
                        idx = row[x / 2] & 0x0F;
                    } else {
                        idx = (row[x / 2] >> 4) & 0x0F;
                    }
                    if (idx < palette_colors) {
                        b = palette[idx * 4 + 0];
                        g = palette[idx * 4 + 1];
                        r = palette[idx * 4 + 2];
                    }
                } else if (bih.bit_count == 8) {
                    int idx = row[x];
                    if (idx < palette_colors) {
                        b = palette[idx * 4 + 0];
                        g = palette[idx * 4 + 1];
                        r = palette[idx * 4 + 2];
                    }
                } else if (bih.bit_count == 24) {
                    b = row[x * 3 + 0];
                    g = row[x * 3 + 1];
                    r = row[x * 3 + 2];
                } else if (bih.bit_count == 32) {
                    b = row[x * 4 + 0];
                    g = row[x * 4 + 1];
                    r = row[x * 4 + 2];
                    a = row[x * 4 + 3];
                }

                output[out_idx + 0] = r;
                output[out_idx + 1] = g;
                output[out_idx + 2] = b;
                output[out_idx + 3] = a;
            }
        }

        free(output);
    }

    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Check minimum RIFF header size */
    if (size < 12) return 0;

    /* Verify RIFF signature */
    uint32_t riff_magic = read_u32_le(data);
    uint32_t riff_size = read_u32_le(data + 4);
    uint32_t acon_magic = read_u32_le(data + 8);

    if (riff_magic != ANI_RIFF_MAGIC) return 0;
    if (acon_magic != ANI_ACON_MAGIC) return 0;

    (void)riff_size;  /* Not strictly validated */

    size_t pos = 12;
    ani_header_t ani_hdr = {0};
    uint32_t *rates = NULL;
    uint32_t *sequence = NULL;
    int num_rates = 0;
    int num_seq = 0;

    /* Parse RIFF chunks */
    while (pos + 8 <= size) {
        uint32_t chunk_id = read_u32_le(data + pos);
        uint32_t chunk_size = read_u32_le(data + pos + 4);
        pos += 8;

        if (chunk_size > size - pos) {
            chunk_size = size - pos;
        }

        if (chunk_id == ANI_ANIH_MAGIC) {
            /* ANI header chunk */
            if (chunk_size >= 36) {
                ani_hdr.size = read_u32_le(data + pos);
                ani_hdr.num_frames = read_u32_le(data + pos + 4);
                ani_hdr.num_steps = read_u32_le(data + pos + 8);
                ani_hdr.width = read_u32_le(data + pos + 12);
                ani_hdr.height = read_u32_le(data + pos + 16);
                ani_hdr.bit_count = read_u32_le(data + pos + 20);
                ani_hdr.num_planes = read_u32_le(data + pos + 24);
                ani_hdr.display_rate = read_u32_le(data + pos + 28);
                ani_hdr.flags = read_u32_le(data + pos + 32);
            }

            /* Validate */
            if (ani_hdr.num_frames > ANI_MAX_FRAMES) {
                ani_hdr.num_frames = ANI_MAX_FRAMES;
            }
        } else if (chunk_id == ANI_RATE_MAGIC) {
            /* Rate chunk - timing for each step */
            num_rates = chunk_size / 4;
            if (num_rates > 0 && num_rates <= ANI_MAX_FRAMES) {
                rates = malloc(num_rates * sizeof(uint32_t));
                if (rates) {
                    for (int i = 0; i < num_rates; i++) {
                        rates[i] = read_u32_le(data + pos + i * 4);
                    }
                }
            }
        } else if (chunk_id == ANI_SEQ_MAGIC) {
            /* Sequence chunk - frame order */
            num_seq = chunk_size / 4;
            if (num_seq > 0 && num_seq <= ANI_MAX_FRAMES) {
                sequence = malloc(num_seq * sizeof(uint32_t));
                if (sequence) {
                    for (int i = 0; i < num_seq; i++) {
                        sequence[i] = read_u32_le(data + pos + i * 4);
                    }
                }
            }
        } else if (chunk_id == ANI_LIST_MAGIC) {
            /* LIST chunk - contains frames */
            if (chunk_size >= 4) {
                uint32_t list_type = read_u32_le(data + pos);
                if (list_type == ANI_FRAM_MAGIC) {
                    /* Frame list */
                    size_t frame_pos = pos + 4;
                    int frame_count = 0;

                    while (frame_pos + 8 <= pos + chunk_size &&
                           frame_count < ANI_MAX_FRAMES) {
                        uint32_t frame_id = read_u32_le(data + frame_pos);
                        uint32_t frame_size = read_u32_le(data + frame_pos + 4);
                        frame_pos += 8;

                        if (frame_size > size - frame_pos) {
                            break;
                        }

                        if (frame_id == ANI_ICON_MAGIC) {
                            /* Decode ICO frame */
                            decode_ico_frame(data + frame_pos, frame_size);
                            frame_count++;
                        }

                        /* Align to word boundary */
                        frame_pos += (frame_size + 1) & ~1;
                    }
                }
            }
        }

        /* Align to word boundary */
        pos += (chunk_size + 1) & ~1;
    }

    free(rates);
    free(sequence);

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
