/*
 * GIF (Graphics Interchange Format) Image Fuzzer
 *
 * Standalone harness for fuzzing GIF image parsing.
 * Based on GIMP's file-gif-load plugin.
 *
 * GIF format features:
 * - LZW compression
 * - Animated sequences with frame delays
 * - Global and local color tables
 * - Interlaced display
 * - Transparency via extension blocks
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* GIF constants */
#define GIF_MAX_WIDTH  65535
#define GIF_MAX_HEIGHT 65535
#define GIF_MAX_IMAGE_SIZE (128 * 1024 * 1024)
#define GIF_MAX_FRAMES 1000
#define GIF_MAX_LZW_BITS 12
#define GIF_LZW_TABLE_SIZE (1 << GIF_MAX_LZW_BITS)

/* Block types */
#define GIF_EXTENSION   0x21
#define GIF_IMAGE_DESC  0x2C
#define GIF_TRAILER     0x3B

/* Extension labels */
#define GIF_EXT_GRAPHIC 0xF9
#define GIF_EXT_COMMENT 0xFE
#define GIF_EXT_PLAIN   0x01
#define GIF_EXT_APP     0xFF

/* GIF header */
typedef struct {
    char signature[3];    /* "GIF" */
    char version[3];      /* "87a" or "89a" */
    uint16_t width;
    uint16_t height;
    uint8_t packed;       /* Global color table info */
    uint8_t bgcolor;
    uint8_t aspect;
} gif_header_t;

/* Image descriptor */
typedef struct {
    uint16_t left;
    uint16_t top;
    uint16_t width;
    uint16_t height;
    uint8_t packed;       /* Local color table, interlace, sort */
} gif_image_desc_t;

/* Graphic control extension */
typedef struct {
    uint8_t packed;
    uint16_t delay;
    uint8_t transparent;
} gif_gce_t;

/* LZW decoder state */
typedef struct {
    int code_size;
    int clear_code;
    int end_code;
    int next_code;
    int bits_left;
    uint32_t bit_buffer;
    int current_code_size;

    /* Code table */
    int prefix[GIF_LZW_TABLE_SIZE];
    uint8_t suffix[GIF_LZW_TABLE_SIZE];
    uint8_t stack[GIF_LZW_TABLE_SIZE];
    int stack_ptr;

    /* Sub-block reading */
    const uint8_t *data;
    size_t data_size;
    size_t pos;
    const uint8_t *block;
    int block_size;
    int block_pos;
} lzw_state_t;

/* Read a sub-block, return size (0 = end of data) */
static int read_sub_block(lzw_state_t *state) {
    if (state->pos >= state->data_size) return 0;

    state->block_size = state->data[state->pos++];
    if (state->block_size == 0) return 0;

    if (state->pos + state->block_size > state->data_size) {
        state->block_size = state->data_size - state->pos;
    }

    state->block = state->data + state->pos;
    state->pos += state->block_size;
    state->block_pos = 0;

    return state->block_size;
}

/* Get next byte from sub-block stream */
static int get_byte(lzw_state_t *state) {
    if (state->block_pos >= state->block_size) {
        if (read_sub_block(state) == 0) {
            return -1;
        }
    }
    return state->block[state->block_pos++];
}

/* Get next LZW code */
static int get_code(lzw_state_t *state) {
    while (state->bits_left < state->current_code_size) {
        int byte = get_byte(state);
        if (byte < 0) return -1;

        state->bit_buffer |= ((uint32_t)byte << state->bits_left);
        state->bits_left += 8;
    }

    int code = state->bit_buffer & ((1 << state->current_code_size) - 1);
    state->bit_buffer >>= state->current_code_size;
    state->bits_left -= state->current_code_size;

    return code;
}

/* Initialize LZW decoder */
static void lzw_init(lzw_state_t *state, const uint8_t *data, size_t size,
                     size_t pos, int min_code_size) {
    state->data = data;
    state->data_size = size;
    state->pos = pos;
    state->block = NULL;
    state->block_size = 0;
    state->block_pos = 0;

    state->code_size = min_code_size;
    state->clear_code = 1 << min_code_size;
    state->end_code = state->clear_code + 1;
    state->next_code = state->end_code + 1;
    state->current_code_size = min_code_size + 1;

    state->bits_left = 0;
    state->bit_buffer = 0;
    state->stack_ptr = 0;

    /* Initialize code table with literal values */
    for (int i = 0; i < state->clear_code; i++) {
        state->prefix[i] = -1;
        state->suffix[i] = i;
    }
}

/* Decode LZW compressed data */
static int lzw_decode(lzw_state_t *state, uint8_t *output, size_t output_size) {
    size_t output_pos = 0;
    int prev_code = -1;
    int first_char = 0;

    while (output_pos < output_size) {
        /* Output any stacked characters first */
        while (state->stack_ptr > 0 && output_pos < output_size) {
            output[output_pos++] = state->stack[--state->stack_ptr];
        }

        if (output_pos >= output_size) break;

        int code = get_code(state);
        if (code < 0) break;

        if (code == state->end_code) {
            break;
        }

        if (code == state->clear_code) {
            /* Reset decoder */
            state->next_code = state->end_code + 1;
            state->current_code_size = state->code_size + 1;
            prev_code = -1;
            continue;
        }

        int in_code = code;

        /* Handle code not in table */
        if (code >= state->next_code) {
            if (code > state->next_code || prev_code < 0) {
                break;  /* Invalid code */
            }
            state->stack[state->stack_ptr++] = first_char;
            code = prev_code;
        }

        /* Unwind code to output stack */
        while (code >= state->clear_code && state->stack_ptr < GIF_LZW_TABLE_SIZE) {
            if (code >= GIF_LZW_TABLE_SIZE) break;
            state->stack[state->stack_ptr++] = state->suffix[code];
            code = state->prefix[code];
            if (code == state->prefix[code]) break;  /* Prevent infinite loop */
        }

        if (code < state->clear_code) {
            first_char = state->suffix[code];
            state->stack[state->stack_ptr++] = first_char;
        }

        /* Add new code to table */
        if (prev_code >= 0 && state->next_code < GIF_LZW_TABLE_SIZE) {
            state->prefix[state->next_code] = prev_code;
            state->suffix[state->next_code] = first_char;
            state->next_code++;

            /* Increase code size if needed */
            if (state->next_code >= (1 << state->current_code_size) &&
                state->current_code_size < GIF_MAX_LZW_BITS) {
                state->current_code_size++;
            }
        }

        prev_code = in_code;
    }

    /* Flush remaining stack */
    while (state->stack_ptr > 0 && output_pos < output_size) {
        output[output_pos++] = state->stack[--state->stack_ptr];
    }

    return output_pos;
}

/* Skip sub-blocks */
static size_t skip_sub_blocks(const uint8_t *data, size_t size, size_t pos) {
    while (pos < size) {
        uint8_t block_size = data[pos++];
        if (block_size == 0) break;
        pos += block_size;
        if (pos > size) break;
    }
    return pos;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Check minimum size for header */
    if (size < 13) return 0;

    /* Verify GIF signature */
    if (memcmp(data, "GIF87a", 6) != 0 && memcmp(data, "GIF89a", 6) != 0) {
        return 0;
    }

    /* Parse header */
    gif_header_t header;
    memcpy(header.signature, data, 3);
    memcpy(header.version, data + 3, 3);
    header.width = data[6] | (data[7] << 8);
    header.height = data[8] | (data[9] << 8);
    header.packed = data[10];
    header.bgcolor = data[11];
    header.aspect = data[12];

    /* Validate dimensions */
    if (header.width == 0 || header.width > GIF_MAX_WIDTH) return 0;
    if (header.height == 0 || header.height > GIF_MAX_HEIGHT) return 0;

    /* Check image size limit */
    size_t image_size = (size_t)header.width * header.height;
    if (image_size > GIF_MAX_IMAGE_SIZE) return 0;

    size_t pos = 13;

    /* Skip global color table if present */
    int has_gct = (header.packed >> 7) & 1;
    int gct_size = 1 << ((header.packed & 7) + 1);
    if (has_gct) {
        pos += gct_size * 3;
        if (pos > size) return 0;
    }

    /* Process blocks */
    int frame_count = 0;
    gif_gce_t gce = {0};

    while (pos < size && frame_count < GIF_MAX_FRAMES) {
        uint8_t block_type = data[pos++];

        if (block_type == GIF_TRAILER) {
            break;
        } else if (block_type == GIF_EXTENSION) {
            if (pos >= size) break;
            uint8_t ext_label = data[pos++];

            if (ext_label == GIF_EXT_GRAPHIC) {
                /* Graphic control extension */
                if (pos >= size) break;
                uint8_t block_size = data[pos++];
                if (block_size >= 4 && pos + 4 <= size) {
                    gce.packed = data[pos];
                    gce.delay = data[pos + 1] | (data[pos + 2] << 8);
                    gce.transparent = data[pos + 3];
                }
                pos += block_size;
                if (pos < size && data[pos] == 0) pos++;  /* Block terminator */
            } else {
                /* Skip other extension blocks */
                pos = skip_sub_blocks(data, size, pos);
            }
        } else if (block_type == GIF_IMAGE_DESC) {
            /* Image descriptor */
            if (pos + 9 > size) break;

            gif_image_desc_t img;
            img.left = data[pos] | (data[pos + 1] << 8);
            img.top = data[pos + 2] | (data[pos + 3] << 8);
            img.width = data[pos + 4] | (data[pos + 5] << 8);
            img.height = data[pos + 6] | (data[pos + 7] << 8);
            img.packed = data[pos + 8];
            pos += 9;

            /* Validate image bounds */
            if (img.width == 0 || img.height == 0) {
                pos = skip_sub_blocks(data, size, pos + 1);
                continue;
            }
            if ((size_t)img.left + img.width > header.width ||
                (size_t)img.top + img.height > header.height) {
                pos = skip_sub_blocks(data, size, pos + 1);
                continue;
            }

            /* Skip local color table if present */
            int has_lct = (img.packed >> 7) & 1;
            int lct_size = 1 << ((img.packed & 7) + 1);
            if (has_lct) {
                pos += lct_size * 3;
                if (pos > size) break;
            }

            /* Get LZW minimum code size */
            if (pos >= size) break;
            int min_code_size = data[pos++];
            if (min_code_size < 2 || min_code_size > 11) {
                pos = skip_sub_blocks(data, size, pos);
                continue;
            }

            /* Allocate output buffer */
            size_t frame_size = (size_t)img.width * img.height;
            if (frame_size > GIF_MAX_IMAGE_SIZE) {
                pos = skip_sub_blocks(data, size, pos);
                continue;
            }

            uint8_t *output = malloc(frame_size);
            if (!output) {
                pos = skip_sub_blocks(data, size, pos);
                continue;
            }

            /* Decode LZW data */
            lzw_state_t lzw;
            lzw_init(&lzw, data, size, pos, min_code_size);
            lzw_decode(&lzw, output, frame_size);

            /* Handle interlacing if needed */
            int interlaced = (img.packed >> 6) & 1;
            if (interlaced && img.height > 1) {
                uint8_t *deinterlaced = malloc(frame_size);
                if (deinterlaced) {
                    /* Deinterlace passes: 0,8,4,2,1 */
                    static const int start[] = {0, 4, 2, 1};
                    static const int step[] = {8, 8, 4, 2};
                    size_t src_row = 0;

                    for (int pass = 0; pass < 4; pass++) {
                        for (int y = start[pass]; y < img.height && src_row < img.height;
                             y += step[pass], src_row++) {
                            memcpy(deinterlaced + y * img.width,
                                   output + src_row * img.width,
                                   img.width);
                        }
                    }
                    free(deinterlaced);
                }
            }

            free(output);
            frame_count++;

            /* Skip remaining sub-blocks */
            pos = lzw.pos;
            pos = skip_sub_blocks(data, size, pos);

            /* Reset GCE for next frame */
            memset(&gce, 0, sizeof(gce));
        } else {
            /* Unknown block type, try to skip */
            break;
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
