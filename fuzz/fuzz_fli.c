/*
 * FLI/FLC Animation Format Fuzzer
 *
 * Standalone harness for fuzzing Autodesk FLI/FLC animation parsing.
 * Based on GIMP's file-fli plugin.
 *
 * FLI/FLC is an animation format supporting:
 * - Multiple compression codecs (BRUN, LC, LC_2, COPY, BLACK)
 * - Palette animation (COLOR, COLOR_2)
 * - Frame-based animation
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* FLI/FLC magic numbers */
#define HEADER_FLI 0xAF11  /* Original Animator FLI */
#define HEADER_FLC 0xAF12  /* Animator Pro FLC */

/* Frame magic */
#define FRAME 0xF1FA

/* Chunk types */
#define FLI_COLOR   11   /* 256-level color palette info (FLI) */
#define FLI_COLOR_2 4    /* 64-level color palette info (FLC) */
#define FLI_BLACK   13   /* Entire frame is black */
#define FLI_BRUN    15   /* Byte-oriented RLE compression */
#define FLI_COPY    16   /* Uncompressed frame */
#define FLI_LC      12   /* Line-compressed FLI */
#define FLI_LC_2    7    /* Word-oriented delta compression (FLC) */
#define FLI_MINI    18   /* Mini palette chunk (ignored) */

/* Maximum dimensions */
#define MAX_WIDTH  4096
#define MAX_HEIGHT 4096
#define MAX_FRAMES 10000
#define MAX_IMAGE_SIZE (16 * 1024 * 1024)

/* FLI header structure */
typedef struct {
    uint32_t filesize;
    uint16_t magic;
    uint16_t frames;
    uint16_t width;
    uint16_t height;
    uint16_t depth;
    uint16_t flags;
    uint32_t speed;
} fli_header_t;

/* Frame header structure */
typedef struct {
    uint32_t size;
    uint16_t magic;
    uint16_t chunks;
} fli_frame_t;

/* Chunk header structure */
typedef struct {
    uint32_t size;
    uint16_t magic;
} fli_chunk_t;

/* Read little-endian integers */
static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* Parse and validate FLI header */
static int parse_fli_header(const uint8_t *data, size_t size, fli_header_t *hdr) {
    if (size < 128) return -1;

    hdr->filesize = read_u32_le(data);
    hdr->magic = read_u16_le(data + 4);
    hdr->frames = read_u16_le(data + 6);
    hdr->width = read_u16_le(data + 8);
    hdr->height = read_u16_le(data + 10);
    hdr->depth = read_u16_le(data + 12);
    hdr->flags = read_u16_le(data + 14);

    /* Validate magic */
    if (hdr->magic != HEADER_FLI && hdr->magic != HEADER_FLC) {
        return -1;
    }

    /* Read speed based on format */
    if (hdr->magic == HEADER_FLI) {
        hdr->speed = read_u16_le(data + 16) * 14;
    } else {
        hdr->speed = read_u32_le(data + 16);
    }

    /* Apply defaults for zero dimensions */
    if (hdr->width == 0) hdr->width = 320;
    if (hdr->height == 0) hdr->height = 200;
    if (hdr->frames == 0) hdr->frames = 2;

    /* Validate dimensions */
    if (hdr->width > MAX_WIDTH) return -1;
    if (hdr->height > MAX_HEIGHT) return -1;
    if (hdr->frames > MAX_FRAMES) return -1;

    /* Validate filesize reasonableness */
    if (hdr->filesize > size + 1) {
        hdr->filesize = size;
    }

    return 0;
}

/* Read FLI_COLOR palette chunk (6-bit colors) */
static int read_color_chunk(const uint8_t *data, size_t chunk_size,
                            uint8_t *old_cmap, uint8_t *cmap) {
    if (chunk_size < 2) return -1;

    uint16_t num_packets = read_u16_le(data);
    size_t offset = 2;
    uint16_t col_pos = 0;

    for (uint16_t p = 0; p < num_packets && offset < chunk_size; p++) {
        if (offset + 2 > chunk_size) break;

        uint8_t skip_col = data[offset++];
        uint8_t num_col = data[offset++];

        /* num_col == 0 means 256 colors */
        if (num_col == 0) {
            if (offset + 768 > chunk_size) return -1;
            for (int i = 0; i < 768; i++) {
                cmap[i] = data[offset++] << 2;  /* 6-bit to 8-bit */
            }
            return 0;
        }

        /* Copy unchanged colors */
        for (uint8_t i = 0; i < skip_col && col_pos < 768; i++) {
            cmap[col_pos] = old_cmap[col_pos]; col_pos++;
            cmap[col_pos] = old_cmap[col_pos]; col_pos++;
            cmap[col_pos] = old_cmap[col_pos]; col_pos++;
        }

        /* Read new colors */
        for (uint8_t i = 0; i < num_col && col_pos < 768; i++) {
            if (offset + 3 > chunk_size) return -1;
            cmap[col_pos++] = data[offset++] << 2;
            cmap[col_pos++] = data[offset++] << 2;
            cmap[col_pos++] = data[offset++] << 2;
        }
    }

    return 0;
}

/* Read FLI_COLOR_2 palette chunk (8-bit colors) */
static int read_color_2_chunk(const uint8_t *data, size_t chunk_size,
                              uint8_t *old_cmap, uint8_t *cmap) {
    if (chunk_size < 2) return -1;

    uint16_t num_packets = read_u16_le(data);
    size_t offset = 2;
    uint16_t col_pos = 0;

    for (uint16_t p = 0; p < num_packets && offset < chunk_size; p++) {
        if (offset + 2 > chunk_size) break;

        uint8_t skip_col = data[offset++];
        uint8_t num_col = data[offset++];

        if (num_col == 0) {
            if (offset + 768 > chunk_size) return -1;
            for (int i = 0; i < 768; i++) {
                cmap[i] = data[offset++];
            }
            return 0;
        }

        for (uint8_t i = 0; i < skip_col && col_pos < 768; i++) {
            cmap[col_pos] = old_cmap[col_pos]; col_pos++;
            cmap[col_pos] = old_cmap[col_pos]; col_pos++;
            cmap[col_pos] = old_cmap[col_pos]; col_pos++;
        }

        for (uint8_t i = 0; i < num_col && col_pos < 768; i++) {
            if (offset + 3 > chunk_size) return -1;
            cmap[col_pos++] = data[offset++];
            cmap[col_pos++] = data[offset++];
            cmap[col_pos++] = data[offset++];
        }
    }

    return 0;
}

/* Read FLI_BLACK chunk - fill with zeros */
static int read_black_chunk(uint8_t *framebuf, size_t frame_size) {
    memset(framebuf, 0, frame_size);
    return 0;
}

/* Read FLI_COPY chunk - uncompressed frame */
static int read_copy_chunk(const uint8_t *data, size_t chunk_size,
                           uint8_t *framebuf, size_t frame_size) {
    size_t copy_size = (chunk_size < frame_size) ? chunk_size : frame_size;
    memcpy(framebuf, data, copy_size);
    return 0;
}

/* Read FLI_BRUN chunk - byte RLE for first frame */
static int read_brun_chunk(const uint8_t *data, size_t chunk_size,
                           uint8_t *framebuf, uint16_t width, uint16_t height) {
    size_t offset = 0;
    size_t frame_size = (size_t)width * height;

    for (uint16_t y = 0; y < height && offset < chunk_size; y++) {
        if (offset >= chunk_size) break;

        uint8_t pc = data[offset++];  /* Packet count (unused for BRUN) */
        (void)pc;

        size_t xc = 0;
        uint8_t *pos = framebuf + (width * y);
        size_t n = (size_t)width * (height - y);

        while (xc < width && offset < chunk_size) {
            uint8_t ps = data[offset++];

            if (ps & 0x80) {
                /* Literal run */
                int len = -(int8_t)ps;
                for (int i = 0; i < len && xc < n && offset < chunk_size; i++) {
                    pos[xc++] = data[offset++];
                }
            } else {
                /* Repeat run */
                if (offset >= chunk_size) break;
                uint8_t val = data[offset++];
                size_t len = (ps < (n - xc)) ? ps : (n - xc);
                memset(&pos[xc], val, len);
                xc += len;
            }
        }
    }

    return 0;
}

/* Read FLI_LC chunk - line compression */
static int read_lc_chunk(const uint8_t *data, size_t chunk_size,
                         uint8_t *old_framebuf, uint8_t *framebuf,
                         uint16_t width, uint16_t height) {
    if (chunk_size < 4) return -1;

    /* Copy old frame as base */
    memcpy(framebuf, old_framebuf, (size_t)width * height);

    uint16_t firstline = read_u16_le(data);
    uint16_t numline = read_u16_le(data + 2);
    size_t offset = 4;

    if (numline > height || height - numline < firstline) {
        return 0;
    }

    for (uint16_t y = 0; y < numline && offset < chunk_size; y++) {
        if (offset >= chunk_size) break;

        uint8_t pc = data[offset++];  /* Packet count */
        size_t xc = 0;
        uint8_t *pos = framebuf + (width * (firstline + y));
        size_t n = (size_t)width * (height - firstline - y);

        for (uint8_t p = 0; p < pc && offset + 2 <= chunk_size; p++) {
            uint8_t skip = data[offset++];
            uint8_t ps = data[offset++];

            xc += (skip < (n - xc)) ? skip : (n - xc);

            if (ps & 0x80) {
                /* Repeat */
                ps = -(int8_t)ps;
                if (offset >= chunk_size) break;
                uint8_t val = data[offset++];
                size_t len = (ps < (n - xc)) ? ps : (n - xc);
                memset(&pos[xc], val, len);
                xc += len;
            } else {
                /* Literal */
                size_t len = (ps < (n - xc)) ? ps : (n - xc);
                if (offset + len > chunk_size) len = chunk_size - offset;
                memcpy(&pos[xc], &data[offset], len);
                offset += len;
                xc += len;
            }
        }
    }

    return 0;
}

/* Read FLI_LC_2 chunk - word-oriented delta compression */
static int read_lc_2_chunk(const uint8_t *data, size_t chunk_size,
                           uint8_t *old_framebuf, uint8_t *framebuf,
                           uint16_t width, uint16_t height) {
    if (chunk_size < 2) return -1;

    memcpy(framebuf, old_framebuf, (size_t)width * height);

    uint16_t numline = read_u16_le(data);
    size_t offset = 2;
    uint16_t yc = 0;

    if (numline > height) numline = height;

    for (uint16_t lc = 0; lc < numline && offset + 2 <= chunk_size; lc++) {
        uint16_t pc = read_u16_le(data + offset);
        offset += 2;

        /* Process opcodes */
        while (pc & 0x8000) {
            if (pc & 0x4000) {
                /* Skip lines */
                yc += -(int16_t)pc;
            }
            /* Otherwise: last pixel value (ignore for fuzzing) */

            if (offset + 2 > chunk_size) return 0;
            pc = read_u16_le(data + offset);
            offset += 2;
        }

        if (yc >= height) break;

        size_t xc = 0;
        uint8_t *pos = framebuf + (width * yc);
        size_t n = (size_t)width * (height - yc);

        for (uint16_t p = 0; p < pc && offset + 2 <= chunk_size; p++) {
            uint8_t skip = data[offset++];
            uint8_t ps = data[offset++];

            xc += (skip < (n - xc)) ? skip : (n - xc);

            if (ps & 0x80) {
                /* Repeat word */
                ps = -(int8_t)ps;
                if (offset + 2 > chunk_size) break;
                uint8_t v1 = data[offset++];
                uint8_t v2 = data[offset++];

                while (ps > 0 && xc + 1 < n) {
                    pos[xc++] = v1;
                    pos[xc++] = v2;
                    ps--;
                }
            } else {
                /* Literal words */
                size_t len = (size_t)ps * 2;
                if (len > n - xc) len = n - xc;
                if (offset + len > chunk_size) len = chunk_size - offset;
                memcpy(&pos[xc], &data[offset], len);
                offset += len;
                xc += len;
            }
        }

        yc++;
    }

    return 0;
}

/* Process a single frame */
static int process_frame(const uint8_t *data, size_t size, size_t *offset,
                         const fli_header_t *hdr,
                         uint8_t *old_framebuf, uint8_t *framebuf,
                         uint8_t *old_cmap, uint8_t *cmap) {
    if (*offset + 8 > size) return -1;

    fli_frame_t frame;
    frame.size = read_u32_le(data + *offset);
    frame.magic = read_u16_le(data + *offset + 4);
    frame.chunks = read_u16_le(data + *offset + 6);

    /* Skip non-frame chunks */
    while (frame.magic != FRAME && *offset + frame.size <= size) {
        *offset += frame.size;
        if (*offset + 8 > size) return -1;
        frame.size = read_u32_le(data + *offset);
        frame.magic = read_u16_le(data + *offset + 4);
        frame.chunks = read_u16_le(data + *offset + 6);
    }

    if (frame.magic != FRAME) return -1;
    if (*offset + frame.size > size) return -1;

    size_t frame_end = *offset + frame.size;
    size_t chunk_offset = *offset + 16;  /* Skip frame header */

    for (uint16_t c = 0; c < frame.chunks && chunk_offset + 6 <= frame_end; c++) {
        fli_chunk_t chunk;
        chunk.size = read_u32_le(data + chunk_offset);
        chunk.magic = read_u16_le(data + chunk_offset + 4);

        if (chunk_offset + chunk.size > frame_end) break;
        if (chunk.size < 6) break;

        const uint8_t *chunk_data = data + chunk_offset + 6;
        size_t chunk_data_size = chunk.size - 6;

        switch (chunk.magic) {
            case FLI_COLOR:
                read_color_chunk(chunk_data, chunk_data_size, old_cmap, cmap);
                break;
            case FLI_COLOR_2:
                read_color_2_chunk(chunk_data, chunk_data_size, old_cmap, cmap);
                break;
            case FLI_BLACK:
                read_black_chunk(framebuf, (size_t)hdr->width * hdr->height);
                break;
            case FLI_BRUN:
                read_brun_chunk(chunk_data, chunk_data_size, framebuf,
                               hdr->width, hdr->height);
                break;
            case FLI_COPY:
                read_copy_chunk(chunk_data, chunk_data_size, framebuf,
                               (size_t)hdr->width * hdr->height);
                break;
            case FLI_LC:
                read_lc_chunk(chunk_data, chunk_data_size,
                             old_framebuf, framebuf,
                             hdr->width, hdr->height);
                break;
            case FLI_LC_2:
                read_lc_2_chunk(chunk_data, chunk_data_size,
                               old_framebuf, framebuf,
                               hdr->width, hdr->height);
                break;
            case FLI_MINI:
                /* Thumbnail, skip */
                break;
            default:
                /* Unknown chunk type */
                break;
        }

        chunk_offset += chunk.size;
    }

    /* Handle empty frames - copy from previous */
    if (frame.chunks == 0) {
        memcpy(framebuf, old_framebuf, (size_t)hdr->width * hdr->height);
    }

    *offset = frame_end;
    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fli_header_t hdr;

    if (parse_fli_header(data, size, &hdr) != 0) {
        return 0;
    }

    size_t frame_size = (size_t)hdr.width * hdr.height;
    if (frame_size > MAX_IMAGE_SIZE) {
        return 0;
    }

    /* Allocate buffers */
    uint8_t *framebuf = malloc(frame_size);
    uint8_t *old_framebuf = malloc(frame_size);
    uint8_t cmap[768];
    uint8_t old_cmap[768];

    if (!framebuf || !old_framebuf) {
        free(framebuf);
        free(old_framebuf);
        return 0;
    }

    memset(framebuf, 0, frame_size);
    memset(old_framebuf, 0, frame_size);
    memset(cmap, 0, sizeof(cmap));
    memset(old_cmap, 0, sizeof(old_cmap));

    /* Process frames (limit to prevent excessive CPU usage) */
    size_t offset = 128;  /* Skip header */
    int max_frames = (hdr.frames < 100) ? hdr.frames : 100;

    for (int f = 0; f < max_frames && offset < size; f++) {
        /* Swap buffers */
        memcpy(old_framebuf, framebuf, frame_size);
        memcpy(old_cmap, cmap, sizeof(cmap));

        if (process_frame(data, size, &offset, &hdr,
                         old_framebuf, framebuf, old_cmap, cmap) != 0) {
            break;
        }
    }

    free(framebuf);
    free(old_framebuf);
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
