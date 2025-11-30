/*
 * PNM (Portable Any Map) Image Format Fuzzer
 *
 * Standalone harness for fuzzing PNM/PBM/PGM/PPM/PAM/PFM image parsing.
 * Based on GIMP's file-pnm plugin.
 *
 * PNM family includes:
 * - PBM (P1/P4): Portable Bitmap (1-bit)
 * - PGM (P2/P5): Portable Graymap (grayscale)
 * - PPM (P3/P6): Portable Pixmap (RGB)
 * - PAM (P7): Portable Arbitrary Map (extended format)
 * - PFM: Portable Float Map (floating point)
 *
 * P1/P2/P3 = ASCII format, P4/P5/P6 = binary (raw) format
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>

/* Maximum dimensions */
#define PNM_MAX_WIDTH  65536
#define PNM_MAX_HEIGHT 65536
#define PNM_MAX_IMAGE_SIZE (128 * 1024 * 1024)

/* PNM format types */
typedef enum {
    PNM_PBM_ASCII = 1,   /* P1 */
    PNM_PGM_ASCII = 2,   /* P2 */
    PNM_PPM_ASCII = 3,   /* P3 */
    PNM_PBM_RAW   = 4,   /* P4 */
    PNM_PGM_RAW   = 5,   /* P5 */
    PNM_PPM_RAW   = 6,   /* P6 */
    PNM_PAM       = 7,   /* P7 */
    PNM_PFM_GRAY  = 'f', /* Pf */
    PNM_PFM_RGB   = 'F'  /* PF */
} pnm_type_t;

/* Scanner state */
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    int eof;
} scanner_t;

/* PNM info */
typedef struct {
    pnm_type_t type;
    int width;
    int height;
    int maxval;
    int depth;          /* Number of channels (PAM) */
    float scale;        /* PFM scale factor */
    int is_ascii;
    int is_float;
} pnm_info_t;

/* Get next character */
static int scanner_getc(scanner_t *s) {
    if (s->pos >= s->size) {
        s->eof = 1;
        return -1;
    }
    return s->data[s->pos++];
}

/* Peek at next character */
static int scanner_peek(scanner_t *s) {
    if (s->pos >= s->size) return -1;
    return s->data[s->pos];
}

/* Skip whitespace and comments */
static void skip_whitespace_comments(scanner_t *s) {
    int c;
    while (!s->eof) {
        c = scanner_peek(s);
        if (c == -1) break;

        if (c == '#') {
            /* Skip comment line */
            while ((c = scanner_getc(s)) != -1 && c != '\n');
        } else if (isspace(c)) {
            scanner_getc(s);
        } else {
            break;
        }
    }
}

/* Read an integer from ASCII */
static int read_int(scanner_t *s) {
    int value = 0;
    int c;
    int digits = 0;

    skip_whitespace_comments(s);

    while (!s->eof && digits < 10) {
        c = scanner_peek(s);
        if (c >= '0' && c <= '9') {
            scanner_getc(s);
            value = value * 10 + (c - '0');
            digits++;
        } else {
            break;
        }
    }

    return value;
}

/* Read a float from ASCII */
static float read_float(scanner_t *s) {
    char buf[64];
    int i = 0;
    int c;

    skip_whitespace_comments(s);

    while (!s->eof && i < 63) {
        c = scanner_peek(s);
        if ((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' ||
            c == 'e' || c == 'E') {
            buf[i++] = scanner_getc(s);
        } else {
            break;
        }
    }
    buf[i] = '\0';

    return (float)atof(buf);
}

/* Read a word (for PAM headers) */
static int read_word(scanner_t *s, char *buf, size_t max_len) {
    size_t i = 0;
    int c;

    skip_whitespace_comments(s);

    while (!s->eof && i < max_len - 1) {
        c = scanner_peek(s);
        if (c != -1 && !isspace(c)) {
            buf[i++] = scanner_getc(s);
        } else {
            break;
        }
    }
    buf[i] = '\0';

    return i;
}

/* Parse PNM header */
static int parse_pnm_header(scanner_t *s, pnm_info_t *info) {
    int c1, c2;
    char word[64];

    memset(info, 0, sizeof(*info));
    info->maxval = 1;
    info->depth = 1;
    info->scale = 1.0f;

    /* Read magic */
    c1 = scanner_getc(s);
    c2 = scanner_getc(s);

    if (c1 != 'P') return -1;

    switch (c2) {
        case '1': info->type = PNM_PBM_ASCII; info->is_ascii = 1; break;
        case '2': info->type = PNM_PGM_ASCII; info->is_ascii = 1; break;
        case '3': info->type = PNM_PPM_ASCII; info->is_ascii = 1; break;
        case '4': info->type = PNM_PBM_RAW; break;
        case '5': info->type = PNM_PGM_RAW; break;
        case '6': info->type = PNM_PPM_RAW; break;
        case '7': info->type = PNM_PAM; break;
        case 'f': info->type = PNM_PFM_GRAY; info->is_float = 1; break;
        case 'F': info->type = PNM_PFM_RGB; info->is_float = 1; break;
        default: return -1;
    }

    /* Parse header based on type */
    if (info->type == PNM_PAM) {
        /* PAM has keyword-based header */
        while (!s->eof) {
            read_word(s, word, sizeof(word));

            if (strcmp(word, "ENDHDR") == 0) {
                /* Skip one whitespace after ENDHDR */
                scanner_getc(s);
                break;
            } else if (strcmp(word, "WIDTH") == 0) {
                info->width = read_int(s);
            } else if (strcmp(word, "HEIGHT") == 0) {
                info->height = read_int(s);
            } else if (strcmp(word, "DEPTH") == 0) {
                info->depth = read_int(s);
            } else if (strcmp(word, "MAXVAL") == 0) {
                info->maxval = read_int(s);
            } else if (strcmp(word, "TUPLTYPE") == 0) {
                read_word(s, word, sizeof(word));
                /* Could be BLACKANDWHITE, GRAYSCALE, RGB, GRAYSCALE_ALPHA, RGB_ALPHA */
            }
        }
    } else if (info->is_float) {
        /* PFM header: width height scale */
        info->width = read_int(s);
        info->height = read_int(s);
        info->scale = read_float(s);
        /* Skip one whitespace after scale */
        scanner_getc(s);
        info->depth = (info->type == PNM_PFM_RGB) ? 3 : 1;
    } else {
        /* Standard PNM header */
        info->width = read_int(s);
        info->height = read_int(s);

        if (info->type != PNM_PBM_ASCII && info->type != PNM_PBM_RAW) {
            info->maxval = read_int(s);
        }

        /* Skip one whitespace after maxval/dimensions */
        scanner_getc(s);

        /* Set depth based on type */
        switch (info->type) {
            case PNM_PBM_ASCII:
            case PNM_PBM_RAW:
            case PNM_PGM_ASCII:
            case PNM_PGM_RAW:
                info->depth = 1;
                break;
            case PNM_PPM_ASCII:
            case PNM_PPM_RAW:
                info->depth = 3;
                break;
            default:
                break;
        }
    }

    /* Validate */
    if (info->width <= 0 || info->width > PNM_MAX_WIDTH) return -1;
    if (info->height <= 0 || info->height > PNM_MAX_HEIGHT) return -1;
    if (!info->is_float && (info->maxval <= 0 || info->maxval > 65535)) return -1;
    if (info->depth <= 0 || info->depth > 4) return -1;

    return 0;
}

/* Load ASCII PBM/PGM/PPM data */
static int load_ascii(scanner_t *s, pnm_info_t *info, uint16_t *output, size_t max_pixels) {
    size_t total = (size_t)info->width * info->height * info->depth;
    if (total > max_pixels) total = max_pixels;

    for (size_t i = 0; i < total && !s->eof; i++) {
        output[i] = read_int(s);
    }

    return 0;
}

/* Load raw PGM/PPM data */
static int load_raw(scanner_t *s, pnm_info_t *info, uint16_t *output, size_t max_pixels) {
    size_t total = (size_t)info->width * info->height * info->depth;
    if (total > max_pixels) total = max_pixels;

    int bytes_per_sample = (info->maxval > 255) ? 2 : 1;

    for (size_t i = 0; i < total && !s->eof; i++) {
        if (bytes_per_sample == 2) {
            int hi = scanner_getc(s);
            int lo = scanner_getc(s);
            if (hi == -1 || lo == -1) break;
            output[i] = (hi << 8) | lo;
        } else {
            int val = scanner_getc(s);
            if (val == -1) break;
            output[i] = val;
        }
    }

    return 0;
}

/* Load raw PBM data (packed bits) */
static int load_raw_pbm(scanner_t *s, pnm_info_t *info, uint8_t *output, size_t max_size) {
    int width = info->width;
    int height = info->height;
    int bytes_per_row = (width + 7) / 8;

    for (int y = 0; y < height && !s->eof; y++) {
        for (int b = 0; b < bytes_per_row && !s->eof; b++) {
            int byte = scanner_getc(s);
            if (byte == -1) break;

            /* Unpack bits */
            for (int bit = 0; bit < 8 && (b * 8 + bit) < width; bit++) {
                size_t idx = (size_t)y * width + b * 8 + bit;
                if (idx < max_size) {
                    output[idx] = (byte & (0x80 >> bit)) ? 1 : 0;
                }
            }
        }
    }

    return 0;
}

/* Load PFM data (floating point) */
static int load_pfm(scanner_t *s, pnm_info_t *info, float *output, size_t max_floats) {
    size_t total = (size_t)info->width * info->height * info->depth;
    if (total > max_floats) total = max_floats;

    int little_endian = (info->scale < 0);
    float scale = fabsf(info->scale);

    for (size_t i = 0; i < total && !s->eof; i++) {
        uint8_t bytes[4];
        for (int j = 0; j < 4; j++) {
            int c = scanner_getc(s);
            if (c == -1) return 0;
            bytes[j] = c;
        }

        uint32_t bits;
        if (little_endian) {
            bits = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
        } else {
            bits = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        }

        float val;
        memcpy(&val, &bits, sizeof(float));
        output[i] = val * scale;
    }

    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    scanner_t scanner;
    pnm_info_t info;

    scanner.data = data;
    scanner.size = size;
    scanner.pos = 0;
    scanner.eof = 0;

    if (parse_pnm_header(&scanner, &info) != 0) {
        return 0;
    }

    /* Calculate output size */
    size_t num_pixels = (size_t)info.width * info.height * info.depth;
    size_t output_size;

    if (info.is_float) {
        output_size = num_pixels * sizeof(float);
    } else {
        output_size = num_pixels * sizeof(uint16_t);
    }

    if (output_size > PNM_MAX_IMAGE_SIZE) {
        return 0;
    }

    /* Allocate output buffer */
    void *output = malloc(output_size);
    if (!output) {
        return 0;
    }

    /* Load based on format */
    switch (info.type) {
        case PNM_PBM_ASCII:
        case PNM_PGM_ASCII:
        case PNM_PPM_ASCII:
            load_ascii(&scanner, &info, (uint16_t *)output, num_pixels);
            break;

        case PNM_PBM_RAW:
            load_raw_pbm(&scanner, &info, (uint8_t *)output, num_pixels);
            break;

        case PNM_PGM_RAW:
        case PNM_PPM_RAW:
        case PNM_PAM:
            load_raw(&scanner, &info, (uint16_t *)output, num_pixels);
            break;

        case PNM_PFM_GRAY:
        case PNM_PFM_RGB:
            load_pfm(&scanner, &info, (float *)output, num_pixels);
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
