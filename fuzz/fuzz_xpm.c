/*
 * XPM (X PixMap) Image Format Fuzzer
 *
 * Standalone harness for fuzzing XPM image parsing.
 * Based on GIMP's file-xpm plugin.
 *
 * XPM format features:
 * - ASCII text-based format (C-style syntax)
 * - Symbolic color names or hex colors
 * - Multiple characters per pixel for large palettes
 * - Comment support
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

/* XPM constants */
#define XPM_MAX_WIDTH  65536
#define XPM_MAX_HEIGHT 65536
#define XPM_MAX_COLORS 65536
#define XPM_MAX_CPP    8      /* Max chars per pixel */
#define XPM_MAX_IMAGE_SIZE (64 * 1024 * 1024)
#define XPM_MAX_LINE_LEN 4096

/* Color entry */
typedef struct {
    char chars[XPM_MAX_CPP + 1];
    uint8_t r, g, b, a;
} xpm_color_t;

/* XPM info */
typedef struct {
    int width;
    int height;
    int ncolors;
    int cpp;  /* Characters per pixel */
} xpm_info_t;

/* Scanner state */
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
} scanner_t;

/* Skip whitespace */
static void skip_whitespace(scanner_t *s) {
    while (s->pos < s->size && isspace(s->data[s->pos])) {
        s->pos++;
    }
}

/* Skip C-style comments */
static void skip_comments(scanner_t *s) {
    while (s->pos + 1 < s->size) {
        skip_whitespace(s);
        if (s->pos + 1 < s->size &&
            s->data[s->pos] == '/' && s->data[s->pos + 1] == '*') {
            s->pos += 2;
            while (s->pos + 1 < s->size) {
                if (s->data[s->pos] == '*' && s->data[s->pos + 1] == '/') {
                    s->pos += 2;
                    break;
                }
                s->pos++;
            }
        } else {
            break;
        }
    }
}

/* Find next quoted string and extract it */
static int read_quoted_string(scanner_t *s, char *buf, size_t max_len) {
    skip_comments(s);

    /* Find opening quote */
    while (s->pos < s->size && s->data[s->pos] != '"') {
        s->pos++;
    }
    if (s->pos >= s->size) return -1;
    s->pos++;  /* Skip quote */

    /* Read string content */
    size_t len = 0;
    while (s->pos < s->size && s->data[s->pos] != '"' && len < max_len - 1) {
        buf[len++] = s->data[s->pos++];
    }
    buf[len] = '\0';

    if (s->pos < s->size && s->data[s->pos] == '"') {
        s->pos++;  /* Skip closing quote */
    }

    return len;
}

/* Parse header line: "width height ncolors cpp" */
static int parse_header(const char *line, xpm_info_t *info) {
    int n = sscanf(line, "%d %d %d %d",
                   &info->width, &info->height, &info->ncolors, &info->cpp);
    return (n == 4) ? 0 : -1;
}

/* Parse hex color (supports #RGB, #RRGGBB, #RRRRGGGGBBBB) */
static int parse_hex_color(const char *str, uint8_t *r, uint8_t *g, uint8_t *b) {
    if (*str != '#') return -1;
    str++;

    size_t len = strlen(str);
    unsigned int rv, gv, bv;

    if (len == 3) {
        /* #RGB */
        if (sscanf(str, "%1x%1x%1x", &rv, &gv, &bv) != 3) return -1;
        *r = rv * 17;
        *g = gv * 17;
        *b = bv * 17;
    } else if (len == 6) {
        /* #RRGGBB */
        if (sscanf(str, "%2x%2x%2x", &rv, &gv, &bv) != 3) return -1;
        *r = rv;
        *g = gv;
        *b = bv;
    } else if (len == 12) {
        /* #RRRRGGGGBBBB */
        if (sscanf(str, "%4x%4x%4x", &rv, &gv, &bv) != 3) return -1;
        *r = rv >> 8;
        *g = gv >> 8;
        *b = bv >> 8;
    } else {
        return -1;
    }

    return 0;
}

/* Known color names (subset) */
static struct { const char *name; uint8_t r, g, b; } known_colors[] = {
    {"none", 0, 0, 0},  /* Transparent */
    {"black", 0, 0, 0},
    {"white", 255, 255, 255},
    {"red", 255, 0, 0},
    {"green", 0, 128, 0},
    {"blue", 0, 0, 255},
    {"yellow", 255, 255, 0},
    {"cyan", 0, 255, 255},
    {"magenta", 255, 0, 255},
    {"gray", 128, 128, 128},
    {"grey", 128, 128, 128},
    {"transparent", 0, 0, 0},
    {NULL, 0, 0, 0}
};

/* Parse color name */
static int parse_color_name(const char *str, uint8_t *r, uint8_t *g, uint8_t *b, uint8_t *a) {
    *a = 255;

    /* Check for hex color */
    if (str[0] == '#') {
        return parse_hex_color(str, r, g, b);
    }

    /* Check known colors */
    for (int i = 0; known_colors[i].name; i++) {
        if (strcasecmp(str, known_colors[i].name) == 0) {
            *r = known_colors[i].r;
            *g = known_colors[i].g;
            *b = known_colors[i].b;
            if (strcasecmp(str, "none") == 0 ||
                strcasecmp(str, "transparent") == 0) {
                *a = 0;
            }
            return 0;
        }
    }

    /* Unknown color - use gray */
    *r = *g = *b = 128;
    return 0;
}

/* Parse color line: "chars c color" or "chars s name c color" */
static int parse_color_line(const char *line, int cpp, xpm_color_t *color) {
    if ((int)strlen(line) < cpp) return -1;

    /* Copy pixel characters */
    memcpy(color->chars, line, cpp);
    color->chars[cpp] = '\0';

    const char *p = line + cpp;
    color->r = color->g = color->b = 0;
    color->a = 255;

    /* Find color specification (c for color, s for symbolic) */
    while (*p) {
        while (*p && isspace(*p)) p++;
        if (*p == '\0') break;

        char key = *p++;
        while (*p && isspace(*p)) p++;

        if (key == 'c' || key == 'g' || key == 'm') {
            /* Extract color value */
            char color_str[64];
            int i = 0;
            while (*p && !isspace(*p) && i < 63) {
                color_str[i++] = *p++;
            }
            color_str[i] = '\0';

            if (i > 0) {
                parse_color_name(color_str, &color->r, &color->g, &color->b, &color->a);
                return 0;
            }
        } else if (key == 's') {
            /* Skip symbolic name */
            while (*p && !isspace(*p)) p++;
        } else {
            /* Skip unknown key value */
            while (*p && !isspace(*p)) p++;
        }
    }

    return 0;
}

/* Find color in palette */
static xpm_color_t *find_color(const char *chars, int cpp,
                                xpm_color_t *colors, int ncolors) {
    for (int i = 0; i < ncolors; i++) {
        if (memcmp(chars, colors[i].chars, cpp) == 0) {
            return &colors[i];
        }
    }
    return NULL;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    scanner_t scanner = {data, size, 0};
    xpm_info_t info;
    char line[XPM_MAX_LINE_LEN];

    /* Look for XPM signature */
    const char *sig1 = "/* XPM */";
    const char *sig2 = "/*XPM*/";
    const char *sig3 = "! XPM2";

    int found = 0;
    for (size_t i = 0; i < size && i < 256; i++) {
        if (size - i >= strlen(sig1) && memcmp(data + i, sig1, strlen(sig1)) == 0) {
            scanner.pos = i + strlen(sig1);
            found = 1;
            break;
        }
        if (size - i >= strlen(sig2) && memcmp(data + i, sig2, strlen(sig2)) == 0) {
            scanner.pos = i + strlen(sig2);
            found = 1;
            break;
        }
        if (size - i >= strlen(sig3) && memcmp(data + i, sig3, strlen(sig3)) == 0) {
            scanner.pos = i + strlen(sig3);
            found = 1;
            break;
        }
    }

    if (!found) return 0;

    /* Read header line */
    if (read_quoted_string(&scanner, line, sizeof(line)) < 0) {
        return 0;
    }

    if (parse_header(line, &info) != 0) {
        return 0;
    }

    /* Validate header */
    if (info.width <= 0 || info.width > XPM_MAX_WIDTH) return 0;
    if (info.height <= 0 || info.height > XPM_MAX_HEIGHT) return 0;
    if (info.ncolors <= 0 || info.ncolors > XPM_MAX_COLORS) return 0;
    if (info.cpp <= 0 || info.cpp > XPM_MAX_CPP) return 0;

    size_t image_size = (size_t)info.width * info.height * 4;
    if (image_size > XPM_MAX_IMAGE_SIZE) return 0;

    /* Allocate color table */
    xpm_color_t *colors = malloc(info.ncolors * sizeof(xpm_color_t));
    if (!colors) return 0;

    /* Read color lines */
    for (int i = 0; i < info.ncolors; i++) {
        if (read_quoted_string(&scanner, line, sizeof(line)) < 0) {
            free(colors);
            return 0;
        }
        if (parse_color_line(line, info.cpp, &colors[i]) != 0) {
            /* Use default color on parse error */
            memset(&colors[i], 0, sizeof(xpm_color_t));
            colors[i].a = 255;
        }
    }

    /* Allocate output buffer (RGBA) */
    uint8_t *output = malloc(image_size);
    if (!output) {
        free(colors);
        return 0;
    }

    /* Read pixel lines */
    for (int y = 0; y < info.height; y++) {
        if (read_quoted_string(&scanner, line, sizeof(line)) < 0) {
            break;
        }

        int line_len = strlen(line);
        for (int x = 0; x < info.width; x++) {
            int pos = x * info.cpp;
            if (pos + info.cpp > line_len) break;

            xpm_color_t *color = find_color(line + pos, info.cpp, colors, info.ncolors);
            size_t out_idx = ((size_t)y * info.width + x) * 4;

            if (color) {
                output[out_idx + 0] = color->r;
                output[out_idx + 1] = color->g;
                output[out_idx + 2] = color->b;
                output[out_idx + 3] = color->a;
            } else {
                /* Unknown pixel - use transparent black */
                output[out_idx + 0] = 0;
                output[out_idx + 1] = 0;
                output[out_idx + 2] = 0;
                output[out_idx + 3] = 0;
            }
        }
    }

    free(output);
    free(colors);
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
