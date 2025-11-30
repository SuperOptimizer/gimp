/*
 * FITS (Flexible Image Transport System) Format Fuzzer
 *
 * Standalone harness for fuzzing FITS astronomical image parsing.
 * Based on GIMP's file-fits plugin.
 *
 * FITS format features:
 * - 2880-byte fixed-size header records
 * - ASCII keyword=value header cards (80 chars each)
 * - Multiple HDUs (Header Data Units)
 * - Various bit depths (8, 16, 32, -32, -64)
 * - Multi-dimensional arrays (NAXIS)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>

/* FITS constants */
#define FITS_RECORD_SIZE  2880    /* Size of each FITS record */
#define FITS_CARD_SIZE    80      /* Size of each header card */
#define FITS_CARDS_PER_RECORD (FITS_RECORD_SIZE / FITS_CARD_SIZE)

#define FITS_MAX_NAXIS    999
#define FITS_MAX_DIM      65536
#define FITS_MAX_IMAGE_SIZE (256 * 1024 * 1024)

/* Bit depth values */
#define FITS_BITPIX_8     8
#define FITS_BITPIX_16    16
#define FITS_BITPIX_32    32
#define FITS_BITPIX_M32  -32     /* 32-bit float */
#define FITS_BITPIX_M64  -64     /* 64-bit float */

/* FITS header info */
typedef struct {
    int  simple;      /* Is a simple FITS file */
    int  bitpix;      /* Bits per pixel */
    int  naxis;       /* Number of axes */
    int  naxisn[10];  /* Dimension of each axis */
    double bscale;    /* Scale factor */
    double bzero;     /* Zero offset */
    double datamin;   /* Minimum data value */
    double datamax;   /* Maximum data value */
    int  extend;      /* Has extensions */
} fits_header_t;

/* Parse a FITS header card (80 chars) */
static int parse_card(const char *card, char *keyword, char *value) {
    /* Extract keyword (first 8 chars) */
    int i;
    for (i = 0; i < 8 && card[i] != ' ' && card[i] != '='; i++) {
        keyword[i] = card[i];
    }
    keyword[i] = '\0';

    /* Check for value indicator */
    if (card[8] != '=' || card[9] != ' ') {
        value[0] = '\0';
        return 0;
    }

    /* Extract value (starting at position 10) */
    const char *vstart = card + 10;
    int vlen = 0;

    /* Skip leading spaces */
    while (*vstart == ' ' && vstart < card + 80) vstart++;

    if (*vstart == '\'') {
        /* String value */
        vstart++;
        while (vstart[vlen] != '\'' && vstart + vlen < card + 80) {
            vlen++;
        }
    } else {
        /* Numeric value - read until space or slash */
        while (vstart[vlen] != ' ' && vstart[vlen] != '/' &&
               vstart + vlen < card + 80) {
            vlen++;
        }
    }

    if (vlen > 70) vlen = 70;
    memcpy(value, vstart, vlen);
    value[vlen] = '\0';

    /* Trim trailing spaces */
    while (vlen > 0 && value[vlen - 1] == ' ') {
        value[--vlen] = '\0';
    }

    return 1;
}

/* Parse FITS header */
static int parse_fits_header(const uint8_t *data, size_t size,
                             fits_header_t *hdr, size_t *data_start) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->bscale = 1.0;
    hdr->bzero = 0.0;

    if (size < FITS_RECORD_SIZE) return -1;

    /* Check SIMPLE keyword */
    if (memcmp(data, "SIMPLE  =", 9) != 0) {
        return -1;
    }

    size_t pos = 0;
    int end_found = 0;
    char keyword[16], value[80];

    /* Parse header cards */
    while (pos < size && !end_found) {
        for (int card = 0; card < FITS_CARDS_PER_RECORD && !end_found; card++) {
            const char *card_data = (const char *)(data + pos + card * FITS_CARD_SIZE);

            if (pos + (card + 1) * FITS_CARD_SIZE > size) {
                return -1;
            }

            /* Check for END keyword */
            if (memcmp(card_data, "END", 3) == 0 &&
                (card_data[3] == ' ' || card_data[3] == '\0')) {
                end_found = 1;
                break;
            }

            if (!parse_card(card_data, keyword, value)) continue;

            /* Parse known keywords */
            if (strcmp(keyword, "SIMPLE") == 0) {
                hdr->simple = (value[0] == 'T');
            } else if (strcmp(keyword, "BITPIX") == 0) {
                hdr->bitpix = atoi(value);
            } else if (strcmp(keyword, "NAXIS") == 0) {
                hdr->naxis = atoi(value);
                if (hdr->naxis < 0 || hdr->naxis > 10) return -1;
            } else if (strncmp(keyword, "NAXIS", 5) == 0 && isdigit(keyword[5])) {
                int axis = atoi(keyword + 5);
                if (axis > 0 && axis <= 10) {
                    hdr->naxisn[axis - 1] = atoi(value);
                }
            } else if (strcmp(keyword, "BSCALE") == 0) {
                hdr->bscale = atof(value);
            } else if (strcmp(keyword, "BZERO") == 0) {
                hdr->bzero = atof(value);
            } else if (strcmp(keyword, "DATAMIN") == 0) {
                hdr->datamin = atof(value);
            } else if (strcmp(keyword, "DATAMAX") == 0) {
                hdr->datamax = atof(value);
            } else if (strcmp(keyword, "EXTEND") == 0) {
                hdr->extend = (value[0] == 'T');
            }
        }

        pos += FITS_RECORD_SIZE;
    }

    if (!end_found) return -1;

    /* Round up to next record boundary */
    *data_start = ((pos + FITS_RECORD_SIZE - 1) / FITS_RECORD_SIZE) * FITS_RECORD_SIZE;

    /* Validate header */
    if (!hdr->simple) return -1;

    if (hdr->bitpix != 8 && hdr->bitpix != 16 && hdr->bitpix != 32 &&
        hdr->bitpix != -32 && hdr->bitpix != -64) {
        return -1;
    }

    if (hdr->naxis < 0 || hdr->naxis > 10) return -1;

    for (int i = 0; i < hdr->naxis; i++) {
        if (hdr->naxisn[i] <= 0 || hdr->naxisn[i] > FITS_MAX_DIM) {
            return -1;
        }
    }

    return 0;
}

/* Swap bytes for 16-bit values */
static void swap16(uint8_t *data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        uint8_t tmp = data[i * 2];
        data[i * 2] = data[i * 2 + 1];
        data[i * 2 + 1] = tmp;
    }
}

/* Swap bytes for 32-bit values */
static void swap32(uint8_t *data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        uint8_t *p = data + i * 4;
        uint8_t tmp;
        tmp = p[0]; p[0] = p[3]; p[3] = tmp;
        tmp = p[1]; p[1] = p[2]; p[2] = tmp;
    }
}

/* Swap bytes for 64-bit values */
static void swap64(uint8_t *data, size_t count) {
    for (size_t i = 0; i < count; i++) {
        uint8_t *p = data + i * 8;
        uint8_t tmp;
        tmp = p[0]; p[0] = p[7]; p[7] = tmp;
        tmp = p[1]; p[1] = p[6]; p[6] = tmp;
        tmp = p[2]; p[2] = p[5]; p[5] = tmp;
        tmp = p[3]; p[3] = p[4]; p[4] = tmp;
    }
}

/* Load FITS image data */
static int load_fits_data(const uint8_t *data, size_t size, size_t offset,
                          fits_header_t *hdr, uint8_t **output, size_t *output_size) {
    /* Calculate total pixels */
    size_t total_pixels = 1;
    for (int i = 0; i < hdr->naxis && i < 3; i++) {
        total_pixels *= hdr->naxisn[i];
    }

    /* Calculate bytes per pixel */
    int bytes_per_pixel = abs(hdr->bitpix) / 8;
    size_t data_size = total_pixels * bytes_per_pixel;

    if (data_size > FITS_MAX_IMAGE_SIZE) return -1;
    if (offset + data_size > size) {
        data_size = size - offset;
    }

    *output = malloc(data_size);
    if (!*output) return -1;

    memcpy(*output, data + offset, data_size);
    *output_size = data_size;

    /* FITS is big-endian - swap to host order on little-endian systems */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    size_t pixel_count = data_size / bytes_per_pixel;
    switch (bytes_per_pixel) {
        case 2:
            swap16(*output, pixel_count);
            break;
        case 4:
            swap32(*output, pixel_count);
            break;
        case 8:
            swap64(*output, pixel_count);
            break;
    }
#endif

    /* Apply BSCALE and BZERO if needed */
    if (hdr->bscale != 1.0 || hdr->bzero != 0.0) {
        /* Would apply scaling here in full implementation */
    }

    return 0;
}

/* Main fuzzing function */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fits_header_t hdr;
    size_t data_start;

    if (parse_fits_header(data, size, &hdr, &data_start) != 0) {
        return 0;
    }

    /* Load image data */
    uint8_t *output = NULL;
    size_t output_size;

    if (load_fits_data(data, size, data_start, &hdr, &output, &output_size) == 0) {
        /* Process extensions if present */
        if (hdr.extend && output_size > 0) {
            size_t ext_offset = data_start +
                ((output_size + FITS_RECORD_SIZE - 1) / FITS_RECORD_SIZE) * FITS_RECORD_SIZE;

            /* Try to parse extension headers */
            if (ext_offset < size) {
                fits_header_t ext_hdr;
                size_t ext_data_start;

                /* Extension might start with XTENSION keyword instead of SIMPLE */
                if (size - ext_offset >= FITS_RECORD_SIZE) {
                    /* Just validate that we can read the extension area */
                    const uint8_t *ext_data = data + ext_offset;
                    (void)ext_data;  /* Prevent unused warning */
                }
            }
        }

        free(output);
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
