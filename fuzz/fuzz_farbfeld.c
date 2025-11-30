/*
 * AFL++ fuzzing harness for GIMP Farbfeld file parser
 * Based on plug-ins/common/file-farbfeld.c
 *
 * Targets: Integer overflow vulnerabilities in FF parsing (ZDI-25-xxx)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#define FARBFELD_MAGIC "farbfeld"
#define MAX_IMAGE_SIZE 262144

typedef struct {
    char magic[8];
    uint32_t width;
    uint32_t height;
} FarbfeldHeader;

static int read_farbfeld_header(FILE *fp, FarbfeldHeader *hdr) {
    if (fread(hdr->magic, 1, 8, fp) != 8)
        return -1;

    /* Check magic */
    if (memcmp(hdr->magic, FARBFELD_MAGIC, 8) != 0)
        return -1;

    uint32_t dims[2];
    if (fread(dims, sizeof(uint32_t), 2, fp) != 2)
        return -1;

    /* Big-endian format */
    hdr->width = ntohl(dims[0]);
    hdr->height = ntohl(dims[1]);

    return 0;
}

static int load_farbfeld_image(FILE *fp, FarbfeldHeader *hdr) {
    /* Validate dimensions */
    if (hdr->width == 0 || hdr->height == 0)
        return -1;
    if (hdr->width > MAX_IMAGE_SIZE || hdr->height > MAX_IMAGE_SIZE)
        return -1;

    /* Farbfeld uses 16-bit RGBA per pixel (8 bytes per pixel) */
    size_t pixel_count = (size_t)hdr->width * hdr->height;
    size_t raw_size = pixel_count * 8;  /* 4 channels * 2 bytes */

    /* Check for integer overflow */
    if (raw_size / 8 != pixel_count)
        return -1;

    if (raw_size > 256 * 1024 * 1024)
        return -1;

    uint16_t *raw_data = malloc(raw_size);
    if (!raw_data)
        return -1;

    if (fread(raw_data, 1, raw_size, fp) != raw_size) {
        free(raw_data);
        return -1;
    }

    /* Convert from big-endian and 16-bit to 8-bit RGBA */
    size_t output_size = pixel_count * 4;
    uint8_t *output = malloc(output_size);
    if (!output) {
        free(raw_data);
        return -1;
    }

    for (size_t i = 0; i < pixel_count; i++) {
        /* Convert from big-endian 16-bit to 8-bit */
        output[i * 4 + 0] = ntohs(raw_data[i * 4 + 0]) >> 8;  /* R */
        output[i * 4 + 1] = ntohs(raw_data[i * 4 + 1]) >> 8;  /* G */
        output[i * 4 + 2] = ntohs(raw_data[i * 4 + 2]) >> 8;  /* B */
        output[i * 4 + 3] = ntohs(raw_data[i * 4 + 3]) >> 8;  /* A */
    }

    free(output);
    free(raw_data);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16)  /* Minimum header: 8 magic + 4 width + 4 height */
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    FarbfeldHeader hdr;
    if (read_farbfeld_header(fp, &hdr) != 0) {
        fclose(fp);
        return 0;
    }

    load_farbfeld_image(fp, &hdr);

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
