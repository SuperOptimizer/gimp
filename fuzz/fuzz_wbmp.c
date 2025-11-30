/*
 * AFL++ fuzzing harness for GIMP WBMP (Wireless Bitmap) parser
 * Based on plug-ins/common/file-wbmp.c
 *
 * Targets: Integer overflow in WBMP dimension parsing (ZDI-25-xxx)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_IMAGE_SIZE 262144

typedef struct {
    uint8_t type;
    uint8_t fixed_header;
    uint32_t width;
    uint32_t height;
} WBMPHeader;

/* WBMP uses multi-byte integer encoding */
static int read_multibyte_int(FILE *fp, uint32_t *value) {
    uint32_t result = 0;
    int count = 0;

    while (count < 5) {  /* Max 5 bytes for 32-bit value */
        int byte = fgetc(fp);
        if (byte == EOF)
            return -1;

        result = (result << 7) | (byte & 0x7f);

        if ((byte & 0x80) == 0)
            break;

        count++;
    }

    if (count >= 5)
        return -1;  /* Too many continuation bytes */

    *value = result;
    return 0;
}

static int read_wbmp_header(FILE *fp, WBMPHeader *hdr) {
    int type = fgetc(fp);
    if (type == EOF)
        return -1;
    hdr->type = type;

    /* Only type 0 is defined */
    if (hdr->type != 0)
        return -1;

    int fixed = fgetc(fp);
    if (fixed == EOF)
        return -1;
    hdr->fixed_header = fixed;

    /* Read width and height as multi-byte integers */
    if (read_multibyte_int(fp, &hdr->width) != 0)
        return -1;
    if (read_multibyte_int(fp, &hdr->height) != 0)
        return -1;

    return 0;
}

static int load_wbmp_image(FILE *fp, WBMPHeader *hdr) {
    /* Validate dimensions */
    if (hdr->width == 0 || hdr->height == 0)
        return -1;
    if (hdr->width > MAX_IMAGE_SIZE || hdr->height > MAX_IMAGE_SIZE)
        return -1;

    /* WBMP is 1-bit per pixel, packed in bytes */
    uint32_t bytes_per_row = (hdr->width + 7) / 8;
    size_t raw_size = (size_t)bytes_per_row * hdr->height;

    /* Check for integer overflow */
    if (raw_size / hdr->height != bytes_per_row)
        return -1;

    if (raw_size > 256 * 1024 * 1024)
        return -1;

    uint8_t *raw_data = malloc(raw_size);
    if (!raw_data)
        return -1;

    if (fread(raw_data, 1, raw_size, fp) != raw_size) {
        free(raw_data);
        return -1;
    }

    /* Convert 1-bit to 8-bit grayscale (simulating GIMP conversion) */
    size_t pixel_count = (size_t)hdr->width * hdr->height;
    uint8_t *output = malloc(pixel_count);
    if (!output) {
        free(raw_data);
        return -1;
    }

    for (uint32_t y = 0; y < hdr->height; y++) {
        uint8_t *row = raw_data + y * bytes_per_row;
        for (uint32_t x = 0; x < hdr->width; x++) {
            uint32_t byte_idx = x / 8;
            uint32_t bit_idx = 7 - (x % 8);
            uint8_t pixel = (row[byte_idx] >> bit_idx) & 1;
            output[y * hdr->width + x] = pixel ? 255 : 0;
        }
    }

    free(output);
    free(raw_data);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4)  /* Minimum: type + fixed + width + height */
        return 0;

    FILE *fp = fmemopen((void *)data, size, "rb");
    if (!fp)
        return 0;

    WBMPHeader hdr;
    if (read_wbmp_header(fp, &hdr) != 0) {
        fclose(fp);
        return 0;
    }

    load_wbmp_image(fp, &hdr);

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
