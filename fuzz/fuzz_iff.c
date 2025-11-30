/*
 * IFF/ILBM (Amiga Interchange File Format) Fuzzer
 *
 * Tests parsing of Amiga image files:
 * - FORM chunk container parsing
 * - BMHD (Bitmap Header) chunk
 * - CMAP (Color Map/Palette) chunk
 * - BODY (Image Data) chunk
 * - CAMG (Viewport Mode) for HAM/EHB detection
 * - PackBits/ByteRun1 decompression
 * - Bitplane deinterleaving
 *
 * AFL++ persistent mode with libFuzzer-compatible entry point.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* IFF FourCC codes */
#define IFF_ID_FORM  0x464F524D  /* "FORM" */
#define IFF_ID_ILBM  0x494C424D  /* "ILBM" */
#define IFF_ID_PBM   0x50424D20  /* "PBM " */
#define IFF_ID_ACBM  0x4143424D  /* "ACBM" */
#define IFF_ID_BMHD  0x424D4844  /* "BMHD" */
#define IFF_ID_CMAP  0x434D4150  /* "CMAP" */
#define IFF_ID_BODY  0x424F4459  /* "BODY" */
#define IFF_ID_CAMG  0x43414D47  /* "CAMG" */
#define IFF_ID_GRAB  0x47524142  /* "GRAB" */
#define IFF_ID_DEST  0x44455354  /* "DEST" */
#define IFF_ID_CRNG  0x43524E47  /* "CRNG" */
#define IFF_ID_CCRT  0x43435254  /* "CCRT" */
#define IFF_ID_DRNG  0x44524E47  /* "DRNG" */

/* BMHD compression types */
#define CMP_NONE     0
#define CMP_BYTERUN1 1  /* PackBits */

/* BMHD masking types */
#define MSK_NONE        0
#define MSK_HASMASK     1
#define MSK_HASTRANSP   2
#define MSK_LASSO       3

/* CAMG viewport mode bits */
#define CAMG_HAM_BIT 11
#define CAMG_EHB_BIT 7

/* Size limits */
#define MAX_WIDTH      4096
#define MAX_HEIGHT     4096
#define MAX_PLANES     32
#define MAX_COLORS     256
#define MAX_FILE_SIZE  (64 * 1024 * 1024)
#define MAX_BODY_SIZE  (32 * 1024 * 1024)

/* BMHD structure (20 bytes) */
typedef struct {
    uint16_t w;              /* Width in pixels */
    uint16_t h;              /* Height in pixels */
    int16_t  x;              /* X origin */
    int16_t  y;              /* Y origin */
    uint8_t  nPlanes;        /* Number of bitplanes */
    uint8_t  masking;        /* Masking type */
    uint8_t  compression;    /* Compression type */
    uint8_t  pad1;           /* Reserved */
    uint16_t transparentColor;
    uint8_t  xAspect;        /* X aspect ratio */
    uint8_t  yAspect;        /* Y aspect ratio */
    int16_t  pageWidth;      /* Page dimensions */
    int16_t  pageHeight;
} BMHD;

/* Color map entry */
typedef struct {
    uint8_t r, g, b;
} ColorEntry;

static const uint8_t *fuzz_data;
static size_t fuzz_size;
static size_t fuzz_pos;

static inline int read_bytes(void *buf, size_t len)
{
    if (fuzz_pos + len > fuzz_size) {
        return 0;
    }
    memcpy(buf, fuzz_data + fuzz_pos, len);
    fuzz_pos += len;
    return 1;
}

static inline int skip_bytes(size_t len)
{
    if (fuzz_pos + len > fuzz_size) {
        return 0;
    }
    fuzz_pos += len;
    return 1;
}

static inline uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint16_t read_u16_be(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

/* PackBits/ByteRun1 decompression */
static int decompress_byterun1(const uint8_t *src, size_t src_size,
                               uint8_t *dst, size_t dst_size)
{
    size_t src_pos = 0;
    size_t dst_pos = 0;

    while (src_pos < src_size && dst_pos < dst_size) {
        int8_t code = (int8_t)src[src_pos++];

        if (code >= 0) {
            /* Literal run: copy (code + 1) bytes */
            size_t count = (size_t)code + 1;
            if (src_pos + count > src_size || dst_pos + count > dst_size) {
                break;
            }
            memcpy(dst + dst_pos, src + src_pos, count);
            src_pos += count;
            dst_pos += count;
        } else if (code != -128) {
            /* Repeated byte: repeat next byte (1 - code) times */
            size_t count = (size_t)(1 - code);
            if (src_pos >= src_size || dst_pos + count > dst_size) {
                break;
            }
            memset(dst + dst_pos, src[src_pos++], count);
            dst_pos += count;
        }
        /* code == -128 is NOP */
    }

    return (int)dst_pos;
}

/* Deleave indexed row from bitplanes */
static void deleave_indexed_row(const uint8_t *bitplanes, uint8_t *pixels,
                                int width, int nPlanes, int row_length)
{
    for (int byte = 0; byte < row_length; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            int x = byte * 8 + bit;
            if (x >= width) break;

            uint8_t pixel = 0;
            uint8_t mask = 0x80 >> bit;

            for (int plane = 0; plane < nPlanes; plane++) {
                if (bitplanes[byte + row_length * plane] & mask) {
                    pixel |= (1 << plane);
                }
            }

            pixels[x] = pixel;
        }
    }
}

/* Deleave RGB row from bitplanes (24-bit or 32-bit) */
static void deleave_rgb_row(const uint8_t *bitplanes, uint8_t *pixels,
                            int width, int nPlanes, int row_length)
{
    int pixel_size = nPlanes / 8;

    for (int byte = 0; byte < row_length; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            int x = byte * 8 + bit;
            if (x >= width) break;

            uint8_t mask = 0x80 >> bit;

            for (int channel = 0; channel < pixel_size; channel++) {
                uint8_t value = 0;
                for (int plane = 0; plane < 8; plane++) {
                    int plane_idx = channel * 8 + plane;
                    if (bitplanes[byte + row_length * plane_idx] & mask) {
                        value |= (1 << plane);
                    }
                }
                pixels[x * pixel_size + channel] = value;
            }
        }
    }
}

/* HAM (Hold-And-Modify) row deinterleaving */
static void deleave_ham_row(const uint8_t *bitplanes, uint8_t *pixels,
                            const ColorEntry *cmap, int width,
                            int nPlanes, int row_length)
{
    uint8_t prev_r = 0, prev_g = 0, prev_b = 0;
    int color_bits = nPlanes - 2;  /* HAM5/6: 4 bits, HAM7/8: 6 bits */
    int color_mask = (1 << color_bits) - 1;

    for (int byte = 0; byte < row_length; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            int x = byte * 8 + bit;
            if (x >= width) break;

            uint8_t pixel = 0;
            uint8_t mask = 0x80 >> bit;

            /* Extract all bits for this pixel */
            for (int plane = 0; plane < nPlanes; plane++) {
                if (bitplanes[byte + row_length * plane] & mask) {
                    pixel |= (1 << plane);
                }
            }

            /* Control bits are in the top 2 planes */
            int control = (pixel >> color_bits) & 0x03;
            int color = pixel & color_mask;

            switch (control) {
                case 0:
                    /* Use palette color */
                    if (color < MAX_COLORS) {
                        prev_r = cmap[color].r;
                        prev_g = cmap[color].g;
                        prev_b = cmap[color].b;
                    }
                    break;
                case 1:
                    /* Modify blue */
                    if (color_bits == 4) {
                        prev_b = color | (color << 4);
                    } else {
                        prev_b = (color << 2) | (color >> 4);
                    }
                    break;
                case 2:
                    /* Modify red */
                    if (color_bits == 4) {
                        prev_r = color | (color << 4);
                    } else {
                        prev_r = (color << 2) | (color >> 4);
                    }
                    break;
                case 3:
                    /* Modify green */
                    if (color_bits == 4) {
                        prev_g = color | (color << 4);
                    } else {
                        prev_g = (color << 2) | (color >> 4);
                    }
                    break;
            }

            pixels[x * 3] = prev_r;
            pixels[x * 3 + 1] = prev_g;
            pixels[x * 3 + 2] = prev_b;
        }
    }
}

/* Main IFF/ILBM parser */
static int parse_iff(void)
{
    uint8_t header[12];
    if (!read_bytes(header, 12)) {
        return 0;
    }

    /* Validate FORM header */
    uint32_t form_id = read_u32_be(header);
    if (form_id != IFF_ID_FORM) {
        return 0;
    }

    uint32_t form_size = read_u32_be(header + 4);
    if (form_size > fuzz_size - 8) {
        form_size = fuzz_size - 8;
    }

    /* Check format type (ILBM, PBM, ACBM) */
    uint32_t format = read_u32_be(header + 8);
    if (format != IFF_ID_ILBM && format != IFF_ID_PBM && format != IFF_ID_ACBM) {
        return 0;
    }

    int is_pbm = (format == IFF_ID_PBM);

    /* Parse chunks */
    BMHD bmhd;
    ColorEntry cmap[MAX_COLORS];
    uint32_t camg_mode = 0;
    uint8_t *body_data = NULL;
    size_t body_size = 0;

    int has_bmhd = 0;
    int has_cmap = 0;
    int has_body = 0;
    int num_colors = 0;

    memset(&bmhd, 0, sizeof(bmhd));
    memset(cmap, 0, sizeof(cmap));

    size_t end_pos = fuzz_pos + form_size - 4;  /* -4 for format ID already read */

    while (fuzz_pos + 8 <= end_pos) {
        uint8_t chunk_header[8];
        if (!read_bytes(chunk_header, 8)) {
            break;
        }

        uint32_t chunk_id = read_u32_be(chunk_header);
        uint32_t chunk_size = read_u32_be(chunk_header + 4);

        /* Sanity check chunk size */
        if (chunk_size > MAX_FILE_SIZE) {
            break;
        }

        size_t chunk_start = fuzz_pos;
        size_t padded_size = (chunk_size + 1) & ~1;  /* IFF chunks are word-aligned */

        switch (chunk_id) {
            case IFF_ID_BMHD:
                if (chunk_size >= 20) {
                    uint8_t bmhd_raw[20];
                    if (read_bytes(bmhd_raw, 20)) {
                        bmhd.w = read_u16_be(bmhd_raw);
                        bmhd.h = read_u16_be(bmhd_raw + 2);
                        bmhd.x = (int16_t)read_u16_be(bmhd_raw + 4);
                        bmhd.y = (int16_t)read_u16_be(bmhd_raw + 6);
                        bmhd.nPlanes = bmhd_raw[8];
                        bmhd.masking = bmhd_raw[9];
                        bmhd.compression = bmhd_raw[10];
                        bmhd.transparentColor = read_u16_be(bmhd_raw + 12);
                        bmhd.xAspect = bmhd_raw[14];
                        bmhd.yAspect = bmhd_raw[15];
                        bmhd.pageWidth = (int16_t)read_u16_be(bmhd_raw + 16);
                        bmhd.pageHeight = (int16_t)read_u16_be(bmhd_raw + 18);
                        has_bmhd = 1;
                    }
                }
                break;

            case IFF_ID_CMAP:
                num_colors = chunk_size / 3;
                if (num_colors > MAX_COLORS) {
                    num_colors = MAX_COLORS;
                }
                for (int i = 0; i < num_colors; i++) {
                    uint8_t rgb[3];
                    if (!read_bytes(rgb, 3)) {
                        break;
                    }
                    cmap[i].r = rgb[0];
                    cmap[i].g = rgb[1];
                    cmap[i].b = rgb[2];
                }
                has_cmap = 1;
                break;

            case IFF_ID_CAMG:
                if (chunk_size >= 4) {
                    uint8_t camg_raw[4];
                    if (read_bytes(camg_raw, 4)) {
                        camg_mode = read_u32_be(camg_raw);
                    }
                }
                break;

            case IFF_ID_BODY:
                if (chunk_size > 0 && chunk_size <= MAX_BODY_SIZE) {
                    body_data = malloc(chunk_size);
                    if (body_data) {
                        if (read_bytes(body_data, chunk_size)) {
                            body_size = chunk_size;
                            has_body = 1;
                        } else {
                            free(body_data);
                            body_data = NULL;
                        }
                    }
                }
                break;

            default:
                /* Skip unknown chunks */
                break;
        }

        /* Skip to next chunk */
        size_t bytes_read = fuzz_pos - chunk_start;
        if (bytes_read < padded_size) {
            skip_bytes(padded_size - bytes_read);
        }
    }

    if (!has_bmhd || !has_body) {
        if (body_data) free(body_data);
        return 0;
    }

    /* Validate dimensions */
    if (bmhd.w == 0 || bmhd.w > MAX_WIDTH ||
        bmhd.h == 0 || bmhd.h > MAX_HEIGHT) {
        free(body_data);
        return 0;
    }

    if (bmhd.nPlanes == 0 || bmhd.nPlanes > MAX_PLANES) {
        free(body_data);
        return 0;
    }

    /* Calculate row sizes */
    int row_length = ((bmhd.w + 15) / 16) * 2;  /* Word-aligned */
    size_t plane_row_size = row_length;
    size_t total_row_size = plane_row_size * bmhd.nPlanes;

    /* Decompress if needed */
    uint8_t *plane_data = NULL;
    size_t expected_size = total_row_size * bmhd.h;

    if (expected_size > MAX_BODY_SIZE) {
        free(body_data);
        return 0;
    }

    if (bmhd.compression == CMP_BYTERUN1) {
        plane_data = malloc(expected_size);
        if (!plane_data) {
            free(body_data);
            return 0;
        }
        decompress_byterun1(body_data, body_size, plane_data, expected_size);
        free(body_data);
        body_data = plane_data;
    } else if (bmhd.compression == CMP_NONE) {
        plane_data = body_data;
    } else {
        /* Unsupported compression */
        free(body_data);
        return 0;
    }

    /* Detect HAM and EHB modes */
    int ham_mode = (camg_mode & (1 << CAMG_HAM_BIT)) &&
                   (bmhd.nPlanes >= 5 && bmhd.nPlanes <= 8);
    int ehb_mode = (camg_mode & (1 << CAMG_EHB_BIT)) &&
                   (bmhd.nPlanes == 6);

    /* Expand EHB palette if needed */
    if (ehb_mode && num_colors == 32) {
        for (int i = 0; i < 32; i++) {
            cmap[i + 32].r = cmap[i].r / 2;
            cmap[i + 32].g = cmap[i].g / 2;
            cmap[i + 32].b = cmap[i].b / 2;
        }
        num_colors = 64;
    }

    /* Determine output format */
    int pixel_size;
    if (bmhd.nPlanes >= 24) {
        pixel_size = bmhd.nPlanes / 8;  /* RGB or RGBA */
    } else if (ham_mode) {
        pixel_size = 3;  /* HAM produces RGB */
    } else if (is_pbm) {
        pixel_size = 1;  /* PBM: direct indexed */
    } else {
        pixel_size = 1;  /* Indexed */
    }

    /* Allocate output buffer */
    size_t output_size = (size_t)bmhd.w * bmhd.h * pixel_size;
    if (output_size > MAX_FILE_SIZE) {
        free(body_data);
        return 0;
    }

    uint8_t *output = malloc(output_size);
    if (!output) {
        free(body_data);
        return 0;
    }

    /* Process each row */
    for (uint32_t y = 0; y < bmhd.h; y++) {
        const uint8_t *row_planes = body_data + y * total_row_size;
        uint8_t *row_pixels = output + y * bmhd.w * pixel_size;

        if (is_pbm) {
            /* PBM: one byte per pixel */
            size_t copy_len = bmhd.w;
            if (y * bmhd.w + copy_len <= expected_size) {
                memcpy(row_pixels, body_data + y * bmhd.w, copy_len);
            }
        } else if (bmhd.nPlanes >= 24) {
            /* Direct RGB/RGBA */
            deleave_rgb_row(row_planes, row_pixels, bmhd.w, bmhd.nPlanes, row_length);
        } else if (ham_mode) {
            /* HAM mode */
            deleave_ham_row(row_planes, row_pixels, cmap, bmhd.w, bmhd.nPlanes, row_length);
        } else {
            /* Indexed */
            deleave_indexed_row(row_planes, row_pixels, bmhd.w, bmhd.nPlanes, row_length);
        }
    }

    free(output);
    free(body_data);
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 12 || size > MAX_FILE_SIZE) {
        return 0;
    }

    fuzz_data = data;
    fuzz_size = size;
    fuzz_pos = 0;

    parse_iff();

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);
    }

    return 0;
}
#else
/* Standalone mode for testing */
int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <iff_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }

    if (fread(data, 1, size, f) != size) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    LLVMFuzzerTestOneInput(data, size);
    free(data);

    return 0;
}
#endif
