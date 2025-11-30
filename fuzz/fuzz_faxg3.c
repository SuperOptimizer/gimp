/*
 * FAX G3 (CCITT Group 3) Format Fuzzer
 *
 * Tests parsing of FAX G3 compressed images:
 * - CCITT Huffman decoding (modified Huffman MH)
 * - White/Black terminating codes (1-63 pixels)
 * - Make-up codes (64-1728 pixels)
 * - EOL (End of Line) detection
 * - Bit-level stream parsing
 *
 * AFL++ persistent mode with libFuzzer-compatible entry point.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* Constants */
#define MAX_COLS     1728   /* Standard ITU-T G3 width */
#define MAX_ROWS     4300   /* Max rows per page */
#define FBITS        8      /* Huffman tree lookup bits */
#define BITM         0xFF   /* Mask for FBITS */

/* Code entry: 16-bit code value, 8-bit bit length */
#define CODE(val, bits)  ((val) | ((bits) << 16))
#define CODE_VAL(c)      ((c) & 0xFFFF)
#define CODE_BITS(c)     (((c) >> 16) & 0xFF)

/* Huffman tree node */
typedef struct TreeNode {
    int nr_pels;               /* Run length (-1 for EOL, -2 for internal) */
    struct TreeNode *sub[256]; /* Sub-nodes for FBITS bits */
} TreeNode;

/* White terminating codes (0-63 pels) */
static const uint32_t t_white[64] = {
    CODE(0x035, 8), CODE(0x007, 6), CODE(0x007, 4), CODE(0x008, 4),
    CODE(0x00b, 4), CODE(0x00c, 4), CODE(0x00e, 4), CODE(0x00f, 4),
    CODE(0x013, 5), CODE(0x014, 5), CODE(0x007, 5), CODE(0x008, 5),
    CODE(0x008, 6), CODE(0x003, 6), CODE(0x034, 6), CODE(0x035, 6),
    CODE(0x02a, 6), CODE(0x02b, 6), CODE(0x027, 7), CODE(0x00c, 7),
    CODE(0x008, 7), CODE(0x017, 7), CODE(0x003, 7), CODE(0x004, 7),
    CODE(0x028, 7), CODE(0x02b, 7), CODE(0x013, 7), CODE(0x024, 7),
    CODE(0x018, 7), CODE(0x002, 8), CODE(0x003, 8), CODE(0x01a, 8),
    CODE(0x01b, 8), CODE(0x012, 8), CODE(0x013, 8), CODE(0x014, 8),
    CODE(0x015, 8), CODE(0x016, 8), CODE(0x017, 8), CODE(0x028, 8),
    CODE(0x029, 8), CODE(0x02a, 8), CODE(0x02b, 8), CODE(0x02c, 8),
    CODE(0x02d, 8), CODE(0x004, 8), CODE(0x005, 8), CODE(0x00a, 8),
    CODE(0x00b, 8), CODE(0x052, 8), CODE(0x053, 8), CODE(0x054, 8),
    CODE(0x055, 8), CODE(0x024, 8), CODE(0x025, 8), CODE(0x058, 8),
    CODE(0x059, 8), CODE(0x05a, 8), CODE(0x05b, 8), CODE(0x04a, 8),
    CODE(0x04b, 8), CODE(0x032, 8), CODE(0x033, 8), CODE(0x034, 8),
};

/* White make-up codes (64-1728 pels) */
static const uint32_t m_white[28] = {
    CODE(0x01b, 5),  CODE(0x012, 5),  CODE(0x017, 6),  CODE(0x037, 7),
    CODE(0x036, 8),  CODE(0x037, 8),  CODE(0x064, 8),  CODE(0x065, 8),
    CODE(0x068, 8),  CODE(0x067, 8),  CODE(0x0cc, 9),  CODE(0x0cd, 9),
    CODE(0x0d2, 9),  CODE(0x0d3, 9),  CODE(0x0d4, 9),  CODE(0x0d5, 9),
    CODE(0x0d6, 9),  CODE(0x0d7, 9),  CODE(0x0d8, 9),  CODE(0x0d9, 9),
    CODE(0x0da, 9),  CODE(0x0db, 9),  CODE(0x098, 9),  CODE(0x099, 9),
    CODE(0x09a, 9),  CODE(0x018, 6),  CODE(0x09b, 9),  CODE(0x1b2, 9),
};

/* Black terminating codes (0-63 pels) */
static const uint32_t t_black[64] = {
    CODE(0x037, 10), CODE(0x002, 3),  CODE(0x003, 2),  CODE(0x002, 2),
    CODE(0x003, 3),  CODE(0x003, 4),  CODE(0x002, 4),  CODE(0x003, 5),
    CODE(0x005, 6),  CODE(0x004, 6),  CODE(0x004, 7),  CODE(0x005, 7),
    CODE(0x007, 7),  CODE(0x004, 8),  CODE(0x007, 8),  CODE(0x018, 9),
    CODE(0x017, 10), CODE(0x018, 10), CODE(0x008, 10), CODE(0x067, 11),
    CODE(0x068, 11), CODE(0x06c, 11), CODE(0x037, 11), CODE(0x028, 11),
    CODE(0x017, 11), CODE(0x018, 11), CODE(0x0ca, 12), CODE(0x0cb, 12),
    CODE(0x0cc, 12), CODE(0x0cd, 12), CODE(0x068, 12), CODE(0x069, 12),
    CODE(0x06a, 12), CODE(0x06b, 12), CODE(0x0d2, 12), CODE(0x0d3, 12),
    CODE(0x0d4, 12), CODE(0x0d5, 12), CODE(0x0d6, 12), CODE(0x0d7, 12),
    CODE(0x06c, 12), CODE(0x06d, 12), CODE(0x0da, 12), CODE(0x0db, 12),
    CODE(0x054, 12), CODE(0x055, 12), CODE(0x056, 12), CODE(0x057, 12),
    CODE(0x064, 12), CODE(0x065, 12), CODE(0x052, 12), CODE(0x053, 12),
    CODE(0x024, 12), CODE(0x037, 12), CODE(0x038, 12), CODE(0x027, 12),
    CODE(0x028, 12), CODE(0x058, 12), CODE(0x059, 12), CODE(0x02b, 12),
    CODE(0x02c, 12), CODE(0x05a, 12), CODE(0x066, 12), CODE(0x067, 12),
};

/* Black make-up codes (64-1728 pels) */
static const uint32_t m_black[28] = {
    CODE(0x00f, 10), CODE(0x0c8, 12), CODE(0x0c9, 12), CODE(0x05b, 12),
    CODE(0x033, 12), CODE(0x034, 12), CODE(0x035, 12), CODE(0x06c, 13),
    CODE(0x06d, 13), CODE(0x04a, 13), CODE(0x04b, 13), CODE(0x04c, 13),
    CODE(0x04d, 13), CODE(0x072, 13), CODE(0x073, 13), CODE(0x074, 13),
    CODE(0x075, 13), CODE(0x076, 13), CODE(0x077, 13), CODE(0x052, 13),
    CODE(0x053, 13), CODE(0x054, 13), CODE(0x055, 13), CODE(0x05a, 13),
    CODE(0x05b, 13), CODE(0x064, 13), CODE(0x065, 13), CODE(0x14c0, 13),
};

/* EOL code: 11 zeros + 1 */
#define EOL_CODE  CODE(0x001, 12)

/* Global Huffman trees */
static TreeNode *white_tree = NULL;
static TreeNode *black_tree = NULL;
static uint8_t byte_tab[256];  /* Bit reversal table */
static int trees_initialized = 0;

/* Bit reversal table */
static void init_byte_tab(void)
{
    for (int i = 0; i < 256; i++) {
        uint8_t v = 0;
        for (int j = 0; j < 8; j++) {
            if (i & (1 << j)) {
                v |= (1 << (7 - j));
            }
        }
        byte_tab[i] = v;
    }
}

/* Free tree recursively */
static void free_tree(TreeNode *node)
{
    if (!node) return;
    for (int i = 0; i < 256; i++) {
        if (node->sub[i] && node->sub[i] != node) {
            free_tree(node->sub[i]);
        }
    }
    free(node);
}

/* Create new tree node */
static TreeNode *new_node(void)
{
    TreeNode *n = calloc(1, sizeof(TreeNode));
    if (n) {
        n->nr_pels = -2;  /* Internal node marker */
    }
    return n;
}

/* Add code to tree */
static void tree_add_node(TreeNode *tree, uint32_t code, int nr_pels)
{
    uint32_t val = CODE_VAL(code);
    int bits = CODE_BITS(code);

    if (bits <= FBITS) {
        /* Direct lookup */
        int shift = FBITS - bits;
        int base = val << shift;
        int count = 1 << shift;
        for (int i = 0; i < count; i++) {
            tree->sub[base + i] = tree;  /* Point to self to mark leaf */
            if (tree->sub[base + i] == tree) {
                TreeNode *leaf = new_node();
                if (leaf) {
                    leaf->nr_pels = nr_pels;
                    tree->sub[base + i] = leaf;
                }
            }
        }
    } else {
        /* Need sub-tree */
        int idx = val >> (bits - FBITS);
        if (!tree->sub[idx] || tree->sub[idx] == tree) {
            tree->sub[idx] = new_node();
        }
        if (tree->sub[idx]) {
            /* Reduce code by FBITS */
            uint32_t remaining = (val & ((1 << (bits - FBITS)) - 1)) |
                                ((bits - FBITS) << 16);
            tree_add_node(tree->sub[idx], remaining, nr_pels);
        }
    }
}

/* Build Huffman tree from code table */
static TreeNode *build_tree(const uint32_t *term, const uint32_t *makeup)
{
    TreeNode *tree = new_node();
    if (!tree) return NULL;

    /* Add terminating codes */
    for (int i = 0; i < 64; i++) {
        tree_add_node(tree, term[i], i);
    }

    /* Add make-up codes */
    for (int i = 0; i < 28; i++) {
        tree_add_node(tree, makeup[i], 64 + i * 64);
    }

    /* Add EOL */
    tree_add_node(tree, EOL_CODE, -1);

    return tree;
}

/* Initialize trees if needed */
static void init_trees(void)
{
    if (!trees_initialized) {
        init_byte_tab();
        white_tree = build_tree(t_white, m_white);
        black_tree = build_tree(t_black, m_black);
        trees_initialized = 1;
    }
}

/* Parse FAX G3 image */
static int parse_faxg3(const uint8_t *data, size_t size)
{
    if (size < 4) return 0;

    init_trees();
    if (!white_tree || !black_tree) return 0;

    /* Skip GhostScript header if present */
    size_t offset = 0;
    if (size > 64 && memcmp(data + 1, "PC Research, Inc", 16) == 0) {
        offset = 64;
    }

    /* Allocate output bitmap */
    uint8_t *bitmap = calloc(MAX_ROWS, (MAX_COLS + 7) / 8);
    if (!bitmap) return 0;

    /* Bit stream state */
    uint32_t bitbuf = 0;
    int bits_avail = 0;
    size_t pos = offset;

    int row = 0;
    int col = 0;
    int color = 0;  /* 0 = white, 1 = black */
    int eol_count = 0;

    while (row < MAX_ROWS && pos < size) {
        /* Refill bit buffer */
        while (bits_avail < 24 && pos < size) {
            bitbuf = (bitbuf << 8) | byte_tab[data[pos++]];
            bits_avail += 8;
        }

        if (bits_avail < 2) break;

        /* Select tree based on current color */
        TreeNode *tree = color ? black_tree : white_tree;
        TreeNode *node = tree;
        int consumed = 0;

        /* Traverse Huffman tree */
        while (node && node->nr_pels == -2 && consumed < bits_avail) {
            int idx = (bitbuf >> (bits_avail - FBITS - consumed)) & BITM;
            node = node->sub[idx];
            consumed += FBITS;
            if (consumed > bits_avail) consumed = bits_avail;
        }

        if (!node) {
            /* Invalid code, skip a bit */
            bitbuf &= (1 << (bits_avail - 1)) - 1;
            bits_avail--;
            continue;
        }

        int nr_pels = node->nr_pels;

        /* Consume used bits */
        if (consumed <= bits_avail) {
            bits_avail -= consumed;
        }

        if (nr_pels == -1) {
            /* EOL */
            eol_count++;
            if (eol_count >= 10) break;  /* 10 EOLs = EOF */

            /* Advance to next row */
            row++;
            col = 0;
            color = 0;
            continue;
        }

        eol_count = 0;

        if (nr_pels >= 0) {
            /* Draw run */
            if (color == 1) {
                /* Black - set bits */
                for (int i = 0; i < nr_pels && col < MAX_COLS; i++, col++) {
                    int byte_idx = row * ((MAX_COLS + 7) / 8) + col / 8;
                    int bit_idx = 7 - (col % 8);
                    bitmap[byte_idx] |= (1 << bit_idx);
                }
            } else {
                /* White - just advance */
                col += nr_pels;
                if (col > MAX_COLS) col = MAX_COLS;
            }

            /* Terminating code (< 64) toggles color */
            if (nr_pels < 64) {
                color = !color;
            }
        }
    }

    free(bitmap);
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4 || size > 64 * 1024 * 1024) {
        return 0;
    }

    parse_faxg3(data, size);

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
        fprintf(stderr, "Usage: %s <g3_file>\n", argv[0]);
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
