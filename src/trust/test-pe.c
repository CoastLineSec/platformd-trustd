/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Unit test for pe_extract_section: a crafted minimal PE confirms it extracts the
 * VirtualSize content (not the zero-padded SizeOfRawData — the regression that
 * once produced wrong measurements), handles an absent section, and rejects a
 * malformed image. */

#include "pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); }
static void put32(uint8_t *p, uint32_t v) {
        p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24);
}

#define CHECK(cond) do { \
        if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", #cond, __LINE__); return 1; } \
} while (0)

static long slurp(const char *path, char *buf, size_t n) {
        FILE *f = fopen(path, "rb");
        long r;
        if (!f)
                return -1;
        r = (long) fread(buf, 1, n, f);
        fclose(f);
        return r;
}

int main(void) {
        uint8_t img[512] = { 0 }, junk[128] = { 0 };
        char out[] = "/tmp/test-pe-XXXXXX";
        size_t pe = 0x40, tbl, data, img_len;
        char rd[64];
        int fd;

        /* DOS + PE signature + COFF header: 2 sections, no optional header. */
        img[0] = 'M'; img[1] = 'Z';
        put32(img + 0x3C, (uint32_t) pe);              /* e_lfanew */
        memcpy(img + pe, "PE\0\0", 4);
        put16(img + pe + 4 + 2, 2);                    /* NumberOfSections */
        put16(img + pe + 4 + 16, 0);                   /* SizeOfOptionalHeader */
        tbl = pe + 4 + 20;
        data = tbl + 2 * 40;

        /* .foo: content "hello" (VirtualSize 5), padded to SizeOfRawData 8. */
        memcpy(img + tbl, ".foo", 4);
        put32(img + tbl + 8, 5);
        put32(img + tbl + 16, 8);
        put32(img + tbl + 20, (uint32_t) data);
        memcpy(img + data, "hello", 5);
        img[data + 5] = img[data + 6] = img[data + 7] = 0xAA;   /* padding, must NOT appear */

        /* .bar: content "abc" (VirtualSize 3), padded to SizeOfRawData 4. */
        memcpy(img + tbl + 40, ".bar", 4);
        put32(img + tbl + 40 + 8, 3);
        put32(img + tbl + 40 + 16, 4);
        put32(img + tbl + 40 + 20, (uint32_t) (data + 8));
        memcpy(img + data + 8, "abc", 3);
        img[data + 11] = 0xBB;

        img_len = data + 12;

        fd = mkstemp(out);
        if (fd >= 0)
                close(fd);

        /* The content, not the padding: 5 bytes "hello". */
        CHECK(pe_extract_section(img, img_len, ".foo", out) == 5);
        CHECK(slurp(out, rd, sizeof rd) == 5);
        CHECK(memcmp(rd, "hello", 5) == 0);

        /* 3 bytes "abc". */
        CHECK(pe_extract_section(img, img_len, ".bar", out) == 3);
        CHECK(slurp(out, rd, sizeof rd) == 3);
        CHECK(memcmp(rd, "abc", 3) == 0);

        /* Absent section → 0; malformed / truncated → -1. */
        CHECK(pe_extract_section(img, img_len, ".nope", out) == 0);
        CHECK(pe_extract_section(junk, sizeof junk, ".foo", out) == -1);
        CHECK(pe_extract_section(img, 4, ".foo", out) == -1);

        unlink(out);
        printf("OK: pe_extract_section (VirtualSize content, absent, malformed)\n");
        return 0;
}
