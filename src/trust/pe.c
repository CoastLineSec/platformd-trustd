/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static uint16_t le16(const uint8_t *p) { return (uint16_t) (p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) {
        return (uint32_t) p[0] | (uint32_t) p[1] << 8 | (uint32_t) p[2] << 16 | (uint32_t) p[3] << 24;
}

long pe_extract_section(const uint8_t *img, size_t len, const char *sect, const char *out_path) {
        uint32_t pe_off;
        uint16_t n_sect, opt_size;
        size_t table_off;

        if (len < 0x40 || img[0] != 'M' || img[1] != 'Z')
                return -1;
        pe_off = le32(img + 0x3C);
        if ((size_t) pe_off + 24 > len || memcmp(img + pe_off, "PE\0\0", 4) != 0)
                return -1;
        n_sect = le16(img + pe_off + 4 + 2);       /* COFF NumberOfSections */
        opt_size = le16(img + pe_off + 4 + 16);    /* SizeOfOptionalHeader */
        table_off = (size_t) pe_off + 4 + 20 + opt_size;
        for (uint16_t i = 0; i < n_sect; i++) {
                size_t sh = table_off + (size_t) i * 40;
                char name[9] = { 0 };
                uint32_t vsize, rsize, size, ptr;
                int fd;

                if (sh + 40 > len)
                        return -1;
                memcpy(name, img + sh, 8);          /* 8-byte, NUL-padded section name */
                if (strcmp(name, sect) != 0)
                        continue;
                vsize = le32(img + sh + 8);         /* VirtualSize: the actual content */
                rsize = le32(img + sh + 16);        /* SizeOfRawData: zero-padded on disk */
                ptr = le32(img + sh + 20);          /* PointerToRawData */
                /* Measure the content, not the alignment padding — as objcopy and
                 * systemd-stub do. */
                size = (vsize > 0 && vsize < rsize) ? vsize : rsize;
                if ((size_t) ptr + size > len)
                        return -1;
                fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                if (fd < 0)
                        return -1;
                if (write(fd, img + ptr, size) != (ssize_t) size) {
                        close(fd);
                        return -1;
                }
                close(fd);
                return (long) size;
        }
        return 0;   /* section not present */
}
