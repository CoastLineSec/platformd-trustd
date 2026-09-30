/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe.h"

#include <errno.h>
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
        size_t table_off, selected = SIZE_MAX;

        if (len < 0x40 || img[0] != 'M' || img[1] != 'Z')
                return -1;
        pe_off = le32(img + 0x3C);
        if (pe_off > len || len - pe_off < 24 || memcmp(img + pe_off, "PE\0\0", 4) != 0)
                return -1;
        n_sect = le16(img + pe_off + 4 + 2);       /* COFF NumberOfSections */
        opt_size = le16(img + pe_off + 4 + 16);    /* SizeOfOptionalHeader */
        table_off = (size_t) pe_off + 4 + 20 + opt_size;
        if (table_off > len || n_sect > (len - table_off) / 40)
                return -EBADMSG;
        for (uint16_t i = 0; i < n_sect; i++) {
                size_t sh = table_off + (size_t) i * 40;
                char name[9] = {};

                memcpy(name, img + sh, 8);
                if (strcmp(name, sect) != 0)
                        continue;
                if (selected != SIZE_MAX)
                        return -EOPNOTSUPP;
                selected = sh;
        }
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
                /* Measure the content rather than the alignment padding, as objcopy and
                 * systemd-stub do. */
                size = (vsize > 0 && vsize < rsize) ? vsize : rsize;
                if ((size_t) ptr > len || rsize > len - ptr || vsize > rsize)
                        return -EBADMSG;
                fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                if (fd < 0)
                        return -1;
                for (size_t offset = 0; offset < size;) {
                        ssize_t n = write(fd, img + ptr + offset, size - offset);

                        if (n < 0 && errno == EINTR)
                                continue;
                        if (n <= 0) {
                                int r = n < 0 ? -errno : -EIO;
                                close(fd);
                                return r;
                        }
                        offset += (size_t) n;
                }
                if (close(fd) < 0)
                        return -errno;
                return (long) size;
        }
        return 0;   /* section not present */
}
