/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Extract a named section from a PE/UKI image to out_path — in C, no objcopy, so
 * the daemon has no binutils runtime dependency (systemd parses PE itself).
 * Extracts VirtualSize (the actual content), not the zero-padded SizeOfRawData.
 * Returns the section size, 0 if absent, or -1 on a malformed image / write error. */
long pe_extract_section(const uint8_t *img, size_t len, const char *sect, const char *out_path);
