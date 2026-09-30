/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <stdint.h>

#define main trustctl_main
#include "trustctl.c"
#undef main

static void put16(uint8_t *p, uint16_t v) {
        p[0] = v;
        p[1] = v >> 8;
}

static void put32(uint8_t *p, uint32_t v) {
        p[0] = v;
        p[1] = v >> 8;
        p[2] = v >> 16;
        p[3] = v >> 24;
}

static sd_json_variant *read_reference(const char *id) {
        sd_json_variant *reference = NULL;
        char *dir = NULL, *path = NULL;
        FILE *f;

        assert(boot_reference_path(id, &dir, &path) >= 0);
        f = fopen(path, "re");
        assert(f);
        assert(sd_json_parse_file(f, path, 0, &reference, NULL, NULL) >= 0);
        assert(fclose(f) == 0);
        free(path);
        free(dir);
        return reference;
}

int main(void) {
        static const char *const sections[] = {
                "linux", "osrel", "cmdline", "initrd", "ucode", "splash", "dtb", "uname", "sbat",
                "pcrpkey", "dtbauto", "hwids", "profile", "efifw",
        };
        const size_t n_sections = sizeof sections / sizeof *sections;
        char directory[] = "/tmp/platformd-provision.XXXXXX";
        char *args[3 + sizeof sections / sizeof *sections + 1] = {
                "/usr/lib/systemd/systemd-measure", "calculate", "--bank=sha256",
        };
        uint8_t image[4096] = {};
        size_t offset = 0x40 + 24 + n_sections * 40;
        sd_json_variant *actual, *expected;
        char *uki = NULL, *output = NULL;
        FILE *f;

        if (access(args[0], X_OK) < 0)
                return 77;
        assert(mkdtemp(directory));
        assert(asprintf(&uki, "%s/test.efi", directory) >= 0);
        image[0] = 'M';
        image[1] = 'Z';
        put32(image + 0x3c, 0x40);
        memcpy(image + 0x40, "PE\0\0", 4);
        put16(image + 0x40 + 6, n_sections);
        for (size_t i = 0; i < n_sections; i++) {
                uint8_t *header = image + 0x40 + 24 + 40 * i;
                char *path = NULL, section[9];
                size_t n = strlen(sections[i]);

                assert(snprintf(section, sizeof section, ".%s", sections[i]) > 0);
                memcpy(header, section, strlen(section));
                put32(header + 8, n);
                put32(header + 16, n + 4);
                put32(header + 20, offset);
                memcpy(image + offset, sections[i], n);
                offset += n + 4;
                assert(asprintf(&path, "%s/%s", directory, sections[i]) >= 0);
                f = fopen(path, "we");
                assert(f);
                assert(fwrite(sections[i], 1, n, f) == n);
                assert(fclose(f) == 0);
                assert(asprintf(&args[3 + i], "--%s=%s", sections[i], path) >= 0);
                free(path);
        }
        f = fopen(uki, "we");
        assert(f);
        assert(fwrite(image, 1, offset, f) == offset);
        assert(fclose(f) == 0);
        assert(cmd_provision(uki, "actual") == EXIT_SUCCESS);
        assert(run_capture(args, &output) == 0 && output);
        assert(write_boot_reference(uki, "expected", output) == EXIT_SUCCESS);
        actual = read_reference("actual");
        expected = read_reference("expected");
        assert(sd_json_variant_equal(sd_json_variant_by_key(actual, "pcr11"),
                                     sd_json_variant_by_key(expected, "pcr11")));
        sd_json_variant_unref(actual);
        sd_json_variant_unref(expected);
        assert(remove_boot_reference("actual") == EXIT_SUCCESS);
        assert(remove_boot_reference("expected") == EXIT_SUCCESS);
        assert(unlink(uki) == 0);
        for (size_t i = 0; i < n_sections; i++) {
                assert(unlink(strchr(args[3 + i], '=') + 1) == 0);
                free(args[3 + i]);
        }
        assert(rmdir(directory) == 0);
        free(output);
        free(uki);
        return 0;
}
