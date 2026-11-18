/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>

#include "attestation-verify.h"

static FILE *fixture_fopen(const char *path, const char *mode);

#define fopen fixture_fopen
#define main trustd_main
#include "trustd.c"
#undef main
#undef fopen

static FILE *fixture_fopen(const char *path, const char *mode) {
        static char value[] = "0000000000000000000000000000000000000000000000000000000000000000\n";
        const char *prefix = "/sys/class/tpm/tpm0/pcr-sha256/";

        if (strncmp(path, prefix, strlen(prefix)) == 0)
                return fmemopen(value, sizeof value - 1, "r");
        return fopen(path, mode);
}

int main(int argc, char **argv) {
        static const uint8_t nonce[32] = { 0x17, 0x2a };
        Manager manager = {};
        BackendRequest *request;
        sd_json_variant *result = NULL, *parameters = NULL, *token = NULL, *report = NULL;
        uint8_t *ak = NULL, *quote = NULL, *signature = NULL, before[32], after[32];
        size_t ak_size, quote_size, signature_size;
        char *key_hex, *nonce_hex;
        const char *tcti = getenv("TSS2_TCTI");
        int expected, r;

        assert(tcti && strncmp(tcti, "swtpm:path=/tmp/", 16) == 0);
        assert(argc == 2);
        assert(strcmp(argv[1], "missing") == 0 || strcmp(argv[1], "valid") == 0);
        expected = strcmp(argv[1], "missing") == 0 ? -ENOENT : 0;
        manager_instance = &manager;
        request = calloc(1, sizeof *request);
        assert(request);
        manager.backend_head = manager.backend_tail = request;
        assert(backend_run(request, &result) == expected);
        backend_finish(&manager, request, expected, result);
        sd_json_variant_unref(result);
        assert(!manager.events && !manager.runtime_log && manager.n_runtime == 0);
        if (expected < 0) {
                assert(manager.runtime_log_incomplete);
                assert(attest_nv_read(before) == -ENOENT);
                return 0;
        }
        assert(!manager.runtime_log_incomplete);
        assert(attest_nv_read(before) == 0);
        assert(attest_quote(nonce, sizeof nonce, &ak, &ak_size, &quote, &quote_size,
                            &signature, &signature_size) == 0);
        key_hex = hex_encode(ak, ak_size);
        nonce_hex = hex_encode(nonce, sizeof nonce);
        assert(key_hex && nonce_hex);
        assert(sd_json_buildo(&parameters, SD_JSON_BUILD_PAIR_STRING("nonceHex", nonce_hex)) >= 0);
        assert(vl_get_attestation_token_run(NULL, parameters, 0, &manager) >= 0);
        result = sd_json_variant_by_key(manager.backend_result, "parameters");
        assert(result);
        assert(sd_json_parse(sd_json_variant_string(sd_json_variant_by_key(result, "eat")),
                             0, &token, NULL, NULL) >= 0);
        r = attestation_verify(token, key_hex, nonce_hex, &report);
        if (r < 0) {
                fprintf(stderr, "Attestation verification failed: %s\n", strerror(-r));
                sd_json_variant_dump(token, SD_JSON_FORMAT_PRETTY, stderr, NULL);
        }
        assert(r == 0);
        assert(sd_json_variant_boolean(sd_json_variant_by_key(report, "nvSignatureVerified")));
        assert(sd_json_variant_boolean(sd_json_variant_by_key(report, "runtimeReplayVerified")));
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(report, "retainedEvents")) == 0);
        assert(attest_nv_read(after) == 0 && memcmp(before, after, sizeof before) == 0);
        assert(!manager.events && !manager.runtime_log && manager.n_runtime == 0);
        sd_json_variant_unref(parameters);
        sd_json_variant_unref(token);
        sd_json_variant_unref(report);
        sd_json_variant_unref(manager.backend_result);
        free(key_hex);
        free(nonce_hex);
        free(ak);
        free(quote);
        free(signature);
        return 0;
}
