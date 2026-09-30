/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "verify.h"
#include "test-user-record.h"

#include <stdio.h>

#include <systemd/sd-json.h>

#define CHECK(cond) do { \
        if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", #cond, __LINE__); return 1; } \
} while (0)

int main(void) {
        sd_json_variant *rec = NULL, *name = NULL, *bare = NULL, *signatures = NULL, *invalid = NULL;

        /* A valid signature is accepted. */
        CHECK(sd_json_parse(user_record_fixture, 0, &rec, NULL, NULL) >= 0);
        CHECK(user_record_verify(rec));
        CHECK(sd_json_parse("{\"key\":\"invalid\",\"data\":\"invalid\"}", 0, &invalid, NULL, NULL) >= 0);
        CHECK(sd_json_variant_append_array(&signatures, invalid) >= 0);
        CHECK(sd_json_variant_append_array(&signatures,
                        sd_json_variant_by_index(sd_json_variant_by_key(rec, "signature"), 0)) >= 0);
        CHECK(sd_json_variant_set_field(&rec, "signature", signatures) >= 0);
        CHECK(user_record_verify(rec));

        /* Tampering with a signed field breaks verification. */
        CHECK(sd_json_variant_new_string(&name, "somebody-else") >= 0);
        CHECK(sd_json_variant_set_field(&rec, "userName", name) >= 0);
        CHECK(!user_record_verify(rec));

        /* A record with no signature is not verified. */
        CHECK(sd_json_parse("{\"userName\":\"x\"}", 0, &bare, NULL, NULL) >= 0);
        CHECK(!user_record_verify(bare));

        sd_json_variant_unref(rec);
        sd_json_variant_unref(name);
        sd_json_variant_unref(bare);
        sd_json_variant_unref(signatures);
        sd_json_variant_unref(invalid);
        printf("OK: user_record_verify (valid accepted, tampered + unsigned rejected)\n");
        return 0;
}
