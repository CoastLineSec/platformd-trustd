/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Unit test for user_record_verify with a synthetic homed-style signed record: a
 * minimal {userName,disposition,uid} record signed with a throwaway Ed25519 key,
 * embedded below. A valid signature is accepted; a tampered signed field or a
 * missing signature is rejected — guarding the Ed25519 normalization against a
 * silent regression (e.g. an sd-json canonicalization change). */

#include "verify.h"

#include <stdio.h>

#include <systemd/sd-json.h>

static const char *const FIXTURE = "{\"userName\": \"platformd-test\", \"disposition\": \"regular\", \"uid\": 65000, \"signature\": [{\"data\": \"ZtGi1l59FUe92cmnkZZDkpRQ4tpWDVVGWe4SZKQ6OXpcJHlycP4jMjoKK++ByBSLtfRmimpeMadEFQ7PbNm3AQ==\", \"key\": \"-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEAKhpGpg9WjQLWAb/elBSCAKjw7m44XNJBZVYrtaF2/ec=\\n-----END PUBLIC KEY-----\\n\"}]}";

#define CHECK(cond) do { \
        if (!(cond)) { fprintf(stderr, "FAIL: %s (line %d)\n", #cond, __LINE__); return 1; } \
} while (0)

int main(void) {
        sd_json_variant *rec = NULL, *name = NULL, *bare = NULL;

        /* A valid signature is accepted. */
        CHECK(sd_json_parse(FIXTURE, 0, &rec, NULL, NULL) >= 0);
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
        printf("OK: user_record_verify (valid accepted, tampered + unsigned rejected)\n");
        return 0;
}
