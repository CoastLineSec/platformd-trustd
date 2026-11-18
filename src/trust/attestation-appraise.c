/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attestation-appraise.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "attestation-verify.h"

#define REFERENCE_COUNT_MAX 1024U
#define PHASE_SIZE_MAX 1024U

static bool object_fields(sd_json_variant *object, const char *const *fields, size_t n_fields) {
        unsigned seen = 0;

        if (!sd_json_variant_is_object(object) || sd_json_variant_elements(object) != 2 * n_fields)
                return false;
        for (size_t i = 0; i < 2 * n_fields; i += 2) {
                const char *key = sd_json_variant_string(sd_json_variant_by_index(object, i));
                size_t j;

                if (!key)
                        return false;
                for (j = 0; j < n_fields; j++)
                        if (strcmp(key, fields[j]) == 0)
                                break;
                if (j == n_fields || (seen & (1U << j)))
                        return false;
                seen |= 1U << j;
        }
        return true;
}

static bool phase_valid(const char *phase) {
        size_t n;

        if (!phase || (n = strnlen(phase, PHASE_SIZE_MAX + 1)) == 0 || n > PHASE_SIZE_MAX)
                return false;
        for (size_t i = 0; i < n; i++)
                if ((unsigned char) phase[i] < 0x20 || phase[i] == 0x7f)
                        return false;
        return true;
}

static int unhex_char(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

static bool digest_parse(sd_json_variant *value, uint8_t ret[32]) {
        const char *s;

        if (!sd_json_variant_is_string(value) ||
            strnlen(s = sd_json_variant_string(value), 65) != 64)
                return false;
        for (size_t i = 0; i < 32; i++) {
                int high = unhex_char(s[2 * i]), low = unhex_char(s[2 * i + 1]);

                if (high < 0 || low < 0)
                        return false;
                ret[i] = (uint8_t) ((high << 4) | low);
        }
        return true;
}

static bool pcr11(sd_json_variant *value) {
        sd_json_variant_type_t type = sd_json_variant_type(value);

        return (type == SD_JSON_VARIANT_INTEGER || type == SD_JSON_VARIANT_UNSIGNED) &&
               sd_json_variant_is_unsigned(value) && sd_json_variant_unsigned(value) == 11;
}

static int reference_match(sd_json_variant *reference, const char *phase, const uint8_t measured[32]) {
        static const char *const root_fields[] = { "sha256" };
        static const char *const candidate_fields[] = { "phase", "pcr", "hash" };
        sd_json_variant *candidates;
        char *encoded = NULL;
        bool matched = false;
        size_t n;
        int r;

        if (!object_fields(reference, root_fields, 1))
                return -EBADMSG;
        candidates = sd_json_variant_by_key(reference, "sha256");
        if (!sd_json_variant_is_array(candidates) || (n = sd_json_variant_elements(candidates)) == 0)
                return -EBADMSG;
        if (n > REFERENCE_COUNT_MAX)
                return -E2BIG;
        for (size_t i = 0; i < n; i++) {
                sd_json_variant *candidate = sd_json_variant_by_index(candidates, i), *p;
                uint8_t expected[32];
                const char *candidate_phase;

                if (!object_fields(candidate, candidate_fields, 3) ||
                    !pcr11(sd_json_variant_by_key(candidate, "pcr")) ||
                    !digest_parse(sd_json_variant_by_key(candidate, "hash"), expected))
                        return -EBADMSG;
                p = sd_json_variant_by_key(candidate, "phase");
                if (!sd_json_variant_is_string(p) || !phase_valid(candidate_phase = sd_json_variant_string(p)))
                        return -EBADMSG;
                if (strcmp(candidate_phase, phase) == 0 && memcmp(expected, measured, 32) == 0)
                        matched = true;
        }
        r = sd_json_variant_format(reference, 0, &encoded);
        if (r < 0)
                return r;
        r = strlen(encoded) > ATTESTATION_REFERENCE_SIZE_MAX ? -E2BIG : matched ? 0 : -EKEYREJECTED;
        free(encoded);
        return r;
}

static int measured_pcr11(sd_json_variant *token, uint8_t ret[32]) {
        sd_json_variant *measurements = sd_json_variant_by_key(token, "measurements");

        for (size_t i = 0; i < sd_json_variant_elements(measurements); i++) {
                sd_json_variant *measurement = sd_json_variant_by_index(measurements, i), *type, *pcrs;

                type = sd_json_variant_by_key(measurement, "type");
                if (!sd_json_variant_is_string(type) || strcmp(sd_json_variant_string(type), "boot-pcrs") != 0)
                        continue;
                pcrs = sd_json_variant_by_key(measurement, "pcrs");
                for (size_t j = 0; j < sd_json_variant_elements(pcrs); j++) {
                        sd_json_variant *pcr = sd_json_variant_by_index(pcrs, j);

                        if (pcr11(sd_json_variant_by_key(pcr, "index")))
                                return digest_parse(sd_json_variant_by_key(pcr, "sha256"), ret) ? 0 : -EBADMSG;
                }
        }
        return -EBADMSG;
}

int attestation_appraise(sd_json_variant *token, const char *expected_ak_hex, const char *nonce_hex,
                        sd_json_variant *reference, const char *phase, sd_json_variant **ret_report) {
        sd_json_variant *report = NULL;
        uint8_t measured[32];
        int r;

        if (!ret_report)
                return -EINVAL;
        *ret_report = NULL;
        if (!phase_valid(phase))
                return -EINVAL;
        r = attestation_verify(token, expected_ak_hex, nonce_hex, &report);
        if (r < 0)
                return r;
        r = measured_pcr11(token, measured);
        if (r >= 0)
                r = reference_match(reference, phase, measured);
        if (r >= 0)
                r = sd_json_variant_set_field_string(&report, "profile", "io.platformd.Trust.AttestationAppraisal.v1");
        if (r >= 0)
                r = sd_json_variant_set_field_boolean(&report, "approvedPcr11Matched", true);
        if (r >= 0)
                r = sd_json_variant_set_field_string(&report, "approvedPhase", phase);
        if (r < 0) {
                sd_json_variant_unref(report);
                return r;
        }
        *ret_report = report;
        return 0;
}
