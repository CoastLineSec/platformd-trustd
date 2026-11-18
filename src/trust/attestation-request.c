/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attestation-request.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "attestation-appraise.h"

static const char *string_field(sd_json_variant *object, const char *name) {
        sd_json_variant *value = sd_json_variant_by_key(object, name);

        return sd_json_variant_is_string(value) ? sd_json_variant_string(value) : NULL;
}

static bool field_equal(sd_json_variant *a, sd_json_variant *b, const char *name) {
        return sd_json_variant_equal(sd_json_variant_by_key(a, name), sd_json_variant_by_key(b, name));
}

static bool fields_valid(sd_json_variant *object, const char * const *fields, size_t n) {
        if (!sd_json_variant_is_object(object) || sd_json_variant_elements(object) != n * 2)
                return false;
        for (size_t i = 0; i < n; i++)
                if (!sd_json_variant_by_key(object, fields[i]))
                        return false;
        return true;
}

static bool request_valid(sd_json_variant *request) {
        static const char * const fields[] = { "uid", "sessionId", "context" };
        static const char * const context_fields[] = { "challengeHex", "audience", "operationDigestHex" };
        sd_json_variant *uid, *context;
        const char *session, *audience;

        if (!fields_valid(request, fields, 3))
                return false;
        uid = sd_json_variant_by_key(request, "uid");
        if ((sd_json_variant_type(uid) != SD_JSON_VARIANT_INTEGER && sd_json_variant_type(uid) != SD_JSON_VARIANT_UNSIGNED) ||
            !sd_json_variant_is_unsigned(uid) || sd_json_variant_unsigned(uid) >= UINT32_MAX)
                return false;
        session = string_field(request, "sessionId");
        if (!session || !*session || strlen(session) > 256)
                return false;
        for (const char *p = session; *p; p++)
                if ((unsigned char) *p < 0x20 || (unsigned char) *p > 0x7e)
                        return false;
        context = sd_json_variant_by_key(request, "context");
        if (!fields_valid(context, context_fields, 3))
                return false;
        audience = string_field(context, "audience");
        if (!audience || !*audience || strlen(audience) > 256)
                return false;
        for (const char *p = audience; *p; p++)
                if ((unsigned char) *p < 0x20 || (unsigned char) *p > 0x7e)
                        return false;
        for (size_t i = 0; i < 3; i += 2) {
                const char *hex = string_field(context, context_fields[i]);

                if (!hex || strlen(hex) != 64)
                        return false;
                for (size_t j = 0; j < 64; j++)
                        if (!((hex[j] >= '0' && hex[j] <= '9') || (hex[j] >= 'a' && hex[j] <= 'f')))
                                return false;
        }
        return true;
}

static int request_match(sd_json_variant *token, sd_json_variant *request) {
        sd_json_variant *measurements = sd_json_variant_by_key(token, "measurements"), *events = NULL;
        bool matched = false;

        for (size_t i = 0; i < sd_json_variant_elements(measurements); i++) {
                sd_json_variant *measurement = sd_json_variant_by_index(measurements, i);
                const char *type = string_field(measurement, "type");

                if (type && strcmp(type, "nv-runtime-log") == 0)
                        events = sd_json_variant_by_key(measurement, "events");
        }
        if (!events)
                return -EBADMSG;
        for (size_t i = 0; i < sd_json_variant_elements(events); i++) {
                sd_json_variant *event = sd_json_variant_by_index(events, i), *record = NULL, *payload;
                const char *description = string_field(event, "description"), *source;
                int r;

                if (!description)
                        return -EBADMSG;
                r = sd_json_parse(description, 0, &record, NULL, NULL);
                if (r < 0)
                        return r;
                source = string_field(record, "source");
                payload = sd_json_variant_by_key(record, "payload");
                if (strcmp(source, "io.platformd.Trust.SubmitVerificationEvent") == 0 &&
                    field_equal(payload, request, "uid") && field_equal(payload, request, "sessionId") &&
                    field_equal(payload, request, "context"))
                        matched = true;
                else if (strcmp(source, "org.freedesktop.login1.Manager.PrepareForSleep") == 0 ||
                         (strcmp(source, "org.freedesktop.login1.Session.LockedHint") == 0 &&
                          field_equal(payload, request, "sessionId") &&
                          sd_json_variant_boolean(sd_json_variant_by_key(payload, "freshnessInvalidated"))))
                        matched = false;
                sd_json_variant_unref(record);
        }
        return matched ? 0 : -EKEYREJECTED;
}

int attestation_appraise_request(sd_json_variant *token, const char *expected_ak_hex,
                                sd_json_variant *request, sd_json_variant *reference, const char *phase,
                                sd_json_variant **ret_report) {
        sd_json_variant *report = NULL, *context;
        int r;

        if (!ret_report)
                return -EINVAL;
        *ret_report = NULL;
        if (!request_valid(request))
                return -EINVAL;
        context = sd_json_variant_by_key(request, "context");
        r = attestation_appraise(token, expected_ak_hex, string_field(context, "challengeHex"), reference, phase, &report);
        if (r < 0)
                return r;
        r = request_match(token, request);
        if (r >= 0)
                r = sd_json_variant_set_field_string(&report, "profile", "io.platformd.Trust.RequestAppraisal.v1");
        if (r >= 0)
                r = sd_json_variant_set_field_boolean(&report, "authenticationDeclarationMatched", true);
        if (r >= 0)
                r = sd_json_variant_set_field_string(&report, "authenticationQuality", "root-declared");
        if (r >= 0)
                r = sd_json_variant_set_field(&report, "request", request);
        if (r < 0) {
                sd_json_variant_unref(report);
                return r;
        }
        *ret_report = report;
        return 0;
}
