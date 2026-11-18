/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

#include "runtime-event.h"

static clockid_t failed_clock = (clockid_t) -1;
static int clock_error;

int __real_clock_gettime(clockid_t clock, struct timespec *ret);

int __wrap_clock_gettime(clockid_t clock, struct timespec *ret) {
        if (clock == failed_clock) {
                errno = clock_error;
                return -1;
        }
        return __real_clock_gettime(clock, ret);
}

static const RuntimeTimestamp timestamp = {
        .boot_id = SD_ID128_MAKE(01,23,45,67,89,ab,cd,ef,01,23,45,67,89,ab,cd,ef),
        .boottime_usec = 123456,
        .realtime_usec = 1794971223000000,
};

static char *format_payload(sd_json_variant *payload) {
        char *record = NULL;

        assert(runtime_event_format(&timestamp, "authentication", "io.platformd.Trust.SubmitAuthEvent",
                                    "declared", payload, &record) == 0);
        assert(record);
        return record;
}

static void test_encoding(void) {
        sd_json_variant *payload = NULL, *parsed = NULL, *field;
        RuntimeTimestamp current;
        char *record;

        assert(sd_json_buildo(&payload,
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "seat\"\\ value=other"),
                             SD_JSON_BUILD_PAIR_STRING("declaredMethod", "pam\n\t"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("uid", 1000),
                             SD_JSON_BUILD_PAIR_BOOLEAN("qualifiesForFreshness", false)) >= 0);
        record = format_payload(payload);
        assert(sd_json_parse(record, 0, &parsed, NULL, NULL) >= 0);
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(parsed, "format")), RUNTIME_EVENT_FORMAT) == 0);
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(parsed, "bootId")),
                      "0123456789abcdef0123456789abcdef") == 0);
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(parsed, "boottimeUSec")) == timestamp.boottime_usec);
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(parsed, "realtimeUSec")) == timestamp.realtime_usec);
        field = sd_json_variant_by_key(parsed, "payload");
        assert(sd_json_variant_equal(field, payload));
        assert(strchr(record, '\n') == NULL);
        assert(runtime_timestamp_now(&current) == 0);
        assert(!sd_id128_is_null(current.boot_id) && current.boottime_usec > 0 && current.realtime_usec > 0);
        free(record);
        sd_json_variant_unref(parsed);
        sd_json_variant_unref(payload);
}

static void test_mutation(void) {
        sd_json_variant *payload = NULL;
        uint8_t previous[32] = {}, digest[32], expected[32], changed[32], input[64];
        char *record, *copy;

        assert(sd_json_buildo(&payload,
                             SD_JSON_BUILD_PAIR_STRING("user", "test-user"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("uid", 1000),
                             SD_JSON_BUILD_PAIR_STRING("pamService", "platformd-verify"),
                             SD_JSON_BUILD_PAIR_STRING("tty", "tty1"),
                             SD_JSON_BUILD_PAIR_STRING("remoteHost", ""),
                             SD_JSON_BUILD_PAIR_STRING("phase", "verify"),
                             SD_JSON_BUILD_PAIR_STRING("declaredMethod", "platformd-verify"),
                             SD_JSON_BUILD_PAIR_STRING("result", "failure"),
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "3"),
                             SD_JSON_BUILD_PAIR_BOOLEAN("qualifiesForFreshness", false),
                             SD_JSON_BUILD_PAIR_UNSIGNED("peerUid", 0)) >= 0);
        record = format_payload(payload);
        assert(runtime_event_digest(record, digest) == 0);
        memcpy(input, previous, 32);
        memcpy(input + 32, digest, 32);
        assert(EVP_Q_digest(NULL, "SHA256", NULL, input, sizeof input, expected, NULL) == 1);
        assert(runtime_event_replay(previous, record, changed) == 0);
        assert(memcmp(expected, changed, 32) == 0);
        copy = strdup(record);
        assert(copy);
        for (size_t i = 0; record[i]; i++) {
                copy[i] = record[i] == 'a' ? 'b' : 'a';
                assert(runtime_event_replay(previous, copy, changed) == 0);
                assert(memcmp(expected, changed, 32) != 0);
                copy[i] = record[i];
        }
        previous[0] = 1;
        assert(runtime_event_replay(previous, record, changed) == 0);
        assert(memcmp(expected, changed, 32) != 0);
        assert(EVP_Q_digest(NULL, "SHA256", NULL, record, strlen(record), changed, NULL) == 1);
        assert(memcmp(expected, changed, 32) != 0);
        free(copy);
        free(record);
        sd_json_variant_unref(payload);
}

static void test_replay(void) {
        sd_json_variant *payload = NULL;
        uint8_t baseline[32] = {}, first[32], second[32], third[32], value[32], changed[32];
        char *records[3];

        for (unsigned i = 0; i < 3; i++) {
                assert(sd_json_buildo(&payload, SD_JSON_BUILD_PAIR_UNSIGNED("sequence", i)) >= 0);
                records[i] = format_payload(payload);
                payload = sd_json_variant_unref(payload);
        }
        assert(runtime_event_replay(baseline, records[0], first) == 0);
        assert(runtime_event_replay(first, records[1], second) == 0);
        assert(runtime_event_replay(second, records[2], third) == 0);
        /* A retained suffix starts at the digest of the last evicted event. */
        assert(runtime_event_replay(first, records[1], value) == 0);
        assert(runtime_event_replay(value, records[2], value) == 0);
        assert(memcmp(third, value, 32) == 0);
        assert(runtime_event_replay(first, records[2], value) == 0);
        assert(memcmp(third, value, 32) != 0);
        assert(runtime_event_replay(baseline, records[2], value) == 0);
        assert(runtime_event_replay(value, records[1], value) == 0);
        assert(runtime_event_replay(value, records[0], changed) == 0);
        assert(memcmp(third, changed, 32) != 0);
        assert(runtime_event_replay(third, records[2], changed) == 0);
        assert(memcmp(third, changed, 32) != 0);
        for (unsigned i = 0; i < 3; i++)
                free(records[i]);
}

static void test_limits(void) {
        sd_json_variant *payload = NULL;
        uint8_t digest[32];
        RuntimeTimestamp invalid = timestamp;
        char *record = NULL, *large = malloc(RUNTIME_EVENT_SIZE_MAX + 2);

        assert(large);
        memset(large, 'x', RUNTIME_EVENT_SIZE_MAX + 1);
        large[RUNTIME_EVENT_SIZE_MAX + 1] = 0;
        assert(runtime_event_digest(large, digest) == -E2BIG);
        large[RUNTIME_EVENT_SIZE_MAX] = 0;
        assert(runtime_event_digest(large, digest) == 0);
        assert(sd_json_buildo(&payload, SD_JSON_BUILD_PAIR_STRING("data", large)) >= 0);
        assert(runtime_event_format(&timestamp, "authentication", "root-peer", "declared", payload, &record) == -E2BIG);
        assert(!record);
        invalid.boot_id = SD_ID128_NULL;
        assert(runtime_event_format(&invalid, "authentication", "root-peer", "declared", payload, &record) == -EINVAL);
        assert(runtime_event_format(&timestamp, "authentication", "root-peer", "declared", NULL, &record) == -EINVAL);
        assert(runtime_event_digest("", digest) == -EINVAL);
        assert(runtime_event_digest(NULL, digest) == -EINVAL);
        sd_json_variant_unref(payload);
        free(large);
}

static void test_clock_change(void) {
        RuntimeTimestamp changed = timestamp;
        sd_json_variant *payload = NULL, *record = NULL;
        char *text = NULL;

        changed.boottime_usec++;
        changed.realtime_usec--;
        assert(sd_json_buildo(&payload, SD_JSON_BUILD_PAIR_BOOLEAN("freshnessInvalidated", true)) >= 0);
        assert(runtime_event_format(&changed, "sleep-state", "org.freedesktop.login1.Manager.PrepareForSleep",
                                    "observed", payload, &text) == 0);
        assert(sd_json_parse(text, 0, &record, NULL, NULL) >= 0);
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(record, "boottimeUSec")) == changed.boottime_usec);
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(record, "realtimeUSec")) == changed.realtime_usec);
        free(text);
        sd_json_variant_unref(payload);
        sd_json_variant_unref(record);
}

static void test_clock_failure(void) {
        RuntimeTimestamp current = timestamp;
        const clockid_t clocks[] = { CLOCK_BOOTTIME, CLOCK_REALTIME };

        for (size_t i = 0; i < sizeof clocks / sizeof clocks[0]; i++) {
                failed_clock = clocks[i];
                clock_error = EINVAL;
                assert(runtime_timestamp_now(&current) == -EINVAL);
                assert(current.boottime_usec == timestamp.boottime_usec);
                assert(current.realtime_usec == timestamp.realtime_usec);
                clock_error = 0;
                assert(runtime_timestamp_now(&current) == -EIO);
                assert(current.boottime_usec == timestamp.boottime_usec);
                assert(current.realtime_usec == timestamp.realtime_usec);
        }
        failed_clock = (clockid_t) -1;
}

int main(void) {
        test_encoding();
        test_mutation();
        test_replay();
        test_limits();
        test_clock_change();
        test_clock_failure();
        return 0;
}
