/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "runtime-event.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>

int runtime_timestamp_now(RuntimeTimestamp *ret) {
        RuntimeTimestamp timestamp;
        struct timespec boottime, realtime;
        int r;

        r = sd_id128_get_boot(&timestamp.boot_id);
        if (r < 0)
                return r;
        if (clock_gettime(CLOCK_BOOTTIME, &boottime) < 0 ||
            clock_gettime(CLOCK_REALTIME, &realtime) < 0)
                return errno > 0 ? -errno : -EIO;
        if (boottime.tv_sec < 0 || realtime.tv_sec < 0 ||
            (uint64_t) boottime.tv_sec > UINT64_MAX / 1000000 - 1 ||
            (uint64_t) realtime.tv_sec > UINT64_MAX / 1000000 - 1)
                return -ERANGE;
        timestamp.boottime_usec = (uint64_t) boottime.tv_sec * 1000000 + boottime.tv_nsec / 1000;
        timestamp.realtime_usec = (uint64_t) realtime.tv_sec * 1000000 + realtime.tv_nsec / 1000;
        *ret = timestamp;
        return 0;
}

int runtime_event_format(const RuntimeTimestamp *timestamp, const char *type, const char *source,
                         const char *quality, sd_json_variant *payload, char **ret) {
        sd_json_variant *record = NULL;
        char boot_id[SD_ID128_STRING_MAX], *text = NULL;
        int r;

        *ret = NULL;
        if (!timestamp || sd_id128_is_null(timestamp->boot_id) || !type || !*type ||
            !source || !*source || !quality || !*quality || !sd_json_variant_is_object(payload))
                return -EINVAL;
        r = sd_json_buildo(&record,
                          SD_JSON_BUILD_PAIR_STRING("format", RUNTIME_EVENT_FORMAT),
                          SD_JSON_BUILD_PAIR_STRING("bootId", sd_id128_to_string(timestamp->boot_id, boot_id)),
                          SD_JSON_BUILD_PAIR_UNSIGNED("boottimeUSec", timestamp->boottime_usec),
                          SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", timestamp->realtime_usec),
                          SD_JSON_BUILD_PAIR_STRING("type", type),
                          SD_JSON_BUILD_PAIR_STRING("source", source),
                          SD_JSON_BUILD_PAIR_STRING("evidenceQuality", quality),
                          SD_JSON_BUILD_PAIR_VARIANT("payload", payload));
        if (r >= 0)
                r = sd_json_variant_format(record, 0, &text);
        sd_json_variant_unref(record);
        if (r < 0)
                return r;
        if (strlen(text) > RUNTIME_EVENT_SIZE_MAX) {
                free(text);
                return -E2BIG;
        }
        *ret = text;
        return 0;
}

int runtime_event_digest(const char *record, uint8_t ret[32]) {
        size_t size;

        if (!record || !*record)
                return -EINVAL;
        size = strnlen(record, RUNTIME_EVENT_SIZE_MAX + 1);
        if (size > RUNTIME_EVENT_SIZE_MAX)
                return -E2BIG;
        return EVP_Q_digest(NULL, "SHA256", NULL, record, size, ret, NULL) == 1 ? 0 : -EIO;
}

int runtime_event_replay(const uint8_t previous[32], const char *record, uint8_t ret[32]) {
        uint8_t input[64];
        int r;

        memcpy(input, previous, 32);
        r = runtime_event_digest(record, input + 32);
        if (r < 0)
                return r;
        return EVP_Q_digest(NULL, "SHA256", NULL, input, sizeof input, ret, NULL) == 1 ? 0 : -EIO;
}
