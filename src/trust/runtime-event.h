/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include <systemd/sd-id128.h>
#include <systemd/sd-json.h>

#define RUNTIME_EVENT_FORMAT "io.platformd.Trust.RuntimeEvent.v2"
#define RUNTIME_LOG_FORMAT "io.platformd.Trust.RuntimeLog.v2"
#define RUNTIME_EVENT_SIZE_MAX 8192U

typedef struct RuntimeTimestamp {
        sd_id128_t boot_id;
        uint64_t boottime_usec;
        uint64_t realtime_usec;
} RuntimeTimestamp;

int runtime_timestamp_now(RuntimeTimestamp *ret);
int runtime_event_format(const RuntimeTimestamp *timestamp, const char *type, const char *source,
                         const char *quality, sd_json_variant *payload, char **ret);
int runtime_event_digest(const char *record, uint8_t ret[32]);
int runtime_event_replay(const uint8_t previous[32], const char *record, uint8_t ret[32]);
