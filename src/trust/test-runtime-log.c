/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#include <openssl/evp.h>

#define main trustd_main
#include "trustd.c"
#undef main

static uint8_t nv_value[32];
static bool read_error, extend_error, corrupt_extend;
static unsigned extensions;

int __wrap_attest_nv_read(uint8_t ret[32]) {
        if (read_error)
                return -EIO;
        memcpy(ret, nv_value, 32);
        return 0;
}

int __wrap_attest_nv_extend(const uint8_t *data, size_t size, uint8_t ret[32]) {
        uint8_t input[64];

        assert(size == 32);
        if (extend_error)
                return -EIO;
        memcpy(input, nv_value, 32);
        memcpy(input + 32, data, 32);
        assert(EVP_Q_digest(NULL, "SHA256", NULL, input, sizeof input, nv_value, NULL) == 1);
        if (corrupt_extend)
                nv_value[0] ^= 1;
        memcpy(ret, nv_value, 32);
        extensions++;
        return 0;
}

static void complete(Manager *m, BackendRequest *request, int expected) {
        sd_json_variant *result = NULL;

        m->backend_head = m->backend_tail = request;
        assert(backend_run(request, &result) == expected);
        backend_finish(m, request, expected, result);
        sd_json_variant_unref(result);
        assert(!m->backend_head && !m->backend_tail);
}

static void append(Manager *m, unsigned sequence, int expected) {
        RuntimeTimestamp timestamp = {
                .boot_id = SD_ID128_MAKE(01,23,45,67,89,ab,cd,ef,01,23,45,67,89,ab,cd,ef),
                .boottime_usec = 1000 + sequence,
                .realtime_usec = 2000 + sequence,
        };
        sd_json_variant *payload = NULL;
        BackendRequest *request = calloc(1, sizeof *request);

        assert(request);
        request->event = calloc(1, sizeof *request->event);
        assert(request->event);
        assert(sd_json_buildo(&payload,
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session"),
                             SD_JSON_BUILD_PAIR_STRING("lockState", "unknown"),
                             SD_JSON_BUILD_PAIR_BOOLEAN("freshnessInvalidated", true),
                             SD_JSON_BUILD_PAIR_UNSIGNED("sequence", sequence)) >= 0);
        assert(runtime_event_format(&timestamp, "lock-state", "org.freedesktop.login1.Session.LockedHint",
                                    "observed", payload, &request->event->desc) == 0);
        request->event->when = timestamp.realtime_usec;
        sd_json_variant_unref(payload);
        complete(m, request, expected);
}

static void clear(Manager *m) {
        while (m->runtime_log) {
                RuntimeEvent *event = m->runtime_log;

                m->runtime_log = event->next;
                free(event->desc);
                free(event);
        }
        sd_json_variant_unref(m->backend_result);
        *m = (Manager) {};
}

static void check_log(Manager *m, bool complete_log) {
        sd_json_variant *reply, *events;
        uint8_t value[32];
        uint8_t *baseline = NULL;
        size_t size;

        m->backend_result = sd_json_variant_unref(m->backend_result);
        assert(vl_get_runtime_log_run(NULL, NULL, 0, m) >= 0);
        reply = sd_json_variant_by_key(m->backend_result, "parameters");
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(reply, "format")), RUNTIME_LOG_FORMAT) == 0);
        assert(sd_json_variant_boolean(sd_json_variant_by_key(reply, "complete")) == complete_log);
        events = sd_json_variant_by_key(reply, "events");
        assert(sd_json_variant_elements(events) == m->n_runtime);
        assert(hex_decode(m->baseline_runtime, &baseline, &size) == 0 && size == 32);
        memcpy(value, baseline, 32);
        free(baseline);
        for (size_t i = 0; i < sd_json_variant_elements(events); i++) {
                sd_json_variant *event = sd_json_variant_by_index(events, i), *record = NULL;
                const char *text = sd_json_variant_string(sd_json_variant_by_key(event, "description"));

                assert(sd_json_parse(text, 0, &record, NULL, NULL) >= 0);
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(record, "realtimeUSec")) ==
                       sd_json_variant_unsigned(sd_json_variant_by_key(event, "realtimeUSec")));
                assert(runtime_event_replay(value, text, value) == 0);
                sd_json_variant_unref(record);
        }
        if (complete_log)
                assert(memcmp(value, nv_value, 32) == 0);
}

int main(void) {
        Manager manager = {};
        BackendRequest *request;
        unsigned before;

        manager_instance = &manager;
        memset(nv_value, 0xa5, sizeof nv_value);
        request = calloc(1, sizeof *request);
        assert(request);
        complete(&manager, request, 0);
        assert(extensions == 0);
        check_log(&manager, true);
        for (unsigned i = 0; i < RUNTIME_LOG_MAX + 3; i++)
                append(&manager, i, 0);
        assert(manager.n_runtime == RUNTIME_LOG_MAX);
        check_log(&manager, true);

        before = extensions;
        nv_value[0] ^= 1;
        append(&manager, 2000, -ESTALE);
        assert(manager.runtime_log_incomplete && extensions == before);
        check_log(&manager, false);
        clear(&manager);

        request = calloc(1, sizeof *request);
        assert(request);
        complete(&manager, request, 0);
        check_log(&manager, true);
        read_error = true;
        append(&manager, 2001, -EIO);
        read_error = false;
        assert(manager.runtime_log_incomplete);
        extend_error = true;
        append(&manager, 2002, -EIO);
        extend_error = false;
        corrupt_extend = true;
        append(&manager, 2003, -ESTALE);
        corrupt_extend = false;
        check_log(&manager, false);
        clear(&manager);
        return 0;
}
