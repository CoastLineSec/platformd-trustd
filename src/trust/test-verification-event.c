/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <systemd/sd-login.h>

static int test_session_get_state(const char *id, char **ret);

#define sd_session_get_state test_session_get_state
#define main trustd_main
#include "trustd.c"
#undef main
#undef sd_session_get_state

static RuntimeTimestamp current;
static uid_t peer_uid, session_uid;
static int session_error, timestamp_error, active, remote;
static const char *session_user, *session_class, *session_state, *reply_error;
static unsigned replies;

int __wrap_runtime_timestamp_now(RuntimeTimestamp *ret) {
        if (timestamp_error)
                return timestamp_error;
        *ret = current;
        return 0;
}

int __wrap_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *ret) {
        *ret = peer_uid;
        return 0;
}

int __wrap_sd_session_get_uid(const char *id, uid_t *ret) {
        assert(streq(id, "test-session"));
        *ret = session_uid;
        return session_error;
}

static int session_string(const char *id, const char *value, char **ret) {
        assert(streq(id, "test-session"));
        if (!value)
                return -ENODATA;
        *ret = strdup(value);
        return *ret ? 0 : -ENOMEM;
}

int __wrap_sd_session_get_username(const char *id, char **ret) {
        return session_string(id, session_user, ret);
}

int __wrap_sd_session_get_class(const char *id, char **ret) {
        return session_string(id, session_class, ret);
}

static int test_session_get_state(const char *id, char **ret) {
        return session_string(id, session_state, ret);
}

int __wrap_sd_session_is_active(const char *id) {
        assert(streq(id, "test-session"));
        return active;
}

int __wrap_sd_session_is_remote(const char *id) {
        assert(streq(id, "test-session"));
        return remote;
}

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        assert(sd_json_variant_is_object(parameters));
        assert(sd_json_variant_elements(parameters) == 0);
        replies++;
        return 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        reply_error = error;
        return 0;
}

int __wrap_sd_varlink_error_invalid_parameter_name(sd_varlink *link, const char *name) {
        reply_error = name;
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) {
        return 0;
}

int __wrap_worker_start(sd_event *event, uint64_t timeout_usec, WorkerRun run, WorkerDone done,
                        void *userdata, Worker **ret) {
        *ret = (Worker *) (uintptr_t) 1;
        return 0;
}

void __wrap_worker_free(Worker *worker) {
        assert(!worker || worker == (Worker *) (uintptr_t) 1);
}

static sd_json_variant *parameters_new(void) {
        sd_json_variant *parameters = NULL, *context = NULL;

        assert(sd_json_buildo(&context,
                             SD_JSON_BUILD_PAIR_STRING("challengeHex", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                             SD_JSON_BUILD_PAIR_STRING("audience", "https://service.example"),
                             SD_JSON_BUILD_PAIR_STRING("operationDigestHex", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")) >= 0);
        assert(sd_json_buildo(&parameters,
                             SD_JSON_BUILD_PAIR_STRING("user", "test-user"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("uid", 1000),
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session"),
                             SD_JSON_BUILD_PAIR_VARIANT("context", context),
                             SD_JSON_BUILD_PAIR_UNSIGNED("verificationBoottimeUSec", current.boottime_usec - 1000),
                             SD_JSON_BUILD_PAIR_UNSIGNED("verificationRealtimeUSec", current.realtime_usec - 1000)) >= 0);
        sd_json_variant_unref(context);
        return parameters;
}

static void run(unsigned fault) {
        Manager manager = { .preparing_for_sleep = 0 };
        TrackedSession tracked = { .id = "test-session", .state = { .lock_state = 0 } };
        sd_json_variant *parameters, *context;

        manager_instance = &manager;
        manager.sessions = &tracked;
        assert(sd_id128_from_string("0123456789abcdef0123456789abcdef", &current.boot_id) >= 0);
        current.boottime_usec = UINT64_C(500000000);
        current.realtime_usec = UINT64_C(1000000000);
        peer_uid = 0;
        session_uid = 1000;
        session_error = timestamp_error = remote = 0;
        active = 1;
        session_user = "test-user";
        session_class = "user";
        session_state = "active";
        reply_error = NULL;
        replies = 0;
        parameters = parameters_new();
        context = sd_json_variant_ref(sd_json_variant_by_key(parameters, "context"));
        switch (fault) {
        case 0: break;
        case 1: peer_uid = 1000; break;
        case 2: session_uid = 1001; break;
        case 3: session_error = -ENXIO; break;
        case 4: session_user = "other-user"; break;
        case 5: session_user = NULL; break;
        case 6: session_class = "greeter"; break;
        case 7: active = 0; break;
        case 8: active = -ENXIO; break;
        case 9: remote = 1; break;
        case 10: remote = -ENXIO; break;
        case 11: tracked.state.lock_state = 1; break;
        case 12: tracked.state.lock_state = -1; break;
        case 13: manager.preparing_for_sleep = 1; break;
        case 14: manager.preparing_for_sleep = -1; break;
        case 15: tracked.verification_invalidated_usec = current.boottime_usec - 1000; break;
        case 16: tracked.verification_invalidated_usec = UINT64_MAX; break;
        case 17:
                assert(sd_json_variant_set_field_unsigned(&parameters, "verificationBoottimeUSec", current.boottime_usec + 1) >= 0);
                break;
        case 18:
                assert(sd_json_variant_set_field_unsigned(&parameters, "verificationRealtimeUSec", current.realtime_usec + 1) >= 0);
                break;
        case 19:
                assert(sd_json_variant_set_field_unsigned(&parameters, "verificationBoottimeUSec", current.boottime_usec - 120000000) >= 0);
                break;
        case 20:
                assert(sd_json_variant_set_field_unsigned(&parameters, "verificationRealtimeUSec", current.realtime_usec - 120000000) >= 0);
                break;
        case 21:
                assert(sd_json_variant_set_field_unsigned(&parameters, "verificationBoottimeUSec", 0) >= 0);
                break;
        case 22:
                assert(sd_json_variant_set_field_string(&context, "challengeHex", "ab") >= 0);
                break;
        case 23:
                assert(sd_json_variant_set_field_string(&context, "operationDigestHex", "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789") >= 0);
                break;
        case 24:
                assert(sd_json_variant_set_field_string(&context, "audience", "bad\nvalue") >= 0);
                break;
        case 25:
                assert(sd_json_variant_set_field_string(&context, "audience", "") >= 0);
                break;
        case 26:
                assert(sd_json_variant_set_field_string(&context, "extra", "") >= 0);
                break;
        case 27:
                assert(sd_json_variant_set_field_unsigned(&parameters, "uid", UINT32_MAX) >= 0);
                break;
        case 28:
                assert(sd_json_variant_set_field_string(&parameters, "user", "") >= 0);
                break;
        case 29:
                tracked.state.last_verification_boottime_usec = current.boottime_usec;
                tracked.state.last_verification_realtime_usec = current.realtime_usec;
                break;
        case 30: {
                sd_json_variant *value = NULL;

                assert(sd_json_variant_new_real(&value, 1000.0) >= 0);
                assert(sd_json_variant_set_field(&parameters, "uid", value) >= 0);
                sd_json_variant_unref(value);
                break;
        }
        case 31: {
                sd_json_variant *value = NULL;

                assert(sd_json_variant_new_real(&value, (double) current.boottime_usec) >= 0);
                assert(sd_json_variant_set_field(&parameters, "verificationBoottimeUSec", value) >= 0);
                sd_json_variant_unref(value);
                break;
        }
        case 32: session_state = "closing"; break;
        case 33: session_state = "opening"; break;
        case 34: session_state = "online"; break;
        case 35: session_state = NULL; break;
        case 36: manager.verification_invalidated_usec = current.boottime_usec - 1000; break;
        case 37: manager.verification_invalidated_usec = UINT64_MAX; break;
        default: assert(false);
        }
        assert(sd_json_variant_set_field(&parameters, "context", context) >= 0);
        assert(vl_submit_verification_event(NULL, parameters, 0, NULL) == 0);
        if (fault == 0 || fault == 29) {
                sd_json_variant *record = NULL, *payload;

                assert(!reply_error && replies == 1);
                assert(manager.n_events == 1 && manager.events->qualifies_for_freshness);
                assert(tracked.state.last_verification_boottime_usec == current.boottime_usec - (fault == 0 ? 1000 : 0));
                assert(manager.backend_head && !manager.runtime_log && !manager.runtime_log_incomplete);
                assert(sd_json_parse(manager.backend_head->event->desc, 0, &record, NULL, NULL) >= 0);
                payload = sd_json_variant_by_key(record, "payload");
                assert(streq(sd_json_variant_string(sd_json_variant_by_key(record, "source")), "io.platformd.Trust.SubmitVerificationEvent"));
                assert(sd_json_variant_equal(sd_json_variant_by_key(payload, "context"), context));
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(payload, "verificationBoottimeUSec")) == current.boottime_usec - 1000);
                sd_json_variant_unref(record);
        } else {
                assert(reply_error && replies == 0);
                assert(!manager.events && !manager.backend_head && !manager.runtime_log_incomplete);
                assert(tracked.state.last_verification_boottime_usec == 0);
        }
        while (manager.events) {
                AuthEvent *event = manager.events;
                manager.events = event->next;
                auth_event_free(event);
        }
        while (manager.backend_head) {
                BackendRequest *request = manager.backend_head;
                manager.backend_head = request->next;
                backend_free(request);
        }
        sd_json_variant_unref(parameters);
        sd_json_variant_unref(context);
}

static TrackedSession *session_new(void) {
        TrackedSession *s = calloc(1, sizeof *s);

        assert(s);
        s->id = strdup("test-session");
        s->path = strdup("/org/freedesktop/login1/session/test_2dsession");
        assert(s->id && s->path);
        return s;
}

static void test_rebuild(bool sleep, bool fail_clock) {
        Manager manager = { .preparing_for_sleep = 0 };
        sd_json_variant *parameters;
        uint64_t invalidated;

        manager_instance = &manager;
        manager.sessions = session_new();
        assert(sd_id128_from_string("0123456789abcdef0123456789abcdef", &current.boot_id) >= 0);
        current.boottime_usec = UINT64_C(500000000);
        current.realtime_usec = UINT64_C(1000000000);
        peer_uid = 0;
        session_uid = 1000;
        session_error = timestamp_error = remote = 0;
        active = 1;
        session_user = "test-user";
        session_class = "user";
        session_state = "active";
        reply_error = NULL;
        replies = 0;
        parameters = parameters_new();
        if (sleep)
                forget_sleep_state(&manager);
        timestamp_error = fail_clock ? -EIO : 0;
        forget_sessions(&manager);
        timestamp_error = 0;
        assert(!manager.sessions);
        invalidated = fail_clock ? UINT64_MAX : current.boottime_usec;
        assert(manager.verification_invalidated_usec == invalidated);
        if (sleep) {
                current.boottime_usec++;
                current.realtime_usec++;
                set_preparing_for_sleep(&manager, 0);
                invalidated = current.boottime_usec;
        }
        manager.sessions = session_new();
        assert(manager.sessions->state.lock_state == 0);
        assert(manager.sessions->verification_invalidated_usec == 0);
        assert(manager.verification_invalidated_usec == invalidated);
        assert(vl_submit_verification_event(NULL, parameters, 0, NULL) == 0);
        assert(reply_error && replies == 0);
        assert(!manager.events && !manager.backend_head);
        assert(manager.sessions->state.last_verification_boottime_usec == 0);

        reply_error = NULL;
        current.boottime_usec += 2000;
        current.realtime_usec += 2000;
        sd_json_variant_unref(parameters);
        parameters = parameters_new();
        assert(vl_submit_verification_event(NULL, parameters, 0, NULL) == 0);
        if (fail_clock && !sleep) {
                assert(reply_error && replies == 0);
                assert(!manager.events && !manager.backend_head);
        } else {
                assert(!reply_error && replies == 1);
                assert(manager.n_events == 1 && manager.backend_head);
                assert(manager.sessions->state.last_verification_boottime_usec == current.boottime_usec - 1000);
        }
        while (manager.events) {
                AuthEvent *event = manager.events;
                manager.events = event->next;
                auth_event_free(event);
        }
        while (manager.backend_head) {
                BackendRequest *request = manager.backend_head;
                manager.backend_head = request->next;
                backend_free(request);
        }
        forget_sessions(&manager);
        sd_json_variant_unref(parameters);
}

int main(void) {
        for (unsigned i = 0; i < 38; i++)
                run(i);
        test_rebuild(false, false);
        test_rebuild(true, false);
        test_rebuild(false, true);
        test_rebuild(true, true);
        return 0;
}
