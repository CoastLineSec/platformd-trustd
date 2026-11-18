/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define main trustd_main
#include "trustd.c"
#undef main

#define TEST_PATH "/org/freedesktop/login1/session/test_2dsession"

static bool preparing = true, query_error, query_trailing;
static unsigned queries;
static uid_t peer_uid;
static const char *reply_error;
static sd_json_variant *reply_parameters;

int __wrap_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *ret) {
        *ret = peer_uid;
        return 0;
}

int __wrap_sd_varlink_reply(sd_varlink *link, sd_json_variant *parameters) {
        reply_parameters = sd_json_variant_unref(reply_parameters);
        reply_parameters = sd_json_variant_ref(parameters);
        return 0;
}

int __wrap_sd_varlink_error(sd_varlink *link, const char *error, sd_json_variant *parameters) {
        reply_error = error;
        return 0;
}

int __wrap_sd_journal_send(const char *format, ...) {
        return 0;
}

static int list_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return sd_bus_reply_method_return(message, "a(susso)", 1,
                                         "test-session", (uint32_t) getuid(), "test-user", "seat0", TEST_PATH);
}

static int get_preparing(sd_bus *bus, const char *path, const char *interface, const char *property,
                         sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        queries++;
        if (query_error)
                return sd_bus_error_set_errno(error, EIO);
        return sd_bus_message_append(reply, "b", preparing);
}

static int filter_preparing(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        if (!query_trailing ||
            !sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Get") ||
            !streq(sd_bus_message_get_path(message), "/org/freedesktop/login1"))
                return 0;
        queries++;
        return sd_bus_reply_method_return(message, "vs", "b", false, "trailing");
}

static int get_locked(sd_bus *bus, const char *path, const char *interface, const char *property,
                      sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return sd_bus_message_append(reply, "b", false);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("ListSessions", "", "a(susso)", list_sessions, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_PROPERTY("PreparingForSleep", "b", get_preparing, 0, 0),
        SD_BUS_VTABLE_END,
};

static const sd_bus_vtable session_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("LockedHint", "b", get_locked, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END,
};

static void await_state(Manager *m, int state) {
        for (unsigned i = 0; i < 500; i++) {
                TrackedSession *s = find_tracked(m, "test-session");

                if (m->preparing_for_sleep == state && !m->sleep_query &&
                    (state < 0 ? m->sleep_retry != NULL : s && s->state.lock_state == 0))
                        return;
                assert(sd_event_run(m->event, 10000) >= 0);
        }
        assert(false);
}

static void submit(Manager *m, uid_t uid) {
        sd_json_variant *parameters = NULL;

        reply_error = NULL;
        assert(sd_json_buildo(&parameters,
                             SD_JSON_BUILD_PAIR_STRING("user", "test-user"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("uid", uid),
                             SD_JSON_BUILD_PAIR_STRING("pamService", "platformd-verify"),
                             SD_JSON_BUILD_PAIR_STRING("tty", ""),
                             SD_JSON_BUILD_PAIR_STRING("remoteHost", ""),
                             SD_JSON_BUILD_PAIR_STRING("phase", "verify"),
                             SD_JSON_BUILD_PAIR_STRING("declaredMethod", "platformd-verify"),
                             SD_JSON_BUILD_PAIR_STRING("result", "success"),
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session")) >= 0);
        assert(vl_submit_auth_event(NULL, parameters, 0, m) == 0);
        sd_json_variant_unref(parameters);
}

static void check_submission(Manager *m, bool qualifies) {
        TrackedSession *s;

        submit(m, getuid());
        assert(!reply_error);
        assert(m->events && m->events->qualifies_for_freshness == qualifies);
        s = find_tracked(m, "test-session");
        assert(s);
        assert((seconds_since_verify(s) >= 0) == qualifies);
        if (qualifies) {
                assert(s->state.last_verification_boottime_usec == m->events->timestamp.boottime_usec);
                assert(s->state.last_verification_realtime_usec == m->events->timestamp.realtime_usec);
        }
}

static void check_policy(Manager *m, bool satisfied) {
        sd_json_variant *parameters = NULL, *result;

        assert(sd_json_buildo(&parameters,
                             SD_JSON_BUILD_PAIR_STRING("policy", "fresh-user-verification"),
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "test-session")) >= 0);
        assert(vl_evaluate_policy(NULL, parameters, 0, m) == 0);
        result = sd_json_variant_by_key(reply_parameters, "result");
        assert(streq(sd_json_variant_string(sd_json_variant_by_key(result, "result")),
                     satisfied ? "policy-satisfied" : "denied"));
        assert(streq(sd_json_variant_string(sd_json_variant_by_key(result, "reasonCode")),
                     satisfied ? "verification-fresh" : "verification-missing"));
        sd_json_variant_unref(parameters);
}

static void emit_sleep(sd_bus *sender, Manager *m, bool state) {
        preparing = state;
        assert(sd_bus_emit_signal(sender, "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                  "PrepareForSleep", "b", state) >= 0);
        for (unsigned i = 0; i < 500; i++) {
                TrackedSession *s = find_tracked(m, "test-session");

                if (m->preparing_for_sleep == state && s && seconds_since_verify(s) < 0)
                        return;
                assert(sd_event_run(m->event, 10000) >= 0);
        }
        assert(false);
}

int main(void) {
        sd_bus *sender = NULL;
        sd_event *event = NULL;
        Manager m = { .fresh_window = 300 };
        unsigned n;
        sigset_t signals;

        assert(setenv("PLATFORMD_TRUST_TEST_SESSION", "1", 1) == 0);
        sigemptyset(&signals);
        sigaddset(&signals, SIGCHLD);
        assert(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
        assert(sd_event_new(&event) >= 0);
        m.event = event;
        manager_instance = &m;
        assert(sd_bus_open_user(&sender) >= 0);
        assert(sd_bus_attach_event(sender, event, 0) >= 0);
        assert(sd_bus_add_filter(sender, NULL, filter_preparing, NULL) >= 0);
        assert(sd_bus_add_object_vtable(sender, NULL, "/org/freedesktop/login1",
                                        "org.freedesktop.login1.Manager", manager_vtable, NULL) >= 0);
        assert(sd_bus_add_object_vtable(sender, NULL, TEST_PATH,
                                        "org.freedesktop.login1.Session", session_vtable, NULL) >= 0);
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        setup_logind(&m);
        assert(m.preparing_for_sleep < 0);
        check_submission(&m, false);
        await_state(&m, 1);
        check_submission(&m, false);
        check_policy(&m, false);

        emit_sleep(sender, &m, false);
        check_policy(&m, false);
        n = m.n_events;
        peer_uid = 65534;
        submit(&m, getuid());
        assert(reply_error && streq(reply_error, "io.platformd.Trust.PermissionDenied"));
        assert(m.n_events == n);
        peer_uid = 0;
        submit(&m, getuid() + 1);
        assert(reply_error && streq(reply_error, "io.platformd.Trust.InvalidAuthEvent"));
        assert(m.n_events == n);
        check_submission(&m, true);
        check_policy(&m, true);

        assert(sd_bus_emit_signal(sender, "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                  "PrepareForSleep", "bs", false, "trailing") >= 0);
        await_state(&m, -1);
        check_submission(&m, false);
        check_policy(&m, false);
        query_trailing = true;
        n = queries;
        query_preparing_for_sleep(&m);
        await_state(&m, -1);
        assert(queries == n + 1);
        check_submission(&m, false);
        check_policy(&m, false);
        query_trailing = false;
        await_state(&m, 0);
        check_submission(&m, true);

        emit_sleep(sender, &m, true);
        check_policy(&m, false);
        check_submission(&m, false);
        emit_sleep(sender, &m, false);
        check_policy(&m, false);
        check_submission(&m, true);

        /* A resume or canceled preparation never restores pre-transition evidence. */
        emit_sleep(sender, &m, false);
        check_policy(&m, false);
        check_submission(&m, true);
        emit_sleep(sender, &m, true);
        emit_sleep(sender, &m, false);
        check_policy(&m, false);

        check_submission(&m, true);
        query_error = true;
        assert(sd_bus_emit_signal(sender, "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                  "PrepareForSleep", "s", "invalid") >= 0);
        await_state(&m, -1);
        check_submission(&m, false);
        check_policy(&m, false);
        n = queries;
        while (queries == n || m.sleep_query)
                assert(sd_event_run(m.event, 10000) >= 0);
        assert(m.preparing_for_sleep < 0 && m.sleep_retry);
        query_error = false;
        await_state(&m, 0);
        check_policy(&m, false);
        check_submission(&m, true);

        assert(sd_bus_release_name(sender, "org.freedesktop.login1") >= 0);
        while (m.sessions)
                assert(sd_event_run(m.event, 10000) >= 0);
        assert(m.preparing_for_sleep < 0 && !m.sleep_query && !m.sleep_retry);
        preparing = true;
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        await_state(&m, 1);
        check_submission(&m, false);
        emit_sleep(sender, &m, false);
        check_submission(&m, true);
        check_policy(&m, true);

        forget_sleep_state(&m);
        forget_sessions(&m);
        while (m.backend_head) {
                BackendRequest *q = m.backend_head;
                m.backend_head = q->next;
                backend_free(q);
        }
        while (m.events) {
                AuthEvent *e = m.events;
                m.events = e->next;
                auth_event_free(e);
        }
        sd_json_variant_unref(reply_parameters);
        sd_event_source_unref(m.reconnect);
        sd_bus_flush_close_unref(m.bus);
        sd_bus_flush_close_unref(sender);
        sd_event_unref(event);
        manager_instance = NULL;
        return 0;
}
