/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define main trustd_main
#include "trustd.c"
#undef main

#define TEST_PATH "/org/freedesktop/login1/session/test_2dsession"

static bool locked;
static unsigned queries;
static enum {
        REPLY_OK,
        REPLY_ERROR,
        REPLY_MISSING,
        REPLY_BAD_SIGNATURE,
        REPLY_TRAILING,
        REPLY_INVALID_ID,
        REPLY_OBSOLETE,
        REPLY_EMPTY,
} reply_mode;

static int filter_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        if (!sd_bus_message_is_method_call(message, "org.freedesktop.login1.Manager", "ListSessions"))
                return 0;

        queries++;
        switch (reply_mode) {
        case REPLY_OK:
                return 0;
        case REPLY_ERROR:
                return sd_bus_reply_method_errno(message, EIO, NULL);
        case REPLY_MISSING:
                return 1;
        case REPLY_BAD_SIGNATURE:
                return sd_bus_reply_method_return(message, "s", "invalid");
        case REPLY_TRAILING:
                return sd_bus_reply_method_return(message, "a(susso)s", 1,
                                                 "test-session", (uint32_t) getuid(), "test-user", "seat0", TEST_PATH,
                                                 "trailing");
        case REPLY_INVALID_ID:
                return sd_bus_reply_method_return(message, "a(susso)", 2,
                                                 "test-session", (uint32_t) getuid(), "test-user", "seat0", TEST_PATH,
                                                 "", (uint32_t) getuid(), "test-user", "seat0", TEST_PATH);
        case REPLY_OBSOLETE:
                assert(sd_bus_emit_signal(sd_bus_message_get_bus(message), "/org/freedesktop/login1",
                                          "org.freedesktop.login1.Manager", "SessionRemoved", "so",
                                          "test-session", TEST_PATH) >= 0);
                return 0;
        case REPLY_EMPTY:
                return sd_bus_reply_method_return(message, "a(susso)", 0);
        default:
                assert(false);
        }
}

static int list_sessions(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return sd_bus_reply_method_return(message, "a(susso)", 1,
                                          "test-session", (uint32_t) getuid(), "test-user", "seat0", TEST_PATH);
}

static int get_locked(sd_bus *bus, const char *path, const char *interface, const char *property,
                      sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        return sd_bus_message_append(reply, "b", locked);
}

static int get_preparing(sd_bus *bus, const char *path, const char *interface, const char *property,
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

                if (state == -2 ? !s : s && s->state.lock_state == state)
                        return;
                assert(sd_event_run(m->event, 10000) >= 0);
        }
        assert(false);
}

static void await_failure(Manager *m, unsigned n) {
        for (unsigned i = 0; i < 500; i++) {
                if (queries == n && !m->session_query && m->session_retry)
                        return;
                assert(sd_event_run(m->event, 10000) >= 0);
        }
        assert(false);
}

static void await_query(Manager *m, unsigned n) {
        for (unsigned i = 0; i < 500; i++) {
                if (queries == n && m->session_query)
                        return;
                assert(sd_event_run(m->event, 10000) >= 0);
        }
        assert(false);
}

static void check_recovery(Manager *m) {
        unsigned n = queries;

        reply_mode = REPLY_OK;
        await_state(m, 0);
        assert(queries == n + 1);
        assert(!m->session_query && !m->session_retry);
        assert(find_tracked(m, "test-session")->state.last_verification_boottime_usec == 0);
}

int main(void) {
        sd_bus *sender = NULL;
        sd_event *event = NULL;
        Manager m = { .fresh_window = 300 };
        TrackedSession *s;
        sd_event_source *retry;
        uint64_t before, deadline;
        unsigned n;
        sigset_t signals;

        sigemptyset(&signals);
        sigaddset(&signals, SIGCHLD);
        assert(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
        assert(sd_event_new(&event) >= 0);
        m.event = event;
        manager_instance = &m;
        assert(sd_bus_open_user(&sender) >= 0);
        assert(sd_bus_attach_event(sender, event, 0) >= 0);
        assert(sd_bus_add_filter(sender, NULL, filter_sessions, NULL) >= 0);
        assert(sd_bus_add_object_vtable(sender, NULL, "/org/freedesktop/login1",
                                        "org.freedesktop.login1.Manager", manager_vtable, NULL) >= 0);
        assert(sd_bus_add_object_vtable(sender, NULL, TEST_PATH,
                                        "org.freedesktop.login1.Session", session_vtable, NULL) >= 0);
        setup_logind(&m);
        assert(m.bus);
        await_failure(&m, 0);
        assert(!m.sessions);
        reply_mode = REPLY_ERROR;
        before = now_boottime();
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        await_failure(&m, 1);
        assert(!m.sessions);
        retry = m.session_retry;
        schedule_session_retry(&m);
        assert(m.session_retry == retry);
        assert(sd_event_source_get_time(retry, &deadline) >= 0);
        assert(deadline >= before + 2000000);
        for (before = now_boottime(); now_boottime() - before < 200000; )
                assert(sd_event_run(event, 10000) >= 0);
        assert(queries == 1 && m.session_retry == retry && !m.session_query);
        check_recovery(&m);

        for (int mode = REPLY_MISSING; mode <= REPLY_OBSOLETE; mode++) {
                forget_sessions(&m);
                reply_mode = mode;
                n = queries;
                enumerate_sessions(&m);
                await_failure(&m, n + 1);
                assert(!m.sessions);
                check_recovery(&m);
        }

        forget_sessions(&m);
        reply_mode = REPLY_EMPTY;
        enumerate_sessions(&m);
        while (m.session_query)
                assert(sd_event_run(event, 10000) >= 0);
        assert(!m.sessions && !m.session_retry);
        reply_mode = REPLY_OK;
        enumerate_sessions(&m);
        await_state(&m, 0);
        s = find_tracked(&m, "test-session");
        assert(s && streq(s->path, TEST_PATH));
        trust_session_record_verification(&s->state, now_boottime(), now_real());
        locked = true;
        assert(sd_bus_emit_properties_changed(sender, TEST_PATH, "org.freedesktop.login1.Session",
                                              "LockedHint", NULL) >= 0);
        await_state(&m, 1);
        assert(s->state.last_verification_boottime_usec == 0);
        locked = false;
        assert(sd_bus_emit_properties_changed(sender, TEST_PATH, "org.freedesktop.login1.Session",
                                              "LockedHint", NULL) >= 0);
        await_state(&m, 0);
        trust_session_record_verification(&s->state, now_boottime(), now_real());
        assert(sd_bus_release_name(sender, "org.freedesktop.login1") >= 0);
        await_state(&m, -2);
        locked = true;
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        await_state(&m, 1);
        s = find_tracked(&m, "test-session");
        assert(s->state.last_verification_boottime_usec == 0);

        locked = false;
        reply_mode = REPLY_ERROR;
        n = queries;
        enumerate_sessions(&m);
        await_failure(&m, n + 1);
        assert(sd_bus_release_name(sender, "org.freedesktop.login1") >= 0);
        while (m.session_retry)
                assert(sd_event_run(event, 10000) >= 0);
        assert(!m.session_query && !m.sessions);
        reply_mode = REPLY_OK;
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        await_state(&m, 0);

        reply_mode = REPLY_MISSING;
        n = queries;
        enumerate_sessions(&m);
        await_query(&m, n + 1);
        assert(sd_bus_release_name(sender, "org.freedesktop.login1") >= 0);
        while (m.session_query)
                assert(sd_event_run(event, 10000) >= 0);
        assert(!m.session_retry && !m.sessions);
        reply_mode = REPLY_OK;
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        await_state(&m, 0);

        reply_mode = REPLY_ERROR;
        n = queries;
        enumerate_sessions(&m);
        await_failure(&m, n + 1);
        assert(shutdown(sd_bus_get_fd(m.bus), SHUT_RDWR) == 0);
        assert(sd_event_loop(event) == EXIT_FAILURE);
        assert(!m.session_query && !m.session_retry && !m.sessions);

        forget_sleep_state(&m);
        forget_sessions(&m);
        while (m.backend_head) {
                BackendRequest *q = m.backend_head;
                m.backend_head = q->next;
                backend_free(q);
        }
        sd_event_source_unref(m.reconnect);
        sd_bus_flush_close_unref(m.bus);
        sd_bus_flush_close_unref(sender);
        sd_event_unref(event);
        manager_instance = NULL;
        return 0;
}
