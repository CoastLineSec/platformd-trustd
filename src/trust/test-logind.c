/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>

#define main trustd_main
#include "trustd.c"
#undef main

#define TEST_PATH "/org/freedesktop/login1/session/test_2dsession"

static bool locked;

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

int main(void) {
        sd_bus *sender = NULL;
        sd_event *event = NULL;
        Manager m = { .fresh_window = 300 };
        TrackedSession *s;
        sigset_t signals;

        sigemptyset(&signals);
        sigaddset(&signals, SIGCHLD);
        assert(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
        assert(sd_event_new(&event) >= 0);
        m.event = event;
        manager_instance = &m;
        assert(sd_bus_open_user(&sender) >= 0);
        assert(sd_bus_attach_event(sender, event, 0) >= 0);
        assert(sd_bus_add_object_vtable(sender, NULL, "/org/freedesktop/login1",
                                        "org.freedesktop.login1.Manager", manager_vtable, NULL) >= 0);
        assert(sd_bus_add_object_vtable(sender, NULL, TEST_PATH,
                                        "org.freedesktop.login1.Session", session_vtable, NULL) >= 0);
        assert(sd_bus_request_name(sender, "org.freedesktop.login1", 0) >= 0);
        setup_logind(&m);
        assert(m.bus);
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
