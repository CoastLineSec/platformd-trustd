/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-login.h>

static bool session_valid(const char *id) {
        return getenv("PLATFORMD_TRUST_TEST_SESSION") && strcmp(id, "test-session") == 0;
}

int __wrap_sd_get_sessions(char ***ret) {
        char **sessions = calloc(2, sizeof(char *));

        if (!sessions)
                return -ENOMEM;
        *ret = sessions;
        if (!session_valid("test-session"))
                return 0;
        sessions[0] = strdup("test-session");
        return sessions[0] ? 1 : -ENOMEM;
}

int __wrap_sd_session_get_uid(const char *id, uid_t *ret) {
        if (!session_valid(id))
                return -ENXIO;
        *ret = getuid();
        return 0;
}

int __wrap_sd_session_get_leader(const char *id, pid_t *ret) {
        if (!session_valid(id))
                return -ENXIO;
        *ret = getpid();
        return 0;
}

int __wrap_sd_session_is_active(const char *id) {
        return session_valid(id) ? 1 : -ENXIO;
}

int __wrap_sd_session_is_remote(const char *id) {
        return session_valid(id) ? 0 : -ENXIO;
}

static int session_string(const char *id, char **ret, const char *value) {
        if (!session_valid(id))
                return -ENXIO;
        *ret = strdup(value);
        return *ret ? 0 : -ENOMEM;
}

int __wrap_sd_session_get_username(const char *id, char **ret) {
        return session_string(id, ret, "test-user");
}

int __wrap_sd_session_get_seat(const char *id, char **ret) {
        return session_string(id, ret, "seat0");
}

int __wrap_sd_session_get_type(const char *id, char **ret) {
        return session_string(id, ret, "wayland");
}

int __wrap_sd_session_get_class(const char *id, char **ret) {
        return session_string(id, ret, "user");
}

int __wrap_sd_session_get_state(const char *id, char **ret) {
        return session_string(id, ret, "active");
}

int __wrap_sd_session_get_tty(const char *id, char **ret) {
        return session_string(id, ret, "tty1");
}

struct passwd *__wrap_getpwuid(uid_t uid) {
        static struct passwd record;

        record.pw_uid = uid;
        record.pw_name = "test-user";
        return &record;
}
