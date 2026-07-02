/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * pam_platformd — record PAM authentication events to platformd-trustd.
 *
 * Observability only: it never changes an authentication outcome. On session
 * open it submits a structured event (user, service, tty, declared method) to
 * the trust authority over Varlink, then returns success. Place it in a PAM
 * stack after pam_systemd so XDG_SESSION_ID is set, e.g.:
 *
 *     session optional pam_platformd.so method=password
 *
 * The declared method is honest by construction: it is whatever the stack line
 * says, recorded as a declaration, never as a verified fact.
 */

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

static const char *arg_method(int argc, const char **argv) {
        for (int i = 0; i < argc; i++)
                if (strncmp(argv[i], "method=", 7) == 0)
                        return argv[i] + 7;
        return "unknown-pam-success";
}

static const char *item(pam_handle_t *pamh, int type) {
        const void *v = NULL;
        return pam_get_item(pamh, type, &v) == PAM_SUCCESS && v ? (const char *) v : "";
}

static void submit(pam_handle_t *pamh, const char *phase, const char *method, const char *result) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *reply = NULL;
        _cleanup_free_ char *addr = NULL;
        const char *dir = getenv("PLATFORMD_TRUSTD_RUNTIME");
        const char *user = item(pamh, PAM_USER);
        const char *sid, *err = NULL;
        struct passwd *pw;

        if (!dir || !*dir)
                dir = "/run/platformd-trustd";
        if (asprintf(&addr, "%s/io.platformd.Trust", dir) < 0)
                return;
        if (sd_varlink_connect_address(&link, addr) < 0)
                return;   /* trust authority not running — nothing to record */

        pw = getpwnam(user);
        sid = pam_getenv(pamh, "XDG_SESSION_ID");

        if (sd_json_buildo(&params,
                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(user)),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(pw ? pw->pw_uid : (uid_t) -1)),
                SD_JSON_BUILD_PAIR("pamService", SD_JSON_BUILD_STRING(item(pamh, PAM_SERVICE))),
                SD_JSON_BUILD_PAIR("tty", SD_JSON_BUILD_STRING(item(pamh, PAM_TTY))),
                SD_JSON_BUILD_PAIR("remoteHost", SD_JSON_BUILD_STRING(item(pamh, PAM_RHOST))),
                SD_JSON_BUILD_PAIR("phase", SD_JSON_BUILD_STRING(phase)),
                SD_JSON_BUILD_PAIR("declaredMethod", SD_JSON_BUILD_STRING(method)),
                SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING(result)),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(sid ?: ""))) < 0)
                return;
        (void) sd_varlink_call(link, "io.platformd.Trust.SubmitAuthEvent", params, &reply, &err);
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        submit(pamh, "session", arg_method(argc, argv), "success");
        return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}
