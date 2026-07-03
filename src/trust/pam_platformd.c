/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * pam_platformd — the PAM face of platformd-trustd. Two roles, selected by the
 * module arguments:
 *
 *   session, method=<m>   Observability. On session open it submits a structured
 *                         event (user, service, tty, declared method) to the trust
 *                         authority over Varlink and returns success. Place it
 *                         after pam_systemd so XDG_SESSION_ID is set, e.g.:
 *
 *                             session optional pam_platformd.so method=password
 *
 *   auth/account, policy=<p>
 *                         A gate. It asks the trust authority to evaluate a named
 *                         policy for the caller's session and returns PAM_SUCCESS
 *                         if satisfied, PAM_AUTH_ERR otherwise — fail closed, so an
 *                         unreachable authority denies. It authenticates nobody; it
 *                         only reports whether the platform meets the policy, for a
 *                         stack to route on, e.g.:
 *
 *                             auth [success=ignore default=3] pam_platformd.so policy=verified-boot
 *
 * The gate is advisory: it routes on the observed platform state, not a hardware
 * boundary. The declared method is honest by construction — whatever the stack
 * line says, recorded as a declaration, never as a verified fact.
 */

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <systemd/sd-json.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

static const char *arg_method(int argc, const char **argv) {
        for (int i = 0; i < argc; i++)
                if (strncmp(argv[i], "method=", 7) == 0)
                        return argv[i] + 7;
        return "unknown-pam-success";
}

static const char *arg_policy(int argc, const char **argv) {
        for (int i = 0; i < argc; i++)
                if (strncmp(argv[i], "policy=", 7) == 0)
                        return argv[i] + 7;
        return NULL;
}

static const char *item(pam_handle_t *pamh, int type) {
        const void *v = NULL;
        return pam_get_item(pamh, type, &v) == PAM_SUCCESS && v ? (const char *) v : "";
}

/* Exchange one Varlink message with trustd over a raw AF_UNIX socket, returning
 * the parsed reply (caller owns it) or NULL. We deliberately do not use
 * sd_varlink_call here: it drives its own event loop, which corrupts the heap when
 * run from inside a PAM module loaded into an arbitrary process. The request is
 * built from a variant, so field values are escaped. */
static sd_json_variant *trustd_call(const char *method, sd_json_variant *params) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *envelope = NULL;
        _cleanup_free_ char *text = NULL, *buf = NULL;
        struct sockaddr_un sa = { .sun_family = AF_UNIX };
        struct timeval tv = { .tv_sec = 5 };
        const char *dir = getenv("PLATFORMD_TRUSTD_RUNTIME");
        sd_json_variant *reply = NULL;
        size_t buflen = 0, cap = 0, tlen;
        int fd;

        if (!dir || !*dir)
                dir = "/run/platformd-trustd";
        if ((size_t) snprintf(sa.sun_path, sizeof sa.sun_path, "%s/io.platformd.Trust", dir) >= sizeof sa.sun_path)
                return NULL;
        if (sd_json_buildo(&envelope,
                SD_JSON_BUILD_PAIR("method", SD_JSON_BUILD_STRING(method)),
                SD_JSON_BUILD_PAIR("parameters", SD_JSON_BUILD_VARIANT(params))) < 0)
                return NULL;
        if (sd_json_variant_format(envelope, 0, &text) < 0)
                return NULL;

        if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
                return NULL;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
                close(fd);
                return NULL;
        }
        tlen = strlen(text);
        if (write(fd, text, tlen + 1) != (ssize_t) (tlen + 1)) {
                close(fd);
                return NULL;
        }
        for (;;) {
                char chunk[1024];
                ssize_t n = read(fd, chunk, sizeof chunk);
                char *nb;

                if (n <= 0)
                        break;
                if (buflen + (size_t) n + 1 > cap) {
                        cap = (buflen + (size_t) n + 1) * 2;
                        if (!(nb = realloc(buf, cap)))
                                break;
                        buf = nb;
                }
                memcpy(buf + buflen, chunk, (size_t) n);
                buflen += (size_t) n;
                if (memchr(chunk, 0, (size_t) n))
                        break;
        }
        close(fd);
        if (!buf)
                return NULL;
        buf[buflen] = 0;
        if (sd_json_parse(buf, 0, &reply, NULL, NULL) < 0)
                return NULL;
        return reply;
}

static void submit(pam_handle_t *pamh, const char *phase, const char *method, const char *result) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *reply = NULL;
        const char *user = item(pamh, PAM_USER);
        const char *sid = pam_getenv(pamh, "XDG_SESSION_ID");
        struct passwd *pw = getpwnam(user);

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
        reply = trustd_call("io.platformd.Trust.SubmitAuthEvent", params);
}

/* Ask the trust authority whether a named policy is satisfied for the caller's
 * session. PAM_SUCCESS if satisfied; PAM_AUTH_ERR if denied or — fail closed — if
 * the authority cannot be reached or does not answer, so an unverifiable platform
 * never routes into the stronger factors. Authenticates nobody. */
static int gate(pam_handle_t *pamh, const char *policy) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *reply = NULL;
        const char *sid = pam_getenv(pamh, "XDG_SESSION_ID");
        sd_json_variant *outer, *inner, *res;

        if (sd_json_buildo(&params,
                SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING(policy)),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(sid ?: ""))) < 0)
                return PAM_AUTH_ERR;
        reply = trustd_call("io.platformd.Trust.EvaluatePolicy", params);
        if (!reply || sd_json_variant_by_key(reply, "error"))
                return PAM_AUTH_ERR;   /* fail closed: unreachable or errored */

        /* raw reply keeps the wire wrapper: { parameters: { result: { result: … } } } */
        outer = sd_json_variant_by_key(reply, "parameters");
        inner = outer ? sd_json_variant_by_key(outer, "result") : NULL;
        res = inner ? sd_json_variant_by_key(inner, "result") : NULL;
        return res && sd_json_variant_is_string(res) &&
               streq(sd_json_variant_string(res), "policy-satisfied") ? PAM_SUCCESS : PAM_AUTH_ERR;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        submit(pamh, "session", arg_method(argc, argv), "success");
        return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        const char *policy = arg_policy(argc, argv);
        return policy ? gate(pamh, policy) : PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        const char *policy = arg_policy(argc, argv);
        return policy ? gate(pamh, policy) : PAM_IGNORE;
}
