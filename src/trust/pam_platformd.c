/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PAM interface for session records and trust policy evaluation. */

#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include <systemd/sd-json.h>
#include <systemd/sd-login.h>

#include "pam-transport.h"

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

static int session_subject(pam_handle_t *pamh, char **ret_session, uid_t *ret_uid) {
        _cleanup_free_ char *sid = NULL;
        const char *user = item(pamh, PAM_USER);
        struct passwd *pw;
        uid_t owner;
        int r;

        *ret_session = NULL;
        if (!*user)
                return -ENODATA;
        pw = pam_modutil_getpwnam(pamh, user);
        if (!pw)
                return -ESRCH;

        r = sd_pid_get_session(0, &sid);
        if (r < 0)
                return r;
        if (!sid || !*sid)
                return -ENODATA;
        r = sd_session_get_uid(sid, &owner);
        if (r < 0)
                return r;

        /* A caller's session cannot establish policy for another PAM account. */
        if (owner != pw->pw_uid)
                return -EPERM;

        if (ret_uid)
                *ret_uid = owner;
        *ret_session = sid;
        sid = NULL;
        return 0;
}

static sd_json_variant *json_field(sd_json_variant *object, const char *name) {
        sd_json_variant *field = NULL;

        if (!sd_json_variant_is_object(object))
                return NULL;

        for (size_t i = 0; i < sd_json_variant_elements(object); i += 2) {
                sd_json_variant *key = sd_json_variant_by_index(object, i);

                if (!streq(sd_json_variant_string(key), name))
                        continue;
                if (field)
                        return NULL;
                field = sd_json_variant_by_index(object, i + 1);
        }

        return field;
}

static const char *policy_reason(const char *policy) {
        if (streq(policy, "verified-boot"))
                return "boot-verified";
        if (streq(policy, "fresh-user-verification"))
                return "verification-fresh";
        if (streq(policy, "local-trusted-session"))
                return "local-trusted-session";
        return NULL;
}

static bool policy_satisfied(sd_json_variant *reply, const char *policy, const char *sid) {
        sd_json_variant *parameters, *record, *field;
        static const char *const string_fields[] = {
                "policyId", "sessionId", "result", "reasonCode", "reason",
        };

        if (!sd_json_variant_is_object(reply) || sd_json_variant_by_key(reply, "error"))
                return false;
        if (sd_json_variant_by_key(reply, "continues")) {
                field = json_field(reply, "continues");
                if (!sd_json_variant_is_boolean(field) || sd_json_variant_boolean(field))
                        return false;
        }

        parameters = json_field(reply, "parameters");
        record = json_field(parameters, "result");
        for (size_t i = 0; i < sizeof string_fields / sizeof string_fields[0]; i++)
                if (!sd_json_variant_is_string(json_field(record, string_fields[i])))
                        return false;
        if (!sd_json_variant_is_unsigned(json_field(record, "windowSec")))
                return false;

        return streq(sd_json_variant_string(json_field(record, "policyId")), policy) &&
               streq(sd_json_variant_string(json_field(record, "sessionId")), sid) &&
               streq(sd_json_variant_string(json_field(record, "result")), "policy-satisfied") &&
               streq(sd_json_variant_string(json_field(record, "reasonCode")), policy_reason(policy));
}

static void submit(pam_handle_t *pamh, const char *phase, const char *method, const char *result) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *reply = NULL;
        _cleanup_free_ char *sid = NULL;
        const char *user = item(pamh, PAM_USER);
        uid_t uid;

        if (session_subject(pamh, &sid, &uid) < 0)
                return;

        if (sd_json_buildo(&params,
                SD_JSON_BUILD_PAIR("user", SD_JSON_BUILD_STRING(user)),
                SD_JSON_BUILD_PAIR("uid", SD_JSON_BUILD_UNSIGNED(uid)),
                SD_JSON_BUILD_PAIR("pamService", SD_JSON_BUILD_STRING(item(pamh, PAM_SERVICE))),
                SD_JSON_BUILD_PAIR("tty", SD_JSON_BUILD_STRING(item(pamh, PAM_TTY))),
                SD_JSON_BUILD_PAIR("remoteHost", SD_JSON_BUILD_STRING(item(pamh, PAM_RHOST))),
                SD_JSON_BUILD_PAIR("phase", SD_JSON_BUILD_STRING(phase)),
                SD_JSON_BUILD_PAIR("declaredMethod", SD_JSON_BUILD_STRING(method)),
                SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_STRING(result)),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(sid))) < 0)
                return;
        (void) pam_trust_call("io.platformd.Trust.SubmitAuthEvent", params, &reply);
}

/* An unavailable authority denies the policy. */
static int gate(pam_handle_t *pamh, const char *policy) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *reply = NULL;
        _cleanup_free_ char *sid = NULL;

        if (!policy_reason(policy))
                return PAM_AUTH_ERR;
        if (!streq(policy, "verified-boot") && session_subject(pamh, &sid, NULL) < 0)
                return PAM_AUTH_ERR;

        if (sd_json_buildo(&params,
                SD_JSON_BUILD_PAIR("policy", SD_JSON_BUILD_STRING(policy)),
                SD_JSON_BUILD_PAIR("sessionId", SD_JSON_BUILD_STRING(sid ?: ""))) < 0)
                return PAM_AUTH_ERR;
        if (pam_trust_call("io.platformd.Trust.EvaluatePolicy", params, &reply) < 0)
                return PAM_AUTH_ERR;

        return policy_satisfied(reply, policy, sid ?: "") ? PAM_SUCCESS : PAM_AUTH_ERR;
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
        if (!policy)
                return PAM_IGNORE;
        /* The account phase reports policy denial with PAM_PERM_DENIED. */
        return gate(pamh, policy) == PAM_SUCCESS ? PAM_SUCCESS : PAM_PERM_DENIED;
}
