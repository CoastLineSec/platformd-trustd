/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include <systemd/sd-json.h>
#include <systemd/sd-login.h>

#define streq(a, b) (strcmp((a), (b)) == 0)
#define _cleanup_(f) __attribute__((cleanup(f)))

typedef struct Fixture {
        const char *policy;
        const char *user;
        const char *session;
        struct passwd account;
        uid_t session_uid;
        bool account_found;
        int session_error;
        int uid_error;
        int transport_error;
        unsigned transport_calls;
        unsigned environment_calls;
        unsigned session_calls;
        unsigned account_calls;
        sd_json_variant *reply;
        sd_json_variant *request;
        const char *method;
} Fixture;

static Fixture fixture;
static unsigned n_checks;

static pam_handle_t *handle(void) {
        return (pam_handle_t *) &fixture;
}

int __wrap_pam_get_item(const pam_handle_t *pamh, int type, const void **ret) {
        assert(pamh == handle());
        assert(ret);

        switch (type) {
        case PAM_USER:
                *ret = fixture.user;
                break;
        case PAM_SERVICE:
                *ret = "test-platformd";
                break;
        case PAM_TTY:
                *ret = "/dev/test-tty";
                break;
        case PAM_RHOST:
                *ret = "test-host";
                break;
        default:
                return PAM_BAD_ITEM;
        }

        return PAM_SUCCESS;
}

const char *__wrap_pam_getenv(pam_handle_t *pamh, const char *name) {
        assert(pamh == handle());
        assert(name);
        fixture.environment_calls++;
        return streq(name, "XDG_SESSION_ID") ? "other-session" : NULL;
}

struct passwd *__wrap_pam_modutil_getpwnam(pam_handle_t *pamh, const char *user) {
        assert(pamh == handle());
        assert(user && fixture.user && streq(user, fixture.user));
        fixture.account_calls++;
        return fixture.account_found ? &fixture.account : NULL;
}

int __wrap_sd_pid_get_session(pid_t pid, char **ret) {
        assert(pid == 0);
        assert(ret);
        fixture.session_calls++;
        if (fixture.session_error < 0)
                return fixture.session_error;
        *ret = strdup(fixture.session);
        return *ret ? 0 : -ENOMEM;
}

int __wrap_sd_session_get_uid(const char *session, uid_t *ret) {
        assert(session && fixture.session && streq(session, fixture.session));
        assert(ret);
        if (fixture.uid_error < 0)
                return fixture.uid_error;
        *ret = fixture.session_uid;
        return 0;
}

int pam_trust_call(const char *method, sd_json_variant *parameters, sd_json_variant **ret) {
        assert(method && parameters && ret);
        fixture.transport_calls++;
        fixture.method = method;
        fixture.request = sd_json_variant_unref(fixture.request);
        fixture.request = sd_json_variant_ref(parameters);
        if (fixture.transport_error < 0)
                return fixture.transport_error;
        *ret = sd_json_variant_ref(fixture.reply);
        return 0;
}

static const char *expected_session(void) {
        return streq(fixture.policy, "verified-boot") ? "" : "test-session";
}

static const char *positive_reason(const char *policy) {
        if (streq(policy, "verified-boot"))
                return "boot-verified";
        if (streq(policy, "fresh-user-verification"))
                return "verification-fresh";
        return "local-trusted-session";
}

static sd_json_variant *record_new(void) {
        sd_json_variant *record = NULL;

        assert(sd_json_buildo(
                       &record,
                       SD_JSON_BUILD_PAIR_STRING("policyId", fixture.policy),
                       SD_JSON_BUILD_PAIR_STRING("sessionId", expected_session()),
                       SD_JSON_BUILD_PAIR_STRING("result", "policy-satisfied"),
                       SD_JSON_BUILD_PAIR_STRING("reasonCode", positive_reason(fixture.policy)),
                       SD_JSON_BUILD_PAIR_STRING("reason", "Policy requirements are satisfied."),
                       SD_JSON_BUILD_PAIR_UNSIGNED("windowSec", 300)) >= 0);
        return record;
}

static void reply_set_record(sd_json_variant *record) {
        fixture.reply = sd_json_variant_unref(fixture.reply);
        assert(sd_json_buildo(
                       &fixture.reply,
                       SD_JSON_BUILD_PAIR("parameters", SD_JSON_BUILD_OBJECT(
                                       SD_JSON_BUILD_PAIR("result", SD_JSON_BUILD_VARIANT(record))))) >= 0);
}

static void fixture_reset(const char *policy) {
        sd_json_variant_unref(fixture.reply);
        sd_json_variant_unref(fixture.request);
        fixture = (Fixture) {
                .policy = policy,
                .user = "test-user",
                .session = "test-session",
                .account = { .pw_name = (char *) "test-user", .pw_uid = 1000 },
                .session_uid = 1000,
                .account_found = true,
        };

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = record_new();
        reply_set_record(record);
}

static void expect_string(sd_json_variant *object, const char *key, const char *expected) {
        sd_json_variant *v;

        v = sd_json_variant_by_key(object, key);
        assert(v && sd_json_variant_is_string(v));
        assert(streq(sd_json_variant_string(v), expected));
}

static void expect_gate(const char *name, bool allowed, unsigned calls) {
        char argument[128];
        const char *arguments[] = { argument };

        assert(snprintf(argument, sizeof(argument), "policy=%s", fixture.policy) > 0);
        for (unsigned account = 0; account < 2; account++) {
                int r, expected = allowed ? PAM_SUCCESS : account ? PAM_PERM_DENIED : PAM_AUTH_ERR;

                fixture.transport_calls = 0;
                r = account ? pam_sm_acct_mgmt(handle(), 0, 1, arguments) :
                              pam_sm_authenticate(handle(), 0, 1, arguments);
                if (r != expected || fixture.transport_calls != calls) {
                        fprintf(stderr, "%s (%s): result=%d expected=%d calls=%u expected=%u\n",
                                name, account ? "account" : "auth", r, expected, fixture.transport_calls, calls);
                        abort();
                }
                assert(fixture.environment_calls == 0);
                if (calls > 0) {
                        assert(streq(fixture.method, "io.platformd.Trust.EvaluatePolicy"));
                        expect_string(fixture.request, "policy", fixture.policy);
                        expect_string(fixture.request, "sessionId", expected_session());
                }
                n_checks++;
        }
}

static sd_json_variant *parse(const char *text) {
        sd_json_variant *v = NULL;

        assert(sd_json_parse(text, 0, &v, NULL, NULL) >= 0);
        return v;
}

static void duplicate_field(sd_json_variant **object, const char *field) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *key = NULL;
        sd_json_variant *elements[32], *copy = NULL;
        size_t n;

        n = sd_json_variant_elements(*object);
        assert(n + 2 <= sizeof(elements) / sizeof(elements[0]));
        for (size_t i = 0; i < n; i++)
                elements[i] = sd_json_variant_by_index(*object, i);
        assert(sd_json_variant_new_string(&key, field) >= 0);
        elements[n++] = key;
        elements[n++] = sd_json_variant_by_key(*object, field);
        assert(elements[n - 1]);
        assert(sd_json_variant_new_object(&copy, elements, n) >= 0);
        sd_json_variant_unref(*object);
        *object = copy;
}

static void test_result_fields(const char *policy) {
        static const char *const fields[] = {
                "policyId", "sessionId", "result", "reasonCode", "reason", "windowSec",
        };
        static const char *const wrong_values[] = { "null", "true", "[]", "{}" };
        static const char *const positive_reasons[] = {
                "boot-verified", "verification-fresh", "local-trusted-session",
        };

        fixture_reset(policy);
        expect_gate("valid policy", true, 1);

        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = NULL;
                char *remove[] = { (char *) fields[i], NULL };

                fixture_reset(policy);
                record = record_new();
                assert(sd_json_variant_filter(&record, remove) >= 0);
                reply_set_record(record);
                expect_gate(fields[i], false, 1);

                for (size_t j = 0; j < sizeof(wrong_values) / sizeof(wrong_values[0]); j++) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = parse(wrong_values[j]);

                        record = sd_json_variant_unref(record);
                        record = record_new();
                        assert(sd_json_variant_set_field(&record, fields[i], value) >= 0);
                        reply_set_record(record);
                        expect_gate(fields[i], false, 1);
                }

                record = sd_json_variant_unref(record);
                record = record_new();
                if (streq(fields[i], "windowSec"))
                        assert(sd_json_variant_set_field_string(&record, fields[i], "300") >= 0);
                else
                        assert(sd_json_variant_set_field_unsigned(&record, fields[i], 300) >= 0);
                reply_set_record(record);
                expect_gate(fields[i], false, 1);

                record = sd_json_variant_unref(record);
                record = record_new();
                duplicate_field(&record, fields[i]);
                reply_set_record(record);
                expect_gate("duplicate result field", false, 1);
        }

        static const struct {
                const char *field;
                const char *value;
        } mismatches[] = {
                { "policyId", "other-policy" },
                { "sessionId", "other-session" },
                { "result", "denied" },
                { "result", "unknown" },
                { "reasonCode", "verification-stale" },
                { "reasonCode", "session-locked" },
                { "reasonCode", "other-reason" },
        };

        for (size_t i = 0; i < sizeof(mismatches) / sizeof(mismatches[0]); i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = record_new();

                assert(sd_json_variant_set_field_string(&record, mismatches[i].field, mismatches[i].value) >= 0);
                reply_set_record(record);
                expect_gate(mismatches[i].field, false, 1);
        }

        for (size_t i = 0; i < sizeof(positive_reasons) / sizeof(positive_reasons[0]); i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = record_new();

                if (streq(positive_reasons[i], positive_reason(policy)))
                        continue;
                assert(sd_json_variant_set_field_string(&record, "reasonCode", positive_reasons[i]) >= 0);
                reply_set_record(record);
                expect_gate("unrelated positive reason", false, 1);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *record = record_new();
        assert(sd_json_variant_set_field_integer(&record, "windowSec", -1) >= 0);
        reply_set_record(record);
        expect_gate("negative window", false, 1);

        assert(sd_json_variant_set_field_unsigned(&record, "windowSec", UINT64_MAX) >= 0);
        assert(sd_json_variant_set_field_string(&record, "reason", "A changed explanatory message.") >= 0);
        assert(sd_json_variant_set_field_boolean(&record, "futureField", true) >= 0);
        reply_set_record(record);
        expect_gate("compatible extension", true, 1);
}

static void test_envelope(void) {
        static const char *const invalid[] = {
                "null", "[]", "true", "{}", "{\"parameters\":null}",
                "{\"parameters\":[]}", "{\"parameters\":{}}",
                "{\"parameters\":{\"result\":null}}",
                "{\"parameters\":{\"result\":[]}}",
        };

        fixture_reset("verified-boot");
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
                fixture.reply = sd_json_variant_unref(fixture.reply);
                fixture.reply = parse(invalid[i]);
                expect_gate("invalid envelope", false, 1);
        }

        fixture_reset("verified-boot");
        assert(sd_json_variant_set_field_string(&fixture.reply, "error", "io.platformd.Trust.UnknownPolicy") >= 0);
        expect_gate("error envelope", false, 1);

        assert(sd_json_variant_set_field(&fixture.reply, "error", NULL) >= 0);
        expect_gate("null error", false, 1);

        fixture_reset("verified-boot");
        assert(sd_json_variant_set_field_boolean(&fixture.reply, "continues", true) >= 0);
        expect_gate("continuing reply", false, 1);

        assert(sd_json_variant_set_field_boolean(&fixture.reply, "continues", false) >= 0);
        expect_gate("final reply", true, 1);

        assert(sd_json_variant_set_field_string(&fixture.reply, "continues", "false") >= 0);
        expect_gate("malformed continuation", false, 1);

        assert(sd_json_variant_set_field_boolean(&fixture.reply, "continues", false) >= 0);
        duplicate_field(&fixture.reply, "continues");
        expect_gate("duplicate continuation", false, 1);

        fixture_reset("verified-boot");
        duplicate_field(&fixture.reply, "parameters");
        expect_gate("duplicate parameters", false, 1);

        fixture_reset("verified-boot");
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters =
                sd_json_variant_ref(sd_json_variant_by_key(fixture.reply, "parameters"));
        duplicate_field(&parameters, "result");
        assert(sd_json_variant_set_field(&fixture.reply, "parameters", parameters) >= 0);
        expect_gate("duplicate result", false, 1);

        fixture_reset("verified-boot");
        fixture.transport_error = -ETIMEDOUT;
        expect_gate("transport error", false, 1);

        fixture_reset("verified-boot");
        fixture.reply = sd_json_variant_unref(fixture.reply);
        expect_gate("missing reply", false, 1);
}

static void test_subject(void) {
        static const char *const policies[] = { "fresh-user-verification", "local-trusted-session" };

        for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
                fixture_reset(policies[i]);
                expect_gate("process session", true, 1);
                assert(fixture.session_calls > 0 && fixture.account_calls > 0);

                fixture.session_uid = 2000;
                expect_gate("wrong session owner", false, 0);

                fixture_reset(policies[i]);
                fixture.user = NULL;
                expect_gate("missing PAM user", false, 0);

                fixture.user = "";
                expect_gate("empty PAM user", false, 0);

                fixture_reset(policies[i]);
                fixture.account_found = false;
                expect_gate("unknown PAM user", false, 0);

                fixture_reset(policies[i]);
                fixture.session_error = -ENODATA;
                expect_gate("missing process session", false, 0);

                fixture_reset(policies[i]);
                fixture.session = "";
                expect_gate("empty process session", false, 0);

                fixture_reset(policies[i]);
                fixture.uid_error = -ENXIO;
                expect_gate("missing session owner", false, 0);
        }

        fixture_reset("verified-boot");
        fixture.user = NULL;
        fixture.account_found = false;
        fixture.session_error = -ENODATA;
        expect_gate("session-independent boot policy", true, 1);
        assert(fixture.session_calls == 0 && fixture.account_calls == 0);

        fixture_reset("unsupported-policy");
        expect_gate("unknown policy", false, 0);
}

static void test_module_phases(void) {
        const char *arguments[] = { "method=password" };
        sd_json_variant *uid;

        fixture_reset("fresh-user-verification");
        assert(pam_sm_authenticate(handle(), 0, 0, NULL) == PAM_IGNORE);
        assert(pam_sm_acct_mgmt(handle(), 0, 0, NULL) == PAM_IGNORE);
        assert(pam_sm_setcred(handle(), 0, 0, NULL) == PAM_IGNORE);
        assert(pam_sm_close_session(handle(), 0, 0, NULL) == PAM_SUCCESS);
        assert(fixture.transport_calls == 0);

        assert(pam_sm_open_session(handle(), 0, 1, arguments) == PAM_SUCCESS);
        assert(fixture.transport_calls == 1);
        assert(streq(fixture.method, "io.platformd.Trust.SubmitAuthEvent"));
        expect_string(fixture.request, "user", "test-user");
        uid = sd_json_variant_by_key(fixture.request, "uid");
        assert(sd_json_variant_is_unsigned(uid) && sd_json_variant_unsigned(uid) == 1000);
        expect_string(fixture.request, "sessionId", "test-session");
        expect_string(fixture.request, "phase", "session");
        expect_string(fixture.request, "result", "success");
        expect_string(fixture.request, "declaredMethod", "password");
        expect_string(fixture.request, "pamService", "test-platformd");
        expect_string(fixture.request, "tty", "/dev/test-tty");
        expect_string(fixture.request, "remoteHost", "test-host");
        assert(fixture.environment_calls == 0);

        fixture.transport_error = -ECONNREFUSED;
        assert(pam_sm_open_session(handle(), 0, 1, arguments) == PAM_SUCCESS);
        assert(fixture.transport_calls == 2);

        fixture_reset("fresh-user-verification");
        fixture.session_uid = 2000;
        assert(pam_sm_open_session(handle(), 0, 1, arguments) == PAM_SUCCESS);
        assert(fixture.transport_calls == 0);

        fixture_reset("fresh-user-verification");
        fixture.session_error = -ENODATA;
        assert(pam_sm_open_session(handle(), 0, 1, arguments) == PAM_SUCCESS);
        assert(fixture.transport_calls == 0);

        fixture_reset("fresh-user-verification");
        fixture.user = NULL;
        assert(pam_sm_open_session(handle(), 0, 1, arguments) == PAM_SUCCESS);
        assert(fixture.transport_calls == 0);
}

int main(void) {
        test_result_fields("verified-boot");
        test_result_fields("fresh-user-verification");
        test_result_fields("local-trusted-session");
        test_envelope();
        test_subject();
        test_module_phases();
        sd_json_variant_unref(fixture.reply);
        sd_json_variant_unref(fixture.request);
        printf("PAM policy tests passed (%u gate checks).\n", n_checks);
        return 0;
}
