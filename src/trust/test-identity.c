/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <sys/socket.h>

#define main trustd_main
#include "trustd.c"
#undef main

#include "test-user-record.h"

static sd_json_variant *record_reply;
static uid_t peer_uid;
static const char *account_name = "platformd-test";

static const char *jstr(sd_json_variant *object, const char *key) {
        sd_json_variant *v = sd_json_variant_by_key(object, key);

        assert(sd_json_variant_is_string(v));
        return sd_json_variant_string(v);
}

struct passwd *__wrap_getpwuid(uid_t uid) {
        static struct passwd account;

        account.pw_uid = uid;
        account.pw_name = (char *) account_name;
        return &account;
}

int __wrap_sd_varlink_connect_address(sd_varlink **ret, const char *address) {
        int pair[2], r;

        assert(streq(address, "/run/systemd/userdb/io.systemd.Home"));
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        r = sd_varlink_connect_fd(ret, pair[0]);
        if (r < 0)
                close(pair[0]);
        close(pair[1]);
        return r;
}

int __wrap_sd_varlink_get_peer_uid(sd_varlink *link, uid_t *uid) {
        *uid = peer_uid;
        return 0;
}

int __wrap_sd_varlink_call(sd_varlink *link, const char *method, sd_json_variant *parameters,
                          sd_json_variant **ret, const char **error) {
        assert(streq(method, "io.systemd.UserDatabase.GetUserRecord"));
        assert(streq(jstr(parameters, "service"), "io.systemd.Home"));
        *ret = record_reply;
        *error = NULL;
        return 0;
}

static void check_identity(uid_t uid, bool verified, const char *source) {
        sd_json_variant *result = NULL;

        assert(identity_read(uid, &result) >= 0);
        assert(sd_json_variant_is_object(record_reply));
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(result, "uid")) == uid);
        assert(sd_json_variant_boolean(sd_json_variant_by_key(result, "verified")) == verified);
        assert(streq(jstr(result, "userName"), account_name));
        assert(streq(jstr(result, "source"), source));
        assert((*jstr(result, "signingKey") != 0) == verified);
        sd_json_variant_unref(result);
}

int main(void) {
        sd_json_variant *record = NULL;

        assert(sd_json_parse(user_record_fixture, 0, &record, NULL, NULL) >= 0);
        assert(sd_json_buildo(&record_reply, SD_JSON_BUILD_PAIR_VARIANT("record", record)) >= 0);
        check_identity(65000, true, "homed");
        check_identity(65001, false, "nss");
        account_name = "another-user";
        check_identity(65000, false, "nss");
        account_name = "platformd-test";
        peer_uid = 65000;
        check_identity(65000, false, "nss");
        peer_uid = 0;
        check_identity(65000, true, "homed");
        sd_json_variant_unref(record_reply);
        sd_json_variant_unref(record);
        return 0;
}
