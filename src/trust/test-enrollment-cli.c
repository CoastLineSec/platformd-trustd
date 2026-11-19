/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <systemd/sd-id128.h>
#include <systemd/sd-varlink.h>
#include <openssl/evp.h>

#include "attestation-request.h"

static int test_fstat(int fd, struct stat *ret);
static int test_connect(sd_varlink **ret, const char *address);
static int test_appraise_request(sd_json_variant *token, const char *expected_ak_hex,
                                 sd_json_variant *request, sd_json_variant *reference, const char *phase,
                                 sd_json_variant **ret_report);
static int test_format(sd_json_variant *v, sd_json_format_flags_t flags, char **ret);

#define fstat test_fstat
#define sd_varlink_connect_address test_connect
#define attestation_appraise_request test_appraise_request
#define sd_json_variant_format test_format
#define main trustctl_main
#include "trustctl.c"
#undef main
#undef sd_json_variant_format
#undef attestation_appraise_request
#undef sd_varlink_connect_address
#undef fstat

#define CHALLENGE "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define RESPONSE "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
#define AUDIENCE "https://service.example"
#define OPERATION "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PHASE "enter-initrd:leave-initrd:sysinit:ready"
#define PCR11 "bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da"
#define EK "007a0023000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa" \
           "00060080004300100003001000206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" \
           "00204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

typedef struct Fixture {
        char directory[PATH_MAX], state[PATH_MAX], record[PATH_MAX];
        char state_option[PATH_MAX + 16], response_option[PATH_MAX + 16];
        char token_option[PATH_MAX + 16], reference_option[PATH_MAX + 16];
        char request_option[PATH_MAX + 16], ek_option[PATH_MAX + 32];
        char id[65], name[69], boot[SD_ID128_STRING_MAX], response_hash[65];
        char *ak;
} Fixture;

static bool wrong_response_owner;
static enum {
        REQUEST_CLOCK_NONE,
        REQUEST_CLOCK_APPRAISED,
        REQUEST_CLOCK_FORMATTED,
        REQUEST_CLOCK_FAILED,
        REQUEST_CLOCK_BEFORE_DEADLINE,
} request_clock;
static uint64_t fixed_boottime_usec, request_deadline_usec;
static bool request_appraised, request_formatted, fail_clock;
static unsigned checks;

int __real_clock_gettime(clockid_t clock, struct timespec *ret);
int __wrap_clock_gettime(clockid_t clock, struct timespec *ret);

int __wrap_clock_gettime(clockid_t clock, struct timespec *ret) {
        if (clock != CLOCK_BOOTTIME || fixed_boottime_usec == 0)
                return __real_clock_gettime(clock, ret);
        if (fail_clock) {
                errno = EIO;
                return -1;
        }
        ret->tv_sec = (time_t) (fixed_boottime_usec / 1000000);
        ret->tv_nsec = (long) (fixed_boottime_usec % 1000000) * 1000;
        return 0;
}

static int test_appraise_request(sd_json_variant *token, const char *expected_ak_hex,
                                 sd_json_variant *request, sd_json_variant *reference, const char *phase,
                                 sd_json_variant **ret_report) {
        int r = attestation_appraise_request(token, expected_ak_hex, request, reference, phase, ret_report);

        if (r >= 0) {
                request_appraised = true;
                if (request_clock == REQUEST_CLOCK_APPRAISED)
                        fixed_boottime_usec = request_deadline_usec;
        }
        return r;
}

static int test_format(sd_json_variant *v, sd_json_format_flags_t flags, char **ret) {
        int r = sd_json_variant_format(v, flags, ret);

        if (r >= 0 && request_appraised) {
                request_formatted = true;
                if (request_clock == REQUEST_CLOCK_FORMATTED)
                        fixed_boottime_usec = request_deadline_usec;
                else if (request_clock == REQUEST_CLOCK_BEFORE_DEADLINE)
                        fixed_boottime_usec = request_deadline_usec - 1;
                else if (request_clock == REQUEST_CLOCK_FAILED)
                        fail_clock = true;
        }
        return r;
}

static int test_fstat(int fd, struct stat *ret) {
        int r = fstat(fd, ret);

        if (r == 0 && wrong_response_owner)
                ret->st_uid = geteuid() == 0 ? 1 : 0;
        return r;
}

static int test_connect(sd_varlink **ret, const char *address) {
        (void) ret;
        (void) address;
        assert(!"Offline command attempted an authority connection");
        return -ENOTCONN;
}

static void encode(const uint8_t *bytes, size_t size, char *ret) {
        static const char digits[] = "0123456789abcdef";

        for (size_t i = 0; i < size; i++) {
                ret[i * 2] = digits[bytes[i] >> 4];
                ret[i * 2 + 1] = digits[bytes[i] & 15];
        }
        ret[size * 2] = 0;
}

static size_t decode(const char *hex, uint8_t *bytes, size_t capacity) {
        size_t size = strlen(hex);

        assert(size % 2 == 0 && size / 2 <= capacity);
        for (size_t i = 0; i < size / 2; i++) {
                unsigned value;

                assert(sscanf(hex + i * 2, "%2x", &value) == 1);
                bytes[i] = (uint8_t) value;
        }
        return size / 2;
}

static void hash(const void *bytes, size_t size, uint8_t ret[32]) {
        assert(EVP_Q_digest(NULL, "SHA256", NULL, bytes, size, ret, NULL) == 1);
}

static void make_path(char ret[static PATH_MAX], const Fixture *f, const char *name) {
        int n = snprintf(ret, PATH_MAX, "%s/%s", f->directory, name);

        assert(n > 0 && n < PATH_MAX);
}

static void write_file(const char *path, const void *data, size_t size) {
        FILE *stream;
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);

        assert(fd >= 0);
        assert(fchmod(fd, 0600) == 0);
        stream = fdopen(fd, "w");
        assert(stream);
        assert(fwrite(data, 1, size, stream) == size);
        assert(fclose(stream) == 0);
}

static void write_fixture(const Fixture *f, const char *name, const char *value) {
        char path[PATH_MAX];

        make_path(path, f, name);
        write_file(path, value, strlen(value));
}

static char *read_file(const char *path) {
        FILE *stream = fopen(path, "re");
        char *text;
        long size;

        assert(stream);
        assert(fseek(stream, 0, SEEK_END) == 0);
        size = ftell(stream);
        assert(size >= 0 && size <= 65536);
        rewind(stream);
        text = malloc((size_t) size + 1);
        assert(text);
        assert(fread(text, 1, (size_t) size, stream) == (size_t) size);
        text[size] = 0;
        assert(fclose(stream) == 0);
        return text;
}

static sd_json_variant *parse(const char *text) {
        sd_json_variant *v = NULL;

        assert(sd_json_parse(text, 0, &v, NULL, NULL) >= 0);
        return v;
}

static uint64_t boottime_usec(void) {
        struct timespec ts;

        assert(clock_gettime(CLOCK_BOOTTIME, &ts) == 0);
        return (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
}

/* These records test command dispatch and appraisal, not credential activation. */
static void write_record(Fixture *f, bool pending, bool request) {
        sd_json_variant *v = NULL, *p = NULL, *q = NULL;
        uint64_t now = boottime_usec();
        char *text = NULL;

        if (pending)
                assert(sd_json_buildo(&p,
                        SD_JSON_BUILD_PAIR_STRING("requestId", CHALLENGE),
                        SD_JSON_BUILD_PAIR_STRING("verifierBootId", f->boot),
                        SD_JSON_BUILD_PAIR_UNSIGNED("createdBoottimeUSec", now),
                        SD_JSON_BUILD_PAIR_UNSIGNED("deadlineBoottimeUSec", now + 600000000),
                        SD_JSON_BUILD_PAIR_STRING("responseSha256", f->response_hash)) >= 0);
        else
                assert(sd_json_variant_new_null(&p) >= 0);
        if (request)
                assert(sd_json_buildo(&q,
                        SD_JSON_BUILD_PAIR_STRING("requestId", CHALLENGE),
                        SD_JSON_BUILD_PAIR_STRING("verifierBootId", f->boot),
                        SD_JSON_BUILD_PAIR_UNSIGNED("createdBoottimeUSec", now),
                        SD_JSON_BUILD_PAIR_UNSIGNED("deadlineBoottimeUSec", now + 600000000),
                        SD_JSON_BUILD_PAIR_UNSIGNED("uid", 1000),
                        SD_JSON_BUILD_PAIR_STRING("sessionId", "fixture-session"),
                        SD_JSON_BUILD_PAIR_STRING("audience", AUDIENCE),
                        SD_JSON_BUILD_PAIR_STRING("operationDigestHex", OPERATION)) >= 0);
        else
                assert(sd_json_variant_new_null(&q) >= 0);
        assert(sd_json_buildo(&v,
                SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.Enrollment.v1"),
                SD_JSON_BUILD_PAIR_STRING("keyId", f->id),
                SD_JSON_BUILD_PAIR_STRING("ekPublicHex", EK),
                SD_JSON_BUILD_PAIR_STRING("akPublicHex", f->ak),
                SD_JSON_BUILD_PAIR_STRING("akNameHex", f->name),
                SD_JSON_BUILD_PAIR_STRING("state", pending ? "pending" : "active"),
                SD_JSON_BUILD_PAIR_UNSIGNED("generation", 1),
                SD_JSON_BUILD_PAIR_UNSIGNED("enrolledRealtimeUSec", pending ? 0 : 1),
                SD_JSON_BUILD_PAIR_UNSIGNED("revokedRealtimeUSec", 0),
                SD_JSON_BUILD_PAIR_VARIANT("pending", p),
                SD_JSON_BUILD_PAIR_VARIANT("request", q)) >= 0);
        assert(sd_json_variant_format(v, 0, &text) >= 0);
        write_file(f->record, text, strlen(text));
        free(text);
        sd_json_variant_unref(v);
        sd_json_variant_unref(p);
        sd_json_variant_unref(q);
}

static sd_json_variant *run(Fixture *f, const char *command, char *const arguments[], bool success) {
        char output[PATH_MAX], error[PATH_MAX], *argv[20], *text, *err;
        sd_json_variant *v = NULL;
        size_t count;
        pid_t pid;
        int status;

        argv[0] = (char *) "trustctl";
        argv[1] = (char *) command;
        for (count = 0; arguments[count]; count++) {
                assert(count + 3 < sizeof argv / sizeof argv[0]);
                argv[count + 2] = arguments[count];
        }
        argv[count + 2] = NULL;
        make_path(output, f, "output");
        make_path(error, f, "error");
        assert(fflush(NULL) == 0);
        pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
                int out = open(output, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                int errfd = open(error, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                int result;

                assert(out >= 0 && errfd >= 0);
                assert(dup2(out, STDOUT_FILENO) == STDOUT_FILENO);
                assert(dup2(errfd, STDERR_FILENO) == STDERR_FILENO);
                close(out);
                close(errfd);
                alarm(5);
                result = trustctl_main((int) count + 2, argv);
                if (request_clock != REQUEST_CLOCK_NONE)
                        assert(request_appraised && request_formatted);
                assert(fflush(NULL) == 0);
                _exit(result);
        }
        while (waitpid(pid, &status, 0) < 0)
                assert(errno == EINTR);
        text = read_file(output);
        err = read_file(error);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != (success ? 0 : 1)) {
                fprintf(stderr, "%s: unexpected status %d: %s\n", command, status, err);
                abort();
        }
        assert(!strstr(err, RESPONSE));
        if (success) {
                assert(!*err);
                if (streq(command, "request-cancel"))
                        assert(!*text);
                else
                        v = parse(text);
        } else {
                assert(!*text && *err);
                assert(!strstr(err, "Sanitizer"));
                assert(!strstr(err, "runtime error:"));
        }
        checks++;
        free(text);
        free(err);
        return v;
}

static void reject(Fixture *f, const char *command, char *const arguments[]) {
        assert(!run(f, command, arguments, false));
}

static void unchanged(Fixture *f, const char *before) {
        char *after = read_file(f->record);

        assert(strcmp(before, after) == 0);
        free(after);
}

static void test_options(Fixture *f, const char *command, char *const arguments[]) {
        char *args[20], *before = read_file(f->record);
        size_t n = 0;

        while (arguments[n])
                n++;
        assert(n + 2 < sizeof args / sizeof args[0]);
        for (size_t skip = 0; skip < n; skip++) {
                size_t k = 0;

                for (size_t j = 0; j < n; j++)
                        if (j != skip)
                                args[k++] = arguments[j];
                args[k] = NULL;
                reject(f, command, args);
                unchanged(f, before);
        }
        memcpy(args, arguments, (n + 1) * sizeof args[0]);
        for (size_t i = 0; i < n; i++) {
                args[n] = arguments[i];
                args[n + 1] = NULL;
                reject(f, command, args);
                unchanged(f, before);
                if (strchr(arguments[i], '=')) {
                        char *empty = strndup(arguments[i], (size_t) (strchr(arguments[i], '=') + 1 - arguments[i]));

                        assert(empty);
                        args[n] = NULL;
                        args[i] = empty;
                        reject(f, command, args);
                        unchanged(f, before);
                        args[i] = arguments[i];
                        free(empty);
                }
        }
        args[n + 1] = NULL;
        args[n] = (char *) "--unknown";
        reject(f, command, args);
        args[n] = (char *) "extra";
        reject(f, command, args);
        unchanged(f, before);
        free(before);
}

static void test_response(Fixture *f) {
        char *args[] = { f->id, f->state_option, (char *) "--request-id=" CHALLENGE, f->response_option, NULL };
        char path[PATH_MAX], other[PATH_MAX], option[PATH_MAX + 16], *before;
        const mode_t modes[] = { 0644, 0400, 0666, 06400 };
        sd_json_variant *v;
        int fd;

        write_record(f, true, false);
        before = read_file(f->record);
        test_options(f, "enrollment-complete", args);
        make_path(path, f, "response");
        write_file(path, RESPONSE "\n", sizeof RESPONSE);
        for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
                assert(chmod(path, modes[i]) == 0);
                reject(f, "enrollment-complete", args);
                unchanged(f, before);
        }
        assert(chmod(path, 0600) == 0);
        wrong_response_owner = true;
        reject(f, "enrollment-complete", args);
        wrong_response_owner = false;
        unchanged(f, before);
        make_path(other, f, "response-link");
        assert(link(path, other) == 0);
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        assert(unlink(other) == 0);
        assert(symlink(path, other) == 0);
        assert(snprintf(option, sizeof option, "--response=%s", other) > 0);
        args[3] = option;
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        assert(unlink(other) == 0);
        assert(mkfifo(other, 0600) == 0);
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        assert(unlink(other) == 0);
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        assert(mkdir(other, 0700) == 0);
        reject(f, "enrollment-complete", args);
        assert(rmdir(other) == 0);
        args[3] = f->response_option;
        write_file(path, RESPONSE, sizeof RESPONSE);
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        assert(fd >= 0 && ftruncate(fd, 257) == 0 && close(fd) == 0);
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        write_file(path, "", 0);
        reject(f, "enrollment-complete", args);
        unchanged(f, before);
        write_file(path, " \t" RESPONSE "\n", sizeof RESPONSE + 2);
        v = run(f, "enrollment-complete", args, true);
        assert(streq(jstr(v, "state"), "active"));
        assert(juint(v, "generation") == 2 && juint(v, "enrolledRealtimeUSec") > 0);
        sd_json_variant_unref(v);
        reject(f, "enrollment-complete", args);
        free(before);
}

static void test_lifetime(Fixture *f) {
        static const char *const invalid[] = { "", "0", "601", "-1", "+1", " 1", "1 ", "1s", "1.0", "18446744073709551616" };
        char *args[] = { f->id, f->state_option, f->request_option, NULL, NULL };
        char option[80], *before;
        uint64_t value;

        write_record(f, false, false);
        before = read_file(f->record);
        for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
                assert(parse_lifetime(invalid[i], &value) < 0);
                assert(snprintf(option, sizeof option, "--lifetime=%s", invalid[i]) > 0);
                args[3] = option;
                reject(f, "request-begin", args);
                unchanged(f, before);
        }
        for (size_t i = 0; i < 2; i++) {
                sd_json_variant *v, *record, *request;
                char *text;

                write_record(f, false, false);
                args[3] = (char *) (i == 0 ? "--lifetime=1" : "--lifetime=600");
                assert(parse_lifetime(args[3] + strlen("--lifetime="), &value) == 0);
                v = run(f, "request-begin", args, true);
                assert(streq(jstr(v, "format"), "io.platformd.Trust.AuthenticationRequest.v1"));
                assert(strlen(jstr(v, "requestId")) == 64);
                text = read_file(f->record);
                record = parse(text);
                request = sd_json_variant_by_key(record, "request");
                assert(juint(request, "deadlineBoottimeUSec") - juint(request, "createdBoottimeUSec") == value * 1000000);
                assert(streq(jstr(request, "requestId"), jstr(v, "requestId")));
                sd_json_variant_unref(v);
                sd_json_variant_unref(record);
                free(text);
        }
        free(before);
}

static void test_requests(Fixture *f) {
        static const char *const excluded[] = { "authenticated", "authenticationFresh", "policySatisfied", "approvedBoot", "requestAccepted" };
        char *args[] = { f->id, f->state_option, (char *) "--request-id=" CHALLENGE,
                        f->token_option, f->reference_option, (char *) "--phase=" PHASE,
                        (char *) "--allow-root-declared-authentication", NULL };
        char *status_args[] = { f->id, f->state_option, NULL };
        sd_json_variant *v;
        char path[PATH_MAX], option[PATH_MAX + 16], *before;

        write_record(f, false, true);
        test_options(f, "request-complete", args);
        before = read_file(f->record);
        args[6] = (char *) "--allow-root-declared-authentication=yes";
        reject(f, "request-complete", args);
        unchanged(f, before);
        args[6] = (char *) "--allow-root-declared-authentication";
        args[2] = (char *) "--request-id=" OPERATION;
        reject(f, "request-complete", args);
        unchanged(f, before);
        args[2] = (char *) "--request-id=" CHALLENGE;
        v = run(f, "request-complete", args, true);
        assert(jbool(v, "activeEnrollmentMatched") && jbool(v, "singleUseChallengeConsumed"));
        assert(jbool(v, "authenticationDeclarationMatched") && jbool(v, "quoteSignatureVerified"));
        assert(streq(jstr(v, "authenticationQuality"), "root-declared"));
        assert(streq(jstr(v, "keyId"), f->id));
        for (size_t i = 0; i < sizeof excluded / sizeof excluded[0]; i++)
                assert(!sd_json_variant_by_key(v, excluded[i]));
        sd_json_variant_unref(v);
        reject(f, "request-complete", args);
        free(before);

        write_record(f, false, true);
        write_fixture(f, "invalid-token", "{}{}");
        make_path(path, f, "invalid-token");
        assert(snprintf(option, sizeof option, "--token=%s", path) > 0);
        args[3] = option;
        reject(f, "request-complete", args);
        args[3] = f->token_option;
        reject(f, "request-complete", args);

        write_record(f, false, true);
        args[5] = (char *) "--phase=unapproved";
        reject(f, "request-complete", args);
        args[5] = (char *) "--phase=" PHASE;
        reject(f, "request-complete", args);

        write_record(f, false, true);
        v = run(f, "enrollment-revoke", status_args, true);
        assert(streq(jstr(v, "state"), "revoked"));
        sd_json_variant_unref(v);
        reject(f, "request-complete", args);
        v = run(f, "enrollment-status", status_args, true);
        assert(streq(jstr(v, "state"), "revoked"));
        sd_json_variant_unref(v);
}

static void test_request_files(Fixture *f) {
        char *args[] = { f->id, f->state_option, (char *) "--request-id=" CHALLENGE,
                        f->token_option, f->reference_option, (char *) "--phase=" PHASE,
                        (char *) "--allow-root-declared-authentication", NULL };
        char path[PATH_MAX], option[PATH_MAX + 16];

        make_path(path, f, "invalid-input");
        for (size_t field = 3; field <= 4; field++)
                for (unsigned kind = 0; kind < 7; kind++) {
                        char *saved = args[field], *text;
                        sd_json_variant *record;
                        int fd;

                        if (kind == 1)
                                assert(mkdir(path, 0700) == 0);
                        else if (kind == 2)
                                assert(mkfifo(path, 0600) == 0);
                        else if (kind == 3)
                                write_file(path, "{}\0", 3);
                        else if (kind == 4)
                                write_file(path, "", 0);
                        else if (kind == 5) {
                                fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                                assert(fd >= 0);
                                assert(ftruncate(fd, (field == 3 ? ATTESTATION_TOKEN_SIZE_MAX : ATTESTATION_REFERENCE_SIZE_MAX) + 1) == 0);
                                assert(close(fd) == 0);
                        } else if (kind == 6)
                                write_file(path, "{}{}", 4);
                        assert(snprintf(option, sizeof option, "--%s=%s", field == 3 ? "token" : "reference", path) > 0);
                        args[field] = option;
                        write_record(f, false, true);
                        reject(f, "request-complete", args);
                        text = read_file(f->record);
                        record = parse(text);
                        assert(sd_json_variant_is_null(sd_json_variant_by_key(record, "request")));
                        assert(juint(record, "generation") == 2);
                        sd_json_variant_unref(record);
                        free(text);
                        args[field] = saved;
                        reject(f, "request-complete", args);
                        if (kind == 1)
                                assert(rmdir(path) == 0);
                        else if (kind != 0)
                                assert(unlink(path) == 0);
                }
}

static void test_request_expiry(Fixture *f) {
        char *args[] = { f->id, f->state_option, (char *) "--request-id=" CHALLENGE,
                        f->token_option, f->reference_option, (char *) "--phase=" PHASE,
                        (char *) "--allow-root-declared-authentication", NULL };

        for (unsigned mode = REQUEST_CLOCK_APPRAISED; mode <= REQUEST_CLOCK_BEFORE_DEADLINE; mode++) {
                sd_json_variant *v, *record;
                char *text;

                request_clock = mode;
                fixed_boottime_usec = UINT64_C(100000000);
                request_deadline_usec = fixed_boottime_usec + 600000000;
                write_record(f, false, true);
                v = run(f, "request-complete", args, mode == REQUEST_CLOCK_BEFORE_DEADLINE);
                if (v)
                        assert(jbool(v, "singleUseChallengeConsumed") && jbool(v, "authenticationDeclarationMatched"));
                sd_json_variant_unref(v);
                request_clock = REQUEST_CLOCK_NONE;
                fixed_boottime_usec = 0;
                text = read_file(f->record);
                record = parse(text);
                assert(sd_json_variant_is_null(sd_json_variant_by_key(record, "request")));
                assert(juint(record, "generation") == 2);
                sd_json_variant_unref(record);
                reject(f, "request-complete", args);
                unchanged(f, text);
                free(text);
        }
}

static void test_request_cancel(Fixture *f) {
        char *cancel_args[] = { f->id, f->state_option, (char *) "--request-id=" CHALLENGE, NULL };
        char *begin_args[] = { f->id, f->state_option, f->request_option, (char *) "--lifetime=600", NULL };
        char *complete_args[] = { f->id, f->state_option, (char *) "--request-id=" CHALLENGE,
                                  f->token_option, f->reference_option, (char *) "--phase=" PHASE,
                                  (char *) "--allow-root-declared-authentication", NULL };
        char *status_args[] = { f->id, f->state_option, NULL };
        char option[sizeof "--request-id=" CHALLENGE], *before;
        sd_json_variant *v;

        write_record(f, false, true);
        test_options(f, "request-cancel", cancel_args);
        before = read_file(f->record);
        cancel_args[2] = (char *) "--request-id=" OPERATION;
        reject(f, "request-cancel", cancel_args);
        cancel_args[2] = (char *) "--request-id=invalid";
        reject(f, "request-cancel", cancel_args);
        unchanged(f, before);
        free(before);

        cancel_args[2] = (char *) "--request-id=" CHALLENGE;
        assert(!run(f, "request-cancel", cancel_args, true));
        before = read_file(f->record);
        v = parse(before);
        assert(juint(v, "generation") == 2);
        assert(sd_json_variant_is_null(sd_json_variant_by_key(v, "request")));
        sd_json_variant_unref(v);
        assert(!run(f, "request-cancel", cancel_args, true));
        reject(f, "request-complete", complete_args);
        unchanged(f, before);
        free(before);

        v = run(f, "request-begin", begin_args, true);
        assert(!streq(jstr(v, "requestId"), CHALLENGE));
        assert(snprintf(option, sizeof option, "--request-id=%s", jstr(v, "requestId")) == (int) sizeof option - 1);
        sd_json_variant_unref(v);
        before = read_file(f->record);
        reject(f, "request-cancel", cancel_args);
        reject(f, "request-complete", complete_args);
        unchanged(f, before);
        free(before);

        cancel_args[2] = option;
        assert(!run(f, "request-cancel", cancel_args, true));
        v = run(f, "enrollment-revoke", status_args, true);
        sd_json_variant_unref(v);
        before = read_file(f->record);
        reject(f, "request-cancel", cancel_args);
        unchanged(f, before);
        free(before);
}

static void test_missing_state(Fixture *f) {
        char option[PATH_MAX + 32];
        char *status_args[] = { f->id, option, NULL };
        char *request_args[] = { f->id, option, f->request_option, (char *) "--lifetime=600", NULL };
        char *begin_args[] = { NULL, f->ek_option, option, (char *) "--lifetime=600", NULL };
        char evidence[PATH_MAX];

        assert(snprintf(option, sizeof option, "--state-dir=%s/missing-state", f->directory) > 0);
        make_path(evidence, f, "evidence.json");
        begin_args[0] = evidence;
        reject(f, "enrollment-status", status_args);
        reject(f, "enrollment-revoke", status_args);
        reject(f, "request-begin", request_args);
        reject(f, "enrollment-begin", begin_args);
        write_record(f, false, false);
        test_options(f, "enrollment-begin", begin_args);
        status_args[1] = f->state_option;
        test_options(f, "enrollment-status", status_args);
        test_options(f, "enrollment-revoke", status_args);
        request_args[1] = f->state_option;
        test_options(f, "request-begin", request_args);
}

static void cleanup_directory(const char *path) {
        DIR *directory = opendir(path);
        struct dirent *entry;

        assert(directory);
        while ((entry = readdir(directory))) {
                struct stat st;
                char child[PATH_MAX];

                if (streq(entry->d_name, ".") || streq(entry->d_name, ".."))
                        continue;
                assert(fstatat(dirfd(directory), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0);
                if (S_ISDIR(st.st_mode)) {
                        assert(snprintf(child, sizeof child, "%s/%s", path, entry->d_name) > 0);
                        cleanup_directory(child);
                } else
                        assert(unlinkat(dirfd(directory), entry->d_name, 0) == 0);
        }
        assert(closedir(directory) == 0);
        assert(rmdir(path) == 0);
}

int main(int argc, char **argv) {
        Fixture f = { .directory = "/tmp/platformd-enrollment-cli.XXXXXX" };
        sd_json_variant *evidence = NULL;
        uint8_t bytes[512], digest[32], name[34];
        char path[PATH_MAX], *text = NULL;
        sd_id128_t id;
        pid_t pid;
        int status;
        size_t size;

        assert(argc == 2);
        assert(mkdtemp(f.directory));
        make_path(f.state, &f, "state");
        assert(mkdir(f.state, 0700) == 0);
        pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
                execl(argv[1], argv[1], "--write-context-fixture", f.directory, NULL);
                _exit(127);
        }
        while (waitpid(pid, &status, 0) < 0)
                assert(errno == EINTR);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        make_path(path, &f, "ak.hex");
        f.ak = read_file(path);
        size = decode(f.ak, bytes, sizeof bytes);
        hash(bytes, size, digest);
        encode(digest, sizeof digest, f.id);
        assert(attestation_key_name(f.ak, name) == 0);
        encode(name, sizeof name, f.name);
        size = decode(RESPONSE, bytes, sizeof bytes);
        hash(bytes, size, digest);
        encode(digest, sizeof digest, f.response_hash);
        assert(sd_id128_get_boot(&id) >= 0);
        sd_id128_to_string(id, f.boot);
        assert(snprintf(f.record, sizeof f.record, "%s/%s.json", f.state, f.id) > 0);
        assert(snprintf(f.state_option, sizeof f.state_option, "--state-dir=%s", f.state) > 0);
        assert(snprintf(f.response_option, sizeof f.response_option, "--response=%s/response", f.directory) > 0);
        assert(snprintf(f.token_option, sizeof f.token_option, "--token=%s/token.json", f.directory) > 0);
        assert(snprintf(f.reference_option, sizeof f.reference_option, "--reference=%s/reference.json", f.directory) > 0);
        assert(snprintf(f.request_option, sizeof f.request_option, "--request=%s/request.json", f.directory) > 0);
        assert(snprintf(f.ek_option, sizeof f.ek_option, "--endorsement-key=%s/ek.hex", f.directory) > 0);
        write_fixture(&f, "reference.json", "{\"sha256\":[{\"phase\":\"" PHASE "\",\"pcr\":11,\"hash\":\"" PCR11 "\"}]}");
        write_fixture(&f, "request.json", "{\"uid\":1000,\"sessionId\":\"fixture-session\",\"audience\":\"" AUDIENCE "\",\"operationDigestHex\":\"" OPERATION "\"}");
        write_fixture(&f, "ek.hex", EK);
        assert(sd_json_buildo(&evidence,
                SD_JSON_BUILD_PAIR_STRING("ekPublicHex", EK),
                SD_JSON_BUILD_PAIR_STRING("ekCertHex", ""),
                SD_JSON_BUILD_PAIR_STRING("akPublicHex", f.ak),
                SD_JSON_BUILD_PAIR_STRING("akNameHex", f.name),
                SD_JSON_BUILD_PAIR_STRING("evidenceQuality", "measured")) >= 0);
        assert(sd_json_variant_format(evidence, 0, &text) >= 0);
        write_fixture(&f, "evidence.json", text);
        free(text);
        sd_json_variant_unref(evidence);

        test_response(&f);
        test_lifetime(&f);
        test_requests(&f);
        test_request_expiry(&f);
        test_request_files(&f);
        test_request_cancel(&f);
        test_missing_state(&f);

        free(f.ak);
        cleanup_directory(f.directory);
        printf("Enrollment command-line checks passed: %u\n", checks);
        return 0;
}
