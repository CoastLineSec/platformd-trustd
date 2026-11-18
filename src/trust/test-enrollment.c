/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <systemd/sd-id128.h>

static ssize_t test_getrandom(void *buffer, size_t size, unsigned flags);
static int test_clock_gettime(clockid_t clock, struct timespec *ret);
static int test_boot_id(sd_id128_t *ret);
static int test_fsync(int fd);
static int test_renameat(int old_fd, const char *old_path, int new_fd, const char *new_path);
static ssize_t test_write(int fd, const void *buffer, size_t size);
static int test_execve(const char *path, char * const argv[], char * const envp[]);
static int test_fstat(int fd, struct stat *ret);

#define getrandom test_getrandom
#define clock_gettime test_clock_gettime
#define sd_id128_get_boot test_boot_id
#define fsync test_fsync
#define renameat test_renameat
#define write test_write
#define execve test_execve
#define fstat test_fstat
#include "enrollment.c"
#undef getrandom
#undef clock_gettime
#undef sd_id128_get_boot
#undef fsync
#undef renameat
#undef write
#undef execve
#undef fstat

static bool capture_response, change_boot, fail_clock, fail_rename, fail_write, short_write;
static uint8_t captured_response[32];
static int fail_sync, sync_count, helper_mode;
static int default_helper_mode;
static int crash_sync;
static bool wrong_file_owner;
static int64_t boottime_offset;
static uint64_t fixed_boottime_usec;
static unsigned assertions;

static ssize_t test_getrandom(void *buffer, size_t size, unsigned flags) {
        ssize_t r = getrandom(buffer, size, flags);

        if (capture_response && size == 32 && r == 32) {
                memcpy(captured_response, buffer, 32);
                capture_response = false;
        }
        return r;
}

static int test_clock_gettime(clockid_t clock, struct timespec *ret) {
        int r;

        if (fail_clock && clock != CLOCK_MONOTONIC) {
                errno = 0;
                return -1;
        }
        if (clock == CLOCK_BOOTTIME && fixed_boottime_usec > 0) {
                ret->tv_sec = (time_t) (fixed_boottime_usec / 1000000);
                ret->tv_nsec = (long) (fixed_boottime_usec % 1000000) * 1000;
                return 0;
        }
        r = clock_gettime(clock, ret);
        if (r == 0 && clock == CLOCK_BOOTTIME)
                ret->tv_sec += boottime_offset;
        return r;
}

static int test_boot_id(sd_id128_t *ret) {
        int r = sd_id128_get_boot(ret);

        if (r >= 0 && change_boot)
                ret->bytes[0] ^= 1;
        return r;
}

static int test_fsync(int fd) {
        if (crash_sync && sync_count + 1 == crash_sync)
                _exit(42);
        if (++sync_count == fail_sync) {
                errno = EIO;
                return -1;
        }
        return fsync(fd);
}

static int test_fstat(int fd, struct stat *ret) {
        int r = fstat(fd, ret);

        if (r == 0 && wrong_file_owner && S_ISREG(ret->st_mode))
                ret->st_uid = geteuid() == 0 ? 1 : 0;
        return r;
}

static int test_renameat(int old_fd, const char *old_path, int new_fd, const char *new_path) {
        if (fail_rename) {
                errno = EIO;
                return -1;
        }
        return renameat(old_fd, old_path, new_fd, new_path);
}

static ssize_t test_write(int fd, const void *buffer, size_t size) {
        struct stat st;

        assert(fstat(fd, &st) == 0);
        if (S_ISREG(st.st_mode) && st.st_nlink == 1) {
                if (fail_write) {
                        errno = EIO;
                        return -1;
                }
                if (short_write && size > 7)
                        size = 7;
        }
        return write(fd, buffer, size);
}

static int test_execve(const char *path, char * const argv[], char * const envp[]) {
        static const uint8_t credential[] = { 0xba, 0xdc, 0xc0, 0xde, 0, 0, 0, 1, 0, 1, 1, 0, 1, 2 };
        uint8_t response[33];

        assert(streq(path, TPM2_MAKECREDENTIAL_PATH));
        assert(streq(argv[1], "-T") && streq(argv[2], "none"));
        assert(streq(argv[3], "-u") && streq(argv[4], "/proc/self/fd/3"));
        assert(streq(argv[5], "-s") && streq(argv[6], "-"));
        assert(streq(argv[7], "-n") && strlen(argv[8]) == 68);
        assert(streq(argv[9], "-o") && streq(argv[10], "/proc/self/fd/4") && !argv[11]);
        assert(streq(envp[0], "PATH=/usr/bin:/bin") && streq(envp[1], "LC_ALL=C") && !envp[2]);
        if (helper_mode == 0)
                return execve(path, argv, envp);
        if (helper_mode == 1) {
                errno = ENOENT;
                return -1;
        }
        assert(read(STDIN_FILENO, response, sizeof response) == 32);
        assert(memcmp(response, captured_response, 32) == 0);
        explicit_bzero(response, sizeof response);
        if (helper_mode == 2)
                _exit(1);
        if (helper_mode == 3) {
                assert(write(4, credential, sizeof credential - 1) == sizeof credential - 1);
                _exit(0);
        }
        if (helper_mode == 4) {
                assert(write(4, credential, sizeof credential) == sizeof credential);
                assert(write(4, "x", 1) == 1);
                _exit(0);
        }
        if (helper_mode == 5)
                for (;;)
                        pause();
        if (helper_mode == 6) {
                assert(write(4, credential, sizeof credential) == sizeof credential);
                _exit(0);
        }
        _exit(2);
}

typedef struct TestIdentity {
        sd_json_variant *evidence;
        char ek[513], ak[513], name[69], id[65];
} TestIdentity;

typedef struct Buffer {
        uint8_t data[512];
        size_t size;
} Buffer;

static void put_number(Buffer *b, uint32_t value, size_t size) {
        assert(size <= 4 && b->size + size <= sizeof b->data);
        for (size_t i = size; i > 0; i--)
                b->data[b->size++] = (uint8_t) (value >> ((i - 1) * 8));
}

static void put_bytes(Buffer *b, const void *data, size_t size) {
        assert(b->size + size <= sizeof b->data);
        memcpy(b->data + b->size, data, size);
        b->size += size;
}

static void public_make(bool endorsement, char ret[static 513]) {
        EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        uint8_t point[65], policy[32];
        size_t size = sizeof point;
        Buffer b = {};

        assert(key);
        assert(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point, &size) == 1);
        assert(size == sizeof point);
        put_number(&b, 0, 2);
        put_number(&b, 0x23, 2);
        put_number(&b, 0x0b, 2);
        put_number(&b, endorsement ? 0x300b2 : 0x50072, 4);
        put_number(&b, endorsement ? 32 : 0, 2);
        if (endorsement) {
                assert(hex_decode("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa",
                                  policy, sizeof policy) == sizeof policy);
                put_bytes(&b, policy, sizeof policy);
                put_number(&b, 6, 2);
                put_number(&b, 128, 2);
                put_number(&b, 0x43, 2);
                put_number(&b, 0x10, 2);
        } else {
                put_number(&b, 0x10, 2);
                put_number(&b, 0x18, 2);
                put_number(&b, 0x0b, 2);
        }
        put_number(&b, 3, 2);
        put_number(&b, 0x10, 2);
        put_number(&b, 32, 2);
        put_bytes(&b, point + 1, 32);
        put_number(&b, 32, 2);
        put_bytes(&b, point + 33, 32);
        b.data[0] = (uint8_t) ((b.size - 2) >> 8);
        b.data[1] = (uint8_t) (b.size - 2);
        hex_encode(b.data, b.size, ret);
        EVP_PKEY_free(key);
}

static TestIdentity identity_make(void) {
        TestIdentity identity = {};
        uint8_t data[256], hash[32], name[34] = { 0, 0x0b };
        int size;

        public_make(true, identity.ek);
        public_make(false, identity.ak);
        size = hex_decode(identity.ak, data, sizeof data);
        assert(size > 2);
        assert(digest(data + 2, (size_t) size - 2, name + 2) == 0);
        assert(digest(data, (size_t) size, hash) == 0);
        hex_encode(name, sizeof name, identity.name);
        hex_encode(hash, sizeof hash, identity.id);
        assert(sd_json_buildo(&identity.evidence,
                              SD_JSON_BUILD_PAIR_STRING("ekPublicHex", identity.ek),
                              SD_JSON_BUILD_PAIR_STRING("ekCertHex", ""),
                              SD_JSON_BUILD_PAIR_STRING("akPublicHex", identity.ak),
                              SD_JSON_BUILD_PAIR_STRING("akNameHex", identity.name),
                              SD_JSON_BUILD_PAIR_STRING("evidenceQuality", "measured")) >= 0);
        return identity;
}

static char *directory_make(void) {
        char *path = strdup("/tmp/platformd-enrollment-test.XXXXXX");

        assert(path && mkdtemp(path));
        assert(chmod(path, 0700) == 0);
        return path;
}

static void directory_remove(char *path) {
        DIR *directory = opendir(path);
        struct dirent *entry;

        assert(directory);
        while ((entry = readdir(directory)))
                if (!streq(entry->d_name, ".") && !streq(entry->d_name, ".."))
                        assert(unlinkat(dirfd(directory), entry->d_name, 0) == 0);
        closedir(directory);
        assert(rmdir(path) == 0);
        free(path);
}

static sd_json_variant *begin(const char *directory, TestIdentity *identity) {
        sd_json_variant *challenge = NULL;

        capture_response = true;
        assert(enrollment_begin(directory, identity->evidence, identity->ek, 60, &challenge) == 0);
        assert(challenge);
        assert(streq(string_field(challenge, "format"), "io.platformd.Trust.EnrollmentChallenge.v1"));
        assert(streq(string_field(challenge, "keyId"), identity->id));
        assert(!sd_json_variant_by_key(challenge, "responseSha256"));
        assert(!sd_json_variant_by_key(challenge, "responseHex"));
        assertions++;
        return challenge;
}

static void response_text(char ret[static 65]) {
        hex_encode(captured_response, sizeof captured_response, ret);
}

static void assert_state(const char *directory, const char *id, const char *state) {
        sd_json_variant *status = NULL;

        assert(enrollment_status(directory, id, &status) >= 0);
        assert(streq(string_field(status, "state"), state));
        assert(!sd_json_variant_by_key(status, "pending"));
        assert(!sd_json_variant_by_key(status, "responseSha256"));
        assert(!sd_json_variant_by_key(status, "requestId"));
        sd_json_variant_unref(status);
        assertions++;
}

static void test_lifecycle(TestIdentity *identity) {
        char *directory = directory_make(), response[65];
        sd_json_variant *challenge, *status = NULL, *other = NULL;
        Enrollment *handle = NULL;

        assert(enrollment_status(directory, identity->id, &status) == -ENOENT);
        challenge = begin(directory, identity);
        response_text(response);
        assert_state(directory, identity->id, "pending");
        assert(enrollment_acquire(directory, identity->id, &handle) == -ENOKEY && !handle);
        assert(enrollment_begin(directory, identity->evidence, identity->ek, 60, &other) == -EALREADY && !other);
        assert(enrollment_complete(directory, identity->id,
                                   "0000000000000000000000000000000000000000000000000000000000000000",
                                   response, &status) == -ESTALE && !status);
        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == 0);
        assert(streq(string_field(status, "state"), "active"));
        sd_json_variant_unref(status);
        status = NULL;
        assert_state(directory, identity->id, "active");
        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == -EALREADY);
        assert(enrollment_begin(directory, identity->evidence, identity->ek, 60, &other) == -EEXIST);
        assert(enrollment_acquire(directory, identity->id, &handle) == 0);
        assert(streq(enrollment_attestation_key(handle), identity->ak));
        assert(enrollment_revoke(directory, identity->id, &status) == -EBUSY && !status);
        enrollment_release(handle);
        assert(enrollment_revoke(directory, identity->id, &status) == 0);
        sd_json_variant_unref(status);
        status = NULL;
        assert_state(directory, identity->id, "revoked");
        assert(enrollment_acquire(directory, identity->id, &handle) == -EKEYREVOKED && !handle);
        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == -EKEYREVOKED);
        assert(enrollment_begin(directory, identity->evidence, identity->ek, 60, &other) == -EKEYREVOKED);
        assert(enrollment_revoke(directory, identity->id, &status) >= 0);
        sd_json_variant_unref(status);
        sd_json_variant_unref(challenge);
        directory_remove(directory);
        assertions += 14;
}

static void test_consumption(TestIdentity *identity) {
        static const char * const wrong[] = { "", "00", "zz", "0000000000000000000000000000000000000000000000000000000000000000" };

        for (size_t i = 0; i < ELEMENTSOF(wrong) + 3; i++) {
                char *directory = directory_make(), response[65];
                sd_json_variant *challenge = begin(directory, identity), *status = NULL;
                int expected = -EKEYREJECTED;

                response_text(response);
                if (i == ELEMENTSOF(wrong)) {
                        boottime_offset = 61;
                        expected = -ETIMEDOUT;
                } else if (i == ELEMENTSOF(wrong) + 1) {
                        change_boot = true;
                        expected = -ETIMEDOUT;
                } else if (i == ELEMENTSOF(wrong) + 2) {
                        boottime_offset = -1;
                        expected = -ETIMEDOUT;
                }
                assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"),
                                           i < ELEMENTSOF(wrong) ? wrong[i] : response, &status) == expected && !status);
                boottime_offset = 0;
                change_boot = false;
                assert_state(directory, identity->id, "inactive");
                assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == -EALREADY);
                sd_json_variant_unref(challenge);
                challenge = begin(directory, identity);
                response_text(response);
                assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == 0);
                sd_json_variant_unref(status);
                sd_json_variant_unref(challenge);
                directory_remove(directory);
                assertions += 3;
        }
}

static void test_expired_replacement(TestIdentity *identity) {
        char *directory = directory_make(), response[65];
        sd_json_variant *old = begin(directory, identity), *new, *status = NULL;

        boottime_offset = 61;
        new = begin(directory, identity);
        response_text(response);
        assert(enrollment_complete(directory, identity->id, string_field(old, "requestId"), response, &status) == -ESTALE);
        assert(enrollment_complete(directory, identity->id, string_field(new, "requestId"), response, &status) == 0);
        boottime_offset = 0;
        sd_json_variant_unref(old);
        sd_json_variant_unref(new);
        sd_json_variant_unref(status);
        directory_remove(directory);
        assertions += 2;
}

static void test_bad_evidence(TestIdentity *identity) {
        char *directory = directory_make();
        TestIdentity other = identity_make();
        sd_json_variant *result = NULL, *bad = NULL;
        uint8_t bytes[256];
        char corrupt[513];
        int n;

        assert(enrollment_begin(directory, identity->evidence, other.ek, 60, &result) == -EKEYREJECTED && !result);
        assert(enrollment_begin(directory, identity->evidence, identity->ek, 0, &result) == -EINVAL);
        assert(enrollment_begin(directory, identity->evidence, identity->ek, 601, &result) == -EINVAL);
        assert(enrollment_begin(directory, identity->evidence, NULL, 60, &result) < 0);
        bad = sd_json_variant_ref(identity->evidence);
        assert(sd_json_variant_set_field_string(&bad, "akNameHex", other.name) >= 0);
        assert(enrollment_begin(directory, bad, identity->ek, 60, &result) == -EKEYREJECTED);
        sd_json_variant_unref(bad);
        bad = sd_json_variant_ref(identity->evidence);
        assert(sd_json_variant_set_field_string(&bad, "unknown", "x") >= 0);
        assert(enrollment_begin(directory, bad, identity->ek, 60, &result) == -EBADMSG);
        sd_json_variant_unref(bad);
        bad = sd_json_variant_ref(identity->evidence);
        n = hex_decode(identity->ek, bytes, sizeof bytes);
        assert(n > 10);
        bytes[9] ^= 1;
        hex_encode(bytes, (size_t) n, corrupt);
        assert(sd_json_variant_set_field_string(&bad, "ekPublicHex", corrupt) >= 0);
        assert(enrollment_begin(directory, bad, corrupt, 60, &result) == -EBADMSG);
        sd_json_variant_unref(bad);
        bad = sd_json_variant_ref(identity->evidence);
        n = hex_decode(identity->ak, bytes, sizeof bytes);
        assert(n > 10);
        bytes[9] ^= 1;
        hex_encode(bytes, (size_t) n, corrupt);
        assert(sd_json_variant_set_field_string(&bad, "akPublicHex", corrupt) >= 0);
        assert(enrollment_begin(directory, bad, identity->ek, 60, &result) < 0);
        sd_json_variant_unref(bad);
        sd_json_variant_unref(other.evidence);
        directory_remove(directory);
        assertions += 8;
}

static void test_files(TestIdentity *identity) {
        char *directory = directory_make(), *link_directory = directory_make();
        char filename[PATH_MAX], linkname[PATH_MAX];
        sd_json_variant *challenge = begin(directory, identity), *status = NULL;
        Enrollment *e = NULL;
        int fd;

        snprintf(filename, sizeof filename, "%s/%s.json", directory, identity->id);
        assert(chmod(filename, 0644) == 0);
        assert(enrollment_status(directory, identity->id, &status) == -EPERM);
        assert(chmod(filename, 0600) == 0);
        wrong_file_owner = true;
        assert(enrollment_status(directory, identity->id, &status) == -EPERM);
        wrong_file_owner = false;
        snprintf(linkname, sizeof linkname, "%s/link", link_directory);
        assert(link(filename, linkname) == 0);
        assert(enrollment_status(directory, identity->id, &status) == -EPERM);
        assert(unlink(linkname) == 0);
        assert(rename(filename, linkname) == 0);
        assert(symlink(linkname, filename) == 0);
        assert(enrollment_status(directory, identity->id, &status) < 0);
        assert(unlink(filename) == 0);
        assert(rename(linkname, filename) == 0);
        assert(chmod(directory, 0755) == 0);
        assert(enrollment_status(directory, identity->id, &status) == -EPERM);
        assert(chmod(directory, 0700) == 0);
        assert(symlink(directory, linkname) == 0);
        assert(enrollment_status(linkname, identity->id, &status) < 0);
        assert(unlink(linkname) == 0);
        assert(enrollment_status(directory, "../invalid", &status) == -EINVAL);
        assert(enrollment_open(directory, true, &e) == 0);
        assert(enrollment_status(directory, identity->id, &status) == -EBUSY);
        enrollment_release(e);
        fd = open(filename, O_WRONLY | O_TRUNC | O_CLOEXEC);
        assert(fd >= 0);
        assert(write(fd, "{\"format\":\"x\",\"format\":\"y\"}", 27) == 27);
        close(fd);
        assert(enrollment_status(directory, identity->id, &status) < 0);
        sd_json_variant_unref(challenge);
        directory_remove(directory);
        directory_remove(link_directory);
        assertions += 8;
}

static void test_failures(TestIdentity *identity) {
        for (int fault = 0; fault < 7; fault++) {
                char *directory = directory_make(), response[65];
                sd_json_variant *challenge = begin(directory, identity), *status = NULL;
                Enrollment *handle = NULL;

                response_text(response);
                sync_count = 0;
                if (fault == 0)
                        fail_write = true;
                else if (fault == 1)
                        fail_sync = 1;
                else if (fault == 2)
                        fail_rename = true;
                else if (fault == 3)
                        fail_sync = 2;
                else if (fault == 4)
                        fail_clock = true;
                else if (fault == 5)
                        short_write = true;
                else
                        fail_sync = 1;
                if (fault == 6)
                        assert(enrollment_revoke(directory, identity->id, &status) == -EIO && !status);
                else if (fault == 5) {
                        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == 0);
                        sd_json_variant_unref(status);
                        status = NULL;
                } else
                        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == -EIO && !status);
                fail_write = fail_rename = fail_clock = short_write = false;
                fail_sync = 0;
                if (fault == 3 || fault == 5) {
                        assert_state(directory, identity->id, "active");
                        assert(enrollment_acquire(directory, identity->id, &handle) == 0);
                        enrollment_release(handle);
                } else
                        assert_state(directory, identity->id, "pending");
                sd_json_variant_unref(challenge);
                directory_remove(directory);
                assertions++;
        }
}

static void test_helpers(TestIdentity *identity) {
        for (int mode = 1; mode <= 5; mode++) {
                char *directory = directory_make();
                sd_json_variant *result = NULL;
                int expected = mode == 1 ? -ENOENT : mode == 2 ? -EIO : mode == 5 ? -ETIMEDOUT : -EBADMSG;

                helper_mode = mode;
                capture_response = true;
                assert(enrollment_begin(directory, identity->evidence, identity->ek, 60, &result) == expected && !result);
                assert(enrollment_status(directory, identity->id, &result) == -ENOENT && !result);
                helper_mode = default_helper_mode;
                directory_remove(directory);
                assertions += 2;
        }
}

static void test_concurrency(TestIdentity *identity) {
        for (int revoke = 0; revoke < 2; revoke++) {
                char *directory = directory_make(), response[65];
                sd_json_variant *challenge = begin(directory, identity), *status = NULL;
                pid_t children[2];
                int gate[2], successes = 0;

                response_text(response);
                assert(pipe(gate) == 0);
                for (int i = 0; i < 2; i++) {
                        children[i] = fork();
                        assert(children[i] >= 0);
                        if (children[i] == 0) {
                                char byte;
                                int r;

                                close(gate[1]);
                                assert(read(gate[0], &byte, 1) == 1);
                                close(gate[0]);
                                if (revoke && i == 1)
                                        r = enrollment_revoke(directory, identity->id, &status);
                                else
                                        r = enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status);
                                sd_json_variant_unref(status);
                                _exit(r == 0 ? 0 : r == -EBUSY || r == -EALREADY || r == -EKEYREVOKED ? 1 : 2);
                        }
                }
                close(gate[0]);
                assert(write(gate[1], "xx", 2) == 2);
                close(gate[1]);
                for (int i = 0; i < 2; i++) {
                        int child_status;

                        assert(waitpid(children[i], &child_status, 0) == children[i]);
                        assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) <= 1);
                        successes += WEXITSTATUS(child_status) == 0;
                }
                assert(successes >= 1 && (revoke || successes == 1));
                assert(enrollment_status(directory, identity->id, &status) >= 0);
                assert(streq(string_field(status, "state"), "active") ||
                       (revoke && streq(string_field(status, "state"), "revoked")));
                sd_json_variant_unref(status);
                sd_json_variant_unref(challenge);
                directory_remove(directory);
                assertions += 2;
        }
}

static void activate(const char *directory, TestIdentity *identity) {
        sd_json_variant *challenge = begin(directory, identity), *status = NULL;
        char response[65];

        response_text(response);
        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == 0);
        sd_json_variant_unref(status);
        sd_json_variant_unref(challenge);
}

static sd_json_variant *context_make(void) {
        sd_json_variant *context = NULL;

        assert(sd_json_buildo(&context,
                              SD_JSON_BUILD_PAIR_STRING("audience", "service.example"),
                              SD_JSON_BUILD_PAIR_STRING("operationDigestHex", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                              SD_JSON_BUILD_PAIR_UNSIGNED("uid", 1000),
                              SD_JSON_BUILD_PAIR_STRING("sessionId", "c42")) >= 0);
        return context;
}

static void test_requests(TestIdentity *identity) {
        char *directory = directory_make();
        sd_json_variant *context = context_make(), *request = NULL, *inner = NULL, *result = NULL;
        Enrollment *e = NULL;
        const char *id;

        assert(enrollment_request_begin(directory, identity->id, context, 60, &request) == -ENOENT);
        activate(directory, identity);
        assert(enrollment_request_begin(directory, identity->id, context, 60, &request) == 0);
        assert(streq(string_field(request, "format"), "io.platformd.Trust.AuthenticationRequest.v1"));
        id = string_field(request, "requestId");
        assert(identifier_valid(id, 64));
        assert(streq(id, string_field(sd_json_variant_by_key(sd_json_variant_by_key(request, "request"), "context"), "challengeHex")));
        assert(enrollment_request_begin(directory, identity->id, context, 60, &result) == -EALREADY && !result);
        assert(enrollment_request_consume(directory, identity->id,
                                          "0000000000000000000000000000000000000000000000000000000000000000",
                                          &e, &inner) == -ESTALE && !e && !inner);
        assert(enrollment_request_consume(directory, identity->id, id, &e, &inner) == 0);
        assert(sd_json_variant_equal(inner, sd_json_variant_by_key(request, "request")));
        assert(streq(enrollment_attestation_key(e), identity->ak));
        assert(enrollment_revoke(directory, identity->id, &result) == -EBUSY);
        assert(attestation_verify(NULL, enrollment_attestation_key(e), id, &result) < 0 && !result);
        enrollment_release(e);
        e = NULL;
        sd_json_variant_unref(inner);
        inner = NULL;
        assert(enrollment_request_consume(directory, identity->id, id, &e, &inner) == -ENODATA && !e && !inner);
        sd_json_variant_unref(request);
        request = NULL;
        assert(enrollment_request_begin(directory, identity->id, context, 60, &request) == 0);
        assert(enrollment_revoke(directory, identity->id, &result) == 0);
        sd_json_variant_unref(result);
        result = NULL;
        assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -EKEYREVOKED);
        assert(enrollment_request_begin(directory, identity->id, context, 60, &result) == -EKEYREVOKED);
        sd_json_variant_unref(context);
        sd_json_variant_unref(request);
        directory_remove(directory);
        assertions += 14;
}

static void test_request_expiry(TestIdentity *identity) {
        for (int mode = 0; mode < 4; mode++) {
                char *directory = directory_make();
                sd_json_variant *context = context_make(), *request = NULL, *new = NULL, *inner = NULL;
                Enrollment *e = NULL;

                activate(directory, identity);
                assert(enrollment_request_begin(directory, identity->id, context, 1, &request) == 0);
                if (mode == 0 || mode == 3)
                        boottime_offset = 2;
                else if (mode == 1)
                        change_boot = true;
                else
                        boottime_offset = -1;
                if (mode == 3) {
                        assert(enrollment_request_begin(directory, identity->id, context, 60, &new) == 0);
                        assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -ESTALE);
                        assert(enrollment_request_consume(directory, identity->id, string_field(new, "requestId"), &e, &inner) == 0);
                        enrollment_release(e);
                        sd_json_variant_unref(inner);
                        inner = NULL;
                        sd_json_variant_unref(new);
                } else {
                        assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -ETIMEDOUT);
                        assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -ENODATA);
                }
                boottime_offset = 0;
                change_boot = false;
                sd_json_variant_unref(request);
                sd_json_variant_unref(context);
                directory_remove(directory);
                assertions += 3;
        }
}

static void test_request_failures(TestIdentity *identity) {
        char *directory = directory_make();
        sd_json_variant *context = context_make(), *request = NULL, *bad = NULL, *inner = NULL;
        Enrollment *e = NULL;

        activate(directory, identity);
        assert(enrollment_request_begin(directory, identity->id, context, 0, &request) == -EINVAL);
        assert(enrollment_request_begin(directory, identity->id, context, 601, &request) == -EINVAL);
        bad = sd_json_variant_ref(context);
        assert(sd_json_variant_set_field_unsigned(&bad, "uid", UINT32_MAX) >= 0);
        assert(enrollment_request_begin(directory, identity->id, bad, 60, &request) == -EINVAL);
        sd_json_variant_unref(bad);
        bad = sd_json_variant_ref(context);
        assert(sd_json_variant_set_field_string(&bad, "audience", "invalid\n") >= 0);
        assert(enrollment_request_begin(directory, identity->id, bad, 60, &request) == -EINVAL);
        sd_json_variant_unref(bad);
        bad = sd_json_variant_ref(context);
        assert(sd_json_variant_set_field_string(&bad, "operationDigestHex", "A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") >= 0);
        assert(enrollment_request_begin(directory, identity->id, bad, 60, &request) == -EINVAL);
        sd_json_variant_unref(bad);
        for (int fault = 0; fault < 4; fault++) {
                sync_count = 0;
                fail_write = fault == 0;
                fail_rename = fault == 1;
                fail_sync = fault == 2 ? 1 : 0;
                fail_clock = fault == 3;
                assert(enrollment_request_begin(directory, identity->id, context, 60, &request) == -EIO && !request);
                fail_write = fail_rename = fail_clock = false;
                fail_sync = 0;
        }
        assert(enrollment_request_begin(directory, identity->id, context, 60, &request) == 0);
        for (int fault = 0; fault < 4; fault++) {
                sync_count = 0;
                fail_write = fault == 0;
                fail_rename = fault == 1;
                fail_sync = fault == 2 ? 1 : 0;
                fail_clock = fault == 3;
                assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -EIO && !e && !inner);
                fail_write = fail_rename = fail_clock = false;
                fail_sync = 0;
        }
        sync_count = 0;
        fail_sync = 2;
        assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -EIO && !e && !inner);
        fail_sync = 0;
        assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == -ENODATA);
        sd_json_variant_unref(request);
        sd_json_variant_unref(context);
        directory_remove(directory);
        assertions += 16;
}

static void test_consumed_request_expiry(TestIdentity *identity) {
        const uint64_t created = UINT64_C(100000000);

        assert(enrollment_request_validate(NULL) == -EINVAL);
        assertions++;
        for (unsigned fault = 0; fault < 5; fault++) {
                char *directory = directory_make();
                sd_json_variant *context = context_make(), *request = NULL, *inner = NULL;
                Enrollment *e = NULL;
                const char *id;

                activate(directory, identity);
                assert(enrollment_acquire(directory, identity->id, &e) == 0);
                assert(enrollment_request_validate(e) == -EINVAL);
                enrollment_release(e);
                e = NULL;
                fixed_boottime_usec = created;
                assert(enrollment_request_begin(directory, identity->id, context, 1, &request) == 0);
                id = string_field(request, "requestId");
                assert(enrollment_request_consume(directory, identity->id, id, &e, &inner) == 0);
                assert(enrollment_request_validate(e) == 0);
                fixed_boottime_usec = created + 1000000 - 1;
                assert(enrollment_request_validate(e) == 0);
                if (fault == 0)
                        fixed_boottime_usec++;
                else if (fault == 1)
                        fixed_boottime_usec += 2;
                else if (fault == 2)
                        fixed_boottime_usec = created - 1;
                else if (fault == 3)
                        change_boot = true;
                else
                        fail_clock = true;
                assert(enrollment_request_validate(e) == (fault == 4 ? -EIO : -ETIMEDOUT));
                enrollment_release(e);
                e = NULL;
                inner = sd_json_variant_unref(inner);
                change_boot = fail_clock = false;
                fixed_boottime_usec = created;
                assert(enrollment_request_consume(directory, identity->id, id, &e, &inner) == -ENODATA && !e && !inner);
                request = sd_json_variant_unref(request);
                assert(enrollment_request_begin(directory, identity->id, context, 1, &request) == 0);
                assert(enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &inner) == 0);
                assert(enrollment_request_validate(e) == 0);
                enrollment_release(e);
                sd_json_variant_unref(inner);
                sd_json_variant_unref(request);
                sd_json_variant_unref(context);
                fixed_boottime_usec = 0;
                directory_remove(directory);
                assertions += 11;
        }
}

static void test_request_concurrency(TestIdentity *identity) {
        for (int mode = 0; mode < 3; mode++) {
                char *directory = directory_make();
                sd_json_variant *context = context_make(), *request = NULL;
                int gate[2], successes = 0;
                pid_t children[2];

                activate(directory, identity);
                if (mode != 0)
                        assert(enrollment_request_begin(directory, identity->id, context, 60, &request) == 0);
                assert(pipe(gate) == 0);
                for (int i = 0; i < 2; i++) {
                        children[i] = fork();
                        assert(children[i] >= 0);
                        if (children[i] == 0) {
                                Enrollment *e = NULL;
                                sd_json_variant *result = NULL;
                                char byte;
                                int r;

                                close(gate[1]);
                                assert(read(gate[0], &byte, 1) == 1);
                                close(gate[0]);
                                if (mode == 0)
                                        r = enrollment_request_begin(directory, identity->id, context, 60, &result);
                                else if (mode == 2 && i == 1)
                                        r = enrollment_revoke(directory, identity->id, &result);
                                else
                                        r = enrollment_request_consume(directory, identity->id, string_field(request, "requestId"), &e, &result);
                                enrollment_release(e);
                                sd_json_variant_unref(result);
                                _exit(r == 0 ? 0 : r == -EBUSY || r == -ENODATA || r == -EALREADY || r == -EKEYREVOKED ? 1 : 2);
                        }
                }
                close(gate[0]);
                assert(write(gate[1], "xx", 2) == 2);
                close(gate[1]);
                for (int i = 0; i < 2; i++) {
                        int status;

                        assert(waitpid(children[i], &status, 0) == children[i]);
                        assert(WIFEXITED(status) && WEXITSTATUS(status) <= 1);
                        successes += WEXITSTATUS(status) == 0;
                }
                assert(successes >= 1 && (mode == 2 || successes == 1));
                sd_json_variant_unref(context);
                sd_json_variant_unref(request);
                directory_remove(directory);
                assertions++;
        }
}

static void test_crash_commit(TestIdentity *identity) {
        for (int at_sync = 1; at_sync <= 2; at_sync++) {
                char *directory = directory_make(), response[65];
                sd_json_variant *challenge = begin(directory, identity), *status = NULL;
                int child_status;
                pid_t child;

                response_text(response);
                child = fork();
                assert(child >= 0);
                if (child == 0) {
                        sync_count = 0;
                        crash_sync = at_sync;
                        (void) enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status);
                        _exit(1);
                }
                assert(waitpid(child, &child_status, 0) == child);
                assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 42);
                assert_state(directory, identity->id, at_sync == 1 ? "pending" : "active");
                if (at_sync == 1) {
                        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == 0);
                        sd_json_variant_unref(status);
                } else {
                        Enrollment *e = NULL;

                        assert(enrollment_acquire(directory, identity->id, &e) == 0);
                        enrollment_release(e);
                        assert(enrollment_complete(directory, identity->id, string_field(challenge, "requestId"), response, &status) == -EALREADY);
                }
                sd_json_variant_unref(challenge);
                directory_remove(directory);
                assertions += 2;
        }
}

static void test_restrictive_umask(TestIdentity *identity) {
        char *directory = directory_make(), path[PATH_MAX];
        sd_json_variant *challenge, *status = NULL;
        mode_t previous = umask(0777);
        struct stat st;

        challenge = begin(directory, identity);
        umask(previous);
        snprintf(path, sizeof path, "%s/.lock", directory);
        assert(stat(path, &st) == 0 && (st.st_mode & 07777) == 0600);
        assert(chmod(path, 0644) == 0);
        assert(enrollment_status(directory, identity->id, &status) == -EPERM);
        assert(stat(path, &st) == 0 && (st.st_mode & 07777) == 0644);
        sd_json_variant_unref(challenge);
        directory_remove(directory);
        assertions += 3;
}

int main(void) {
        TestIdentity identity;

        if (access(TPM2_MAKECREDENTIAL_PATH, X_OK) < 0)
                default_helper_mode = helper_mode = 6;
        umask(0077);
        identity = identity_make();
        test_bad_evidence(&identity);
        test_lifecycle(&identity);
        test_consumption(&identity);
        test_expired_replacement(&identity);
        test_files(&identity);
        test_failures(&identity);
        test_concurrency(&identity);
        test_requests(&identity);
        test_request_expiry(&identity);
        test_request_failures(&identity);
        test_consumed_request_expiry(&identity);
        test_request_concurrency(&identity);
        test_crash_commit(&identity);
        test_restrictive_umask(&identity);
        test_helpers(&identity);
        sd_json_variant_unref(identity.evidence);
        explicit_bzero(captured_response, sizeof captured_response);
        printf("Enrollment checks passed: %u; external credential helper: %s\n", assertions,
               default_helper_mode == 0 ? "tested" : "unavailable");
        return 0;
}
