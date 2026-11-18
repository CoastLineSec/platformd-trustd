/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "enrollment.h"
#include "attestation-verify.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/pidfd.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <systemd/sd-id128.h>

#ifndef TPM2_MAKECREDENTIAL_PATH
#define TPM2_MAKECREDENTIAL_PATH "/usr/bin/tpm2_makecredential"
#endif

#define ELEMENTSOF(x) (sizeof(x) / sizeof((x)[0]))
#define RECORD_SIZE_MAX 16384U
#define PUBLIC_SIZE_MAX 256U
#define HELPER_TIMEOUT_USEC (10U * 1000000U)

typedef enum EnrollmentState {
        ENROLLMENT_INACTIVE,
        ENROLLMENT_PENDING,
        ENROLLMENT_ACTIVE,
        ENROLLMENT_REVOKED,
        _ENROLLMENT_STATE_MAX,
} EnrollmentState;

typedef struct AuthenticationRequest {
        char id[65];
        char boot_id[SD_ID128_STRING_MAX];
        char audience[257];
        char operation_digest[65];
        char session[257];
        uint64_t uid;
        uint64_t created_usec;
        uint64_t deadline_usec;
} AuthenticationRequest;

typedef struct EnrollmentRecord {
        char key_id[65];
        char ek[PUBLIC_SIZE_MAX * 2 + 1];
        char ak[PUBLIC_SIZE_MAX * 2 + 1];
        char name[69];
        EnrollmentState state;
        uint64_t generation;
        uint64_t enrolled_usec;
        uint64_t revoked_usec;
        char request_id[65];
        char boot_id[SD_ID128_STRING_MAX];
        char response_hash[65];
        uint64_t created_usec;
        uint64_t deadline_usec;
        AuthenticationRequest request;
} EnrollmentRecord;

struct Enrollment {
        int directory_fd;
        int lock_fd;
        EnrollmentRecord record;
};

static const char * const state_names[] = { "inactive", "pending", "active", "revoked" };

static int negative_errno(void) {
        return errno > 0 ? -errno : -EIO;
}

static bool streq(const char *a, const char *b) {
        return a && b && strcmp(a, b) == 0;
}

static void hex_encode(const void *data, size_t size, char *ret) {
        static const char digits[] = "0123456789abcdef";
        const uint8_t *bytes = data;

        for (size_t i = 0; i < size; i++) {
                ret[i * 2] = digits[bytes[i] >> 4];
                ret[i * 2 + 1] = digits[bytes[i] & 15];
        }
        ret[size * 2] = 0;
}

static int unhex_char(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

static int hex_decode(const char *text, uint8_t *ret, size_t capacity) {
        size_t size;

        if (!text)
                return -EBADMSG;
        size = strnlen(text, capacity * 2 + 1);
        if (size > capacity * 2)
                return -E2BIG;
        if (size % 2)
                return -EBADMSG;
        for (size_t i = 0; i < size / 2; i++) {
                int a = unhex_char(text[i * 2]), b = unhex_char(text[i * 2 + 1]);

                if (a < 0 || b < 0)
                        return -EBADMSG;
                if (ret)
                        ret[i] = (uint8_t) ((a << 4) | b);
        }
        return (int) (size / 2);
}

static bool identifier_valid(const char *s, size_t size) {
        if (!s || strnlen(s, size + 1) != size)
                return false;
        for (size_t i = 0; i < size; i++)
                if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
                        return false;
        return true;
}

static int digest(const void *data, size_t size, uint8_t ret[32]) {
        return EVP_Q_digest(NULL, "SHA256", NULL, data, size, ret, NULL) == 1 ? 0 : -EIO;
}

static int random_bytes(void *ret, size_t size) {
        uint8_t *p = ret;

        while (size > 0) {
                ssize_t n = getrandom(p, size, 0);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return negative_errno();
                }
                if (n == 0)
                        return -EIO;
                p += n;
                size -= (size_t) n;
        }
        return 0;
}

static int response_allocate(uint8_t **ret) {
        uint8_t *response;
        int r;

        response = mmap(NULL, 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (response == MAP_FAILED)
                return negative_errno();
        if (mlock(response, 32) < 0 || madvise(response, 32, MADV_DONTDUMP) < 0 ||
            madvise(response, 32, MADV_WIPEONFORK) < 0) {
                r = negative_errno();
                munmap(response, 32);
                return r;
        }
        *ret = response;
        return 0;
}

static void response_free(uint8_t *response) {
        if (!response)
                return;
        explicit_bzero(response, 32);
        munmap(response, 32);
}

static int now_usec(clockid_t clock, uint64_t *ret) {
        struct timespec ts;

        if (clock_gettime(clock, &ts) < 0)
                return negative_errno();
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000 ||
            (uint64_t) ts.tv_sec > UINT64_MAX / 1000000 - 1)
                return -ERANGE;
        *ret = (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;
        return 0;
}

static int boot_id(char ret[static SD_ID128_STRING_MAX]) {
        sd_id128_t id;
        int r;

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;
        if (sd_id128_is_null(id))
                return -ENODATA;
        sd_id128_to_string(id, ret);
        return 0;
}

static const char *string_field(sd_json_variant *object, const char *field) {
        sd_json_variant *v = sd_json_variant_by_key(object, field);

        return sd_json_variant_is_string(v) ? sd_json_variant_string(v) : NULL;
}

static bool unsigned_field(sd_json_variant *object, const char *field, uint64_t *ret) {
        sd_json_variant *v = sd_json_variant_by_key(object, field);
        sd_json_variant_type_t type = sd_json_variant_type(v);

        if ((type != SD_JSON_VARIANT_UNSIGNED && type != SD_JSON_VARIANT_INTEGER) ||
            !sd_json_variant_is_unsigned(v))
                return false;
        *ret = sd_json_variant_unsigned(v);
        return true;
}

static bool printable(const char *s, size_t maximum) {
        if (!s || !*s || strnlen(s, maximum + 1) > maximum)
                return false;
        for (const unsigned char *p = (const unsigned char *) s; *p; p++)
                if (*p < 0x20 || *p > 0x7e)
                        return false;
        return true;
}

static bool object_fields(sd_json_variant *v, const char * const *fields, size_t count) {
        if (!sd_json_variant_is_object(v) || sd_json_variant_elements(v) != count * 2)
                return false;
        for (size_t i = 0; i < count * 2; i += 2) {
                const char *key = sd_json_variant_string(sd_json_variant_by_index(v, i));
                bool found = false;

                if (!key)
                        return false;
                for (size_t j = 0; j < i; j += 2)
                        if (streq(key, sd_json_variant_string(sd_json_variant_by_index(v, j))))
                                return false;
                for (size_t j = 0; j < count; j++)
                        if (streq(key, fields[j])) {
                                found = true;
                                break;
                        }
                if (!found)
                        return false;
        }
        return true;
}

static int ek_validate(const uint8_t *data, size_t size) {
        static const uint8_t prefix[] = {
                0, 0x23, 0, 0x0b, 0, 3, 0, 0xb2, 0, 32,
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
                0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
                0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
                0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
                0, 6, 0, 128, 0, 0x43, 0, 0x10, 0, 3, 0, 0x10,
        };
        uint8_t point[65] = { 4 };
        EVP_PKEY_CTX *context = NULL;
        EVP_PKEY *key = NULL;
        OSSL_PARAM parameters[3];
        size_t offset, n;
        int r = -EBADMSG;

        if (size < sizeof prefix + 8 || size - 2 != ((size_t) data[0] << 8 | data[1]) ||
            memcmp(data + 2, prefix, sizeof prefix) != 0)
                return -EBADMSG;
        offset = sizeof prefix + 2;
        n = (size_t) data[offset] << 8 | data[offset + 1];
        offset += 2;
        if (n < 1 || n > 32 || offset + n + 2 > size)
                return -EBADMSG;
        memcpy(point + 33 - n, data + offset, n);
        offset += n;
        n = (size_t) data[offset] << 8 | data[offset + 1];
        offset += 2;
        if (n < 1 || n > 32 || offset + n != size)
                return -EBADMSG;
        memcpy(point + 65 - n, data + offset, n);
        parameters[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        parameters[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point);
        parameters[2] = OSSL_PARAM_construct_end();
        context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!context)
                return -ENOMEM;
        if (EVP_PKEY_fromdata_init(context) != 1 ||
            EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) != 1)
                goto finish;
        EVP_PKEY_CTX_free(context);
        context = EVP_PKEY_CTX_new(key, NULL);
        if (!context) {
                r = -ENOMEM;
                goto finish;
        }
        if (EVP_PKEY_public_check(context) == 1)
                r = 0;
finish:
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(key);
        return r;
}

static int identity_validate(const char *ek, const char *ak, const char *name, EnrollmentRecord *ret) {
        uint8_t ek_bytes[PUBLIC_SIZE_MAX], ak_bytes[PUBLIC_SIZE_MAX], name_bytes[34], supplied_name[34], hash[32];
        int ek_size, ak_size, r;

        ek_size = hex_decode(ek, ek_bytes, sizeof ek_bytes);
        if (ek_size < 0)
                return ek_size;
        r = ek_validate(ek_bytes, (size_t) ek_size);
        if (r < 0)
                return r;
        ak_size = hex_decode(ak, ak_bytes, sizeof ak_bytes);
        if (ak_size < 0)
                return ak_size;
        r = attestation_key_name(ak, name_bytes);
        if (r < 0)
                return r;
        if (hex_decode(name, supplied_name, sizeof supplied_name) != sizeof supplied_name ||
            memcmp(supplied_name, name_bytes, sizeof name_bytes) != 0)
                return -EKEYREJECTED;
        r = digest(ak_bytes, (size_t) ak_size, hash);
        if (r < 0)
                return r;
        hex_encode(ek_bytes, (size_t) ek_size, ret->ek);
        hex_encode(ak_bytes, (size_t) ak_size, ret->ak);
        hex_encode(name_bytes, sizeof name_bytes, ret->name);
        hex_encode(hash, sizeof hash, ret->key_id);
        return 0;
}

static int evidence_parse(sd_json_variant *evidence, const char *expected_ek, EnrollmentRecord *ret) {
        static const char * const fields[] = {
                "ekPublicHex", "ekCertHex", "akPublicHex", "akNameHex", "evidenceQuality",
        };
        uint8_t pin[PUBLIC_SIZE_MAX], actual[PUBLIC_SIZE_MAX];
        int n, size, r;

        if (!object_fields(evidence, fields, ELEMENTSOF(fields)) ||
            !streq(string_field(evidence, "evidenceQuality"), "measured") ||
            hex_decode(string_field(evidence, "ekCertHex"), NULL, 16384) < 0)
                return -EBADMSG;
        n = hex_decode(expected_ek, pin, sizeof pin);
        if (n < 0)
                return n;
        size = hex_decode(string_field(evidence, "ekPublicHex"), actual, sizeof actual);
        if (size < 0)
                return size;
        if (n != size || memcmp(pin, actual, (size_t) n) != 0)
                return -EKEYREJECTED;
        r = identity_validate(string_field(evidence, "ekPublicHex"), string_field(evidence, "akPublicHex"),
                              string_field(evidence, "akNameHex"), ret);
        return r;
}

static int private_file_check(int fd) {
        struct stat st;

        if (fstat(fd, &st) < 0)
                return negative_errno();
        if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != geteuid() ||
            (st.st_mode & 07777) != 0600)
                return -EPERM;
        return 0;
}

static int directory_open(const char *path) {
        char *copy = NULL, *save = NULL, *part;
        struct stat st;
        int fd = -1, next, r;

        if (!path || path[0] != '/' || strlen(path) > PATH_MAX)
                return -EINVAL;
        copy = strdup(path);
        if (!copy)
                return -ENOMEM;
        fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
                r = negative_errno();
                goto fail;
        }
        for (part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
                if (streq(part, ".") || streq(part, "..")) {
                        r = -EINVAL;
                        goto fail;
                }
                next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
                if (next < 0) {
                        r = negative_errno();
                        goto fail;
                }
                close(fd);
                fd = next;
        }
        if (fstat(fd, &st) < 0) {
                r = negative_errno();
                goto fail;
        }
        if (st.st_uid != geteuid() || (st.st_mode & 07777) != 0700) {
                r = -EPERM;
                goto fail;
        }
        free(copy);
        return fd;
fail:
        if (fd >= 0)
                close(fd);
        free(copy);
        return r;
}

void enrollment_release(Enrollment *e) {
        if (!e)
                return;
        if (e->lock_fd >= 0)
                close(e->lock_fd);
        if (e->directory_fd >= 0)
                close(e->directory_fd);
        free(e);
}

static int enrollment_open(const char *directory, bool exclusive, Enrollment **ret) {
        Enrollment *e;
        int r;

        *ret = NULL;
        e = calloc(1, sizeof *e);
        if (!e)
                return -ENOMEM;
        e->lock_fd = -1;
        e->directory_fd = directory_open(directory);
        if (e->directory_fd < 0) {
                r = e->directory_fd;
                goto fail;
        }
        e->lock_fd = openat(e->directory_fd, ".lock", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
        if (e->lock_fd >= 0) {
                if (fchmod(e->lock_fd, 0600) < 0) {
                        r = negative_errno();
                        goto fail;
                }
        } else if (errno == EEXIST)
                e->lock_fd = openat(e->directory_fd, ".lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (e->lock_fd < 0) {
                r = negative_errno();
                goto fail;
        }
        r = private_file_check(e->lock_fd);
        if (r < 0)
                goto fail;
        if (flock(e->lock_fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) < 0) {
                r = errno == EWOULDBLOCK ? -EBUSY : negative_errno();
                goto fail;
        }
        *ret = e;
        return 0;
fail:
        enrollment_release(e);
        return r;
}

static int read_bounded(int fd, char *buffer, size_t capacity, size_t *ret_size) {
        size_t size = 0;

        for (;;) {
                ssize_t n = read(fd, buffer + size, capacity - size);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return negative_errno();
                }
                if (n == 0) {
                        *ret_size = size;
                        return 0;
                }
                size += (size_t) n;
                if (size == capacity)
                        return -E2BIG;
        }
}

static int record_parse(sd_json_variant *v, const char *key_id, EnrollmentRecord *ret) {
        static const char * const fields[] = {
                "format", "keyId", "ekPublicHex", "akPublicHex", "akNameHex", "state", "generation",
                "enrolledRealtimeUSec", "revokedRealtimeUSec", "pending", "request",
        };
        static const char * const pending_fields[] = {
                "requestId", "verifierBootId", "createdBoottimeUSec", "deadlineBoottimeUSec", "responseSha256",
        };
        static const char * const request_fields[] = {
                "requestId", "verifierBootId", "createdBoottimeUSec", "deadlineBoottimeUSec",
                "uid", "sessionId", "audience", "operationDigestHex",
        };
        EnrollmentRecord record = {};
        sd_json_variant *pending;
        const char *s;
        int r;

        if (!object_fields(v, fields, ELEMENTSOF(fields)) ||
            !streq(string_field(v, "format"), "io.platformd.Trust.Enrollment.v1") ||
            !streq(string_field(v, "keyId"), key_id) ||
            !unsigned_field(v, "generation", &record.generation) || record.generation == 0 ||
            !unsigned_field(v, "enrolledRealtimeUSec", &record.enrolled_usec) ||
            !unsigned_field(v, "revokedRealtimeUSec", &record.revoked_usec))
                return -EBADMSG;
        r = identity_validate(string_field(v, "ekPublicHex"), string_field(v, "akPublicHex"),
                              string_field(v, "akNameHex"), &record);
        if (r < 0)
                return r;
        if (!streq(record.key_id, key_id))
                return -EKEYREJECTED;
        s = string_field(v, "state");
        for (record.state = 0; record.state < _ENROLLMENT_STATE_MAX; record.state++)
                if (streq(s, state_names[record.state]))
                        break;
        if (record.state >= _ENROLLMENT_STATE_MAX ||
            (record.state == ENROLLMENT_ACTIVE && record.enrolled_usec == 0) ||
            (record.state != ENROLLMENT_ACTIVE && record.state != ENROLLMENT_REVOKED && record.enrolled_usec != 0) ||
            ((record.state == ENROLLMENT_REVOKED) != (record.revoked_usec != 0)))
                return -EBADMSG;
        pending = sd_json_variant_by_key(v, "pending");
        if (record.state != ENROLLMENT_PENDING) {
                if (!sd_json_variant_is_null(pending))
                        return -EBADMSG;
        } else {
                if (!object_fields(pending, pending_fields, ELEMENTSOF(pending_fields)) ||
                    !identifier_valid(string_field(pending, "requestId"), 64) ||
                    !identifier_valid(string_field(pending, "verifierBootId"), 32) ||
                    streq(string_field(pending, "verifierBootId"), "00000000000000000000000000000000") ||
                    !identifier_valid(string_field(pending, "responseSha256"), 64) ||
                    !unsigned_field(pending, "createdBoottimeUSec", &record.created_usec) ||
                    !unsigned_field(pending, "deadlineBoottimeUSec", &record.deadline_usec) ||
                    record.created_usec == 0 || record.deadline_usec <= record.created_usec ||
                    record.deadline_usec - record.created_usec > 600U * 1000000U)
                        return -EBADMSG;
                strcpy(record.request_id, string_field(pending, "requestId"));
                strcpy(record.boot_id, string_field(pending, "verifierBootId"));
                strcpy(record.response_hash, string_field(pending, "responseSha256"));
        }
        pending = sd_json_variant_by_key(v, "request");
        if (!sd_json_variant_is_null(pending)) {
                AuthenticationRequest *request = &record.request;

                if (record.state != ENROLLMENT_ACTIVE ||
                    !object_fields(pending, request_fields, ELEMENTSOF(request_fields)) ||
                    !identifier_valid(string_field(pending, "requestId"), 64) ||
                    !identifier_valid(string_field(pending, "verifierBootId"), 32) ||
                    streq(string_field(pending, "verifierBootId"), "00000000000000000000000000000000") ||
                    !unsigned_field(pending, "createdBoottimeUSec", &request->created_usec) ||
                    !unsigned_field(pending, "deadlineBoottimeUSec", &request->deadline_usec) ||
                    request->created_usec == 0 || request->deadline_usec <= request->created_usec ||
                    request->deadline_usec - request->created_usec > 600U * 1000000U ||
                    !unsigned_field(pending, "uid", &request->uid) || request->uid >= UINT32_MAX ||
                    !printable(string_field(pending, "sessionId"), 256) ||
                    !printable(string_field(pending, "audience"), 256) ||
                    !identifier_valid(string_field(pending, "operationDigestHex"), 64))
                        return -EBADMSG;
                strcpy(request->id, string_field(pending, "requestId"));
                strcpy(request->boot_id, string_field(pending, "verifierBootId"));
                strcpy(request->session, string_field(pending, "sessionId"));
                strcpy(request->audience, string_field(pending, "audience"));
                strcpy(request->operation_digest, string_field(pending, "operationDigestHex"));
        }
        *ret = record;
        return 0;
}

static int record_load(Enrollment *e, const char *key_id) {
        char filename[70], buffer[RECORD_SIZE_MAX + 1];
        sd_json_variant *v = NULL;
        size_t size;
        int fd, r;

        if (!identifier_valid(key_id, 64))
                return -EINVAL;
        snprintf(filename, sizeof filename, "%s.json", key_id);
        fd = openat(e->directory_fd, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return negative_errno();
        r = private_file_check(fd);
        if (r >= 0)
                r = read_bounded(fd, buffer, sizeof buffer, &size);
        close(fd);
        if (r < 0)
                return r;
        if (memchr(buffer, 0, size))
                return -EBADMSG;
        buffer[size] = 0;
        r = sd_json_parse(buffer, 0, &v, NULL, NULL);
        if (r >= 0)
                r = record_parse(v, key_id, &e->record);
        sd_json_variant_unref(v);
        return r;
}

static int record_format(const EnrollmentRecord *record, sd_json_variant **ret) {
        sd_json_variant *pending = NULL, *request = NULL;
        int r;

        if (record->state == ENROLLMENT_PENDING)
                r = sd_json_buildo(&pending,
                                  SD_JSON_BUILD_PAIR_STRING("requestId", record->request_id),
                                  SD_JSON_BUILD_PAIR_STRING("verifierBootId", record->boot_id),
                                  SD_JSON_BUILD_PAIR_UNSIGNED("createdBoottimeUSec", record->created_usec),
                                  SD_JSON_BUILD_PAIR_UNSIGNED("deadlineBoottimeUSec", record->deadline_usec),
                                  SD_JSON_BUILD_PAIR_STRING("responseSha256", record->response_hash));
        else
                r = sd_json_variant_new_null(&pending);
        if (r < 0)
                return r;
        if (record->request.id[0])
                r = sd_json_buildo(&request,
                                  SD_JSON_BUILD_PAIR_STRING("requestId", record->request.id),
                                  SD_JSON_BUILD_PAIR_STRING("verifierBootId", record->request.boot_id),
                                  SD_JSON_BUILD_PAIR_UNSIGNED("createdBoottimeUSec", record->request.created_usec),
                                  SD_JSON_BUILD_PAIR_UNSIGNED("deadlineBoottimeUSec", record->request.deadline_usec),
                                  SD_JSON_BUILD_PAIR_UNSIGNED("uid", record->request.uid),
                                  SD_JSON_BUILD_PAIR_STRING("sessionId", record->request.session),
                                  SD_JSON_BUILD_PAIR_STRING("audience", record->request.audience),
                                  SD_JSON_BUILD_PAIR_STRING("operationDigestHex", record->request.operation_digest));
        else
                r = sd_json_variant_new_null(&request);
        if (r < 0) {
                sd_json_variant_unref(pending);
                return r;
        }
        r = sd_json_buildo(ret,
                          SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.Enrollment.v1"),
                          SD_JSON_BUILD_PAIR_STRING("keyId", record->key_id),
                          SD_JSON_BUILD_PAIR_STRING("ekPublicHex", record->ek),
                          SD_JSON_BUILD_PAIR_STRING("akPublicHex", record->ak),
                          SD_JSON_BUILD_PAIR_STRING("akNameHex", record->name),
                          SD_JSON_BUILD_PAIR_STRING("state", state_names[record->state]),
                          SD_JSON_BUILD_PAIR_UNSIGNED("generation", record->generation),
                          SD_JSON_BUILD_PAIR_UNSIGNED("enrolledRealtimeUSec", record->enrolled_usec),
                          SD_JSON_BUILD_PAIR_UNSIGNED("revokedRealtimeUSec", record->revoked_usec),
                          SD_JSON_BUILD_PAIR_VARIANT("pending", pending),
                          SD_JSON_BUILD_PAIR_VARIANT("request", request));
        sd_json_variant_unref(pending);
        sd_json_variant_unref(request);
        return r;
}

static int write_all(int fd, const void *data, size_t size) {
        const uint8_t *p = data;

        while (size > 0) {
                ssize_t n = write(fd, p, size);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return negative_errno();
                }
                if (n == 0)
                        return -EIO;
                p += n;
                size -= (size_t) n;
        }
        return 0;
}

static int record_save(Enrollment *e) {
        sd_json_variant *v = NULL;
        uint8_t random[16];
        char temporary[40] = ".tmp-", filename[70], *text = NULL;
        int fd = -1, r;
        bool created = false;

        r = record_format(&e->record, &v);
        if (r < 0)
                goto finish;
        r = sd_json_variant_format(v, 0, &text);
        if (r < 0)
                goto finish;
        if (strlen(text) > RECORD_SIZE_MAX) {
                r = -E2BIG;
                goto finish;
        }
        r = random_bytes(random, sizeof random);
        if (r < 0)
                goto finish;
        hex_encode(random, sizeof random, temporary + 5);
        fd = openat(e->directory_fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
                r = negative_errno();
                goto finish;
        }
        created = true;
        if (fchmod(fd, 0600) < 0) {
                r = negative_errno();
                goto finish;
        }
        r = write_all(fd, text, strlen(text));
        if (r < 0)
                goto finish;
        if (fsync(fd) < 0) {
                r = negative_errno();
                goto finish;
        }
        snprintf(filename, sizeof filename, "%s.json", e->record.key_id);
        if (renameat(e->directory_fd, temporary, e->directory_fd, filename) < 0) {
                r = negative_errno();
                goto finish;
        }
        created = false;
        r = fsync(e->directory_fd) < 0 ? negative_errno() : 0;
finish:
        if (fd >= 0)
                close(fd);
        if (created)
                (void) unlinkat(e->directory_fd, temporary, 0);
        sd_json_variant_unref(v);
        free(text);
        return r;
}

static int status_format(const EnrollmentRecord *record, sd_json_variant **ret) {
        return sd_json_buildo(ret,
                              SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.EnrollmentStatus.v1"),
                              SD_JSON_BUILD_PAIR_STRING("keyId", record->key_id),
                              SD_JSON_BUILD_PAIR_STRING("ekPublicHex", record->ek),
                              SD_JSON_BUILD_PAIR_STRING("akPublicHex", record->ak),
                              SD_JSON_BUILD_PAIR_STRING("akNameHex", record->name),
                              SD_JSON_BUILD_PAIR_STRING("state", state_names[record->state]),
                              SD_JSON_BUILD_PAIR_UNSIGNED("generation", record->generation),
                              SD_JSON_BUILD_PAIR_UNSIGNED("enrolledRealtimeUSec", record->enrolled_usec),
                              SD_JSON_BUILD_PAIR_UNSIGNED("revokedRealtimeUSec", record->revoked_usec));
}

static int deadline_valid(const char *verifier_boot, uint64_t created, uint64_t deadline) {
        char current_boot[SD_ID128_STRING_MAX];
        uint64_t now;
        int r;

        r = boot_id(current_boot);
        if (r < 0)
                return r;
        r = now_usec(CLOCK_BOOTTIME, &now);
        if (r < 0)
                return r;
        return streq(verifier_boot, current_boot) && now >= created && now < deadline;
}

static int pending_valid(const EnrollmentRecord *record) {
        return deadline_valid(record->boot_id, record->created_usec, record->deadline_usec);
}

static int wait_child(pid_t pid, int pid_fd, bool *ret_reaped) {
        uint64_t start, now;
        int status, r;

        r = now_usec(CLOCK_MONOTONIC, &start);
        if (r < 0)
                return r;
        for (;;) {
                struct pollfd fd = { .fd = pid_fd, .events = POLLIN };
                uint64_t elapsed;

                r = now_usec(CLOCK_MONOTONIC, &now);
                if (r < 0)
                        return r;
                if (now < start)
                        return -EIO;
                elapsed = now - start;
                if (elapsed >= HELPER_TIMEOUT_USEC)
                        return -ETIMEDOUT;
                r = poll(&fd, 1, (int) ((HELPER_TIMEOUT_USEC - elapsed + 999) / 1000));
                if (r < 0) {
                        if (errno == EINTR)
                                continue;
                        return negative_errno();
                }
                if (r == 0)
                        continue;
                if (!(fd.revents & POLLIN))
                        return -EIO;
                while (waitpid(pid, &status, 0) < 0)
                        if (errno != EINTR)
                                return negative_errno();
                *ret_reaped = true;
                if (!WIFEXITED(status))
                        return -EIO;
                if (WEXITSTATUS(status) == 127)
                        return -ENOENT;
                return WEXITSTATUS(status) == 0 ? 0 : -EIO;
        }
}

static int credential_parse(const uint8_t *data, size_t size, char **ret_credential, char **ret_secret) {
        static const uint8_t header[] = { 0xba, 0xdc, 0xc0, 0xde, 0, 0, 0, 1 };
        size_t credential_size, secret_offset, secret_size;
        char *credential, *secret;

        if (size < 12 || memcmp(data, header, sizeof header) != 0)
                return -EBADMSG;
        credential_size = (size_t) data[8] << 8 | data[9];
        secret_offset = 10 + credential_size;
        if (credential_size < 1 || credential_size > 256 || secret_offset + 2 > size)
                return -EBADMSG;
        secret_size = (size_t) data[secret_offset] << 8 | data[secret_offset + 1];
        if (secret_size < 1 || secret_size > 256 || secret_offset + 2 + secret_size != size)
                return -EBADMSG;
        credential = malloc((credential_size + 2) * 2 + 1);
        secret = malloc((secret_size + 2) * 2 + 1);
        if (!credential || !secret) {
                free(credential);
                free(secret);
                return -ENOMEM;
        }
        hex_encode(data + 8, credential_size + 2, credential);
        hex_encode(data + secret_offset, secret_size + 2, secret);
        *ret_credential = credential;
        *ret_secret = secret;
        return 0;
}

static int make_credential(const EnrollmentRecord *record, const uint8_t response[32],
                           char **ret_credential, char **ret_secret) {
        uint8_t public[PUBLIC_SIZE_MAX], output[1024];
        int input_fd = -1, output_fd = -1, pipe_fd[2] = { -1, -1 }, null_fd = -1, pid_fd = -1;
        size_t output_size;
        pid_t pid = -1;
        int n, r;
        bool reaped = false;

        n = hex_decode(record->ek, public, sizeof public);
        if (n < 0)
                return n;
        input_fd = memfd_create("enrollment-public", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        output_fd = memfd_create("enrollment-credential", MFD_CLOEXEC);
        null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (input_fd < 0 || output_fd < 0 || null_fd < 0 || pipe2(pipe_fd, O_CLOEXEC) < 0) {
                r = negative_errno();
                goto finish;
        }
        r = write_all(input_fd, public, (size_t) n);
        if (r < 0)
                goto finish;
        if (fcntl(input_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) {
                r = negative_errno();
                goto finish;
        }
        r = write_all(pipe_fd[1], response, 32);
        if (r < 0)
                goto finish;
        close(pipe_fd[1]);
        pipe_fd[1] = -1;
        pid = fork();
        if (pid < 0) {
                r = negative_errno();
                goto finish;
        }
        if (pid == 0) {
                char * const arguments[] = {
                        TPM2_MAKECREDENTIAL_PATH, "-T", "none", "-u", "/proc/self/fd/3", "-s", "-",
                        "-n", (char *) record->name, "-o", "/proc/self/fd/4", NULL,
                };
                char * const environment[] = { "PATH=/usr/bin:/bin", "LC_ALL=C", NULL };
                struct rlimit file_limit = { 1024, 1024 }, core_limit = { 0, 0 };
                int input_copy, output_copy, null_copy, pipe_copy;

                input_copy = fcntl(input_fd, F_DUPFD_CLOEXEC, 5);
                output_copy = fcntl(output_fd, F_DUPFD_CLOEXEC, 5);
                null_copy = fcntl(null_fd, F_DUPFD_CLOEXEC, 5);
                pipe_copy = fcntl(pipe_fd[0], F_DUPFD_CLOEXEC, 5);
                if (input_copy < 0 || output_copy < 0 || null_copy < 0 || pipe_copy < 0 ||
                    dup2(pipe_copy, STDIN_FILENO) < 0 || dup2(null_copy, STDOUT_FILENO) < 0 ||
                    dup2(null_copy, STDERR_FILENO) < 0 || dup2(input_copy, 3) < 0 || dup2(output_copy, 4) < 0 ||
                    close_range(5, UINT_MAX, 0) < 0 || setrlimit(RLIMIT_FSIZE, &file_limit) < 0 ||
                    setrlimit(RLIMIT_CORE, &core_limit) < 0)
                        _exit(126);
                execve(TPM2_MAKECREDENTIAL_PATH, arguments, environment);
                _exit(errno == ENOENT ? 127 : 126);
        }
        pid_fd = pidfd_open(pid, 0);
        if (pid_fd < 0) {
                r = negative_errno();
                goto finish;
        }
        r = wait_child(pid, pid_fd, &reaped);
        if (reaped)
                pid = -1;
        if (r < 0)
                goto finish;
        if (lseek(output_fd, 0, SEEK_SET) < 0) {
                r = negative_errno();
                goto finish;
        }
        r = read_bounded(output_fd, (char *) output, sizeof output, &output_size);
        if (r >= 0)
                r = credential_parse(output, output_size, ret_credential, ret_secret);
finish:
        if (pid > 0) {
                if (pid_fd >= 0)
                        (void) pidfd_send_signal(pid_fd, SIGKILL, NULL, 0);
                else
                        (void) kill(pid, SIGKILL);
                while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
                        ;
        }
        if (pid_fd >= 0)
                close(pid_fd);
        if (input_fd >= 0)
                close(input_fd);
        if (output_fd >= 0)
                close(output_fd);
        if (null_fd >= 0)
                close(null_fd);
        if (pipe_fd[0] >= 0)
                close(pipe_fd[0]);
        if (pipe_fd[1] >= 0)
                close(pipe_fd[1]);
        return r;
}

int enrollment_begin(const char *state_dir, sd_json_variant *evidence, const char *expected_ek_hex,
                     uint64_t lifetime_sec, sd_json_variant **ret_challenge) {
        EnrollmentRecord record = {};
        Enrollment *e = NULL;
        sd_json_variant *challenge = NULL;
        uint8_t *response = NULL, random[32], hash[32];
        char *credential = NULL, *secret = NULL;
        int r;

        if (!ret_challenge)
                return -EINVAL;
        *ret_challenge = NULL;
        if (lifetime_sec < 1 || lifetime_sec > 600)
                return -EINVAL;
        r = evidence_parse(evidence, expected_ek_hex, &record);
        if (r < 0)
                return r;
        r = enrollment_open(state_dir, true, &e);
        if (r < 0)
                return r;
        r = record_load(e, record.key_id);
        if (r >= 0) {
                if (!streq(record.ek, e->record.ek) || !streq(record.ak, e->record.ak)) {
                        r = -EKEYREJECTED;
                        goto finish;
                }
                if (e->record.state == ENROLLMENT_REVOKED) {
                        r = -EKEYREVOKED;
                        goto finish;
                }
                if (e->record.state == ENROLLMENT_ACTIVE) {
                        r = -EEXIST;
                        goto finish;
                }
                if (e->record.state == ENROLLMENT_PENDING) {
                        r = pending_valid(&e->record);
                        if (r != 0) {
                                if (r > 0)
                                        r = -EALREADY;
                                goto finish;
                        }
                }
                if (e->record.generation == UINT64_MAX) {
                        r = -EOVERFLOW;
                        goto finish;
                }
                record.generation = e->record.generation + 1;
        } else if (r == -ENOENT)
                record.generation = 1;
        else
                goto finish;
        r = response_allocate(&response);
        if (r < 0)
                goto finish;
        r = random_bytes(response, 32);
        if (r < 0)
                goto finish;
        r = digest(response, 32, hash);
        if (r < 0)
                goto finish;
        hex_encode(hash, sizeof hash, record.response_hash);
        r = random_bytes(random, sizeof random);
        if (r < 0)
                goto finish;
        hex_encode(random, sizeof random, record.request_id);
        r = make_credential(&record, response, &credential, &secret);
        explicit_bzero(response, 32);
        if (r < 0)
                goto finish;
        r = boot_id(record.boot_id);
        if (r < 0)
                goto finish;
        r = now_usec(CLOCK_BOOTTIME, &record.created_usec);
        if (r < 0)
                goto finish;
        if (record.created_usec == 0 || record.created_usec > UINT64_MAX - lifetime_sec * 1000000) {
                r = -ERANGE;
                goto finish;
        }
        record.deadline_usec = record.created_usec + lifetime_sec * 1000000;
        record.state = ENROLLMENT_PENDING;
        r = sd_json_buildo(&challenge,
                          SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.EnrollmentChallenge.v1"),
                          SD_JSON_BUILD_PAIR_STRING("keyId", record.key_id),
                          SD_JSON_BUILD_PAIR_STRING("requestId", record.request_id),
                          SD_JSON_BUILD_PAIR_STRING("credentialHex", credential),
                          SD_JSON_BUILD_PAIR_STRING("secretHex", secret));
        if (r < 0)
                goto finish;
        e->record = record;
        r = record_save(e);
        if (r < 0)
                goto finish;
        *ret_challenge = challenge;
        challenge = NULL;
finish:
        response_free(response);
        free(credential);
        free(secret);
        sd_json_variant_unref(challenge);
        enrollment_release(e);
        return r;
}

static void pending_clear(EnrollmentRecord *record) {
        record->request_id[0] = record->boot_id[0] = record->response_hash[0] = 0;
        record->created_usec = record->deadline_usec = 0;
}

int enrollment_complete(const char *state_dir, const char *key_id, const char *request_id,
                        const char *response_hex, sd_json_variant **ret_status) {
        Enrollment *e = NULL;
        sd_json_variant *status = NULL;
        uint8_t response[32] = {}, hash[32] = {}, expected[32];
        int r, result;

        if (!ret_status)
                return -EINVAL;
        *ret_status = NULL;
        if (!identifier_valid(request_id, 64) || !identifier_valid(key_id, 64))
                return -EINVAL;
        r = enrollment_open(state_dir, true, &e);
        if (r < 0)
                return r;
        r = record_load(e, key_id);
        if (r < 0)
                goto finish;
        if (e->record.state != ENROLLMENT_PENDING) {
                r = e->record.state == ENROLLMENT_REVOKED ? -EKEYREVOKED : -EALREADY;
                goto finish;
        }
        if (!streq(e->record.request_id, request_id)) {
                r = -ESTALE;
                goto finish;
        }
        r = pending_valid(&e->record);
        if (r < 0)
                goto finish;
        result = r == 0 ? -ETIMEDOUT : 0;
        if (result == 0) {
                if (hex_decode(response_hex, response, sizeof response) != sizeof response)
                        result = -EKEYREJECTED;
                else {
                        r = digest(response, sizeof response, hash);
                        if (r < 0)
                                goto finish;
                        if (hex_decode(e->record.response_hash, expected, sizeof expected) != sizeof expected) {
                                r = -EBADMSG;
                                goto finish;
                        }
                        if (CRYPTO_memcmp(expected, hash, sizeof hash) != 0)
                                result = -EKEYREJECTED;
                }
        }
        if (e->record.generation == UINT64_MAX) {
                r = -EOVERFLOW;
                goto finish;
        }
        e->record.generation++;
        pending_clear(&e->record);
        e->record.state = result == 0 ? ENROLLMENT_ACTIVE : ENROLLMENT_INACTIVE;
        if (result == 0) {
                r = now_usec(CLOCK_REALTIME, &e->record.enrolled_usec);
                if (r < 0)
                        goto finish;
                if (e->record.enrolled_usec == 0) {
                        r = -ERANGE;
                        goto finish;
                }
                r = status_format(&e->record, &status);
                if (r < 0)
                        goto finish;
        }
        r = record_save(e);
        if (r < 0)
                goto finish;
        r = result;
        if (r == 0) {
                *ret_status = status;
                status = NULL;
        }
finish:
        explicit_bzero(response, sizeof response);
        explicit_bzero(hash, sizeof hash);
        sd_json_variant_unref(status);
        enrollment_release(e);
        return r;
}

int enrollment_revoke(const char *state_dir, const char *key_id, sd_json_variant **ret_status) {
        Enrollment *e = NULL;
        sd_json_variant *status = NULL;
        int r;

        if (!ret_status)
                return -EINVAL;
        *ret_status = NULL;
        if (!identifier_valid(key_id, 64))
                return -EINVAL;
        r = enrollment_open(state_dir, true, &e);
        if (r < 0)
                return r;
        r = record_load(e, key_id);
        if (r < 0)
                goto finish;
        if (e->record.state != ENROLLMENT_REVOKED) {
                if (e->record.generation == UINT64_MAX) {
                        r = -EOVERFLOW;
                        goto finish;
                }
                e->record.generation++;
                pending_clear(&e->record);
                e->record.request = (AuthenticationRequest) {};
                e->record.state = ENROLLMENT_REVOKED;
                r = now_usec(CLOCK_REALTIME, &e->record.revoked_usec);
                if (r < 0)
                        goto finish;
                if (e->record.revoked_usec == 0) {
                        r = -ERANGE;
                        goto finish;
                }
                r = status_format(&e->record, &status);
                if (r < 0)
                        goto finish;
                r = record_save(e);
                if (r < 0)
                        goto finish;
        } else {
                if (fsync(e->directory_fd) < 0) {
                        r = negative_errno();
                        goto finish;
                }
                r = status_format(&e->record, &status);
                if (r < 0)
                        goto finish;
        }
        *ret_status = status;
        status = NULL;
finish:
        sd_json_variant_unref(status);
        enrollment_release(e);
        return r;
}

int enrollment_status(const char *state_dir, const char *key_id, sd_json_variant **ret_status) {
        Enrollment *e = NULL;
        int r;

        if (!ret_status)
                return -EINVAL;
        *ret_status = NULL;
        if (!identifier_valid(key_id, 64))
                return -EINVAL;
        r = enrollment_open(state_dir, false, &e);
        if (r < 0)
                return r;
        r = record_load(e, key_id);
        if (r >= 0)
                r = status_format(&e->record, ret_status);
        enrollment_release(e);
        return r;
}

int enrollment_acquire(const char *state_dir, const char *key_id, Enrollment **ret) {
        Enrollment *e = NULL;
        int r;

        if (!ret)
                return -EINVAL;
        *ret = NULL;
        if (!identifier_valid(key_id, 64))
                return -EINVAL;
        r = enrollment_open(state_dir, false, &e);
        if (r < 0)
                return r;
        r = record_load(e, key_id);
        if (r < 0)
                goto fail;
        if (e->record.state != ENROLLMENT_ACTIVE) {
                r = e->record.state == ENROLLMENT_REVOKED ? -EKEYREVOKED : -ENOKEY;
                goto fail;
        }
        if (fsync(e->directory_fd) < 0) {
                r = negative_errno();
                goto fail;
        }
        *ret = e;
        return 0;
fail:
        enrollment_release(e);
        return r;
}

const char *enrollment_attestation_key(const Enrollment *e) {
        return e ? e->record.ak : NULL;
}

static int active_open(const char *state_dir, const char *key_id, Enrollment **ret) {
        Enrollment *e = NULL;
        int r;

        r = enrollment_open(state_dir, true, &e);
        if (r < 0)
                return r;
        r = record_load(e, key_id);
        if (r < 0)
                goto fail;
        if (e->record.state != ENROLLMENT_ACTIVE) {
                r = e->record.state == ENROLLMENT_REVOKED ? -EKEYREVOKED : -ENOKEY;
                goto fail;
        }
        *ret = e;
        return 0;
fail:
        enrollment_release(e);
        return r;
}

static int request_format(const AuthenticationRequest *request, sd_json_variant **ret) {
        sd_json_variant *context = NULL;
        int r;

        r = sd_json_buildo(&context,
                          SD_JSON_BUILD_PAIR_STRING("challengeHex", request->id),
                          SD_JSON_BUILD_PAIR_STRING("audience", request->audience),
                          SD_JSON_BUILD_PAIR_STRING("operationDigestHex", request->operation_digest));
        if (r < 0)
                return r;
        r = sd_json_buildo(ret,
                          SD_JSON_BUILD_PAIR_UNSIGNED("uid", request->uid),
                          SD_JSON_BUILD_PAIR_STRING("sessionId", request->session),
                          SD_JSON_BUILD_PAIR_VARIANT("context", context));
        sd_json_variant_unref(context);
        return r;
}

int enrollment_request_begin(const char *state_dir, const char *key_id, sd_json_variant *context,
                             uint64_t lifetime_sec, sd_json_variant **ret_request) {
        static const char * const fields[] = { "audience", "operationDigestHex", "uid", "sessionId" };
        Enrollment *e = NULL;
        AuthenticationRequest request = {};
        sd_json_variant *inner = NULL, *result = NULL;
        uint8_t random[32];
        int r;

        if (!ret_request)
                return -EINVAL;
        *ret_request = NULL;
        if (!identifier_valid(key_id, 64) || lifetime_sec < 1 || lifetime_sec > 600 ||
            !object_fields(context, fields, ELEMENTSOF(fields)) ||
            !printable(string_field(context, "audience"), 256) ||
            !printable(string_field(context, "sessionId"), 256) ||
            !identifier_valid(string_field(context, "operationDigestHex"), 64) ||
            !unsigned_field(context, "uid", &request.uid) || request.uid >= UINT32_MAX)
                return -EINVAL;
        strcpy(request.audience, string_field(context, "audience"));
        strcpy(request.session, string_field(context, "sessionId"));
        strcpy(request.operation_digest, string_field(context, "operationDigestHex"));
        r = active_open(state_dir, key_id, &e);
        if (r < 0)
                return r;
        if (e->record.request.id[0]) {
                r = deadline_valid(e->record.request.boot_id, e->record.request.created_usec, e->record.request.deadline_usec);
                if (r != 0) {
                        if (r > 0)
                                r = -EALREADY;
                        goto finish;
                }
        }
        if (e->record.generation == UINT64_MAX) {
                r = -EOVERFLOW;
                goto finish;
        }
        r = random_bytes(random, sizeof random);
        if (r < 0)
                goto finish;
        hex_encode(random, sizeof random, request.id);
        r = boot_id(request.boot_id);
        if (r < 0)
                goto finish;
        r = now_usec(CLOCK_BOOTTIME, &request.created_usec);
        if (r < 0)
                goto finish;
        if (request.created_usec == 0 || request.created_usec > UINT64_MAX - lifetime_sec * 1000000) {
                r = -ERANGE;
                goto finish;
        }
        request.deadline_usec = request.created_usec + lifetime_sec * 1000000;
        r = request_format(&request, &inner);
        if (r < 0)
                goto finish;
        r = sd_json_buildo(&result,
                          SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.AuthenticationRequest.v1"),
                          SD_JSON_BUILD_PAIR_STRING("keyId", key_id),
                          SD_JSON_BUILD_PAIR_STRING("requestId", request.id),
                          SD_JSON_BUILD_PAIR_VARIANT("request", inner));
        if (r < 0)
                goto finish;
        e->record.request = request;
        e->record.generation++;
        r = record_save(e);
        if (r < 0)
                goto finish;
        *ret_request = result;
        result = NULL;
finish:
        sd_json_variant_unref(inner);
        sd_json_variant_unref(result);
        enrollment_release(e);
        return r;
}

int enrollment_request_consume(const char *state_dir, const char *key_id, const char *request_id,
                               Enrollment **ret_enrollment, sd_json_variant **ret_request) {
        Enrollment *e = NULL;
        sd_json_variant *request = NULL;
        int r, valid;

        if (!ret_enrollment || !ret_request)
                return -EINVAL;
        *ret_enrollment = NULL;
        *ret_request = NULL;
        if (!identifier_valid(key_id, 64) || !identifier_valid(request_id, 64))
                return -EINVAL;
        r = active_open(state_dir, key_id, &e);
        if (r < 0)
                return r;
        if (!e->record.request.id[0]) {
                r = -ENODATA;
                goto finish;
        }
        if (!streq(request_id, e->record.request.id)) {
                r = -ESTALE;
                goto finish;
        }
        valid = deadline_valid(e->record.request.boot_id, e->record.request.created_usec, e->record.request.deadline_usec);
        if (valid < 0) {
                r = valid;
                goto finish;
        }
        if (e->record.generation == UINT64_MAX) {
                r = -EOVERFLOW;
                goto finish;
        }
        if (valid) {
                r = request_format(&e->record.request, &request);
                if (r < 0)
                        goto finish;
        }
        e->record.request = (AuthenticationRequest) {};
        e->record.generation++;
        r = record_save(e);
        if (r < 0)
                goto finish;
        if (!valid) {
                r = -ETIMEDOUT;
                goto finish;
        }
        *ret_enrollment = e;
        e = NULL;
        *ret_request = request;
        request = NULL;
finish:
        sd_json_variant_unref(request);
        enrollment_release(e);
        return r;
}
