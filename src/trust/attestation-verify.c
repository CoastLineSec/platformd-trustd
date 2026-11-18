/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "attestation-verify.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define ELEMENTSOF(x) (sizeof(x) / sizeof((x)[0]))
#define RECORD_SIZE_MAX 8192U
#define EVENT_COUNT_MAX 1024U
#define JSON_DEPTH_MAX 32U
#define JSON_NODE_MAX 65536U

typedef struct Bytes {
        const uint8_t *data;
        size_t size;
} Bytes;

typedef struct Reader {
        Bytes bytes;
        size_t offset;
        bool failed;
} Reader;

typedef struct JsonBudget {
        size_t nodes;
        size_t bytes;
} JsonBudget;

typedef struct AttestationIdentity {
        uint8_t signer[34];
        uint64_t clock;
        uint64_t firmware;
        uint32_t resets;
        uint32_t restarts;
} AttestationIdentity;

static bool streq(const char *a, const char *b) {
        return a && b && strcmp(a, b) == 0;
}

static Bytes take(Reader *r, size_t size) {
        Bytes result;

        if (r->failed || size > r->bytes.size - r->offset) {
                r->failed = true;
                return (Bytes) {};
        }
        result = (Bytes) { r->bytes.data + r->offset, size };
        r->offset += size;
        return result;
}

static uint64_t number(Reader *r, size_t size) {
        Bytes bytes = take(r, size);
        uint64_t result = 0;

        for (size_t i = 0; i < bytes.size; i++)
                result = (result << 8) | bytes.data[i];
        return result;
}

static Bytes sized(Reader *r) {
        size_t size = number(r, 2);

        return take(r, size);
}

static bool reader_end(const Reader *r) {
        return !r->failed && r->offset == r->bytes.size;
}

static bool bytes_equal(Bytes a, Bytes b) {
        return a.size == b.size && (a.size == 0 || memcmp(a.data, b.data, a.size) == 0);
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

static int unhex(const char *s, uint8_t *ret, size_t capacity) {
        size_t n;

        if (!s)
                return -EBADMSG;
        n = strnlen(s, capacity * 2 + 1);
        if (n > capacity * 2)
                return -E2BIG;
        if (n % 2 != 0)
                return -EBADMSG;
        for (size_t i = 0; i < n / 2; i++) {
                int high = unhex_char(s[2 * i]), low = unhex_char(s[2 * i + 1]);

                if (high < 0 || low < 0)
                        return -EBADMSG;
                ret[i] = (uint8_t) ((high << 4) | low);
        }
        return (int) (n / 2);
}

static const char *string_field(sd_json_variant *v, const char *key) {
        sd_json_variant *field = sd_json_variant_by_key(v, key);

        return sd_json_variant_is_string(field) ? sd_json_variant_string(field) : NULL;
}

static bool unsigned_value(sd_json_variant *v, uint64_t *ret) {
        sd_json_variant_type_t type = sd_json_variant_type(v);

        if ((type != SD_JSON_VARIANT_INTEGER && type != SD_JSON_VARIANT_UNSIGNED) ||
            !sd_json_variant_is_unsigned(v))
                return false;
        *ret = sd_json_variant_unsigned(v);
        return true;
}

static bool unsigned_field(sd_json_variant *v, const char *key, uint64_t *ret) {
        return unsigned_value(sd_json_variant_by_key(v, key), ret);
}

static bool boolean_field(sd_json_variant *v, const char *key, bool *ret) {
        sd_json_variant *field = sd_json_variant_by_key(v, key);

        if (!sd_json_variant_is_boolean(field))
                return false;
        *ret = sd_json_variant_boolean(field);
        return true;
}

static bool text_field(sd_json_variant *v, const char *key, size_t maximum, bool empty) {
        const char *s = string_field(v, key);

        if (!s || (!empty && !*s) || strnlen(s, maximum + 1) > maximum)
                return false;
        for (const unsigned char *p = (const unsigned char *) s; *p; p++)
                if (*p < 0x20 || *p == 0x7f)
                        return false;
        return true;
}

static int json_check(sd_json_variant *v, unsigned depth, JsonBudget *budget) {
        size_t n;
        int r;

        if (!v)
                return -EBADMSG;
        if (depth > JSON_DEPTH_MAX || ++budget->nodes > JSON_NODE_MAX)
                return -E2BIG;
        if (sd_json_variant_is_string(v)) {
                n = strnlen(sd_json_variant_string(v), ATTESTATION_TOKEN_SIZE_MAX + 1);
                if (n > ATTESTATION_TOKEN_SIZE_MAX - budget->bytes)
                        return -E2BIG;
                budget->bytes += n;
                return 0;
        }
        if (!sd_json_variant_is_object(v) && !sd_json_variant_is_array(v))
                return 0;
        n = sd_json_variant_elements(v);
        if (sd_json_variant_is_object(v)) {
                if (n % 2 != 0)
                        return -EBADMSG;
                if (n > 128)
                        return -E2BIG;
                for (size_t i = 0; i < n; i += 2) {
                        const char *key = sd_json_variant_string(sd_json_variant_by_index(v, i));

                        if (!key)
                                return -EBADMSG;
                        for (size_t j = 0; j < i; j += 2)
                                if (streq(key, sd_json_variant_string(sd_json_variant_by_index(v, j))))
                                        return -EBADMSG;
                }
        } else if (n > EVENT_COUNT_MAX)
                return -E2BIG;
        for (size_t i = 0; i < n; i++) {
                r = json_check(sd_json_variant_by_index(v, i), depth + 1, budget);
                if (r < 0)
                        return r;
        }
        return 0;
}

static bool object_fields(sd_json_variant *v, const char * const *fields, size_t count, bool exact) {
        size_t n;

        if (!sd_json_variant_is_object(v))
                return false;
        n = sd_json_variant_elements(v);
        if (n > count * 2 || (exact && n != count * 2))
                return false;
        for (size_t i = 0; i < n; i += 2) {
                const char *key = sd_json_variant_string(sd_json_variant_by_index(v, i));
                bool found = false;

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

static int sha256(Bytes data, uint8_t ret[32]) {
        return EVP_Q_digest(NULL, "SHA256", NULL, data.data, data.size, ret, NULL) == 1 ? 0 : -EIO;
}

static int public_key(Bytes encoded, EVP_PKEY **ret, uint8_t ret_qualified_name[34]) {
        EVP_PKEY_CTX *context = NULL;
        EVP_PKEY *key = NULL;
        uint8_t point[65] = { 4 };
        uint8_t qualified_input[38] = { 0x40, 0, 0, 1, 0, 0x0b };
        OSSL_PARAM parameters[3];
        Reader outer = { .bytes = encoded }, reader;
        Bytes public, policy, x, y;
        int r = -EBADMSG;

        public = sized(&outer);
        if (!reader_end(&outer))
                return -EBADMSG;
        reader = (Reader) { .bytes = public };
        if (number(&reader, 2) != 0x23 || number(&reader, 2) != 0x0b ||
            number(&reader, 4) != 0x00050072)
                return -EBADMSG;
        policy = sized(&reader);
        if (policy.size != 0 || number(&reader, 2) != 0x10 || number(&reader, 2) != 0x18 ||
            number(&reader, 2) != 0x0b || number(&reader, 2) != 3 || number(&reader, 2) != 0x10)
                return -EBADMSG;
        x = sized(&reader);
        y = sized(&reader);
        if (!reader_end(&reader) || x.size == 0 || x.size > 32 || y.size == 0 || y.size > 32)
                return -EBADMSG;
        /* The profile uses a primary AK in the owner hierarchy. */
        r = sha256(public, qualified_input + 6);
        if (r < 0)
                return r;
        ret_qualified_name[0] = 0;
        ret_qualified_name[1] = 0x0b;
        r = sha256((Bytes) { qualified_input, sizeof qualified_input }, ret_qualified_name + 2);
        if (r < 0)
                return r;
        r = -EBADMSG;
        memcpy(point + 33 - x.size, x.data, x.size);
        memcpy(point + 65 - y.size, y.data, y.size);
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
        if (EVP_PKEY_public_check(context) != 1)
                goto finish;
        *ret = key;
        key = NULL;
        r = 0;
finish:
        EVP_PKEY_CTX_free(context);
        EVP_PKEY_free(key);
        return r;
}

int attestation_key_name(const char *ak_hex, uint8_t ret_name[static 34]) {
        uint8_t encoded[256], qualified_name[34], name[34] = { 0, 0x0b };
        EVP_PKEY *key = NULL;
        int n, r;

        n = unhex(ak_hex, encoded, sizeof encoded);
        if (n < 0)
                return n;
        r = public_key((Bytes) { encoded, (size_t) n }, &key, qualified_name);
        EVP_PKEY_free(key);
        if (r < 0)
                return r;
        r = sha256((Bytes) { encoded + 2, (size_t) n - 2 }, name + 2);
        if (r < 0)
                return r;
        memcpy(ret_name, name, sizeof name);
        return 0;
}

static int signature_verify(EVP_PKEY *key, Bytes data, const char *signature) {
        uint8_t encoded[128];
        unsigned char *der = NULL;
        EVP_MD_CTX *context = NULL;
        ECDSA_SIG *sig = NULL;
        BIGNUM *r = NULL, *s = NULL;
        Reader reader;
        Bytes rb, sb;
        int n, size, result = -EBADMSG;

        n = unhex(signature, encoded, sizeof encoded);
        if (n < 0)
                return n;
        reader = (Reader) { .bytes = { encoded, (size_t) n } };
        if (number(&reader, 2) != 0x18 || number(&reader, 2) != 0x0b)
                return -EBADMSG;
        rb = sized(&reader);
        sb = sized(&reader);
        if (!reader_end(&reader) || rb.size == 0 || rb.size > 32 || sb.size == 0 || sb.size > 32)
                return -EBADMSG;
        sig = ECDSA_SIG_new();
        r = BN_bin2bn(rb.data, (int) rb.size, NULL);
        s = BN_bin2bn(sb.data, (int) sb.size, NULL);
        context = EVP_MD_CTX_new();
        if (!sig || !r || !s || !context) {
                result = -ENOMEM;
                goto finish;
        }
        if (ECDSA_SIG_set0(sig, r, s) != 1)
                goto finish;
        r = s = NULL;
        size = i2d_ECDSA_SIG(sig, &der);
        if (size <= 0 || EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) != 1) {
                result = -EIO;
                goto finish;
        }
        result = EVP_DigestVerify(context, der, (size_t) size, data.data, data.size) == 1 ? 0 : -EKEYREJECTED;
finish:
        OPENSSL_free(der);
        EVP_MD_CTX_free(context);
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return result;
}

static int attestation_header(Reader *reader, unsigned type, Bytes nonce, const uint8_t qualified_name[34],
                              AttestationIdentity *ret) {
        Bytes signer, challenge;
        AttestationIdentity identity;
        uint64_t safe;

        if (number(reader, 4) != 0xff544347 || number(reader, 2) != type)
                return -EBADMSG;
        signer = sized(reader);
        challenge = sized(reader);
        if (!bytes_equal(signer, (Bytes) { qualified_name, sizeof identity.signer }) ||
            !bytes_equal(challenge, nonce))
                return -EBADMSG;
        memcpy(identity.signer, signer.data, sizeof identity.signer);
        identity.clock = number(reader, 8);
        identity.resets = (uint32_t) number(reader, 4);
        identity.restarts = (uint32_t) number(reader, 4);
        safe = number(reader, 1);
        identity.firmware = number(reader, 8);
        if (reader->failed || safe > 1)
                return -EBADMSG;
        *ret = identity;
        return 0;
}

static int quote_verify(EVP_PKEY *key, sd_json_variant *quote, sd_json_variant *boot, Bytes nonce,
                        const uint8_t qualified_name[34],
                        AttestationIdentity *ret_identity) {
        static const char * const quote_fields[] = { "type", "pcrBank", "quoted", "signature" };
        static const char * const boot_fields[] = { "type", "quality", "pcrs" };
        static const char * const pcr_fields[] = { "index", "sha256" };
        static const uint8_t selection[] = { 0xff, 0xff, 0 };
        uint8_t data[2048], pcr_values[16 * 32], digest[32];
        sd_json_variant *pcrs, *quality;
        Reader reader;
        Bytes selected, quoted_digest;
        unsigned seen = 0;
        int n, r;

        if (!object_fields(quote, quote_fields, ELEMENTSOF(quote_fields), true) ||
            !streq(string_field(quote, "pcrBank"), "sha256") ||
            !object_fields(boot, boot_fields, ELEMENTSOF(boot_fields), false))
                return -EBADMSG;
        quality = sd_json_variant_by_key(boot, "quality");
        if (quality && !text_field(boot, "quality", 64, true))
                return -EBADMSG;
        n = unhex(string_field(quote, "quoted"), data, sizeof data);
        if (n < 0)
                return n;
        reader = (Reader) { .bytes = { data, (size_t) n } };
        r = signature_verify(key, reader.bytes, string_field(quote, "signature"));
        if (r < 0)
                return r;
        r = attestation_header(&reader, 0x8018, nonce, qualified_name, ret_identity);
        if (r < 0)
                return r;
        if (number(&reader, 4) != 1 || number(&reader, 2) != 0x0b)
                return -EBADMSG;
        selected = take(&reader, number(&reader, 1));
        quoted_digest = sized(&reader);
        if (!reader_end(&reader) || !bytes_equal(selected, (Bytes) { selection, sizeof selection }) ||
            quoted_digest.size != 32)
                return -EBADMSG;
        pcrs = sd_json_variant_by_key(boot, "pcrs");
        if (!sd_json_variant_is_array(pcrs) || sd_json_variant_elements(pcrs) != 16)
                return -EBADMSG;
        for (size_t i = 0; i < 16; i++) {
                sd_json_variant *pcr = sd_json_variant_by_index(pcrs, i);
                uint64_t index;

                if (!object_fields(pcr, pcr_fields, ELEMENTSOF(pcr_fields), true) ||
                    !unsigned_field(pcr, "index", &index) || index >= 16 || (seen & (1U << index)))
                        return -EBADMSG;
                if (unhex(string_field(pcr, "sha256"), pcr_values + index * 32, 32) != 32)
                        return -EBADMSG;
                seen |= 1U << index;
        }
        r = sha256((Bytes) { pcr_values, sizeof pcr_values }, digest);
        if (r < 0)
                return r;
        return bytes_equal(quoted_digest, (Bytes) { digest, sizeof digest }) ? 0 : -EBADMSG;
}

static int nv_verify(EVP_PKEY *key, sd_json_variant *runtime, Bytes nonce, const uint8_t qualified_name[34],
                     const AttestationIdentity *quote_identity, uint8_t ret_current[32]) {
        static const char * const fields[] = {
                "type", "format", "nvIndex", "baseline", "current", "certifyInfo", "nvPublicHex", "signature", "events",
        };
        uint8_t encoded[128], data[2048], name[34] = { 0, 0x0b };
        Reader reader, outer;
        AttestationIdentity identity;
        Bytes public, policy, certified_name, certified;
        uint64_t attributes;
        int n, r;

        if (!object_fields(runtime, fields, ELEMENTSOF(fields), true) ||
            !streq(string_field(runtime, "format"), "io.platformd.Trust.RuntimeLog.v2") ||
            !streq(string_field(runtime, "nvIndex"), "0x01800001"))
                return -EBADMSG;
        n = unhex(string_field(runtime, "nvPublicHex"), encoded, sizeof encoded);
        if (n < 0)
                return n;
        outer = (Reader) { .bytes = { encoded, (size_t) n } };
        public = sized(&outer);
        if (!reader_end(&outer))
                return -EBADMSG;
        reader = (Reader) { .bytes = public };
        if (number(&reader, 4) != 0x01800001 || number(&reader, 2) != 0x0b)
                return -EBADMSG;
        attributes = number(&reader, 4);
        policy = sized(&reader);
        if ((attributes & ~UINT64_C(0x20000000)) != 0x0a060046 || policy.size != 0 ||
            number(&reader, 2) != 32 || !reader_end(&reader))
                return -EBADMSG;
        r = sha256(public, name + 2);
        if (r < 0)
                return r;
        n = unhex(string_field(runtime, "certifyInfo"), data, sizeof data);
        if (n < 0)
                return n;
        reader = (Reader) { .bytes = { data, (size_t) n } };
        r = signature_verify(key, reader.bytes, string_field(runtime, "signature"));
        if (r < 0)
                return r;
        r = attestation_header(&reader, 0x8014, nonce, qualified_name, &identity);
        if (r < 0)
                return r;
        if (memcmp(identity.signer, quote_identity->signer, sizeof identity.signer) != 0 ||
            identity.resets != quote_identity->resets || identity.restarts != quote_identity->restarts ||
            identity.firmware != quote_identity->firmware || identity.clock < quote_identity->clock)
                return -EBADMSG;
        certified_name = sized(&reader);
        if (!bytes_equal(certified_name, (Bytes) { name, sizeof name }) || number(&reader, 2) != 0)
                return -EBADMSG;
        certified = sized(&reader);
        if (!reader_end(&reader) || certified.size != 32 ||
            unhex(string_field(runtime, "current"), ret_current, 32) != 32 ||
            memcmp(certified.data, ret_current, 32) != 0)
                return -EBADMSG;
        return 0;
}

static int authentication_payload(sd_json_variant *payload, bool login, uint64_t boottime,
                                  uint64_t realtime, uint64_t *ret_observed) {
        static const char * const fields[] = {
                "user", "uid", "pamService", "tty", "remoteHost", "phase", "declaredMethod", "result",
                "sessionId", "qualifiesForFreshness", "realtimeUSec", "evidenceQuality", "peerUid",
                "peerPid", "sessionLeader", "receivedBoottimeUSec", "receivedRealtimeUSec",
                "completedBoottimeUSec", "completedRealtimeUSec",
        };
        uint64_t uid, peer, copied_time;
        bool qualifies;

        if (!object_fields(payload, fields, login ? ELEMENTSOF(fields) : 13, true) ||
            !text_field(payload, "user", 256, false) || !text_field(payload, "pamService", 128, false) ||
            !text_field(payload, "tty", 256, true) || !text_field(payload, "remoteHost", 256, true) ||
            !text_field(payload, "sessionId", 256, false) || !text_field(payload, "declaredMethod", 128, false) ||
            !unsigned_field(payload, "uid", &uid) || uid >= UINT32_MAX ||
            !unsigned_field(payload, "peerUid", &peer) || peer != 0 ||
            !unsigned_field(payload, "realtimeUSec", &copied_time) || copied_time != realtime ||
            !boolean_field(payload, "qualifiesForFreshness", &qualifies) ||
            !streq(string_field(payload, "evidenceQuality"), "declared"))
                return -EBADMSG;
        if (login) {
                uint64_t pid, leader, received_boot, received_real, completed_boot, completed_real;

                if (!streq(string_field(payload, "phase"), "login") ||
                    !streq(string_field(payload, "declaredMethod"), "pam-policy") ||
                    !streq(string_field(payload, "result"), "success") || !qualifies ||
                    !unsigned_field(payload, "peerPid", &pid) || pid == 0 || pid > INT32_MAX ||
                    !unsigned_field(payload, "sessionLeader", &leader) || leader != pid ||
                    !unsigned_field(payload, "receivedBoottimeUSec", &received_boot) ||
                    !unsigned_field(payload, "receivedRealtimeUSec", &received_real) ||
                    !unsigned_field(payload, "completedBoottimeUSec", &completed_boot) ||
                    !unsigned_field(payload, "completedRealtimeUSec", &completed_real) ||
                    boottime == 0 || realtime == 0 || received_boot < boottime || received_real < realtime ||
                    completed_boot < received_boot || completed_real < received_real ||
                    completed_boot - boottime >= UINT64_C(120000000) ||
                    completed_real - realtime >= UINT64_C(120000000))
                        return -EBADMSG;
                *ret_observed = completed_boot;
        } else {
                if ((!streq(string_field(payload, "phase"), "session") &&
                     !streq(string_field(payload, "phase"), "verify")) ||
                    (!streq(string_field(payload, "result"), "success") &&
                     !streq(string_field(payload, "result"), "failure")))
                        return -EBADMSG;
                if (qualifies && (!streq(string_field(payload, "phase"), "verify") ||
                                  !streq(string_field(payload, "pamService"), "platformd-verify") ||
                                  !streq(string_field(payload, "declaredMethod"), "platformd-verify") ||
                                  !streq(string_field(payload, "result"), "success")))
                        return -EBADMSG;
                *ret_observed = boottime;
        }
        return 0;
}

static int verification_payload(sd_json_variant *payload, uint64_t boottime, uint64_t realtime,
                                uint64_t *ret_observed) {
        static const char * const fields[] = {
                "user", "uid", "pamService", "tty", "remoteHost", "phase", "declaredMethod", "result",
                "sessionId", "qualifiesForFreshness", "realtimeUSec", "evidenceQuality", "peerUid",
                "context", "verificationBoottimeUSec", "verificationRealtimeUSec",
        };
        static const char * const context_fields[] = { "challengeHex", "audience", "operationDigestHex" };
        sd_json_variant *context;
        uint64_t uid, peer, copied_time, verification_boot, verification_real;
        bool qualifies;

        if (!object_fields(payload, fields, ELEMENTSOF(fields), true) ||
            !text_field(payload, "user", 256, false) || !text_field(payload, "sessionId", 256, false) ||
            !streq(string_field(payload, "pamService"), "platformd-verify") ||
            !streq(string_field(payload, "declaredMethod"), "platformd-verify") ||
            !streq(string_field(payload, "phase"), "verify") || !streq(string_field(payload, "result"), "success") ||
            !streq(string_field(payload, "tty"), "") || !streq(string_field(payload, "remoteHost"), "") ||
            !streq(string_field(payload, "evidenceQuality"), "declared") ||
            !unsigned_field(payload, "uid", &uid) || uid >= UINT32_MAX ||
            !unsigned_field(payload, "peerUid", &peer) || peer != 0 ||
            !unsigned_field(payload, "realtimeUSec", &copied_time) || copied_time != realtime ||
            !boolean_field(payload, "qualifiesForFreshness", &qualifies) || !qualifies ||
            !unsigned_field(payload, "verificationBoottimeUSec", &verification_boot) || verification_boot == 0 ||
            !unsigned_field(payload, "verificationRealtimeUSec", &verification_real) || verification_real == 0 ||
            verification_boot > boottime || boottime - verification_boot >= UINT64_C(120000000) ||
            verification_real > realtime || realtime - verification_real >= UINT64_C(120000000))
                return -EBADMSG;
        context = sd_json_variant_by_key(payload, "context");
        if (!object_fields(context, context_fields, ELEMENTSOF(context_fields), true) ||
            !text_field(context, "audience", 256, false))
                return -EBADMSG;
        for (const char *p = string_field(context, "audience"); *p; p++)
                if ((unsigned char) *p > 0x7e)
                        return -EBADMSG;
        for (size_t i = 0; i < ELEMENTSOF(context_fields); i += 2) {
                const char *hex = string_field(context, context_fields[i]);

                if (!hex || strlen(hex) != 64)
                        return -EBADMSG;
                for (size_t j = 0; j < 64; j++)
                        if (!((hex[j] >= '0' && hex[j] <= '9') || (hex[j] >= 'a' && hex[j] <= 'f')))
                                return -EBADMSG;
        }
        *ret_observed = boottime;
        return 0;
}

static int record_verify(sd_json_variant *record, uint64_t copied_time, char boot_id[33],
                         uint64_t *ret_observed) {
        static const char * const fields[] = {
                "format", "bootId", "boottimeUSec", "realtimeUSec", "type", "source", "evidenceQuality", "payload",
        };
        static const char * const lock_fields[] = { "sessionId", "lockState", "freshnessInvalidated" };
        static const char * const sleep_fields[] = { "preparationState", "freshnessInvalidated" };
        const char *boot, *type, *source, *quality, *state;
        sd_json_variant *payload;
        uint64_t boottime, realtime;
        bool nonzero = false, invalidated;

        if (!object_fields(record, fields, ELEMENTSOF(fields), true) ||
            !streq(string_field(record, "format"), "io.platformd.Trust.RuntimeEvent.v2") ||
            !unsigned_field(record, "boottimeUSec", &boottime) ||
            !unsigned_field(record, "realtimeUSec", &realtime) || realtime != copied_time)
                return -EBADMSG;
        boot = string_field(record, "bootId");
        if (!boot || strlen(boot) != 32)
                return -EBADMSG;
        for (size_t i = 0; i < 32; i++) {
                if (!((boot[i] >= '0' && boot[i] <= '9') || (boot[i] >= 'a' && boot[i] <= 'f')))
                        return -EBADMSG;
                nonzero |= boot[i] != '0';
        }
        if (!nonzero || (*boot_id && strcmp(boot_id, boot) != 0))
                return -EBADMSG;
        memcpy(boot_id, boot, 33);
        type = string_field(record, "type");
        source = string_field(record, "source");
        quality = string_field(record, "evidenceQuality");
        payload = sd_json_variant_by_key(record, "payload");
        if (streq(type, "authentication") && streq(quality, "declared")) {
                if (streq(source, "io.platformd.Trust.SubmitAuthEvent"))
                        return authentication_payload(payload, false, boottime, realtime, ret_observed);
                if (streq(source, "io.platformd.Trust.CompleteLoginAuthentication"))
                        return authentication_payload(payload, true, boottime, realtime, ret_observed);
                if (streq(source, "io.platformd.Trust.SubmitVerificationEvent"))
                        return verification_payload(payload, boottime, realtime, ret_observed);
                return -EBADMSG;
        }
        if (!streq(quality, "observed"))
                return -EBADMSG;
        if (streq(type, "lock-state") && streq(source, "org.freedesktop.login1.Session.LockedHint")) {
                if (!object_fields(payload, lock_fields, ELEMENTSOF(lock_fields), true) ||
                    !text_field(payload, "sessionId", 256, false) ||
                    !boolean_field(payload, "freshnessInvalidated", &invalidated))
                        return -EBADMSG;
                state = string_field(payload, "lockState");
                if ((!streq(state, "unknown") && !streq(state, "locked") && !streq(state, "unlocked")) ||
                    invalidated != !streq(state, "unlocked"))
                        return -EBADMSG;
        } else if (streq(type, "sleep-state") && streq(source, "org.freedesktop.login1.Manager.PrepareForSleep")) {
                if (!object_fields(payload, sleep_fields, ELEMENTSOF(sleep_fields), true) ||
                    !boolean_field(payload, "freshnessInvalidated", &invalidated) || !invalidated)
                        return -EBADMSG;
                state = string_field(payload, "preparationState");
                if (!streq(state, "unknown") && !streq(state, "preparing") && !streq(state, "finished"))
                        return -EBADMSG;
        } else
                return -EBADMSG;
        *ret_observed = boottime;
        return 0;
}

static int runtime_verify(sd_json_variant *runtime, const uint8_t current[32], size_t *ret_count) {
        static const char * const fields[] = { "description", "digest", "realtimeUSec" };
        sd_json_variant *events = sd_json_variant_by_key(runtime, "events");
        uint8_t value[32], input[64], expected[32];
        char boot_id[33] = {};
        uint64_t previous = 0;
        size_t count;
        int r;

        if (!sd_json_variant_is_array(events) ||
            unhex(string_field(runtime, "baseline"), value, sizeof value) != 32)
                return -EBADMSG;
        count = sd_json_variant_elements(events);
        if (count > EVENT_COUNT_MAX)
                return -E2BIG;
        for (size_t i = 0; i < count; i++) {
                sd_json_variant *event = sd_json_variant_by_index(events, i), *record = NULL;
                const char *description;
                JsonBudget budget = {};
                uint64_t copied_time, observed = 0;
                size_t size;

                if (!object_fields(event, fields, ELEMENTSOF(fields), true) ||
                    !unsigned_field(event, "realtimeUSec", &copied_time))
                        return -EBADMSG;
                description = string_field(event, "description");
                if (!description || !(size = strnlen(description, RECORD_SIZE_MAX + 1)))
                        return -EBADMSG;
                if (size > RECORD_SIZE_MAX)
                        return -E2BIG;
                r = sd_json_parse(description, 0, &record, NULL, NULL);
                if (r < 0)
                        return r;
                r = json_check(record, 0, &budget);
                if (r >= 0)
                        r = record_verify(record, copied_time, boot_id, &observed);
                sd_json_variant_unref(record);
                if (r < 0)
                        return r;
                if (observed < previous)
                        return -EBADMSG;
                previous = observed;
                memcpy(input, value, sizeof value);
                r = sha256((Bytes) { (const uint8_t *) description, size }, input + 32);
                if (r >= 0)
                        r = sha256((Bytes) { input, sizeof input }, value);
                if (r < 0)
                        return r;
                if (unhex(string_field(event, "digest"), expected, sizeof expected) != 32 ||
                    memcmp(value, expected, sizeof value) != 0)
                        return -EBADMSG;
        }
        if (memcmp(value, current, sizeof value) != 0)
                return -EBADMSG;
        *ret_count = count;
        return 0;
}

int attestation_verify(sd_json_variant *token, const char *expected_ak_hex, const char *nonce_hex,
                       sd_json_variant **ret_report) {
        static const char * const fields[] = { "profile", "nonceHex", "attestationKey", "localAssertions", "measurements" };
        static const char * const key_fields[] = { "tpm_ak" };
        static const char * const assertion_fields[] = { "machineId", "realtimeUSec", "secureBoot" };
        sd_json_variant *measurements, *key_object, *assertions, *quote = NULL, *boot = NULL, *runtime = NULL;
        uint8_t expected_key[256], encoded_key[256], nonce[64], envelope_nonce[64], current[32];
        uint8_t qualified_name[34];
        EVP_PKEY *key = NULL;
        AttestationIdentity identity;
        JsonBudget budget = {};
        size_t count = 0;
        uint64_t ignored;
        int expected_size, key_size, nonce_size, n, r;

        if (!ret_report)
                return -EINVAL;
        *ret_report = NULL;
        expected_size = unhex(expected_ak_hex, expected_key, sizeof expected_key);
        nonce_size = unhex(nonce_hex, nonce, sizeof nonce);
        if (expected_size <= 0 || nonce_size <= 0)
                return -EINVAL;
        r = json_check(token, 0, &budget);
        if (r < 0)
                return r;
        if (!object_fields(token, fields, ELEMENTSOF(fields), true) ||
            !streq(string_field(token, "profile"), "io.platformd.Trust.Attestation.v2"))
                return -EBADMSG;
        n = unhex(string_field(token, "nonceHex"), envelope_nonce, sizeof envelope_nonce);
        if (n != nonce_size || memcmp(nonce, envelope_nonce, (size_t) nonce_size) != 0)
                return -EBADMSG;
        key_object = sd_json_variant_by_key(token, "attestationKey");
        if (!object_fields(key_object, key_fields, ELEMENTSOF(key_fields), true))
                return -EBADMSG;
        key_size = unhex(string_field(key_object, "tpm_ak"), encoded_key, sizeof encoded_key);
        if (key_size < 0)
                return key_size;
        if (key_size != expected_size || memcmp(expected_key, encoded_key, (size_t) expected_size) != 0)
                return -EKEYREJECTED;
        assertions = sd_json_variant_by_key(token, "localAssertions");
        if (!object_fields(assertions, assertion_fields, ELEMENTSOF(assertion_fields), false) ||
            (sd_json_variant_by_key(assertions, "machineId") && !text_field(assertions, "machineId", 32, true)) ||
            (sd_json_variant_by_key(assertions, "secureBoot") && !text_field(assertions, "secureBoot", 64, true)) ||
            (sd_json_variant_by_key(assertions, "realtimeUSec") && !unsigned_field(assertions, "realtimeUSec", &ignored)))
                return -EBADMSG;
        measurements = sd_json_variant_by_key(token, "measurements");
        if (!sd_json_variant_is_array(measurements) || sd_json_variant_elements(measurements) != 3)
                return -EBADMSG;
        for (size_t i = 0; i < 3; i++) {
                sd_json_variant *entry = sd_json_variant_by_index(measurements, i);
                const char *type = string_field(entry, "type");

                if (streq(type, "tpm2-quote") && !quote)
                        quote = entry;
                else if (streq(type, "boot-pcrs") && !boot)
                        boot = entry;
                else if (streq(type, "nv-runtime-log") && !runtime)
                        runtime = entry;
                else
                        return -EBADMSG;
        }
        if (!quote || !boot || !runtime)
                return -EBADMSG;
        r = public_key((Bytes) { encoded_key, (size_t) key_size }, &key, qualified_name);
        if (r < 0)
                return r;
        r = quote_verify(key, quote, boot, (Bytes) { nonce, (size_t) nonce_size }, qualified_name, &identity);
        if (r >= 0)
                r = nv_verify(key, runtime, (Bytes) { nonce, (size_t) nonce_size }, qualified_name, &identity, current);
        if (r >= 0)
                r = runtime_verify(runtime, current, &count);
        EVP_PKEY_free(key);
        if (r < 0)
                return r;
        return sd_json_buildo(ret_report,
                              SD_JSON_BUILD_PAIR_STRING("profile", "io.platformd.Trust.AttestationVerification.v1"),
                              SD_JSON_BUILD_PAIR_BOOLEAN("expectedKeyMatched", true),
                              SD_JSON_BUILD_PAIR_BOOLEAN("nonceMatched", true),
                              SD_JSON_BUILD_PAIR_BOOLEAN("quoteSignatureVerified", true),
                              SD_JSON_BUILD_PAIR_BOOLEAN("nvSignatureVerified", true),
                              SD_JSON_BUILD_PAIR_BOOLEAN("pcrDigestVerified", true),
                              SD_JSON_BUILD_PAIR_BOOLEAN("nvPublicVerified", true),
                              SD_JSON_BUILD_PAIR_BOOLEAN("runtimeReplayVerified", true),
                              SD_JSON_BUILD_PAIR_UNSIGNED("retainedEvents", count));
}
