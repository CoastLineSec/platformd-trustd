/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "attestation-verify.h"

typedef struct Buffer {
        uint8_t data[4096];
        size_t size;
} Buffer;

typedef enum Fault {
        FAULT_NONE,
        FAULT_AK_ATTRIBUTES,
        FAULT_AK_POLICY,
        FAULT_AK_CURVE,
        FAULT_QUOTE_MAGIC,
        FAULT_QUOTE_TYPE,
        FAULT_QUOTE_SIGNER,
        FAULT_JOINT_SIGNER,
        FAULT_QUOTE_NONCE,
        FAULT_QUOTE_SAFE,
        FAULT_PCR_COUNT,
        FAULT_PCR_ALGORITHM,
        FAULT_PCR_SELECTION,
        FAULT_PCR_DIGEST,
        FAULT_NV_TYPE,
        FAULT_NV_SIGNER,
        FAULT_NV_NONCE,
        FAULT_NV_RESET,
        FAULT_NV_RESTART,
        FAULT_NV_FIRMWARE,
        FAULT_NV_CLOCK,
        FAULT_NV_SAFE,
        FAULT_NV_INDEX,
        FAULT_NV_ALGORITHM,
        FAULT_NV_ATTRIBUTES,
        FAULT_NV_POLICY,
        FAULT_NV_SIZE,
        FAULT_NV_NAME,
        FAULT_NV_OFFSET,
        FAULT_NV_VALUE,
        FAULT_RECORD_FORMAT,
        FAULT_RECORD_SOURCE,
        FAULT_RECORD_QUALITY,
        FAULT_RECORD_BOOT_ID,
        FAULT_RECORD_OTHER_BOOT,
        FAULT_RECORD_TIME,
        FAULT_RECORD_TIMESTAMP,
        FAULT_RECORD_PAYLOAD,
        FAULT_RECORD_DUPLICATE,
        FAULT_RECORD_ENCODING,
        FAULT_AUTH_PEER,
        FAULT_AUTH_UID,
        FAULT_AUTH_SERVICE,
        FAULT_AUTH_QUALITY,
        FAULT_AUTH_TIMESTAMP,
        FAULT_AUTH_REAL_UID,
        FAULT_LOGIN_LEADER,
        FAULT_LOGIN_RECEIVED,
        FAULT_LOGIN_COMPLETED,
        FAULT_LOGIN_EXPIRED,
        FAULT_LOGIN_RESULT,
        FAULT_SLEEP_INVALIDATION,
        FAULT_CONTEXT_CHALLENGE,
        FAULT_CONTEXT_DIGEST,
        FAULT_CONTEXT_AUDIENCE,
        FAULT_CONTEXT_EXTRA,
        FAULT_CONTEXT_DUPLICATE,
        FAULT_CONTEXT_BOOT_FUTURE,
        FAULT_CONTEXT_REAL_FUTURE,
        FAULT_CONTEXT_BOOT_ZERO,
        FAULT_CONTEXT_REAL_ZERO,
        FAULT_CONTEXT_TTY,
        FAULT_CONTEXT_SERVICE,
        FAULT_CONTEXT_RESULT,
        FAULT_CONTEXT_QUALITY,
        FAULT_CONTEXT_FRESHNESS,
        _FAULT_MAX,
        VALID_VERIFY_SUCCESS,
        VALID_VERIFY_FAILURE,
        VALID_LOGIN,
        VALID_DELAYED_LOGIN,
        VALID_SLEEP,
        VALID_UNSAFE_CLOCK,
        VALID_NV_UNWRITTEN,
        VALID_CONTEXT,
        VALID_UNLOCKED,
        VALID_OTHER_SESSION_LOCK,
        VALID_UNKNOWN_LOCK,
        VALID_CONTEXT_THEN_LOCK,
        VALID_CONTEXT_THEN_UNLOCK,
        VALID_CONTEXT_THEN_UNKNOWN,
        VALID_CONTEXT_THEN_OTHER_LOCK,
        VALID_CONTEXT_THEN_SLEEP,
        VALID_CONTEXT_AFTER_LOCK,
        VALID_CONTEXT_AFTER_SLEEP,
        VALID_CONTEXT_SLEEP_REAUTH,
        VALID_CONTEXT_LOCK_UNLOCK,
} Fault;

typedef struct Fixture {
        sd_json_variant *token;
        char *ak;
        char *nonce;
} Fixture;

typedef struct FixtureRequest {
        uint32_t uid;
        char session[257];
        char challenge[65];
        char audience[257];
        char operation[65];
} FixtureRequest;

static const FixtureRequest default_request = {
        .uid = 1000,
        .session = "fixture-session",
        .challenge = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        .audience = "https://service.example",
        .operation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

static unsigned accepted_tokens, rejected_tokens;

static void put(Buffer *b, const void *data, size_t size) {
        assert(size <= sizeof b->data - b->size);
        if (size > 0)
                memcpy(b->data + b->size, data, size);
        b->size += size;
}

static void number(Buffer *b, uint64_t n, size_t size) {
        assert(size > 0 && size <= sizeof n);
        for (size_t i = size; i > 0; i--) {
                uint8_t v = (uint8_t) (n >> (8 * (i - 1)));
                put(b, &v, 1);
        }
}

static void sized(Buffer *b, const void *data, size_t size) {
        assert(size <= UINT16_MAX);
        number(b, size, 2);
        put(b, data, size);
}

static void digest(const void *data, size_t size, uint8_t ret[32]) {
        size_t n = 32;

        assert(EVP_Q_digest(NULL, "SHA256", NULL, data, size, ret, &n) == 1);
        assert(n == 32);
}

static char *hex(const void *data, size_t size) {
        static const char digits[] = "0123456789abcdef";
        const uint8_t *p = data;
        char *s = malloc(size * 2 + 1);

        assert(s);
        for (size_t i = 0; i < size; i++) {
                s[i * 2] = digits[p[i] >> 4];
                s[i * 2 + 1] = digits[p[i] & 15];
        }
        s[size * 2] = 0;
        return s;
}

static void set_hex(sd_json_variant **object, const char *field, const void *data, size_t size) {
        char *s = hex(data, size);

        assert(sd_json_variant_set_field_string(object, field, s) >= 0);
        free(s);
}

static void set_signature(sd_json_variant **object, EVP_PKEY *key, const char *field, const Buffer *data) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        uint8_t der[128], r_bytes[32], s_bytes[32];
        size_t size = sizeof der;
        const unsigned char *p = der;
        const BIGNUM *r, *s;
        ECDSA_SIG *signature;
        Buffer b = {};

        assert(ctx);
        assert(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) == 1);
        assert(EVP_DigestSign(ctx, der, &size, data->data, data->size) == 1);
        signature = d2i_ECDSA_SIG(NULL, &p, (long) size);
        assert(signature && p == der + size);
        ECDSA_SIG_get0(signature, &r, &s);
        assert(BN_bn2binpad(r, r_bytes, sizeof r_bytes) == sizeof r_bytes);
        assert(BN_bn2binpad(s, s_bytes, sizeof s_bytes) == sizeof s_bytes);
        number(&b, 0x0018, 2);
        number(&b, 0x000b, 2);
        sized(&b, r_bytes, sizeof r_bytes);
        sized(&b, s_bytes, sizeof s_bytes);
        set_hex(object, field, b.data, b.size);
        ECDSA_SIG_free(signature);
        EVP_MD_CTX_free(ctx);
}

static Buffer public_key(EVP_PKEY *key, Fault fault, uint8_t signer[34]) {
        Buffer public = {}, wrapped = {}, name = {}, qualified = {};
        BIGNUM *x = NULL, *y = NULL;
        uint8_t coordinate[32], hash[32];

        assert(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) == 1);
        assert(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) == 1);
        number(&public, 0x0023, 2);
        number(&public, 0x000b, 2);
        number(&public, fault == FAULT_AK_ATTRIBUTES ? 0x00050070 : 0x00050072, 4);
        sized(&public, "x", fault == FAULT_AK_POLICY ? 1 : 0);
        number(&public, 0x0010, 2);
        number(&public, 0x0018, 2);
        number(&public, 0x000b, 2);
        number(&public, fault == FAULT_AK_CURVE ? 4 : 3, 2);
        number(&public, 0x0010, 2);
        assert(BN_bn2binpad(x, coordinate, sizeof coordinate) == sizeof coordinate);
        sized(&public, coordinate, sizeof coordinate);
        assert(BN_bn2binpad(y, coordinate, sizeof coordinate) == sizeof coordinate);
        sized(&public, coordinate, sizeof coordinate);
        sized(&wrapped, public.data, public.size);
        digest(public.data, public.size, hash);
        number(&name, 0x000b, 2);
        put(&name, hash, sizeof hash);
        number(&qualified, 0x40000001, 4);
        put(&qualified, name.data, name.size);
        signer[0] = 0;
        signer[1] = 0x0b;
        digest(qualified.data, qualified.size, signer + 2);
        BN_free(x);
        BN_free(y);
        return wrapped;
}

static Buffer header(bool nv, const uint8_t signer[34], const uint8_t nonce[32], Fault fault) {
        Buffer b = {};
        uint8_t local_signer[34], local_nonce[32];

        memcpy(local_signer, signer, sizeof local_signer);
        memcpy(local_nonce, nonce, sizeof local_nonce);
        if ((!nv && fault == FAULT_QUOTE_SIGNER) || (nv && fault == FAULT_NV_SIGNER))
                local_signer[nv ? 2 : 1] ^= 1;
        if (fault == FAULT_JOINT_SIGNER)
                local_signer[2] ^= 1;
        if ((!nv && fault == FAULT_QUOTE_NONCE) || (nv && fault == FAULT_NV_NONCE))
                local_nonce[0] ^= 1;
        number(&b, !nv && fault == FAULT_QUOTE_MAGIC ? 0xff544346 : 0xff544347, 4);
        number(&b, nv ? (fault == FAULT_NV_TYPE ? 0x8018 : 0x8014) :
                       (fault == FAULT_QUOTE_TYPE ? 0x8014 : 0x8018), 2);
        sized(&b, local_signer, sizeof local_signer);
        sized(&b, local_nonce, sizeof local_nonce);
        number(&b, nv ? (fault == FAULT_NV_CLOCK ? 99 : 101) : 100, 8);
        number(&b, nv && fault == FAULT_NV_RESET ? 2 : 1, 4);
        number(&b, nv && fault == FAULT_NV_RESTART ? 3 : 2, 4);
        number(&b, (!nv && fault == FAULT_QUOTE_SAFE) || (nv && fault == FAULT_NV_SAFE) ? 2 :
                   fault == VALID_UNSAFE_CLOCK ? 0 : 1, 1);
        number(&b, nv && fault == FAULT_NV_FIRMWARE ? 4 : 3, 8);
        return b;
}

static char *record(unsigned index, Fault fault, const FixtureRequest *request) {
        if (fault == VALID_CONTEXT_THEN_LOCK)
                fault = index == 0 ? VALID_CONTEXT : FAULT_NONE;
        else if (fault == VALID_CONTEXT_THEN_UNLOCK)
                fault = index == 0 ? VALID_CONTEXT : VALID_UNLOCKED;
        else if (fault == VALID_CONTEXT_THEN_UNKNOWN)
                fault = index == 0 ? VALID_CONTEXT : VALID_UNKNOWN_LOCK;
        else if (fault == VALID_CONTEXT_THEN_OTHER_LOCK)
                fault = index == 0 ? VALID_CONTEXT : VALID_OTHER_SESSION_LOCK;
        else if (fault == VALID_CONTEXT_THEN_SLEEP)
                fault = index == 0 ? VALID_CONTEXT : VALID_SLEEP;
        else if (fault == VALID_CONTEXT_AFTER_LOCK)
                fault = index == 0 ? FAULT_NONE : VALID_CONTEXT;
        else if (fault == VALID_CONTEXT_AFTER_SLEEP)
                fault = index == 0 ? VALID_SLEEP : VALID_CONTEXT;
        else if (fault == VALID_CONTEXT_SLEEP_REAUTH)
                fault = index == 1 ? VALID_SLEEP : VALID_CONTEXT;
        else if (fault == VALID_CONTEXT_LOCK_UNLOCK)
                fault = index == 0 ? VALID_CONTEXT : index == 1 ? FAULT_NONE : VALID_UNLOCKED;

        sd_json_variant *payload = NULL, *object = NULL;
        char *text = NULL;
        uint64_t boottime = index + 1;
        const char *boot_id = "0123456789abcdef0123456789abcdef";
        const char *type = "lock-state", *source = "org.freedesktop.login1.Session.LockedHint", *quality = "observed";
        bool login = fault == VALID_LOGIN || (fault == VALID_DELAYED_LOGIN && index == 1) ||
                     (fault >= FAULT_LOGIN_LEADER && fault <= FAULT_LOGIN_RESULT);
        bool context = fault == VALID_CONTEXT || (fault >= FAULT_CONTEXT_CHALLENGE && fault <= FAULT_CONTEXT_FRESHNESS);
        bool authentication = login || context || fault == VALID_VERIFY_SUCCESS || fault == VALID_VERIFY_FAILURE ||
                              (fault >= FAULT_AUTH_PEER && fault <= FAULT_AUTH_REAL_UID);

        if (fault == FAULT_RECORD_BOOT_ID)
                boot_id = "00000000000000000000000000000000";
        else if (fault == FAULT_RECORD_OTHER_BOOT && index == 1)
                boot_id = "1123456789abcdef0123456789abcdef";
        if (fault == FAULT_RECORD_TIME && index == 1)
                boottime = 0;
        if (fault == VALID_DELAYED_LOGIN)
                boottime = index == 1 ? 2 : index + 5;
        if (authentication) {
                type = "authentication";
                source = login ? "io.platformd.Trust.CompleteLoginAuthentication" :
                         context ? "io.platformd.Trust.SubmitVerificationEvent" : "io.platformd.Trust.SubmitAuthEvent";
                quality = "declared";
                assert(sd_json_buildo(&payload,
                                     SD_JSON_BUILD_PAIR_STRING("user", "fixture-user"),
                                     SD_JSON_BUILD_PAIR_UNSIGNED("uid", fault == FAULT_AUTH_UID ? UINT32_MAX : request->uid),
                                     SD_JSON_BUILD_PAIR_STRING("pamService", login ? "fixture-login" :
                                                              fault == FAULT_AUTH_SERVICE ? "other-service" : "platformd-verify"),
                                     SD_JSON_BUILD_PAIR_STRING("tty", "tty1"),
                                     SD_JSON_BUILD_PAIR_STRING("remoteHost", ""),
                                     SD_JSON_BUILD_PAIR_STRING("phase", login ? "login" : "verify"),
                                     SD_JSON_BUILD_PAIR_STRING("declaredMethod", login ? "pam-policy" : "platformd-verify"),
                                     SD_JSON_BUILD_PAIR_STRING("result", fault == VALID_VERIFY_FAILURE || fault == FAULT_LOGIN_RESULT ?
                                                              "failure" : "success"),
                                     SD_JSON_BUILD_PAIR_STRING("sessionId", request->session),
                                     SD_JSON_BUILD_PAIR_BOOLEAN("qualifiesForFreshness", fault != VALID_VERIFY_FAILURE),
                                     SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", fault == FAULT_AUTH_TIMESTAMP ? 0 : 1000000 + index),
                                     SD_JSON_BUILD_PAIR_STRING("evidenceQuality", fault == FAULT_AUTH_QUALITY ? "verified" : "declared"),
                                     SD_JSON_BUILD_PAIR_UNSIGNED("peerUid", fault == FAULT_AUTH_PEER ? 1000 : 0)) >= 0);
                if (fault == FAULT_AUTH_REAL_UID) {
                        sd_json_variant *uid = NULL;

                        assert(sd_json_variant_new_real(&uid, 1000.0) >= 0);
                        assert(sd_json_variant_set_field(&payload, "uid", uid) >= 0);
                        sd_json_variant_unref(uid);
                }
                if (login) {
                        assert(sd_json_variant_set_field_unsigned(&payload, "peerPid", 1234) >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "sessionLeader", fault == FAULT_LOGIN_LEADER ? 1235 : 1234) >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "receivedBoottimeUSec",
                                                                 fault == FAULT_LOGIN_RECEIVED ? 0 : boottime + 1) >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "receivedRealtimeUSec", 1000001 + index) >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "completedBoottimeUSec",
                                                                 fault == FAULT_LOGIN_COMPLETED ? boottime :
                                                                 fault == FAULT_LOGIN_EXPIRED ? boottime + 120000000 :
                                                                 fault == VALID_DELAYED_LOGIN ? 6 : boottime + 2) >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "completedRealtimeUSec", 1000002 + index) >= 0);
                }
                if (context) {
                        sd_json_variant *value = NULL;

                        assert(sd_json_buildo(&value,
                                             SD_JSON_BUILD_PAIR_STRING("challengeHex", fault == FAULT_CONTEXT_CHALLENGE ? "01" :
                                                                      request->challenge),
                                             SD_JSON_BUILD_PAIR_STRING("audience", fault == FAULT_CONTEXT_AUDIENCE ? "\n" : request->audience),
                                             SD_JSON_BUILD_PAIR_STRING("operationDigestHex", fault == FAULT_CONTEXT_DIGEST ? "not-hex" :
                                                                      request->operation)) >= 0);
                        if (fault == FAULT_CONTEXT_EXTRA)
                                assert(sd_json_variant_set_field_string(&value, "extra", "") >= 0);
                        if (fault == FAULT_CONTEXT_DUPLICATE) {
                                value = sd_json_variant_unref(value);
                                assert(sd_json_parse("{\"challengeHex\":\"\",\"challengeHex\":\"\",\"audience\":\"x\",\"operationDigestHex\":\"\"}",
                                                     0, &value, NULL, NULL) >= 0);
                        }
                        assert(sd_json_variant_set_field(&payload, "context", value) >= 0);
                        sd_json_variant_unref(value);
                        assert(sd_json_variant_set_field_string(&payload, "tty", fault == FAULT_CONTEXT_TTY ? "tty1" : "") >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "verificationBoottimeUSec",
                                                                 fault == FAULT_CONTEXT_BOOT_ZERO ? 0 : boottime + (fault == FAULT_CONTEXT_BOOT_FUTURE)) >= 0);
                        assert(sd_json_variant_set_field_unsigned(&payload, "verificationRealtimeUSec",
                                                                 fault == FAULT_CONTEXT_REAL_ZERO ? 0 : 1000000 + index + (fault == FAULT_CONTEXT_REAL_FUTURE)) >= 0);
                        if (fault == FAULT_CONTEXT_SERVICE)
                                assert(sd_json_variant_set_field_string(&payload, "pamService", "other") >= 0);
                        if (fault == FAULT_CONTEXT_RESULT)
                                assert(sd_json_variant_set_field_string(&payload, "result", "failure") >= 0);
                        if (fault == FAULT_CONTEXT_QUALITY)
                                assert(sd_json_variant_set_field_string(&payload, "evidenceQuality", "verified") >= 0);
                        if (fault == FAULT_CONTEXT_FRESHNESS)
                                assert(sd_json_variant_set_field_boolean(&payload, "qualifiesForFreshness", false) >= 0);
                }
        } else if (fault == VALID_SLEEP || fault == FAULT_SLEEP_INVALIDATION) {
                type = "sleep-state";
                source = "org.freedesktop.login1.Manager.PrepareForSleep";
                assert(sd_json_buildo(&payload,
                                     SD_JSON_BUILD_PAIR_STRING("preparationState", index == 0 ? "preparing" : "finished"),
                                     SD_JSON_BUILD_PAIR_BOOLEAN("freshnessInvalidated", fault != FAULT_SLEEP_INVALIDATION)) >= 0);
        } else
                assert(sd_json_buildo(&payload,
                                     SD_JSON_BUILD_PAIR_STRING("sessionId", fault == VALID_OTHER_SESSION_LOCK ? "other-session" : request->session),
                                     SD_JSON_BUILD_PAIR_STRING("lockState", fault == FAULT_RECORD_PAYLOAD ? "yes" :
                                                              fault == VALID_UNLOCKED ? "unlocked" :
                                                              fault == VALID_UNKNOWN_LOCK ? "unknown" : "locked"),
                                     SD_JSON_BUILD_PAIR_BOOLEAN("freshnessInvalidated", fault != VALID_UNLOCKED)) >= 0);
        assert(sd_json_buildo(&object,
                             SD_JSON_BUILD_PAIR_STRING("format", fault == FAULT_RECORD_FORMAT ?
                                                      "io.platformd.Trust.RuntimeEvent.v1" : "io.platformd.Trust.RuntimeEvent.v2"),
                             SD_JSON_BUILD_PAIR_STRING("bootId", boot_id),
                             SD_JSON_BUILD_PAIR_UNSIGNED("boottimeUSec", boottime),
                             SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", 1000000 + index),
                             SD_JSON_BUILD_PAIR_STRING("type", type),
                             SD_JSON_BUILD_PAIR_STRING("source", fault == FAULT_RECORD_SOURCE ?
                                                      "untrusted" : source),
                             SD_JSON_BUILD_PAIR_STRING("evidenceQuality", fault == FAULT_RECORD_QUALITY ? "measured" : quality),
                             SD_JSON_BUILD_PAIR_VARIANT("payload", payload)) >= 0);
        assert(sd_json_variant_format(object, 0, &text) >= 0);
        if (fault == FAULT_RECORD_DUPLICATE) {
                size_t n = strlen(text);
                char *copy = malloc(n + sizeof ",\"type\":\"lock-state\"}");

                assert(copy);
                memcpy(copy, text, n - 1);
                strcpy(copy + n - 1, ",\"type\":\"lock-state\"}");
                free(text);
                text = copy;
        } else if (fault == FAULT_RECORD_ENCODING)
                text[0] = '[';
        sd_json_variant_unref(object);
        sd_json_variant_unref(payload);
        return text;
}

static Fixture fixture_new_full(EVP_PKEY *key, unsigned n_events, Fault fault, const FixtureRequest *request) {
        sd_json_variant *quote = NULL, *boot = NULL, *runtime = NULL, *pcrs = NULL, *events = NULL;
        sd_json_variant *measurements = NULL, *ak = NULL, *local = NULL;
        uint8_t signer[34], nonce[32], pcr_values[16][32], hash[32], current[32], baseline[32];
        uint8_t nv_name[34], selected[3] = { 0xff, 0xff, 0 };
        Buffer public, q, nv, nv_public = {}, wrapped = {};
        Fixture f = {};

        for (unsigned i = 0; i < sizeof nonce; i++) {
                unsigned value;

                assert(sscanf(request->challenge + i * 2, "%2x", &value) == 1);
                nonce[i] = (uint8_t) value;
        }
        memset(baseline, 0xa5, sizeof baseline);
        memcpy(current, baseline, sizeof current);
        public = public_key(key, fault, signer);
        f.ak = hex(public.data, public.size);
        f.nonce = hex(nonce, sizeof nonce);
        assert(sd_json_variant_new_array(&events, NULL, 0) >= 0);
        for (unsigned i = 0; i < n_events; i++) {
                sd_json_variant *event = NULL;
                uint8_t input[64];
                char *description = record(i, fault, request);

                memcpy(input, current, sizeof current);
                digest(description, strlen(description), input + 32);
                digest(input, sizeof input, current);
                assert(sd_json_buildo(&event,
                                     SD_JSON_BUILD_PAIR_STRING("description", description),
                                     SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", fault == FAULT_RECORD_TIMESTAMP ? 0 : 1000000 + i)) >= 0);
                set_hex(&event, "digest", current, sizeof current);
                assert(sd_json_variant_append_array(&events, event) >= 0);
                sd_json_variant_unref(event);
                free(description);
        }
        for (unsigned i = 0; i < 16; i++) {
                sd_json_variant *pcr = NULL;

                for (unsigned j = 0; j < 32; j++)
                        pcr_values[i][j] = (uint8_t) (i * 17 + j);
                assert(sd_json_buildo(&pcr, SD_JSON_BUILD_PAIR_UNSIGNED("index", i)) >= 0);
                set_hex(&pcr, "sha256", pcr_values[i], 32);
                assert(sd_json_variant_append_array(&pcrs, pcr) >= 0);
                sd_json_variant_unref(pcr);
        }
        digest(pcr_values, sizeof pcr_values, hash);
        if (fault == FAULT_PCR_DIGEST)
                hash[0] ^= 1;
        if (fault == FAULT_PCR_SELECTION)
                selected[2] = 1;
        q = header(false, signer, nonce, fault);
        number(&q, fault == FAULT_PCR_COUNT ? 2 : 1, 4);
        number(&q, fault == FAULT_PCR_ALGORITHM ? 4 : 0x000b, 2);
        number(&q, sizeof selected, 1);
        put(&q, selected, sizeof selected);
        sized(&q, hash, sizeof hash);
        assert(sd_json_buildo(&quote, SD_JSON_BUILD_PAIR_STRING("type", "tpm2-quote"),
                             SD_JSON_BUILD_PAIR_STRING("pcrBank", "sha256")) >= 0);
        set_hex(&quote, "quoted", q.data, q.size);
        set_signature(&quote, key, "signature", &q);
        assert(sd_json_buildo(&boot, SD_JSON_BUILD_PAIR_STRING("type", "boot-pcrs"),
                             SD_JSON_BUILD_PAIR_STRING("quality", "observed"),
                             SD_JSON_BUILD_PAIR_VARIANT("pcrs", pcrs)) >= 0);
        number(&nv_public, fault == FAULT_NV_INDEX ? 0x01800002 : 0x01800001, 4);
        number(&nv_public, fault == FAULT_NV_ALGORITHM ? 4 : 0x000b, 2);
        number(&nv_public, fault == FAULT_NV_ATTRIBUTES ? 0x2a060044 :
                           fault == VALID_NV_UNWRITTEN ? 0x0a060046 : 0x2a060046, 4);
        sized(&nv_public, "x", fault == FAULT_NV_POLICY ? 1 : 0);
        number(&nv_public, fault == FAULT_NV_SIZE ? 31 : 32, 2);
        sized(&wrapped, nv_public.data, nv_public.size);
        nv_name[0] = 0;
        nv_name[1] = 0x0b;
        digest(nv_public.data, nv_public.size, nv_name + 2);
        if (fault == FAULT_NV_NAME)
                nv_name[2] ^= 1;
        nv = header(true, signer, nonce, fault);
        sized(&nv, nv_name, sizeof nv_name);
        number(&nv, fault == FAULT_NV_OFFSET ? 1 : 0, 2);
        memcpy(hash, current, sizeof hash);
        if (fault == FAULT_NV_VALUE)
                hash[0] ^= 1;
        sized(&nv, hash, sizeof hash);
        assert(sd_json_buildo(&runtime,
                             SD_JSON_BUILD_PAIR_STRING("type", "nv-runtime-log"),
                             SD_JSON_BUILD_PAIR_STRING("format", "io.platformd.Trust.RuntimeLog.v2"),
                             SD_JSON_BUILD_PAIR_STRING("nvIndex", "0x01800001"),
                             SD_JSON_BUILD_PAIR_VARIANT("events", events)) >= 0);
        set_hex(&runtime, "baseline", baseline, sizeof baseline);
        set_hex(&runtime, "current", current, sizeof current);
        set_hex(&runtime, "nvPublicHex", wrapped.data, wrapped.size);
        set_hex(&runtime, "certifyInfo", nv.data, nv.size);
        set_signature(&runtime, key, "signature", &nv);
        assert(sd_json_variant_append_array(&measurements, quote) >= 0);
        assert(sd_json_variant_append_array(&measurements, boot) >= 0);
        assert(sd_json_variant_append_array(&measurements, runtime) >= 0);
        assert(sd_json_buildo(&ak, SD_JSON_BUILD_PAIR_STRING("tpm_ak", f.ak)) >= 0);
        assert(sd_json_buildo(&local,
                             SD_JSON_BUILD_PAIR_STRING("machineId", "1123456789abcdef0123456789abcdef"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", 42),
                             SD_JSON_BUILD_PAIR_STRING("secureBoot", "enabled")) >= 0);
        assert(sd_json_buildo(&f.token,
                             SD_JSON_BUILD_PAIR_STRING("profile", "io.platformd.Trust.Attestation.v2"),
                             SD_JSON_BUILD_PAIR_STRING("nonceHex", f.nonce),
                             SD_JSON_BUILD_PAIR_VARIANT("attestationKey", ak),
                             SD_JSON_BUILD_PAIR_VARIANT("localAssertions", local),
                             SD_JSON_BUILD_PAIR_VARIANT("measurements", measurements)) >= 0);
        sd_json_variant_unref(quote);
        sd_json_variant_unref(boot);
        sd_json_variant_unref(runtime);
        sd_json_variant_unref(pcrs);
        sd_json_variant_unref(events);
        sd_json_variant_unref(measurements);
        sd_json_variant_unref(ak);
        sd_json_variant_unref(local);
        return f;
}

static Fixture fixture_new(EVP_PKEY *key, unsigned n_events, Fault fault) {
        return fixture_new_full(key, n_events, fault, &default_request);
}

static void fixture_done(Fixture *f) {
        sd_json_variant_unref(f->token);
        free(f->ak);
        free(f->nonce);
}

static sd_json_variant *at(sd_json_variant *v, const char *path) {
        char field[64];
        const char *slash = strchr(path, '/');
        size_t n = slash ? (size_t) (slash - path) : strlen(path);

        assert(n < sizeof field);
        memcpy(field, path, n);
        field[n] = 0;
        v = sd_json_variant_is_array(v) ? sd_json_variant_by_index(v, strtoul(field, NULL, 10)) :
                                        sd_json_variant_by_key(v, field);
        assert(v);
        return slash ? at(v, slash + 1) : v;
}

static sd_json_variant *replace(sd_json_variant *v, const char *path, sd_json_variant *value) {
        sd_json_variant *result = NULL, *child;
        char field[64];
        const char *slash = strchr(path, '/');
        size_t n = slash ? (size_t) (slash - path) : strlen(path);

        assert(n < sizeof field);
        memcpy(field, path, n);
        field[n] = 0;
        child = slash ? replace(at(v, field), slash + 1, value) : sd_json_variant_ref(value);
        if (sd_json_variant_is_array(v)) {
                size_t count = sd_json_variant_elements(v), index = strtoul(field, NULL, 10);
                sd_json_variant **items = calloc(count, sizeof *items);

                assert(items && index < count);
                for (size_t i = 0; i < count; i++)
                        items[i] = i == index ? child : sd_json_variant_by_index(v, i);
                assert(sd_json_variant_new_array(&result, items, count) >= 0);
                free(items);
        } else {
                result = sd_json_variant_ref(v);
                assert(sd_json_variant_set_field(&result, field, child) >= 0);
        }
        sd_json_variant_unref(child);
        return result;
}

static void rejected(sd_json_variant *token, const char *key, const char *nonce) {
        sd_json_variant *report = NULL;

        assert(attestation_verify(token, key, nonce, &report) < 0);
        assert(!report);
        rejected_tokens++;
}

static void rejected_value(const Fixture *f, const char *path, sd_json_variant *value) {
        sd_json_variant *token = replace(f->token, path, value);

        rejected(token, f->ak, f->nonce);
        sd_json_variant_unref(token);
}

static void rejected_string(const Fixture *f, const char *path, const char *value) {
        sd_json_variant *v = NULL;

        assert(sd_json_variant_new_string(&v, value) >= 0);
        rejected_value(f, path, v);
        sd_json_variant_unref(v);
}

static sd_json_variant *accepted(const Fixture *f, unsigned n_events) {
        static const char *const fields[] = {
                "expectedKeyMatched", "nonceMatched", "quoteSignatureVerified", "nvSignatureVerified",
                "pcrDigestVerified", "nvPublicVerified", "runtimeReplayVerified",
        };
        sd_json_variant *report = NULL;

        assert(attestation_verify(f->token, f->ak, f->nonce, &report) == 0);
        assert(sd_json_variant_is_object(report));
        assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "profile")),
                      "io.platformd.Trust.AttestationVerification.v1") == 0);
        for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
                sd_json_variant *v = sd_json_variant_by_key(report, fields[i]);

                assert(sd_json_variant_is_boolean(v) && sd_json_variant_boolean(v));
        }
        assert(sd_json_variant_unsigned(sd_json_variant_by_key(report, "retainedEvents")) == n_events);
        accepted_tokens++;
        return report;
}

static void test_positive(EVP_PKEY *key) {
        static const Fault variants[] = {
                VALID_VERIFY_SUCCESS, VALID_VERIFY_FAILURE, VALID_LOGIN, VALID_DELAYED_LOGIN,
                VALID_SLEEP, VALID_UNSAFE_CLOCK, VALID_NV_UNWRITTEN, VALID_CONTEXT,
        };

        for (unsigned n = 0; n <= 3; n++) {
                Fixture f = fixture_new(key, n, FAULT_NONE);
                sd_json_variant *report = accepted(&f, n);

                sd_json_variant_unref(report);
                fixture_done(&f);
        }
        for (size_t i = 0; i < sizeof variants / sizeof variants[0]; i++) {
                Fixture f = fixture_new(key, 3, variants[i]);
                sd_json_variant *report = accepted(&f, 3);

                sd_json_variant_unref(report);
                fixture_done(&f);
        }
}

static void test_signed_invalid(EVP_PKEY *key) {
        for (Fault fault = FAULT_NONE + 1; fault < _FAULT_MAX; fault++) {
                Fixture f = fixture_new(key, 3, fault);
                sd_json_variant *report = NULL;
                int r = attestation_verify(f.token, f.ak, f.nonce, &report);

                if (r >= 0)
                        fprintf(stderr, "Accepted invalid signed fixture: %u\n", (unsigned) fault);
                assert(r < 0 && !report);
                rejected_tokens++;
                fixture_done(&f);
        }
}

static void test_mutations(EVP_PKEY *key) {
        static const struct {
                const char *path;
                const char *value;
        } strings[] = {
                { "profile", "io.platformd.Trust.Attestation.v1" },
                { "nonceHex", "00" },
                { "attestationKey/tpm_ak", "00" },
                { "measurements/0/type", "boot-pcrs" },
                { "measurements/0/pcrBank", "sha1" },
                { "measurements/1/pcrs/0/sha256", "0000000000000000000000000000000000000000000000000000000000000000" },
                { "measurements/2/format", "io.platformd.Trust.RuntimeLog.v1" },
                { "measurements/2/nvIndex", "0x01800002" },
                { "measurements/2/baseline", "0000000000000000000000000000000000000000000000000000000000000000" },
                { "measurements/2/current", "0000000000000000000000000000000000000000000000000000000000000000" },
                { "measurements/2/events/0/digest", "0000000000000000000000000000000000000000000000000000000000000000" },
                { "measurements/2/events/0/description", "{}" },
                { "measurements/2/events/0/realtimeUSec", "1000000" },
        };
        Fixture f = fixture_new(key, 3, FAULT_NONE);
        EVP_PKEY *other_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        Fixture other;
        sd_json_variant *v = NULL;
        char large[1025];

        assert(other_key);
        other = fixture_new(other_key, 3, FAULT_NONE);
        rejected(f.token, other.ak, f.nonce);
        rejected(f.token, NULL, f.nonce);
        rejected(f.token, "", f.nonce);
        rejected(f.token, f.ak, NULL);
        rejected(f.token, f.ak, "");
        rejected(f.token, f.ak, "00");
        rejected(NULL, f.ak, f.nonce);
        memset(large, '0', sizeof large - 1);
        large[sizeof large - 1] = 0;
        rejected(f.token, large, f.nonce);
        rejected(f.token, f.ak, large);
        rejected(f.token, "gg", f.nonce);
        rejected(f.token, f.ak, "gg");
        rejected_value(&f, "measurements/0/signature", at(other.token, "measurements/0/signature"));
        rejected_value(&f, "measurements/2/signature", at(other.token, "measurements/2/signature"));
        for (size_t i = 0; i < sizeof strings / sizeof strings[0]; i++)
                rejected_string(&f, strings[i].path, strings[i].value);
        assert(sd_json_variant_new_unsigned(&v, 1) >= 0);
        rejected_value(&f, "measurements/1/pcrs/0/index", v);
        sd_json_variant_unref(v);
        fixture_done(&other);
        EVP_PKEY_free(other_key);
        fixture_done(&f);
}

static void rejected_binary(const Fixture *f, const char *path, const char *value) {
        sd_json_variant *v = NULL, *token;

        assert(sd_json_variant_new_string(&v, value) >= 0);
        token = replace(f->token, path, v);
        rejected(token, strcmp(path, "attestationKey/tpm_ak") == 0 ? value : f->ak, f->nonce);
        sd_json_variant_unref(token);
        sd_json_variant_unref(v);
}

static void test_binary_bounds(EVP_PKEY *key) {
        static const char *const paths[] = {
                "attestationKey/tpm_ak", "measurements/0/quoted", "measurements/0/signature",
                "measurements/2/nvPublicHex", "measurements/2/certifyInfo", "measurements/2/signature",
        };
        Fixture f = fixture_new(key, 1, FAULT_NONE);
        char large[8193];

        memset(large, '0', sizeof large - 1);
        large[sizeof large - 1] = 0;

        for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) {
                const char *value = sd_json_variant_string(at(f.token, paths[i]));
                size_t n = strlen(value);
                char *copy = malloc(n + 3);

                assert(copy);
                memcpy(copy, value, n + 1);
                for (size_t j = 0; j < n; j++) {
                        copy[j] = 0;
                        rejected_binary(&f, paths[i], copy);
                        copy[j] = value[j];
                }
                memcpy(copy + n, "00", 3);
                rejected_binary(&f, paths[i], copy);
                copy[n] = 0;
                copy[0] = 'g';
                rejected_binary(&f, paths[i], copy);
                memcpy(copy, value, n + 1);
                copy[n - 1] = copy[n - 1] == '0' ? '1' : '0';
                rejected_binary(&f, paths[i], copy);
                rejected_binary(&f, paths[i], large);
                free(copy);
        }
        fixture_done(&f);
}

static void test_event_order(EVP_PKEY *key) {
        Fixture f = fixture_new(key, 3, FAULT_NONE);
        sd_json_variant *events = at(f.token, "measurements/2/events"), *array = NULL;
        sd_json_variant *items[4];

        for (size_t i = 0; i < 3; i++)
                items[i] = sd_json_variant_by_index(events, i);
        assert(sd_json_variant_new_array(&array, items, 2) >= 0);
        rejected_value(&f, "measurements/2/events", array);
        array = sd_json_variant_unref(array);
        items[3] = items[2];
        assert(sd_json_variant_new_array(&array, items, 4) >= 0);
        rejected_value(&f, "measurements/2/events", array);
        array = sd_json_variant_unref(array);
        items[0] = sd_json_variant_by_index(events, 1);
        items[1] = sd_json_variant_by_index(events, 0);
        assert(sd_json_variant_new_array(&array, items, 3) >= 0);
        rejected_value(&f, "measurements/2/events", array);
        sd_json_variant_unref(array);
        fixture_done(&f);
}

static void test_array_order(EVP_PKEY *key) {
        Fixture f = fixture_new(key, 1, FAULT_NONE);
        sd_json_variant *items[16], *array = NULL, *token, *report;

        for (size_t i = 0; i < 16; i++)
                items[i] = sd_json_variant_by_index(at(f.token, "measurements/1/pcrs"), 15 - i);
        assert(sd_json_variant_new_array(&array, items, 16) >= 0);
        token = replace(f.token, "measurements/1/pcrs", array);
        sd_json_variant_unref(f.token);
        f.token = token;
        array = sd_json_variant_unref(array);
        report = accepted(&f, 1);
        sd_json_variant_unref(report);
        for (size_t i = 0; i < 3; i++)
                items[i] = sd_json_variant_by_index(at(f.token, "measurements"), 2 - i);
        assert(sd_json_variant_new_array(&array, items, 3) >= 0);
        token = replace(f.token, "measurements", array);
        sd_json_variant_unref(f.token);
        f.token = token;
        sd_json_variant_unref(array);
        report = accepted(&f, 1);
        sd_json_variant_unref(report);
        fixture_done(&f);
}

static void test_json_bounds(EVP_PKEY *key) {
        Fixture f = fixture_new(key, 1, FAULT_NONE);
        sd_json_variant *duplicate = NULL, *deep = NULL, *next = NULL, *array = NULL;
        sd_json_variant *items[1025];
        char *text = NULL, *copy, *large;
        size_t n;

        assert(sd_json_variant_format(f.token, 0, &text) >= 0);
        n = strlen(text);
        copy = malloc(n + sizeof ",\"nonceHex\":\"00\"}");
        assert(copy);
        memcpy(copy, text, n - 1);
        strcpy(copy + n - 1, ",\"nonceHex\":\"00\"}");
        assert(sd_json_parse(copy, 0, &duplicate, NULL, NULL) >= 0);
        rejected(duplicate, f.ak, f.nonce);
        sd_json_variant_unref(duplicate);
        free(copy);
        free(text);
        assert(sd_json_parse("{\"secureBoot\":\"enabled\",\"secureBoot\":\"disabled\"}",
                             0, &duplicate, NULL, NULL) >= 0);
        rejected_value(&f, "localAssertions", duplicate);
        sd_json_variant_unref(duplicate);
        large = malloc(8194);
        assert(large);
        memset(large, 'x', 8193);
        large[8193] = 0;
        rejected_string(&f, "measurements/2/events/0/description", large);
        free(large);
        for (size_t i = 0; i < sizeof items / sizeof items[0]; i++)
                items[i] = at(f.token, "measurements/2/events/0");
        assert(sd_json_variant_new_array(&array, items, sizeof items / sizeof items[0]) >= 0);
        rejected_value(&f, "measurements/2/events", array);
        sd_json_variant_unref(array);
        assert(sd_json_variant_new_unsigned(&deep, 1) >= 0);
        for (unsigned i = 0; i < 33; i++) {
                assert(sd_json_buildo(&next, SD_JSON_BUILD_PAIR_VARIANT("nested", deep)) >= 0);
                sd_json_variant_unref(deep);
                deep = next;
                next = NULL;
        }
        rejected_value(&f, "localAssertions", deep);
        sd_json_variant_unref(deep);
        fixture_done(&f);
}

static void test_unsigned_assertions(EVP_PKEY *key) {
        Fixture f = fixture_new(key, 1, FAULT_NONE);
        sd_json_variant *before = accepted(&f, 1), *after, *value = NULL, *token;

        assert(sd_json_buildo(&value,
                             SD_JSON_BUILD_PAIR_STRING("machineId", "unverified machine identity"),
                             SD_JSON_BUILD_PAIR_UNSIGNED("realtimeUSec", UINT64_MAX),
                             SD_JSON_BUILD_PAIR_STRING("secureBoot", "unverified Secure Boot state")) >= 0);
        token = replace(f.token, "localAssertions", value);
        sd_json_variant_unref(f.token);
        f.token = token;
        value = sd_json_variant_unref(value);
        assert(sd_json_variant_new_string(&value, "unverified PCR quality") >= 0);
        token = replace(f.token, "measurements/1/quality", value);
        sd_json_variant_unref(f.token);
        f.token = token;
        after = accepted(&f, 1);
        assert(sd_json_variant_equal(before, after));
        assert(!sd_json_variant_by_key(after, "secureBoot"));
        assert(!sd_json_variant_by_key(after, "machineId"));
        assert(!sd_json_variant_by_key(after, "policySatisfied"));
        assert(!sd_json_variant_by_key(after, "authenticated"));
        sd_json_variant_unref(before);
        sd_json_variant_unref(after);
        sd_json_variant_unref(value);
        fixture_done(&f);
}

static bool object_fields(sd_json_variant *object, const char *const *fields, size_t n) {
        if (!sd_json_variant_is_object(object) || sd_json_variant_elements(object) != n * 2)
                return false;
        for (size_t i = 0; i < n; i++)
                if (!sd_json_variant_by_key(object, fields[i]))
                        return false;
        return true;
}

static bool request_string(sd_json_variant *object, const char *field, char *ret, size_t capacity, bool hex_value) {
        sd_json_variant *value = sd_json_variant_by_key(object, field);
        const char *s;
        size_t n;

        if (!sd_json_variant_is_string(value))
                return false;
        s = sd_json_variant_string(value);
        n = strlen(s);
        if (n == 0 || n >= capacity || (hex_value && n != 64))
                return false;
        for (size_t i = 0; i < n; i++)
                if (hex_value ? !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')) :
                    (unsigned char) s[i] < 0x20 || (unsigned char) s[i] > 0x7e)
                        return false;
        memcpy(ret, s, n + 1);
        return true;
}

static bool request_parse(sd_json_variant *value, FixtureRequest *ret) {
        static const char *const fields[] = { "uid", "sessionId", "context" };
        static const char *const context_fields[] = { "challengeHex", "audience", "operationDigestHex" };
        FixtureRequest request = {};
        sd_json_variant *uid, *context;

        if (!object_fields(value, fields, sizeof fields / sizeof fields[0]))
                return false;
        uid = sd_json_variant_by_key(value, "uid");
        if ((sd_json_variant_type(uid) != SD_JSON_VARIANT_INTEGER && sd_json_variant_type(uid) != SD_JSON_VARIANT_UNSIGNED) ||
            !sd_json_variant_is_unsigned(uid) || sd_json_variant_unsigned(uid) >= UINT32_MAX)
                return false;
        request.uid = (uint32_t) sd_json_variant_unsigned(uid);
        context = sd_json_variant_by_key(value, "context");
        if (!object_fields(context, context_fields, sizeof context_fields / sizeof context_fields[0]) ||
            !request_string(value, "sessionId", request.session, sizeof request.session, false) ||
            !request_string(context, "challengeHex", request.challenge, sizeof request.challenge, true) ||
            !request_string(context, "audience", request.audience, sizeof request.audience, false) ||
            !request_string(context, "operationDigestHex", request.operation, sizeof request.operation, true))
                return false;
        *ret = request;
        return true;
}

static char *read_fixture_input(const char *path) {
        char *text = malloc(65537);
        size_t size = 0;
        struct stat st;
        int fd;

        assert(text);
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0);
        assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 && st.st_size <= 65536);
        for (;;) {
                ssize_t n = read(fd, text + size, 65537 - size);

                if (n < 0 && errno == EINTR)
                        continue;
                assert(n >= 0);
                if (n == 0)
                        break;
                size += (size_t) n;
                assert(size <= 65536);
        }
        assert(close(fd) == 0);
        assert(size > 0 && !memchr(text, 0, size));
        text[size] = 0;
        return text;
}

static EVP_PKEY *read_fixture_key(const char *path) {
        char *text = read_fixture_input(path), group[32];
        BIO *bio = BIO_new_mem_buf(text, (int) strlen(text));
        EVP_PKEY_CTX *context;
        EVP_PKEY *key;
        size_t n;

        assert(bio);
        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *) "");
        assert(key && EVP_PKEY_is_a(key, "EC") == 1);
        assert(EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &n) == 1);
        assert(strcmp(group, "prime256v1") == 0);
        context = EVP_PKEY_CTX_new(key, NULL);
        assert(context && EVP_PKEY_private_check(context) == 1);
        while (BIO_read(bio, group, 1) == 1)
                assert(group[0] == ' ' || group[0] == '\t' || group[0] == '\r' || group[0] == '\n');
        EVP_PKEY_CTX_free(context);
        BIO_free(bio);
        free(text);
        return key;
}

static FILE *fixture_output(int dirfd, const char *name) {
        int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        FILE *out;

        assert(fd >= 0);
        out = fdopen(fd, "w");
        assert(out);
        return out;
}

static void write_fixture_key(EVP_PKEY *key, const char *directory) {
        uint8_t signer[34];
        Buffer public = public_key(key, FAULT_NONE, signer);
        char *ak = hex(public.data, public.size);
        FILE *out;
        int dirfd;

        dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(dirfd >= 0);
        out = fixture_output(dirfd, "key.pem");
        assert(PEM_write_PrivateKey(out, key, NULL, NULL, 0, NULL, NULL) == 1);
        assert(fclose(out) == 0);
        out = fixture_output(dirfd, "ak.hex");
        assert(fputs(ak, out) >= 0);
        assert(fclose(out) == 0);
        assert(close(dirfd) == 0);
        free(ak);
}

static void write_fixture_full(EVP_PKEY *key, const char *directory, Fault fault, const FixtureRequest *request) {
        Fixture f = fixture_new_full(key, 3, fault, request);
        char *text = NULL;
        const char *names[] = { "token.json", "ak.hex", "nonce.hex" };
        const char *values[3];
        int dirfd;

        assert(sd_json_variant_format(f.token, SD_JSON_FORMAT_NEWLINE, &text) >= 0);
        values[0] = text;
        values[1] = f.ak;
        values[2] = f.nonce;
        dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(dirfd >= 0);
        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
                FILE *out = fixture_output(dirfd, names[i]);

                assert(fputs(values[i], out) >= 0);
                assert(fclose(out) == 0);
        }
        assert(close(dirfd) == 0);
        free(text);
        fixture_done(&f);
}

static void write_fixture(EVP_PKEY *key, const char *directory, Fault fault) {
        write_fixture_full(key, directory, fault, &default_request);
}

static void write_request_fixture(EVP_PKEY *key, const char *directory, const char *request_path) {
        char *text = read_fixture_input(request_path);
        sd_json_variant *value = NULL;
        FixtureRequest request;

        assert(sd_json_parse(text, 0, &value, NULL, NULL) >= 0);
        assert(request_parse(value, &request));
        write_fixture_full(key, directory, VALID_CONTEXT, &request);
        sd_json_variant_unref(value);
        free(text);
}

static void test_request_fixture(EVP_PKEY *key) {
        static const char *const invalid[] = { "", "\n", "\x7f", "\xc3\xa9" };
        static const char *const fields[] = { "challengeHex", "audience", "operationDigestHex" };
        sd_json_variant *value = NULL, *context = NULL, *report = NULL, *copy = NULL, *number = NULL;
        FixtureRequest request;
        Fixture f;
        char large[258];
        char *text = NULL, *duplicate = NULL;

        assert(sd_json_buildo(&context,
                             SD_JSON_BUILD_PAIR_STRING("challengeHex", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                             SD_JSON_BUILD_PAIR_STRING("audience", "https://verifier.example"),
                             SD_JSON_BUILD_PAIR_STRING("operationDigestHex", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")) >= 0);
        assert(sd_json_buildo(&value,
                             SD_JSON_BUILD_PAIR_UNSIGNED("uid", 42),
                             SD_JSON_BUILD_PAIR_STRING("sessionId", "request-session"),
                             SD_JSON_BUILD_PAIR_VARIANT("context", context)) >= 0);
        assert(request_parse(value, &request));
        assert(request.uid == 42 && strcmp(request.session, "request-session") == 0);
        f = fixture_new_full(key, 3, VALID_CONTEXT, &request);
        assert(strcmp(f.nonce, request.challenge) == 0);
        assert(attestation_verify(f.token, f.ak, request.challenge, &report) == 0);
        for (size_t i = 0; i < 3; i++) {
                sd_json_variant *record = NULL, *payload, *events = at(f.token, "measurements/2/events");
                const char *description = sd_json_variant_string(at(sd_json_variant_by_index(events, i), "description"));

                assert(sd_json_parse(description, 0, &record, NULL, NULL) >= 0);
                payload = sd_json_variant_by_key(record, "payload");
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(payload, "uid")) == request.uid);
                assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(payload, "sessionId")), request.session) == 0);
                assert(sd_json_variant_equal(sd_json_variant_by_key(payload, "context"), context));
                sd_json_variant_unref(record);
        }
        fixture_done(&f);
        assert(!request_parse(NULL, &request));
        assert(!request_parse(context, &request));
        assert(sd_json_variant_format(value, 0, &text) >= 0);
        assert(asprintf(&duplicate, "%.*s,\"uid\":42}", (int) strlen(text) - 1, text) >= 0);
        assert(sd_json_parse(duplicate, 0, &copy, NULL, NULL) >= 0);
        assert(!request_parse(copy, &request));
        copy = sd_json_variant_unref(copy);
        free(duplicate);
        free(text);
        text = NULL;
        assert(sd_json_variant_format(context, 0, &text) >= 0);
        assert(asprintf(&duplicate, "%.*s,\"audience\":\"https://verifier.example\"}", (int) strlen(text) - 1, text) >= 0);
        assert(sd_json_parse(duplicate, 0, &copy, NULL, NULL) >= 0);
        assert(sd_json_variant_set_field(&value, "context", copy) >= 0);
        assert(!request_parse(value, &request));
        assert(sd_json_variant_set_field(&value, "context", context) >= 0);
        copy = sd_json_variant_unref(copy);
        free(duplicate);
        free(text);
        copy = sd_json_variant_ref(value);
        assert(sd_json_variant_set_field_unsigned(&copy, "uid", UINT32_MAX) >= 0);
        assert(!request_parse(copy, &request));
        assert(sd_json_variant_set_field_unsigned(&copy, "uid", UINT32_MAX - 1) >= 0);
        assert(request_parse(copy, &request));
        assert(sd_json_variant_new_real(&number, 42.0) >= 0);
        assert(sd_json_variant_set_field(&copy, "uid", number) >= 0);
        assert(!request_parse(copy, &request));
        sd_json_variant_unref(copy);
        copy = sd_json_variant_ref(value);
        assert(sd_json_variant_set_field_boolean(&copy, "extra", true) >= 0);
        assert(!request_parse(copy, &request));
        sd_json_variant_unref(copy);
        memset(large, 'a', sizeof large - 1);
        large[sizeof large - 1] = 0;
        for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++)
                for (size_t j = 0; j < sizeof invalid / sizeof invalid[0] + 1; j++) {
                        sd_json_variant *bad_context = sd_json_variant_ref(context);

                        copy = sd_json_variant_ref(value);
                        assert(sd_json_variant_set_field_string(&bad_context, fields[i],
                                                                j < sizeof invalid / sizeof invalid[0] ? invalid[j] : large) >= 0);
                        assert(sd_json_variant_set_field(&copy, "context", bad_context) >= 0);
                        assert(!request_parse(copy, &request));
                        sd_json_variant_unref(bad_context);
                        sd_json_variant_unref(copy);
                }
        for (size_t i = 0; i < sizeof invalid / sizeof invalid[0] + 1; i++) {
                copy = sd_json_variant_ref(value);
                assert(sd_json_variant_set_field_string(&copy, "sessionId",
                                                        i < sizeof invalid / sizeof invalid[0] ? invalid[i] : large) >= 0);
                assert(!request_parse(copy, &request));
                sd_json_variant_unref(copy);
        }
        sd_json_variant_unref(number);
        sd_json_variant_unref(report);
        sd_json_variant_unref(context);
        sd_json_variant_unref(value);
}

int main(int argc, char **argv) {
        bool request_fixture = argc == 5 && strcmp(argv[1], "--write-request-fixture") == 0;
        EVP_PKEY *key = request_fixture ? read_fixture_key(argv[3]) : EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");

        assert(key);
        if (request_fixture)
                write_request_fixture(key, argv[2], argv[4]);
        else if (argc == 3 && strcmp(argv[1], "--write-request-key") == 0)
                write_fixture_key(key, argv[2]);
        else if (argc == 3 && strcmp(argv[1], "--write-fixture") == 0)
                write_fixture(key, argv[2], FAULT_NONE);
        else if (argc == 3 && strcmp(argv[1], "--write-context-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT);
        else if (argc == 3 && strcmp(argv[1], "--write-context-lock-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_THEN_LOCK);
        else if (argc == 3 && strcmp(argv[1], "--write-context-unlock-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_THEN_UNLOCK);
        else if (argc == 3 && strcmp(argv[1], "--write-context-unknown-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_THEN_UNKNOWN);
        else if (argc == 3 && strcmp(argv[1], "--write-context-other-lock-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_THEN_OTHER_LOCK);
        else if (argc == 3 && strcmp(argv[1], "--write-context-sleep-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_THEN_SLEEP);
        else if (argc == 3 && strcmp(argv[1], "--write-lock-context-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_AFTER_LOCK);
        else if (argc == 3 && strcmp(argv[1], "--write-sleep-context-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_AFTER_SLEEP);
        else if (argc == 3 && strcmp(argv[1], "--write-context-sleep-context-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_SLEEP_REAUTH);
        else if (argc == 3 && strcmp(argv[1], "--write-context-lock-unlock-fixture") == 0)
                write_fixture(key, argv[2], VALID_CONTEXT_LOCK_UNLOCK);
        else if (argc == 2 && strcmp(argv[1], "--fixture") == 0) {
                Fixture f = fixture_new(key, 3, FAULT_NONE);
                char *text = NULL;

                assert(sd_json_variant_format(f.token, SD_JSON_FORMAT_NEWLINE, &text) >= 0);
                assert(fputs(text, stdout) >= 0);
                free(text);
                fixture_done(&f);
        } else {
                assert(argc == 1);
                test_positive(key);
                test_signed_invalid(key);
                test_mutations(key);
                test_binary_bounds(key);
                test_event_order(key);
                test_array_order(key);
                test_json_bounds(key);
                test_unsigned_assertions(key);
                test_request_fixture(key);
                printf("Accepted %u valid tokens; rejected %u invalid tokens.\n", accepted_tokens, rejected_tokens);
        }
        EVP_PKEY_free(key);
        return 0;
}
