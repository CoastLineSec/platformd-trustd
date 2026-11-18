/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <systemd/sd-json.h>

#include "endorsement.h"

#define ROOT_DP "https://ca.example.invalid/root.crl"
#define ISSUER_DP "https://ca.example.invalid/issuer.crl"
#define OTHER_DP "https://ca.example.invalid/other.crl"

typedef enum CertificateMode {
        CERTIFICATE_VALID,
        CERTIFICATE_EXPIRED,
        CERTIFICATE_FUTURE,
        CERTIFICATE_CA,
        CERTIFICATE_WRONG_EKU,
        CERTIFICATE_MISSING_EKU,
        CERTIFICATE_WRONG_USAGE,
        CERTIFICATE_MISSING_USAGE,
        CERTIFICATE_MISSING_SAN,
        CERTIFICATE_INCOMPLETE_SAN,
        CERTIFICATE_NONCRITICAL_SAN,
        CERTIFICATE_UNKNOWN_CRITICAL,
        CERTIFICATE_WRONG_KEY,
        CERTIFICATE_BAD_SIGNATURE,
        CERTIFICATE_DUPLICATE_EKU,
} CertificateMode;

typedef enum RevocationMode {
        REVOCATION_VALID,
        REVOCATION_EXPIRED,
        REVOCATION_FUTURE,
        REVOCATION_REVOKED,
        REVOCATION_BAD_SIGNATURE,
        REVOCATION_WRONG_SCOPE,
        REVOCATION_DELTA,
        REVOCATION_PARTIAL,
        REVOCATION_UNKNOWN_CRITICAL,
} RevocationMode;

typedef struct Fixture {
        EVP_PKEY *root_key, *issuer_key, *ek_key, *ak_key;
        X509 *root, *issuer, *leaf;
        X509_CRL *root_crl, *issuer_crl;
        char *root_pem, *chain_pem;
        sd_json_variant *evidence, *revocations;
        unsigned certificate_count;
} Fixture;

typedef struct Buffer {
        uint8_t data[512];
        size_t size;
} Buffer;

static unsigned tests;

static void hex_encode(const void *data, size_t size, char *ret) {
        static const char digits[] = "0123456789abcdef";
        const uint8_t *bytes = data;

        for (size_t i = 0; i < size; i++) {
                ret[2 * i] = digits[bytes[i] >> 4];
                ret[2 * i + 1] = digits[bytes[i] & 15];
        }
        ret[2 * size] = 0;
}

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

static void public_make(EVP_PKEY *key, bool endorsement, char ret[static 513], char *ret_name) {
        static const uint8_t policy[] = {
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
                0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
                0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
                0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
        };
        uint8_t point[65], name[34] = { 0, 0x0b };
        size_t size = sizeof point;
        Buffer b = {};

        assert(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point, &size) == 1);
        assert(size == sizeof point);
        put_number(&b, 0, 2);
        put_number(&b, 0x23, 2);
        put_number(&b, 0x0b, 2);
        put_number(&b, endorsement ? 0x300b2 : 0x50072, 4);
        put_number(&b, endorsement ? sizeof policy : 0, 2);
        if (endorsement) {
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
        if (ret_name) {
                assert(EVP_Q_digest(NULL, "SHA256", NULL, b.data + 2, b.size - 2, name + 2, NULL) == 1);
                hex_encode(name, sizeof name, ret_name);
        }
}

static char *bio_string(BIO *bio) {
        char *data, *ret;
        long size = BIO_get_mem_data(bio, &data);

        assert(size >= 0);
        ret = strndup(data, (size_t) size);
        assert(ret);
        return ret;
}

static char *certificate_pem(X509 *certificate) {
        BIO *bio = BIO_new(BIO_s_mem());
        char *ret;

        assert(bio && PEM_write_bio_X509(bio, certificate) == 1);
        ret = bio_string(bio);
        BIO_free(bio);
        return ret;
}

static char *crl_pem(X509_CRL *crl) {
        BIO *bio = BIO_new(BIO_s_mem());
        char *ret;

        assert(bio && PEM_write_bio_X509_CRL(bio, crl) == 1);
        ret = bio_string(bio);
        BIO_free(bio);
        return ret;
}

static void certificate_extension(X509 *certificate, X509 *issuer, int nid, const char *value) {
        X509V3_CTX context;
        X509_EXTENSION *extension;

        X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
        extension = X509V3_EXT_conf_nid(NULL, &context, nid, value);
        assert(extension && X509_add_ext(certificate, extension, -1) == 1);
        X509_EXTENSION_free(extension);
}

static void name_entry(X509_NAME *name, const char *oid, const char *value) {
        ASN1_OBJECT *object = OBJ_txt2obj(oid, 1);

        assert(object && X509_NAME_add_entry_by_OBJ(name, object, MBSTRING_UTF8,
                                                  (const unsigned char *) value, -1, -1, 0) == 1);
        ASN1_OBJECT_free(object);
}

static void certificate_san(X509 *certificate, CertificateMode mode) {
        GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
        GENERAL_NAME *entry = GENERAL_NAME_new();
        X509_NAME *name = X509_NAME_new();

        assert(names && entry && name);
        name_entry(name, "2.23.133.2.1", "id:494E5443");
        name_entry(name, "2.23.133.2.2", "Test TPM");
        if (mode != CERTIFICATE_INCOMPLETE_SAN)
                name_entry(name, "2.23.133.2.3", "id:00010000");
        GENERAL_NAME_set0_value(entry, GEN_DIRNAME, name);
        assert(sk_GENERAL_NAME_push(names, entry) == 1);
        assert(X509_add1_ext_i2d(certificate, NID_subject_alt_name, names,
                                 mode != CERTIFICATE_NONCRITICAL_SAN, X509V3_ADD_DEFAULT) == 1);
        GENERAL_NAMES_free(names);
}

static X509 *certificate_make(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key,
                              long serial, const char *subject, const char *distribution_point,
                              CertificateMode mode) {
        X509 *certificate = X509_new();
        X509_NAME *name;
        char dp[256];
        bool ca = subject != NULL || mode == CERTIFICATE_CA;

        assert(certificate);
        assert(X509_set_version(certificate, 2) == 1);
        assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial) == 1);
        assert(X509_gmtime_adj(X509_getm_notBefore(certificate), mode == CERTIFICATE_FUTURE ? 3600 : -3600));
        assert(X509_gmtime_adj(X509_getm_notAfter(certificate), mode == CERTIFICATE_EXPIRED ? -60 : 86400));
        assert(X509_set_pubkey(certificate, key) == 1);
        name = X509_NAME_new();
        assert(name);
        if (subject)
                assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                                  (const unsigned char *) subject, -1, -1, 0) == 1);
        assert(X509_set_subject_name(certificate, name) == 1);
        assert(X509_set_issuer_name(certificate, issuer ? X509_get_subject_name(issuer) : name) == 1);
        X509_NAME_free(name);
        certificate_extension(certificate, issuer ?: certificate, NID_basic_constraints,
                              ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
        if (mode != CERTIFICATE_MISSING_USAGE)
                certificate_extension(certificate, issuer ?: certificate, NID_key_usage,
                                      ca ? "critical,keyCertSign,cRLSign" :
                                      mode == CERTIFICATE_WRONG_USAGE ? "critical,digitalSignature" : "critical,keyAgreement");
        certificate_extension(certificate, issuer ?: certificate, NID_subject_key_identifier, "hash");
        certificate_extension(certificate, issuer ?: certificate, NID_authority_key_identifier, "keyid:always");
        if (!subject) {
                if (mode != CERTIFICATE_MISSING_EKU) {
                        certificate_extension(certificate, issuer, NID_ext_key_usage,
                                              mode == CERTIFICATE_WRONG_EKU ? "serverAuth" : "2.23.133.8.1");
                        if (mode == CERTIFICATE_DUPLICATE_EKU)
                                certificate_extension(certificate, issuer, NID_ext_key_usage, "2.23.133.8.1");
                }
                if (mode != CERTIFICATE_MISSING_SAN)
                        certificate_san(certificate, mode);
        }
        if (distribution_point) {
                assert(snprintf(dp, sizeof dp, "URI:%s", distribution_point) > 0);
                certificate_extension(certificate, issuer, NID_crl_distribution_points, dp);
        }
        if (mode == CERTIFICATE_UNKNOWN_CRITICAL) {
                ASN1_OBJECT *object = OBJ_txt2obj("1.3.6.1.4.1.55555.99", 1);
                ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
                X509_EXTENSION *extension;

                assert(object && value && ASN1_OCTET_STRING_set(value, (const unsigned char *) "\x05\x00", 2) == 1);
                extension = X509_EXTENSION_create_by_OBJ(NULL, object, 1, value);
                assert(extension && X509_add_ext(certificate, extension, -1) == 1);
                X509_EXTENSION_free(extension);
                ASN1_OCTET_STRING_free(value);
                ASN1_OBJECT_free(object);
        }
        assert(X509_sign(certificate, issuer_key ?: key, EVP_sha256()) > 0);
        return certificate;
}

static X509_CRL *crl_make(X509 *issuer, EVP_PKEY *key, X509 *revoked, RevocationMode mode) {
        X509_CRL *crl = X509_CRL_new();
        ASN1_TIME *last = ASN1_TIME_new(), *next = ASN1_TIME_new();
        ASN1_INTEGER *number = ASN1_INTEGER_new();
        AUTHORITY_KEYID *authority = AUTHORITY_KEYID_new();

        assert(crl && last && next && number && authority);
        assert(X509_CRL_set_version(crl, 1) == 1);
        assert(X509_CRL_set_issuer_name(crl, X509_get_subject_name(issuer)) == 1);
        assert(X509_gmtime_adj(last, mode == REVOCATION_FUTURE ? 3600 : -3600));
        assert(X509_gmtime_adj(next, mode == REVOCATION_EXPIRED ? -60 : 86400));
        assert(X509_CRL_set1_lastUpdate(crl, last) == 1 && X509_CRL_set1_nextUpdate(crl, next) == 1);
        assert(ASN1_INTEGER_set(number, 1) == 1);
        assert(X509_CRL_add1_ext_i2d(crl, NID_crl_number, number, 0, X509V3_ADD_DEFAULT) == 1);
        authority->keyid = X509_get_ext_d2i(issuer, NID_subject_key_identifier, NULL, NULL);
        assert(authority->keyid);
        assert(X509_CRL_add1_ext_i2d(crl, NID_authority_key_identifier, authority, 0, X509V3_ADD_DEFAULT) == 1);
        if (mode == REVOCATION_REVOKED) {
                X509_REVOKED *entry = X509_REVOKED_new();
                ASN1_TIME *when = ASN1_TIME_new();

                assert(entry && when && X509_gmtime_adj(when, -60));
                assert(X509_REVOKED_set_serialNumber(entry, X509_get_serialNumber(revoked)) == 1);
                assert(X509_REVOKED_set_revocationDate(entry, when) == 1);
                assert(X509_CRL_add0_revoked(crl, entry) == 1);
                ASN1_TIME_free(when);
        }
        if (mode == REVOCATION_DELTA)
                assert(X509_CRL_add1_ext_i2d(crl, NID_delta_crl, number, 1, X509V3_ADD_DEFAULT) == 1);
        if (mode == REVOCATION_PARTIAL) {
                ISSUING_DIST_POINT *point = ISSUING_DIST_POINT_new();

                assert(point);
                point->onlysomereasons = ASN1_BIT_STRING_new();
                assert(point->onlysomereasons && ASN1_BIT_STRING_set_bit(point->onlysomereasons, 1, 1) == 1);
                assert(X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point, point, 1, X509V3_ADD_DEFAULT) == 1);
                ISSUING_DIST_POINT_free(point);
        }
        if (mode == REVOCATION_WRONG_SCOPE) {
                ISSUING_DIST_POINT *point = ISSUING_DIST_POINT_new();
                GENERAL_NAME *name = GENERAL_NAME_new();
                ASN1_IA5STRING *uri = ASN1_IA5STRING_new();

                assert(point && name && uri);
                point->distpoint = DIST_POINT_NAME_new();
                assert(point->distpoint);
                point->distpoint->type = 0;
                point->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
                assert(point->distpoint->name.fullname);
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
                assert(ASN1_STRING_set1_string(uri, OTHER_DP) == 1);
#else
                assert(ASN1_STRING_set(uri, OTHER_DP, -1) == 1);
#endif
                GENERAL_NAME_set0_value(name, GEN_URI, uri);
                assert(sk_GENERAL_NAME_push(point->distpoint->name.fullname, name) == 1);
                assert(X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point, point, 1, X509V3_ADD_DEFAULT) == 1);
                ISSUING_DIST_POINT_free(point);
        }
        if (mode == REVOCATION_UNKNOWN_CRITICAL) {
                ASN1_OBJECT *object = OBJ_txt2obj("1.3.6.1.4.1.55555.99", 1);
                ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
                X509_EXTENSION *extension;

                assert(object && value && ASN1_OCTET_STRING_set(value, (const unsigned char *) "\x05\x00", 2) == 1);
                extension = X509_EXTENSION_create_by_OBJ(NULL, object, 1, value);
                assert(extension && X509_CRL_add_ext(crl, extension, -1) == 1);
                X509_EXTENSION_free(extension);
                ASN1_OCTET_STRING_free(value);
                ASN1_OBJECT_free(object);
        }
        assert(X509_CRL_sort(crl) == 1 && X509_CRL_sign(crl, key, EVP_sha256()) > 0);
        AUTHORITY_KEYID_free(authority);
        ASN1_INTEGER_free(number);
        ASN1_TIME_free(last);
        ASN1_TIME_free(next);
        return crl;
}

static sd_json_variant *revocations_make(X509_CRL *root, X509_CRL *issuer, const char *issuer_dp) {
        sd_json_variant *result = NULL;
        char *root_pem = crl_pem(root), *issuer_pem = crl_pem(issuer);

        assert(sd_json_buildo(&result,
                             SD_JSON_BUILD_PAIR("crls", SD_JSON_BUILD_ARRAY(
                                     SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING("distributionPoint", ROOT_DP),
                                                          SD_JSON_BUILD_PAIR_STRING("pem", root_pem)),
                                     SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING("distributionPoint", issuer_dp),
                                                          SD_JSON_BUILD_PAIR_STRING("pem", issuer_pem))))) >= 0);
        free(root_pem);
        free(issuer_pem);
        return result;
}

static sd_json_variant *evidence_make(EVP_PKEY *ek, EVP_PKEY *ak, X509 *certificate) {
        sd_json_variant *evidence = NULL;
        unsigned char *der = NULL;
        char ek_hex[513], ak_hex[513], name[69], *cert_hex;
        int size;

        public_make(ek, true, ek_hex, NULL);
        public_make(ak, false, ak_hex, name);
        size = i2d_X509(certificate, &der);
        assert(size > 0);
        cert_hex = malloc((size_t) size * 2 + 1);
        assert(cert_hex);
        hex_encode(der, (size_t) size, cert_hex);
        assert(sd_json_buildo(&evidence,
                             SD_JSON_BUILD_PAIR_STRING("ekPublicHex", ek_hex),
                             SD_JSON_BUILD_PAIR_STRING("ekCertHex", cert_hex),
                             SD_JSON_BUILD_PAIR_STRING("akPublicHex", ak_hex),
                             SD_JSON_BUILD_PAIR_STRING("akNameHex", name),
                             SD_JSON_BUILD_PAIR_STRING("evidenceQuality", "measured")) >= 0);
        OPENSSL_free(der);
        free(cert_hex);
        return evidence;
}

static Fixture fixture_make(CertificateMode certificate_mode, RevocationMode revocation_mode) {
        Fixture f = {};

        f.root_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        f.issuer_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        f.ek_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        f.ak_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
        assert(f.root_key && f.issuer_key && f.ek_key && f.ak_key);
        f.root = certificate_make(f.root_key, NULL, NULL, 1, "Test Endorsement Root", NULL, CERTIFICATE_VALID);
        f.issuer = certificate_make(f.issuer_key, f.root, f.root_key, 2, "Test Endorsement Issuer", ROOT_DP, CERTIFICATE_VALID);
        f.leaf = certificate_make(certificate_mode == CERTIFICATE_WRONG_KEY ? f.ak_key : f.ek_key,
                                  f.issuer, certificate_mode == CERTIFICATE_BAD_SIGNATURE ? f.root_key : f.issuer_key,
                                  3, NULL, ISSUER_DP, certificate_mode);
        f.root_crl = crl_make(f.root, f.root_key, f.issuer, REVOCATION_VALID);
        f.issuer_crl = crl_make(f.issuer, revocation_mode == REVOCATION_BAD_SIGNATURE ? f.root_key : f.issuer_key,
                               f.leaf, revocation_mode);
        f.root_pem = certificate_pem(f.root);
        f.chain_pem = certificate_pem(f.issuer);
        f.evidence = evidence_make(f.ek_key, f.ak_key, f.leaf);
        f.revocations = revocations_make(f.root_crl, f.issuer_crl, ISSUER_DP);
        f.certificate_count = 3;
        return f;
}

static void fixture_clear(Fixture *f) {
        sd_json_variant_unref(f->evidence);
        sd_json_variant_unref(f->revocations);
        free(f->root_pem);
        free(f->chain_pem);
        X509_CRL_free(f->root_crl);
        X509_CRL_free(f->issuer_crl);
        X509_free(f->root);
        X509_free(f->issuer);
        X509_free(f->leaf);
        EVP_PKEY_free(f->root_key);
        EVP_PKEY_free(f->issuer_key);
        EVP_PKEY_free(f->ek_key);
        EVP_PKEY_free(f->ak_key);
}

static void verify(Fixture *f, bool success, const char *description) {
        sd_json_variant *report = NULL;
        struct timespec before, after;
        int r;

        assert(clock_gettime(CLOCK_REALTIME, &before) == 0);
        r = endorsement_verify(f->evidence, f->root_pem, f->chain_pem, f->revocations, &report);

        if ((r >= 0) != success) {
                fprintf(stderr, "%s: expected %s, got %d (%s)\n", description,
                        success ? "acceptance" : "rejection", r, r < 0 ? strerror(-r) : "success");
                abort();
        }
        assert(success ? sd_json_variant_is_object(report) : !report);
        if (success) {
                uint8_t hash[32];
                char encoded[65];
                unsigned char *der = NULL;
                uint64_t checked;
                int size;

                assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "profile")),
                              "io.platformd.Trust.EndorsementVerification.v1") == 0);
                assert(sd_json_variant_boolean(sd_json_variant_by_key(report, "endorsementKeyMatched")));
                assert(sd_json_variant_boolean(sd_json_variant_by_key(report, "certificateChainVerified")));
                assert(sd_json_variant_boolean(sd_json_variant_by_key(report, "revocationChecked")));
                assert(sd_json_variant_unsigned(sd_json_variant_by_key(report, "certificateCount")) == f->certificate_count);
                size = i2d_X509(f->leaf, &der);
                assert(size > 0 && EVP_Q_digest(NULL, "SHA256", NULL, der, (size_t) size, hash, NULL) == 1);
                hex_encode(hash, sizeof hash, encoded);
                assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "certificateSha256")), encoded) == 0);
                OPENSSL_free(der);
                der = NULL;
                size = i2d_X509(f->root, &der);
                assert(size > 0 && EVP_Q_digest(NULL, "SHA256", NULL, der, (size_t) size, hash, NULL) == 1);
                hex_encode(hash, sizeof hash, encoded);
                assert(strcmp(sd_json_variant_string(sd_json_variant_by_key(report, "anchorSha256")), encoded) == 0);
                OPENSSL_free(der);
                assert(clock_gettime(CLOCK_REALTIME, &after) == 0);
                checked = sd_json_variant_unsigned(sd_json_variant_by_key(report, "checkedAtRealtimeUSec"));
                assert(checked >= (uint64_t) before.tv_sec * 1000000 &&
                       checked <= (uint64_t) after.tv_sec * 1000000 + (uint64_t) after.tv_nsec / 1000);
        }
        sd_json_variant_unref(report);
        tests++;
}

static void test_certificates(void) {
        static const char * const descriptions[] = {
                "valid chain", "expired leaf", "future leaf", "CA leaf", "wrong EKU", "missing EKU",
                "wrong key usage", "missing key usage", "missing SAN", "incomplete SAN", "noncritical SAN",
                "unknown critical extension", "wrong EK", "wrong certificate signature", "duplicate EKU",
        };

        for (size_t i = 0; i < sizeof descriptions / sizeof descriptions[0]; i++) {
                Fixture f = fixture_make((CertificateMode) i, REVOCATION_VALID);

                verify(&f, i == CERTIFICATE_VALID || i == CERTIFICATE_MISSING_EKU, descriptions[i]);
                fixture_clear(&f);
        }
}

static void test_revocations(void) {
        static const char * const descriptions[] = {
                "current CRLs", "expired CRL", "future CRL", "revoked EK", "wrong CRL signature", "wrong CRL scope",
                "delta CRL", "partitioned CRL", "unknown critical CRL extension",
        };
        Fixture f;
        sd_json_variant *saved, *empty = NULL;
        X509_CRL *revoked;

        for (size_t i = 0; i < sizeof descriptions / sizeof descriptions[0]; i++) {
                f = fixture_make(CERTIFICATE_VALID, (RevocationMode) i);
                verify(&f, i == REVOCATION_VALID, descriptions[i]);
                fixture_clear(&f);
        }
        f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
        saved = f.revocations;
        f.revocations = NULL;
        verify(&f, false, "absent CRL policy");
        assert(sd_json_buildo(&empty, SD_JSON_BUILD_PAIR("crls", SD_JSON_BUILD_EMPTY_ARRAY)) >= 0);
        f.revocations = empty;
        verify(&f, false, "missing CRLs");
        sd_json_variant_unref(empty);
        f.revocations = revocations_make(f.root_crl, f.issuer_crl, OTHER_DP);
        verify(&f, false, "unmapped distribution point");
        sd_json_variant_unref(f.revocations);
        revoked = crl_make(f.root, f.root_key, f.issuer, REVOCATION_REVOKED);
        f.revocations = revocations_make(revoked, f.issuer_crl, ISSUER_DP);
        verify(&f, false, "revoked intermediate");
        X509_CRL_free(revoked);
        sd_json_variant_unref(saved);
        fixture_clear(&f);
}

static void test_direct_root(void) {
        Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
        char *pem = crl_pem(f.root_crl);

        X509_free(f.leaf);
        f.leaf = certificate_make(f.ek_key, f.root, f.root_key, 3, NULL, ISSUER_DP, CERTIFICATE_VALID);
        sd_json_variant_unref(f.evidence);
        f.evidence = evidence_make(f.ek_key, f.ak_key, f.leaf);
        sd_json_variant_unref(f.revocations);
        f.revocations = NULL;
        assert(sd_json_buildo(&f.revocations,
                             SD_JSON_BUILD_PAIR("crls", SD_JSON_BUILD_ARRAY(
                                     SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_STRING("distributionPoint", ISSUER_DP),
                                                          SD_JSON_BUILD_PAIR_STRING("pem", pem))))) >= 0);
        free(pem);
        free(f.chain_pem);
        f.chain_pem = NULL;
        f.certificate_count = 2;
        verify(&f, true, "root-issued certificate without intermediate input");
        fixture_clear(&f);
}

static void certificate_remove_extension(X509 *certificate, int nid) {
        int index = X509_get_ext_by_NID(certificate, nid, -1);
        X509_EXTENSION *extension;

        assert(index >= 0);
        extension = X509_delete_ext(certificate, index);
        assert(extension);
        X509_EXTENSION_free(extension);
}

static void test_chain_constraints(void) {
        static const char * const descriptions[] = {
                "expired root", "expired intermediate", "non-CA intermediate", "non-signing intermediate",
                "wrong CA EKU", "missing leaf distribution point", "missing intermediate distribution point",
        };

        for (unsigned mode = 0; mode < sizeof descriptions / sizeof descriptions[0]; mode++) {
                Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
                X509 *certificate = mode == 0 ? f.root : mode == 5 ? f.leaf : f.issuer;
                EVP_PKEY *signer = mode == 5 ? f.issuer_key : f.root_key;

                if (mode < 2)
                        assert(X509_gmtime_adj(X509_getm_notAfter(certificate), -60));
                else if (mode == 2) {
                        certificate_remove_extension(certificate, NID_basic_constraints);
                        certificate_extension(certificate, f.root, NID_basic_constraints, "critical,CA:FALSE");
                } else if (mode == 3) {
                        certificate_remove_extension(certificate, NID_key_usage);
                        certificate_extension(certificate, f.root, NID_key_usage, "critical,cRLSign");
                } else if (mode == 4)
                        certificate_extension(certificate, f.root, NID_ext_key_usage, "serverAuth");
                else
                        certificate_remove_extension(certificate, NID_crl_distribution_points);
                assert(X509_sign(certificate, signer, EVP_sha256()) > 0);
                free(f.root_pem);
                free(f.chain_pem);
                f.root_pem = certificate_pem(f.root);
                f.chain_pem = certificate_pem(f.issuer);
                sd_json_variant_unref(f.evidence);
                f.evidence = evidence_make(f.ek_key, f.ak_key, f.leaf);
                verify(&f, false, descriptions[mode]);
                fixture_clear(&f);
        }
}

static GENERAL_NAMES *directory_names(X509 *certificate) {
        GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
        GENERAL_NAME *name = GENERAL_NAME_new();
        X509_NAME *subject = X509_NAME_dup(X509_get_subject_name(certificate));

        assert(names && name && subject);
        GENERAL_NAME_set0_value(name, GEN_DIRNAME, subject);
        assert(sk_GENERAL_NAME_push(names, name) == 1);
        return names;
}

static void test_distribution_point_bounds(void) {
        for (unsigned count = 0; count <= 17; count += 17) {
                Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
                CRL_DIST_POINTS *points = X509_get_ext_d2i(f.leaf, NID_crl_distribution_points, NULL, NULL);
                DIST_POINT *point = DIST_POINT_new();

                assert(points && point);
                point->distpoint = DIST_POINT_NAME_new();
                assert(point->distpoint);
                point->distpoint->type = 0;
                point->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
                assert(point->distpoint->name.fullname);
                for (unsigned i = 0; i < count; i++) {
                        GENERAL_NAME *name = GENERAL_NAME_new();
                        ASN1_IA5STRING *uri = ASN1_IA5STRING_new();

                        assert(name && uri);
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
                        assert(ASN1_STRING_set1_string(uri, OTHER_DP) == 1);
#else
                        assert(ASN1_STRING_set(uri, OTHER_DP, -1) == 1);
#endif
                        GENERAL_NAME_set0_value(name, GEN_URI, uri);
                        assert(sk_GENERAL_NAME_push(point->distpoint->name.fullname, name) > 0);
                }
                assert(sk_DIST_POINT_push(points, point) == 2);
                certificate_remove_extension(f.leaf, NID_crl_distribution_points);
                assert(X509_add1_ext_i2d(f.leaf, NID_crl_distribution_points, points, 0, X509V3_ADD_DEFAULT) == 1);
                assert(X509_sign(f.leaf, f.issuer_key, EVP_sha256()) > 0);
                sd_json_variant_unref(f.evidence);
                f.evidence = evidence_make(f.ek_key, f.ak_key, f.leaf);
                verify(&f, false, count ? "oversized DP after valid DP" : "empty DP after valid DP");
                CRL_DIST_POINTS_free(points);
                fixture_clear(&f);
        }
}

static void indirect_distribution_point(X509 *certificate, X509 *signer) {
        CRL_DIST_POINTS *points = sk_DIST_POINT_new_null();
        DIST_POINT *point = DIST_POINT_new();
        GENERAL_NAME *name = GENERAL_NAME_new();
        ASN1_IA5STRING *uri = ASN1_IA5STRING_new();
        X509_EXTENSION *old;
        int index = X509_get_ext_by_NID(certificate, NID_crl_distribution_points, -1);

        assert(index >= 0 && points && point && name && uri);
        old = X509_delete_ext(certificate, index);
        X509_EXTENSION_free(old);
        point->distpoint = DIST_POINT_NAME_new();
        assert(point->distpoint);
        point->distpoint->type = 0;
        point->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
        assert(point->distpoint->name.fullname);
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
        assert(ASN1_STRING_set1_string(uri, ISSUER_DP) == 1);
#else
        assert(ASN1_STRING_set(uri, ISSUER_DP, -1) == 1);
#endif
        GENERAL_NAME_set0_value(name, GEN_URI, uri);
        assert(sk_GENERAL_NAME_push(point->distpoint->name.fullname, name) == 1);
        point->CRLissuer = directory_names(signer);
        assert(sk_DIST_POINT_push(points, point) == 1);
        assert(X509_add1_ext_i2d(certificate, NID_crl_distribution_points, points, 0, X509V3_ADD_DEFAULT) == 1);
        CRL_DIST_POINTS_free(points);
}

static void test_indirect_revocations(void) {
        for (unsigned mode = 0; mode < 3; mode++) {
                Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
                X509_CRL *crl;
                ISSUING_DIST_POINT *point = ISSUING_DIST_POINT_new();

                assert(point);
                indirect_distribution_point(f.leaf, f.root);
                assert(X509_sign(f.leaf, f.issuer_key, EVP_sha256()) > 0);
                crl = crl_make(f.root, f.root_key, f.leaf, mode ? REVOCATION_REVOKED : REVOCATION_VALID);
                point->indirectCRL = 0xff;
                assert(X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point, point, 1, X509V3_ADD_DEFAULT) == 1);
                if (mode) {
                        X509_REVOKED *entry = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), 0);
                        GENERAL_NAMES *names = directory_names(mode == 1 ? f.issuer : f.root);

                        assert(entry && X509_REVOKED_add1_ext_i2d(entry, NID_certificate_issuer, names,
                                                                  1, X509V3_ADD_DEFAULT) == 1);
                        GENERAL_NAMES_free(names);
                }
                assert(X509_CRL_sign(crl, f.root_key, EVP_sha256()) > 0);
                sd_json_variant_unref(f.evidence);
                f.evidence = evidence_make(f.ek_key, f.ak_key, f.leaf);
                sd_json_variant_unref(f.revocations);
                f.revocations = revocations_make(f.root_crl, crl, ISSUER_DP);
                verify(&f, mode != 1, mode == 0 ? "indirect CRL" :
                       mode == 1 ? "indirect revoked EK" : "indirect serial from another issuer");
                ISSUING_DIST_POINT_free(point);
                X509_CRL_free(crl);
                fixture_clear(&f);
        }
}

static void test_inputs(void) {
        Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
        Fixture other = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
        sd_json_variant *saved, *value = NULL;
        char *root, *chain, *bad, *certificate;
        const char *text;
        size_t size;

        root = f.root_pem;
        f.root_pem = NULL;
        verify(&f, false, "absent trust anchor");
        f.root_pem = other.root_pem;
        verify(&f, false, "unrelated trust anchor");
        f.root_pem = f.chain_pem;
        verify(&f, false, "intermediate as trust anchor");
        f.root_pem = strdup("not a certificate\n");
        assert(f.root_pem);
        verify(&f, false, "malformed trust anchor");
        free(f.root_pem);
        assert(asprintf(&bad, "%sTRAILING\n", root) >= 0);
        f.root_pem = bad;
        verify(&f, false, "trailing trust anchor input");
        free(bad);
        assert(asprintf(&bad, "%s%s", root, root) >= 0);
        f.root_pem = bad;
        verify(&f, false, "multiple trust anchors");
        free(bad);
        f.root_pem = root;

        chain = f.chain_pem;
        f.chain_pem = NULL;
        verify(&f, false, "missing intermediate");
        assert(asprintf(&bad, "%sTRAILING\n", chain) >= 0);
        f.chain_pem = bad;
        verify(&f, false, "trailing chain input");
        free(bad);
        f.chain_pem = chain;

        saved = f.evidence;
        f.evidence = NULL;
        verify(&f, false, "absent evidence");
        f.evidence = sd_json_variant_ref(saved);
        assert(sd_json_variant_set_field_string(&f.evidence, "ekCertHex", "") >= 0);
        verify(&f, false, "absent EK certificate");
        sd_json_variant_unref(f.evidence);
        f.evidence = sd_json_variant_ref(saved);
        text = sd_json_variant_string(sd_json_variant_by_key(saved, "ekCertHex"));
        size = strlen(text);
        assert(asprintf(&certificate, "%s00", text) >= 0);
        assert(sd_json_variant_set_field_string(&f.evidence, "ekCertHex", certificate) >= 0);
        verify(&f, false, "trailing certificate DER");
        free(certificate);
        sd_json_variant_unref(f.evidence);
        f.evidence = sd_json_variant_ref(saved);
        certificate = strndup(text, size - 2);
        assert(certificate && sd_json_variant_set_field_string(&f.evidence, "ekCertHex", certificate) >= 0);
        verify(&f, false, "truncated certificate DER");
        free(certificate);
        sd_json_variant_unref(f.evidence);
        f.evidence = sd_json_variant_ref(saved);
        assert(sd_json_variant_set_field_string(&f.evidence, "evidenceQuality", "declared") >= 0);
        verify(&f, false, "incorrect evidence profile");
        sd_json_variant_unref(f.evidence);
        f.evidence = sd_json_variant_ref(saved);
        assert(sd_json_variant_set_field_string(&f.evidence, "akNameHex", "000b") >= 0);
        verify(&f, false, "unbound attestation name");
        sd_json_variant_unref(f.evidence);
        f.evidence = saved;

        assert(sd_json_buildo(&value, SD_JSON_BUILD_PAIR("crls", SD_JSON_BUILD_EMPTY_ARRAY),
                             SD_JSON_BUILD_PAIR_BOOLEAN("trusted", true)) >= 0);
        saved = f.revocations;
        f.revocations = value;
        verify(&f, false, "unknown revocation policy field");
        sd_json_variant_unref(value);
        f.revocations = saved;
        verify(&f, true, "valid fixture after rejections");
        fixture_clear(&other);
        fixture_clear(&f);
}

static void test_bounds(void) {
        Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);
        sd_json_variant *saved = f.revocations, *array = NULL;
        sd_json_variant *entry = sd_json_variant_by_index(sd_json_variant_by_key(saved, "crls"), 0);
        char *chain = f.chain_pem, *oversized, *pem = crl_pem(f.issuer_crl);
        size_t length = strlen(chain);
        BIO *bio;

        f.revocations = NULL;
        assert(sd_json_variant_new_array(&array, NULL, 0) >= 0);
        assert(sd_json_variant_append_array(&array, entry) >= 0);
        assert(sd_json_variant_append_array(&array, entry) >= 0);
        assert(sd_json_buildo(&f.revocations, SD_JSON_BUILD_PAIR_VARIANT("crls", array)) >= 0);
        verify(&f, false, "duplicate distribution point");
        sd_json_variant_unref(array);
        sd_json_variant_unref(f.revocations);
        array = NULL;
        f.revocations = NULL;
        assert(sd_json_variant_new_array(&array, NULL, 0) >= 0);
        for (unsigned i = 0; i < 33; i++) {
                char uri[128];

                assert(snprintf(uri, sizeof uri, "https://ca.example.invalid/%u.crl", i) > 0);
                assert(sd_json_variant_append_arraybo(&array,
                                                     SD_JSON_BUILD_PAIR_STRING("distributionPoint", uri),
                                                     SD_JSON_BUILD_PAIR_STRING("pem", pem)) >= 0);
        }
        assert(sd_json_buildo(&f.revocations, SD_JSON_BUILD_PAIR_VARIANT("crls", array)) >= 0);
        verify(&f, false, "CRL count limit");
        sd_json_variant_unref(array);
        sd_json_variant_unref(f.revocations);
        f.revocations = saved;
        free(pem);

        oversized = malloc(length * 17 + 1);
        assert(oversized);
        for (unsigned i = 0; i < 17; i++)
                memcpy(oversized + i * length, chain, length);
        oversized[length * 17] = 0;
        f.chain_pem = oversized;
        verify(&f, false, "repeated certificate chain");
        free(oversized);
        f.chain_pem = chain;

        bio = BIO_new(BIO_s_mem());
        assert(bio && PEM_write_bio_X509(bio, f.issuer) == 1);
        for (unsigned i = 0; i < 16; i++) {
                X509 *certificate = certificate_make(f.issuer_key, f.root, f.root_key,
                                                     100 + i, "Additional Issuer", ROOT_DP, CERTIFICATE_VALID);

                assert(PEM_write_bio_X509(bio, certificate) == 1);
                X509_free(certificate);
        }
        f.chain_pem = bio_string(bio);
        verify(&f, false, "certificate chain count limit");
        BIO_free(bio);
        free(f.chain_pem);
        f.chain_pem = chain;

        saved = f.evidence;
        f.evidence = sd_json_variant_ref(saved);
        oversized = malloc(32771);
        assert(oversized);
        memset(oversized, '0', 32770);
        oversized[32770] = 0;
        assert(sd_json_variant_set_field_string(&f.evidence, "ekCertHex", oversized) >= 0);
        verify(&f, false, "certificate size limit");
        free(oversized);
        sd_json_variant_unref(f.evidence);
        f.evidence = saved;
        fixture_clear(&f);
}

static void fixture_write(const Fixture *f, const char *directory) {
        const char *names[] = { "evidence.json", "root.pem", "chain.pem", "revocations.json", "ek.hex" };
        const char *contents[] = { NULL, f->root_pem, f->chain_pem, NULL,
                                  sd_json_variant_string(sd_json_variant_by_key(f->evidence, "ekPublicHex")) };

        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
                char *path;
                FILE *stream;

                assert(asprintf(&path, "%s/%s", directory, names[i]) >= 0);
                stream = fopen(path, "wxe");
                assert(stream);
                if (contents[i])
                        assert(fputs(contents[i], stream) >= 0);
                else
                        assert(sd_json_variant_dump(i == 0 ? f->evidence : f->revocations,
                                                    SD_JSON_FORMAT_PRETTY | SD_JSON_FORMAT_NEWLINE, stream, NULL) >= 0);
                assert(fclose(stream) == 0);
                free(path);
        }
}

int main(int argc, char **argv) {
        if (argc == 3 && strcmp(argv[1], "--write-fixture") == 0) {
                Fixture f = fixture_make(CERTIFICATE_VALID, REVOCATION_VALID);

                fixture_write(&f, argv[2]);
                fixture_clear(&f);
                return 0;
        }
        assert(argc == 1);
        test_certificates();
        test_direct_root();
        test_chain_constraints();
        test_revocations();
        test_distribution_point_bounds();
        test_indirect_revocations();
        test_inputs();
        test_bounds();
        printf("%u endorsement checks passed\n", tests);
        return 0;
}
