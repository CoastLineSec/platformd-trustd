/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "endorsement.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "enrollment.h"

#define CERTIFICATE_SIZE_MAX 16384U
#define ROOT_SIZE_MAX (64U * 1024U)
#define MATERIAL_SIZE_MAX (1024U * 1024U)
#define CERTIFICATE_COUNT_MAX 16
#define CRL_COUNT_MAX 32U
#define URI_SIZE_MAX 2048U
#define EXTENSION_COUNT_MAX 64

typedef struct Revocation {
        const char *uri;
        X509_CRL *crl;
} Revocation;

static size_t asn1_length(const ASN1_STRING *value) {
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
        return ASN1_STRING_get_length(value);
#else
        int n = ASN1_STRING_length(value);

        return n < 0 ? SIZE_MAX : (size_t) n;
#endif
}

static bool object_fields(sd_json_variant *object, const char *const *fields, size_t count) {
        unsigned seen = 0;

        if (!sd_json_variant_is_object(object) || sd_json_variant_elements(object) != count * 2)
                return false;
        for (size_t i = 0; i < count * 2; i += 2) {
                const char *key = sd_json_variant_string(sd_json_variant_by_index(object, i));
                size_t j;

                if (!key)
                        return false;
                for (j = 0; j < count; j++)
                        if (strcmp(key, fields[j]) == 0)
                                break;
                if (j == count || (seen & (1U << j)))
                        return false;
                seen |= 1U << j;
        }
        return true;
}

static const char *string_field(sd_json_variant *object, const char *key) {
        return sd_json_variant_string(sd_json_variant_by_key(object, key));
}

static bool whitespace(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char *skip_space(const char *p) {
        while (whitespace(*p))
                p++;
        return p;
}

static int hex_digit(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

static int hash_hex(const void *data, size_t size, char ret[static 65]) {
        unsigned char hash[32];
        unsigned n;

        if (EVP_Digest(data, size, hash, &n, EVP_sha256(), NULL) != 1 || n != sizeof hash)
                return -EIO;
        for (size_t i = 0; i < sizeof hash; i++) {
                ret[i * 2] = "0123456789abcdef"[hash[i] >> 4];
                ret[i * 2 + 1] = "0123456789abcdef"[hash[i] & 15];
        }
        ret[64] = 0;
        return 0;
}

static bool oid_equal(const ASN1_OBJECT *object, const char *expected) {
        char text[64];
        int n = OBJ_obj2txt(text, sizeof text, object, 1);

        return n > 0 && (size_t) n < sizeof text && strcmp(text, expected) == 0;
}

static int certificate_extensions(X509 *certificate) {
        int n = X509_get_ext_count(certificate);

        if (n < 0 || n > EXTENSION_COUNT_MAX)
                return -EBADMSG;
        for (int i = 0; i < n; i++) {
                for (int j = 0; j < i; j++)
                        if (OBJ_cmp(X509_EXTENSION_get_object(X509_get_ext(certificate, i)),
                                    X509_EXTENSION_get_object(X509_get_ext(certificate, j))) == 0)
                                return -EBADMSG;
                if (X509_EXTENSION_get_critical(X509_get_ext(certificate, i)) &&
                    !X509_supported_extension(X509_get_ext(certificate, i)))
                        return -EOPNOTSUPP;
        }
        return 0;
}

static int pem_decode(const char **cursor, const char *label, unsigned char **ret, long *ret_size) {
        char begin[64], end[64], *name = NULL, *header = NULL;
        unsigned char *data = NULL;
        const char *start = skip_space(*cursor), *finish;
        BIO *bio = NULL;
        long size = 0;
        int r = -EBADMSG;

        snprintf(begin, sizeof begin, "-----BEGIN %s-----", label);
        snprintf(end, sizeof end, "-----END %s-----", label);
        if (strncmp(start, begin, strlen(begin)) != 0 ||
            (start[strlen(begin)] != '\n' && start[strlen(begin)] != '\r'))
                return -EBADMSG;
        finish = strstr(start + strlen(begin), end);
        if (!finish)
                return -EBADMSG;
        finish += strlen(end);
        if (*finish && !whitespace(*finish))
                return -EBADMSG;
        bio = BIO_new_mem_buf(start, (int) (finish - start));
        if (!bio)
                return -ENOMEM;
        if (PEM_read_bio(bio, &name, &header, &data, &size) != 1 || strcmp(name, label) != 0 ||
            *header || size <= 0 || size > MATERIAL_SIZE_MAX)
                goto finish;
        *cursor = skip_space(finish);
        *ret = data;
        *ret_size = size;
        data = NULL;
        r = 0;
finish:
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        BIO_free(bio);
        return r;
}

static int certificate_der(const unsigned char *data, size_t size, X509 **ret) {
        const unsigned char *p = data;
        X509 *certificate;
        int r;

        if (!size || size > CERTIFICATE_SIZE_MAX)
                return -EBADMSG;
        certificate = d2i_X509(NULL, &p, (long) size);
        if (!certificate)
                return -EBADMSG;
        r = p == data + size ? certificate_extensions(certificate) : -EBADMSG;
        if (r < 0) {
                X509_free(certificate);
                return r;
        }
        *ret = certificate;
        return 0;
}

static int certificate_pem(const char **cursor, X509 **ret, char *ret_hash) {
        unsigned char *data = NULL;
        long size;
        int r;

        r = pem_decode(cursor, "CERTIFICATE", &data, &size);
        if (r < 0)
                return r;
        r = certificate_der(data, (size_t) size, ret);
        if (r >= 0 && ret_hash)
                r = hash_hex(data, (size_t) size, ret_hash);
        OPENSSL_free(data);
        return r;
}

static int eku_check(X509 *certificate, bool leaf) {
        EXTENDED_KEY_USAGE *usage;
        int critical = -1, r = -EKEYREJECTED;
        bool allowed = false;

        usage = X509_get_ext_d2i(certificate, NID_ext_key_usage, &critical, NULL);
        if (!usage)
                return critical == -1 ? 0 : -EBADMSG;
        if ((leaf && critical) || sk_ASN1_OBJECT_num(usage) < 1 || sk_ASN1_OBJECT_num(usage) > 16)
                goto finish;
        for (int i = 0; i < sk_ASN1_OBJECT_num(usage); i++) {
                ASN1_OBJECT *oid = sk_ASN1_OBJECT_value(usage, i);

                if (oid_equal(oid, "2.23.133.8.1") || (!leaf && OBJ_obj2nid(oid) == NID_anyExtendedKeyUsage))
                        allowed = true;
        }
        r = allowed ? 0 : -EKEYREJECTED;
finish:
        EXTENDED_KEY_USAGE_free(usage);
        return r;
}

static bool device_attribute(const ASN1_STRING *value, bool identifier) {
        const unsigned char *data = ASN1_STRING_get0_data(value);
        size_t n = asn1_length(value);
        sd_json_variant *string = NULL;
        bool valid;

        if (ASN1_STRING_type(value) != V_ASN1_UTF8STRING || n < 1 || n > 256 || memchr(data, 0, n))
                return false;
        if (identifier) {
                if (n != 11 || memcmp(data, "id:", 3) != 0)
                        return false;
                for (size_t i = 3; i < n; i++)
                        if (!((data[i] >= '0' && data[i] <= '9') || (data[i] >= 'A' && data[i] <= 'F')))
                                return false;
                return true;
        }
        valid = sd_json_variant_new_stringn(&string, (const char *) data, n) >= 0;
        sd_json_variant_unref(string);
        return valid;
}

static int leaf_profile(X509 *certificate) {
        BASIC_CONSTRAINTS *constraints = NULL;
        ASN1_BIT_STRING *usage = NULL;
        AUTHORITY_KEYID *authority = NULL;
        GENERAL_NAMES *names = NULL;
        unsigned seen = 0;
        int critical, r = -EBADMSG;

        if (X509_get_version(certificate) != 2)
                return -EBADMSG;
        constraints = X509_get_ext_d2i(certificate, NID_basic_constraints, &critical, NULL);
        if (!constraints || critical != 1 || constraints->ca || constraints->pathlen)
                goto finish;
        usage = X509_get_ext_d2i(certificate, NID_key_usage, &critical, NULL);
        if (!usage || critical != 1 || asn1_length(usage) > 2)
                goto finish;
        for (int i = 0; i < 16; i++)
                if (ASN1_BIT_STRING_get_bit(usage, i) != (i == 4))
                        goto finish;
        authority = X509_get_ext_d2i(certificate, NID_authority_key_identifier, &critical, NULL);
        if (!authority || critical != 0 || !authority->keyid ||
            asn1_length(authority->keyid) < 1 || asn1_length(authority->keyid) > 64)
                goto finish;
        names = X509_get_ext_d2i(certificate, NID_subject_alt_name, &critical, NULL);
        if (!names || (X509_NAME_entry_count(X509_get_subject_name(certificate)) == 0 && critical != 1) ||
            sk_GENERAL_NAME_num(names) < 1 || sk_GENERAL_NAME_num(names) > 16)
                goto finish;
        for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
                GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
                int count;

                if (name->type != GEN_DIRNAME)
                        continue;
                count = X509_NAME_entry_count(name->d.directoryName);
                if (count < 1 || count > 64)
                        goto finish;
                for (int j = 0; j < count; j++) {
                        const X509_NAME_ENTRY *entry = X509_NAME_get_entry(name->d.directoryName, j);
                        unsigned field = oid_equal(X509_NAME_ENTRY_get_object(entry), "2.23.133.2.1") ? 1U :
                                         oid_equal(X509_NAME_ENTRY_get_object(entry), "2.23.133.2.2") ? 2U :
                                         oid_equal(X509_NAME_ENTRY_get_object(entry), "2.23.133.2.3") ? 4U : 0;

                        if (!field)
                                continue;
                        if ((seen & field) || !device_attribute(X509_NAME_ENTRY_get_data(entry), field != 2U))
                                goto finish;
                        seen |= field;
                }
        }
        if (seen == 7)
                r = eku_check(certificate, true);
finish:
        BASIC_CONSTRAINTS_free(constraints);
        ASN1_BIT_STRING_free(usage);
        AUTHORITY_KEYID_free(authority);
        GENERAL_NAMES_free(names);
        return r;
}

static bool uri_valid(const char *uri) {
        size_t n;

        if (!uri || (n = strnlen(uri, URI_SIZE_MAX + 1)) == 0 || n > URI_SIZE_MAX ||
            (strncmp(uri, "http://", 7) != 0 && strncmp(uri, "https://", 8) != 0))
                return false;
        for (size_t i = 0; i < n; i++)
                if ((unsigned char) uri[i] <= 0x20 || (unsigned char) uri[i] >= 0x7f)
                        return false;
        return true;
}

static bool uri_equal(const ASN1_STRING *value, const char *uri) {
        size_t n = asn1_length(value);

        return ASN1_STRING_type(value) == V_ASN1_IA5STRING && n > 0 &&
               n == strlen(uri) && memcmp(ASN1_STRING_get0_data(value), uri, n) == 0;
}

static bool crl_time_valid(X509_CRL *crl, time_t now) {
        ASN1_TIME *current;
        int beginning, ending;

        if (!X509_CRL_get0_lastUpdate(crl) || !X509_CRL_get0_nextUpdate(crl))
                return false;
        current = ASN1_TIME_set(NULL, now);
        if (!current)
                return false;
        beginning = ASN1_TIME_compare(X509_CRL_get0_lastUpdate(crl), current);
        ending = ASN1_TIME_compare(X509_CRL_get0_nextUpdate(crl), current);
        ASN1_TIME_free(current);
        return (beginning == -1 || beginning == 0) && ending == 1;
}

static int crl_profile(X509_CRL *crl, time_t now) {
        ISSUING_DIST_POINT *point = NULL;
        int critical = -1, digest_nid, key_nid, n = X509_CRL_get_ext_count(crl), r = -EBADMSG;

        if (X509_CRL_get_version(crl) != 1 || n < 0 || n > EXTENSION_COUNT_MAX ||
            !crl_time_valid(crl, now))
                return -EKEYREJECTED;
        for (int i = 0; i < n; i++)
                for (int j = 0; j < i; j++)
                        if (OBJ_cmp(X509_EXTENSION_get_object(X509_CRL_get_ext(crl, i)),
                                    X509_EXTENSION_get_object(X509_CRL_get_ext(crl, j))) == 0)
                                return -EBADMSG;
        if (X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0 ||
            X509_CRL_get_ext_by_NID(crl, NID_freshest_crl, -1) >= 0)
                return -EOPNOTSUPP;
        if (OBJ_find_sigid_algs(X509_CRL_get_signature_nid(crl), &digest_nid, &key_nid) != 1 ||
            (digest_nid != NID_sha256 && digest_nid != NID_sha384 && digest_nid != NID_sha512))
                return -EOPNOTSUPP;
        point = X509_CRL_get_ext_d2i(crl, NID_issuing_distribution_point, &critical, NULL);
        if (!point)
                return critical == -1 ? 0 : -EBADMSG;
        if (point->onlysomereasons || point->onlyattr || (point->distpoint && point->distpoint->type != 0))
                r = -EOPNOTSUPP;
        else
                r = 0;
        ISSUING_DIST_POINT_free(point);
        return r;
}

static int revocations_parse(sd_json_variant *input, Revocation records[static CRL_COUNT_MAX],
                             size_t *ret_count, time_t now) {
        static const char *const fields[] = { "crls" }, *const item_fields[] = { "distributionPoint", "pem" };
        sd_json_variant *list;
        size_t total = 0;

        if (!object_fields(input, fields, 1))
                return -EBADMSG;
        list = sd_json_variant_by_key(input, "crls");
        if (!sd_json_variant_is_array(list) || sd_json_variant_elements(list) < 1 ||
            sd_json_variant_elements(list) > CRL_COUNT_MAX)
                return -EBADMSG;
        for (size_t i = 0; i < sd_json_variant_elements(list); i++) {
                sd_json_variant *item = sd_json_variant_by_index(list, i);
                const unsigned char *cursor;
                const char *pem, *uri;
                unsigned char *data = NULL;
                long size;
                int r;

                if (!object_fields(item, item_fields, 2))
                        return -EBADMSG;
                uri = string_field(item, "distributionPoint");
                pem = string_field(item, "pem");
                if (!uri_valid(uri) || !pem || strnlen(pem, MATERIAL_SIZE_MAX + 1) > MATERIAL_SIZE_MAX)
                        return -EBADMSG;
                total += strlen(uri) + strlen(pem);
                if (total > MATERIAL_SIZE_MAX)
                        return -E2BIG;
                for (size_t j = 0; j < i; j++)
                        if (strcmp(uri, records[j].uri) == 0)
                                return -EBADMSG;
                r = pem_decode(&pem, "X509 CRL", &data, &size);
                if (r < 0)
                        return r;
                cursor = data;
                records[i].crl = d2i_X509_CRL(NULL, &cursor, size);
                r = records[i].crl && cursor == data + size && !*pem ? 0 : -EBADMSG;
                OPENSSL_free(data);
                records[i].uri = uri;
                *ret_count = i + 1;
                if (r >= 0)
                        r = crl_profile(records[i].crl, now);
                if (r < 0)
                        return r;
        }
        return 0;
}

static int verify_chain(X509 *certificate, X509 *root, STACK_OF(X509) *untrusted,
                        X509_CRL *crl, time_t now, STACK_OF(X509) **ret_chain) {
        X509_STORE_CTX *context = NULL;
        X509_STORE *store = NULL;
        STACK_OF(X509_CRL) *crls = NULL;
        X509_VERIFY_PARAM *parameters;
        unsigned long flags = X509_V_FLAG_X509_STRICT | X509_V_FLAG_CHECK_SS_SIGNATURE;
        int r = -EKEYREJECTED;

        store = X509_STORE_new();
        context = X509_STORE_CTX_new();
        if (!store || !context) {
                r = -ENOMEM;
                goto finish;
        }
        if (X509_STORE_add_cert(store, root) != 1 ||
            X509_STORE_CTX_init(context, store, certificate, untrusted) != 1)
                goto finish;
        if (crl) {
                crls = sk_X509_CRL_new_null();
                if (!crls || !sk_X509_CRL_push(crls, crl)) {
                        r = -ENOMEM;
                        goto finish;
                }
                X509_STORE_CTX_set0_crls(context, crls);
        }
        parameters = X509_STORE_CTX_get0_param(context);
        if (crl)
                flags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_EXTENDED_CRL_SUPPORT;
        if (X509_VERIFY_PARAM_set_flags(parameters, flags) != 1)
                goto finish;
        X509_VERIFY_PARAM_set_time(parameters, now);
        X509_VERIFY_PARAM_set_auth_level(parameters, 2);
        X509_VERIFY_PARAM_set_depth(parameters, CERTIFICATE_COUNT_MAX);
        if (X509_verify_cert(context) != 1)
                goto finish;
        if (ret_chain) {
                *ret_chain = X509_STORE_CTX_get1_chain(context);
                if (!*ret_chain) {
                        r = -ENOMEM;
                        goto finish;
                }
        }
        r = 0;
finish:
        X509_STORE_CTX_free(context);
        X509_STORE_free(store);
        sk_X509_CRL_free(crls);
        ERR_clear_error();
        return r;
}

static bool selected_scope(X509 *certificate, DIST_POINT *point, const Revocation *record) {
        ISSUING_DIST_POINT *issuing;
        bool valid = false;
        int critical;

        issuing = X509_CRL_get_ext_d2i(record->crl, NID_issuing_distribution_point, &critical, NULL);
        if (point->CRLissuer) {
                GENERAL_NAME *name;

                if (sk_GENERAL_NAME_num(point->CRLissuer) != 1 || !issuing || !issuing->indirectCRL)
                        goto finish;
                name = sk_GENERAL_NAME_value(point->CRLissuer, 0);
                if (name->type != GEN_DIRNAME ||
                    X509_NAME_cmp(name->d.directoryName, X509_CRL_get_issuer(record->crl)) != 0)
                        goto finish;
        } else if (X509_NAME_cmp(X509_get_issuer_name(certificate), X509_CRL_get_issuer(record->crl)) != 0)
                goto finish;
        if (issuing && issuing->distpoint) {
                GENERAL_NAMES *names = issuing->distpoint->name.fullname;
                bool matched = false;

                if (sk_GENERAL_NAME_num(names) < 1 || sk_GENERAL_NAME_num(names) > 16)
                        goto finish;
                for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
                        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

                        if (name->type == GEN_URI && uri_equal(name->d.uniformResourceIdentifier, record->uri))
                                matched = true;
                }
                if (!matched)
                        goto finish;
        }
        valid = true;
finish:
        ISSUING_DIST_POINT_free(issuing);
        return valid;
}

static int certificate_revocation(STACK_OF(X509) *chain, int index, const Revocation *records,
                                   size_t count, time_t now) {
        X509 *certificate = sk_X509_value(chain, index), *root = sk_X509_value(chain, sk_X509_num(chain) - 1);
        STACK_OF(X509) *suffix = NULL, *verified = NULL;
        CRL_DIST_POINTS *points = NULL;
        int critical = -1, r = -EKEYREJECTED;
        bool accepted = false;

        if (X509_get_ext_by_NID(certificate, NID_freshest_crl, -1) >= 0)
                return -EOPNOTSUPP;
        points = X509_get_ext_d2i(certificate, NID_crl_distribution_points, &critical, NULL);
        if (!points || critical != 0 || sk_DIST_POINT_num(points) < 1 || sk_DIST_POINT_num(points) > 16)
                goto finish;
        suffix = sk_X509_new_null();
        if (!suffix) {
                r = -ENOMEM;
                goto finish;
        }
        for (int i = index + 1; i < sk_X509_num(chain) - 1; i++)
                if (!sk_X509_push(suffix, sk_X509_value(chain, i))) {
                        r = -ENOMEM;
                        goto finish;
                }
        for (int i = 0; i < sk_DIST_POINT_num(points); i++) {
                DIST_POINT *point = sk_DIST_POINT_value(points, i);
                GENERAL_NAMES *names;

                if (!point->distpoint || point->distpoint->type != 0 || point->reasons) {
                        r = -EOPNOTSUPP;
                        goto finish;
                }
                names = point->distpoint->name.fullname;
                if (sk_GENERAL_NAME_num(names) < 1 || sk_GENERAL_NAME_num(names) > 16) {
                        r = -EBADMSG;
                        goto finish;
                }
                for (int j = 0; j < sk_GENERAL_NAME_num(names); j++) {
                        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);

                        if (name->type != GEN_URI) {
                                r = -EOPNOTSUPP;
                                goto finish;
                        }
                        for (size_t k = 0; k < count; k++) {
                                if (!uri_equal(name->d.uniformResourceIdentifier, records[k].uri) ||
                                    !selected_scope(certificate, point, &records[k]))
                                        continue;
                                r = verify_chain(certificate, root, suffix, records[k].crl, now, &verified);
                                if (r < 0)
                                        goto finish;
                                if (sk_X509_num(verified) != sk_X509_num(chain) - index) {
                                        r = -EKEYREJECTED;
                                        goto finish;
                                }
                                for (int l = 0; l < sk_X509_num(verified); l++)
                                        if (X509_cmp(sk_X509_value(verified, l), sk_X509_value(chain, index + l)) != 0) {
                                                r = -EKEYREJECTED;
                                                goto finish;
                                        }
                                sk_X509_pop_free(verified, X509_free);
                                verified = NULL;
                                accepted = true;
                        }
                }
        }
        r = accepted ? 0 : -EKEYREJECTED;
finish:
        sk_X509_pop_free(verified, X509_free);
        sk_X509_free(suffix);
        CRL_DIST_POINTS_free(points);
        return r;
}

int endorsement_verify(sd_json_variant *evidence, const char *trust_anchor_pem,
                       const char *certificate_chain_pem, sd_json_variant *revocations,
                       sd_json_variant **ret_report) {
        X509 *root = NULL, *leaf = NULL, *certificate = NULL;
        EVP_PKEY *expected = NULL;
        STACK_OF(X509) *untrusted = NULL, *chain = NULL;
        Revocation records[CRL_COUNT_MAX] = {};
        unsigned char leaf_data[CERTIFICATE_SIZE_MAX];
        char root_hash[65], leaf_hash[65];
        size_t count = 0, length;
        const char *cursor, *hex;
        struct timespec timestamp;
        uint64_t checked;
        int r;

        if (!ret_report)
                return -EINVAL;
        *ret_report = NULL;
        if (!trust_anchor_pem || strnlen(trust_anchor_pem, ROOT_SIZE_MAX + 1) > ROOT_SIZE_MAX ||
            (certificate_chain_pem && strnlen(certificate_chain_pem, MATERIAL_SIZE_MAX + 1) > MATERIAL_SIZE_MAX))
                return -E2BIG;
        if (clock_gettime(CLOCK_REALTIME, &timestamp) < 0)
                return errno > 0 ? -errno : -EIO;
        if (timestamp.tv_sec <= 0 || timestamp.tv_nsec < 0 || timestamp.tv_nsec >= 1000000000 ||
            (uint64_t) timestamp.tv_sec > (UINT64_MAX - (uint64_t) timestamp.tv_nsec / 1000) / 1000000)
                return -ERANGE;
        checked = (uint64_t) timestamp.tv_sec * 1000000 + (uint64_t) timestamp.tv_nsec / 1000;
        r = enrollment_evidence_key(evidence, &expected);
        if (r < 0)
                goto finish;
        hex = string_field(evidence, "ekCertHex");
        if (!hex || (length = strnlen(hex, sizeof leaf_data * 2 + 1)) == 0 ||
            length > sizeof leaf_data * 2 || length % 2) {
                r = -EBADMSG;
                goto finish;
        }
        for (size_t i = 0; i < length; i += 2) {
                int a = hex_digit(hex[i]), b = hex_digit(hex[i + 1]);

                if (a < 0 || b < 0) {
                        r = -EBADMSG;
                        goto finish;
                }
                leaf_data[i / 2] = (unsigned char) ((a << 4) | b);
        }
        r = certificate_der(leaf_data, length / 2, &leaf);
        if (r < 0)
                goto finish;
        r = hash_hex(leaf_data, length / 2, leaf_hash);
        if (r < 0)
                goto finish;
        r = leaf_profile(leaf);
        if (r < 0)
                goto finish;
        if (EVP_PKEY_eq(expected, X509_get0_pubkey(leaf)) != 1) {
                r = -EKEYREJECTED;
                goto finish;
        }
        cursor = trust_anchor_pem;
        r = certificate_pem(&cursor, &root, root_hash);
        if (r < 0)
                goto finish;
        if (*cursor || X509_check_issued(root, root) != X509_V_OK ||
            X509_check_ca(root) <= 0 || X509_verify(root, X509_get0_pubkey(root)) != 1) {
                r = -EKEYREJECTED;
                goto finish;
        }
        untrusted = sk_X509_new_null();
        if (!untrusted) {
                r = -ENOMEM;
                goto finish;
        }
        cursor = skip_space(certificate_chain_pem ?: "");
        while (*cursor) {
                if (sk_X509_num(untrusted) >= CERTIFICATE_COUNT_MAX) {
                        r = -E2BIG;
                        goto finish;
                }
                r = certificate_pem(&cursor, &certificate, NULL);
                if (r < 0)
                        goto finish;
                for (int i = 0; i < sk_X509_num(untrusted); i++)
                        if (X509_cmp(certificate, sk_X509_value(untrusted, i)) == 0) {
                                r = -EBADMSG;
                                goto finish;
                        }
                if (X509_cmp(certificate, root) == 0 || X509_cmp(certificate, leaf) == 0) {
                        r = -EBADMSG;
                        goto finish;
                }
                if (!sk_X509_push(untrusted, certificate)) {
                        r = -ENOMEM;
                        goto finish;
                }
                certificate = NULL;
        }
        r = verify_chain(leaf, root, untrusted, NULL, timestamp.tv_sec, &chain);
        if (r < 0)
                goto finish;
        if (sk_X509_num(chain) < 2 || sk_X509_num(chain) > CERTIFICATE_COUNT_MAX + 2 ||
            X509_cmp(sk_X509_value(chain, sk_X509_num(chain) - 1), root) != 0) {
                r = -EKEYREJECTED;
                goto finish;
        }
        for (int i = 1; i < sk_X509_num(chain); i++) {
                r = eku_check(sk_X509_value(chain, i), false);
                if (r < 0)
                        goto finish;
        }
        r = revocations_parse(revocations, records, &count, timestamp.tv_sec);
        if (r < 0)
                goto finish;
        for (int i = 0; i < sk_X509_num(chain) - 1; i++) {
                r = certificate_revocation(chain, i, records, count, timestamp.tv_sec);
                if (r < 0)
                        goto finish;
        }
        r = sd_json_buildo(ret_report,
                           SD_JSON_BUILD_PAIR_STRING("profile", "io.platformd.Trust.EndorsementVerification.v1"),
                           SD_JSON_BUILD_PAIR_BOOLEAN("endorsementKeyMatched", true),
                           SD_JSON_BUILD_PAIR_BOOLEAN("certificateChainVerified", true),
                           SD_JSON_BUILD_PAIR_BOOLEAN("revocationChecked", true),
                           SD_JSON_BUILD_PAIR_STRING("anchorSha256", root_hash),
                           SD_JSON_BUILD_PAIR_STRING("certificateSha256", leaf_hash),
                           SD_JSON_BUILD_PAIR_UNSIGNED("checkedAtRealtimeUSec", checked),
                           SD_JSON_BUILD_PAIR_UNSIGNED("certificateCount", (uint64_t) sk_X509_num(chain)));
finish:
        for (size_t i = 0; i < count; i++)
                X509_CRL_free(records[i].crl);
        sk_X509_pop_free(chain, X509_free);
        sk_X509_pop_free(untrusted, X509_free);
        EVP_PKEY_free(expected);
        X509_free(root);
        X509_free(leaf);
        X509_free(certificate);
        ERR_clear_error();
        return r;
}
