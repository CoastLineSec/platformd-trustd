/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#define _cleanup_(f) __attribute__((cleanup(f)))
static inline void freep(void *p) { free(*(void **) p); }
#define _cleanup_free_ _cleanup_(freep)

bool user_record_verify(sd_json_variant *record) {
        static char *exclude[] = {
                (char *) "binding", (char *) "status", (char *) "signature", (char *) "secret", NULL,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *signable = NULL;
        _cleanup_free_ char *text = NULL;
        _cleanup_free_ void *sig = NULL;
        sd_json_variant *sigarr, *sig0, *data, *key;
        EVP_PKEY *pkey = NULL;
        EVP_MD_CTX *ctx = NULL;
        size_t sig_len = 0;
        bool ok = false;
        BIO *bio;

        sigarr = sd_json_variant_by_key(record, "signature");
        sig0 = sigarr && sd_json_variant_is_array(sigarr) && sd_json_variant_elements(sigarr) > 0
                ? sd_json_variant_by_index(sigarr, 0) : NULL;
        if (!sig0)
                return false;
        data = sd_json_variant_by_key(sig0, "data");
        key = sd_json_variant_by_key(sig0, "key");
        if (!data || !sd_json_variant_is_string(data) || !key || !sd_json_variant_is_string(key))
                return false;
        if (sd_json_variant_unbase64(data, &sig, &sig_len) < 0 || sig_len != 64)
                return false;   /* not an Ed25519 signature */

        /* The signed form: the record without the non-signable sections, key-sorted
         * (normalize) and compact — the same normalization homed signs. */
        signable = sd_json_variant_ref(record);
        if (sd_json_variant_filter(&signable, exclude) < 0 ||
            sd_json_variant_normalize(&signable) < 0 ||
            sd_json_variant_format(signable, 0, &text) < 0)
                return false;

        bio = BIO_new_mem_buf(sd_json_variant_string(key), -1);
        if (!bio)
                return false;
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (!pkey)
                return false;

        ctx = EVP_MD_CTX_new();
        if (ctx &&
            EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, sig, sig_len, (const unsigned char *) text, strlen(text)) == 1)
                ok = true;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ok;
}
