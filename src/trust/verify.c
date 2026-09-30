/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "verify.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

const char *user_record_signing_key(sd_json_variant *record) {
        static char *exclude[] = { "binding", "status", "signature", "secret", NULL };
        sd_json_variant *signable = NULL, *signatures;
        char *text = NULL;
        const char *verified_key = NULL;

        signatures = sd_json_variant_by_key(record, "signature");
        if (!sd_json_variant_is_array(signatures) || sd_json_variant_elements(signatures) > 64)
                return NULL;

        signable = sd_json_variant_ref(record);
        if (sd_json_variant_filter(&signable, exclude) < 0 ||
            sd_json_variant_normalize(&signable) < 0 ||
            sd_json_variant_format(signable, 0, &text) < 0)
                goto finish;

        for (size_t i = 0; i < sd_json_variant_elements(signatures); i++) {
                sd_json_variant *signature = sd_json_variant_by_index(signatures, i);
                sd_json_variant *data = sd_json_variant_by_key(signature, "data");
                sd_json_variant *key = sd_json_variant_by_key(signature, "key");
                EVP_PKEY *pkey = NULL;
                EVP_MD_CTX *context = NULL;
                void *bytes = NULL;
                size_t size = 0;
                BIO *bio;

                if (!sd_json_variant_is_string(data) || !sd_json_variant_is_string(key))
                        continue;
                if (sd_json_variant_unbase64(data, &bytes, &size) < 0)
                        continue;
                bio = BIO_new_mem_buf(sd_json_variant_string(key), -1);
                if (bio) {
                        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
                        BIO_free(bio);
                }
                context = EVP_MD_CTX_new();
                if (size == 64 && pkey && EVP_PKEY_is_a(pkey, "ED25519") && context &&
                    EVP_DigestVerifyInit(context, NULL, NULL, NULL, pkey) == 1 &&
                    EVP_DigestVerify(context, bytes, size, (const unsigned char *) text, strlen(text)) == 1)
                        verified_key = sd_json_variant_string(key);
                EVP_MD_CTX_free(context);
                EVP_PKEY_free(pkey);
                free(bytes);
                if (verified_key)
                        break;
        }

finish:
        free(text);
        sd_json_variant_unref(signable);
        return verified_key;
}

bool user_record_verify(sd_json_variant *record) {
        return user_record_signing_key(record) != NULL;
}
