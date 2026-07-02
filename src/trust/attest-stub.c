/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Built when the tss2 libraries are absent: attestation is unsupported. */

#include "attest.h"

#include <errno.h>

int attest_quote(const uint8_t *nonce, size_t nonce_len,
                 uint8_t **ak_pub, size_t *ak_pub_len,
                 uint8_t **quoted, size_t *quoted_len,
                 uint8_t **sig, size_t *sig_len) {
        return -ENOTSUP;
}

int attest_nv_read(uint8_t value_out[32]) {
        return -ENOTSUP;
}

int attest_nv_extend(const uint8_t *data, size_t len, uint8_t value_out[32]) {
        return -ENOTSUP;
}

int attest_nv_certify(const uint8_t *nonce, size_t nonce_len,
                      uint8_t **ak_pub, size_t *ak_pub_len,
                      uint8_t **certify_info, size_t *certify_info_len,
                      uint8_t **sig, size_t *sig_len) {
        return -ENOTSUP;
}

int attest_get_enrollment(uint8_t **ek_pub, size_t *ek_pub_len,
                          uint8_t **ek_cert, size_t *ek_cert_len,
                          uint8_t **ak_pub, size_t *ak_pub_len,
                          uint8_t **ak_name, size_t *ak_name_len) {
        return -ENOTSUP;
}

int attest_activate_credential(const uint8_t *cred, size_t cred_len,
                               const uint8_t *secret, size_t secret_len,
                               uint8_t **challenge, size_t *challenge_len) {
        return -ENOTSUP;
}
