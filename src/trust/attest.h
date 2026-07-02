/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * TPM2 attestation for platformd-trustd. Produces a hardware-signed quote over
 * the SHA-256 boot PCRs, bound to a caller nonce, verifiable against the
 * attestation key's public part without trusting trustd. Built on tss2-esys; a
 * stub returns -ENOTSUP when the TPM libraries are absent.
 *
 * The attestation key is a restricted ECC (NIST P-256, ECDSA-SHA256) signing
 * primary in the owner hierarchy — deterministic from the TPM's primary seed, so
 * it is regenerated (not stored) on each call and is stable across reboots.
 */

/* Produce a quote over PCRs 0..15 (SHA-256), bound to `nonce`. Outputs are
 * malloc'd (caller frees): the marshaled AK public (TPM2B_PUBLIC), the raw
 * attestation data (TPMS_ATTEST), and the marshaled signature (TPMT_SIGNATURE).
 * Returns 0, or a negative errno-style code (-ENOTSUP without TPM2 support,
 * -EACCES when the TPM is unreachable, -EIO on a TPM error). */
int attest_quote(const uint8_t *nonce, size_t nonce_len,
                 uint8_t **ak_pub, size_t *ak_pub_len,
                 uint8_t **quoted, size_t *quoted_len,
                 uint8_t **sig, size_t *sig_len);

/* The runtime auth log lives in an extend-only NV index (append-only within a
 * boot; not resettable at locality 0 like an application PCR). Read the current
 * value, extend it with an event (TPM computes H(old || data)), and produce an
 * AK-signed certification of the value bound to a nonce. value_out is 32 bytes;
 * the certify outputs are malloc'd. Return 0 or a negative errno-style code. */
int attest_nv_read(uint8_t value_out[32]);
int attest_nv_extend(const uint8_t *data, size_t len, uint8_t value_out[32]);
int attest_nv_certify(const uint8_t *nonce, size_t nonce_len,
                      uint8_t **ak_pub, size_t *ak_pub_len,
                      uint8_t **certify_info, size_t *certify_info_len,
                      uint8_t **sig, size_t *sig_len);

/* Enrollment evidence for binding the AK to a genuine TPM: the EK public and (if
 * present in NV) its manufacturer certificate, plus the AK public and its TPM
 * name. All outputs are malloc'd (caller frees); ek_cert may be NULL. */
int attest_get_enrollment(uint8_t **ek_pub, size_t *ek_pub_len,
                          uint8_t **ek_cert, size_t *ek_cert_len,
                          uint8_t **ak_pub, size_t *ak_pub_len,
                          uint8_t **ak_name, size_t *ak_name_len);

/* Activate a credential a verifier made (TPM2_MakeCredential) for the AK's name
 * and the EK: recovers the challenge only if the AK and EK are on this TPM —
 * proving the AK is genuine. cred/secret are the marshaled TPM2B_ID_OBJECT /
 * TPM2B_ENCRYPTED_SECRET. challenge is malloc'd. */
int attest_activate_credential(const uint8_t *cred, size_t cred_len,
                               const uint8_t *secret, size_t secret_len,
                               uint8_t **challenge, size_t *challenge_len);
