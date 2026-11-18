/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <systemd/sd-json.h>

typedef struct Enrollment Enrollment;

/* The state directory must exist, be absolute, and be owned by the effective UID with mode 0700.
 * The endorsement key is an independently provisioned TPM2B_PUBLIC, not an evidence field. */
int enrollment_begin(const char *state_dir, sd_json_variant *evidence, const char *expected_ek_hex,
                     uint64_t lifetime_sec, sd_json_variant **ret_challenge);
int enrollment_complete(const char *state_dir, const char *key_id, const char *request_id,
                        const char *response_hex, sd_json_variant **ret_status);
int enrollment_revoke(const char *state_dir, const char *key_id, sd_json_variant **ret_status);
int enrollment_status(const char *state_dir, const char *key_id, sd_json_variant **ret_status);

/* Acquisition holds a shared lock until release. A successful verification is a snapshot of this
 * enrollment state; it does not remain valid across a subsequent revocation. */
int enrollment_acquire(const char *state_dir, const char *key_id, Enrollment **ret);
const char *enrollment_attestation_key(const Enrollment *enrollment);
void enrollment_release(Enrollment *enrollment);

int enrollment_request_begin(const char *state_dir, const char *key_id, sd_json_variant *context,
                             uint64_t lifetime_sec, sd_json_variant **ret_request);
/* A matching request is durably consumed before returning. The exclusive enrollment lock must
 * remain held through appraisal. Consumption alone does not establish authentication. */
int enrollment_request_consume(const char *state_dir, const char *key_id, const char *request_id,
                               Enrollment **ret_enrollment, sd_json_variant **ret_request);
