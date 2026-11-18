/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#include <systemd/sd-json.h>

#define ATTESTATION_TOKEN_SIZE_MAX (16U * 1024U * 1024U)

int attestation_key_name(const char *ak_hex, uint8_t ret_name[static 34]);

/* The expected TPM2B_PUBLIC and nonce must come from the verifier, not the token.
 * A successful result checks evidence integrity, not enrollment or policy. */
int attestation_verify(sd_json_variant *token, const char *expected_ak_hex, const char *nonce_hex,
                       sd_json_variant **ret_report);
