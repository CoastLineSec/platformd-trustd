/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-json.h>

#define ATTESTATION_REFERENCE_SIZE_MAX (1024U * 1024U)

/* The reference and phase are independently approved inputs. A match appraises
 * PCR 11 only; it does not establish enrollment or authentication freshness. */
int attestation_appraise(sd_json_variant *token, const char *expected_ak_hex, const char *nonce_hex,
                        sd_json_variant *reference, const char *phase, sd_json_variant **ret_report);
