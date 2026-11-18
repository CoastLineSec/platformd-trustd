/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-json.h>

/* The root and distribution-point mappings are verifier inputs, not device evidence.
 * Verification does not establish possession of the endorsement key. */
int endorsement_verify(sd_json_variant *evidence, const char *trust_anchor_pem,
                       const char *certificate_chain_pem, sd_json_variant *revocations,
                       sd_json_variant **ret_report);
