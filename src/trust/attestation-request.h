/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-json.h>

/* Expiry and single use belong to the verifier's request store. */
int attestation_appraise_request(sd_json_variant *token, const char *expected_ak_hex,
                                sd_json_variant *request, sd_json_variant *reference, const char *phase,
                                sd_json_variant **ret_report);
