/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-json.h>

__attribute__((visibility("hidden")))
int pam_trust_call(const char *method, sd_json_variant *params, sd_json_variant **ret_reply);
