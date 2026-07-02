/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include <systemd/sd-json.h>

/* Cryptographically verify a homed user record in-process: reproduce the signed
 * form (the record minus the non-signable sections {binding,status,signature,
 * secret}, key-sorted and compact — the same sd-json normalization homed signs)
 * and check the embedded Ed25519 signature against the embedded public key.
 * Makes trustd a true verifier of the identity, not a relay of userdb's claim. */
bool user_record_verify(sd_json_variant *record);
