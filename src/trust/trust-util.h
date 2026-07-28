/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct TrustSessionState {
        int lock_state;
        uint64_t last_verification_boottime_usec;
        uint64_t last_verification_realtime_usec;
} TrustSessionState;

typedef struct TrustPolicyInput {
        bool session_exists;
        int active;
        int class_eligible;
        int lock_state;
        int remote;
        int64_t seconds_since_verification;
        bool user_verified;
        bool boot_verified;
        uint64_t freshness_window_sec;
} TrustPolicyInput;

typedef struct TrustPolicyDecision {
        bool satisfied;
        const char *reason_code;
        const char *reason;
} TrustPolicyDecision;

bool trust_text_valid(const char *text, size_t max);
bool trust_session_class_allowed(const char *class);
bool trust_auth_event_qualifies(
                const char *pam_service,
                const char *phase,
                const char *declared_method,
                const char *result);
void trust_session_set_lock(TrustSessionState *state, int locked);
void trust_session_record_verification(
                TrustSessionState *state,
                uint64_t boottime_usec,
                uint64_t realtime_usec);
void trust_session_invalidate_verification(TrustSessionState *state);
int64_t trust_seconds_since_verification(
                const TrustSessionState *state,
                uint64_t now_boottime_usec);
int trust_evaluate_policy(
                const char *policy,
                const TrustPolicyInput *input,
                TrustPolicyDecision *decision);
