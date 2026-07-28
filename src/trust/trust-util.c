/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "trust-util.h"

#include <errno.h>
#include <string.h>

#define streq(a, b) (strcmp((a), (b)) == 0)

bool trust_text_valid(const char *text, size_t max) {
        size_t n;

        if (!text)
                return false;

        n = strnlen(text, max + 1);
        if (n > max)
                return false;

        for (size_t i = 0; i < n; i++)
                if ((unsigned char) text[i] < 0x20 || (unsigned char) text[i] == 0x7f)
                        return false;

        return true;
}

bool trust_session_class_allowed(const char *class) {
        return class &&
               (streq(class, "user") ||
                streq(class, "user-early") ||
                streq(class, "user-light") ||
                streq(class, "user-early-light"));
}

bool trust_auth_event_qualifies(
                const char *pam_service,
                const char *phase,
                const char *declared_method,
                const char *result) {

        return pam_service && phase && declared_method && result &&
               streq(pam_service, "platformd-verify") &&
               streq(phase, "verify") &&
               streq(declared_method, "platformd-verify") &&
               streq(result, "success");
}

void trust_session_set_lock(TrustSessionState *state, int locked) {
        if (!state)
                return;

        state->lock_state = locked < 0 ? -1 : locked > 0;
}

void trust_session_record_verification(
                TrustSessionState *state,
                uint64_t boottime_usec,
                uint64_t realtime_usec) {

        if (!state)
                return;

        state->last_verification_boottime_usec = boottime_usec;
        state->last_verification_realtime_usec = realtime_usec;
}

void trust_session_invalidate_verification(TrustSessionState *state) {
        if (!state)
                return;

        state->last_verification_boottime_usec = 0;
        state->last_verification_realtime_usec = 0;
}

int64_t trust_seconds_since_verification(
                const TrustSessionState *state,
                uint64_t now_boottime_usec) {

        if (!state || state->last_verification_boottime_usec == 0)
                return -1;
        if (now_boottime_usec < state->last_verification_boottime_usec)
                return -1;

        return (int64_t)
                ((now_boottime_usec - state->last_verification_boottime_usec) / 1000000U);
}

static void deny(TrustPolicyDecision *decision, const char *code, const char *reason) {
        decision->satisfied = false;
        decision->reason_code = code;
        decision->reason = reason;
}

static void satisfy(TrustPolicyDecision *decision, const char *code, const char *reason) {
        decision->satisfied = true;
        decision->reason_code = code;
        decision->reason = reason;
}

int trust_evaluate_policy(
                const char *policy,
                const TrustPolicyInput *input,
                TrustPolicyDecision *decision) {

        if (!policy || !input || !decision)
                return -EINVAL;

        if (streq(policy, "verified-boot")) {
                if (input->boot_verified)
                        satisfy(
                                        decision,
                                        "boot-verified",
                                        "boot matches a provisioned reference");
                else
                        deny(
                                        decision,
                                        "boot-not-verified",
                                        "boot does not match a provisioned reference");
                return 0;
        }

        if (!streq(policy, "fresh-user-verification") &&
            !streq(policy, "local-trusted-session"))
                return -EOPNOTSUPP;

        if (!input->session_exists) {
                deny(decision, "session-not-found", "session does not exist");
                return 0;
        }
        if (input->class_eligible < 0) {
                deny(decision, "session-class-unknown", "session class is unavailable");
                return 0;
        }
        if (input->class_eligible == 0) {
                deny(decision, "session-class-ineligible", "session class is not eligible");
                return 0;
        }
        if (input->active < 0) {
                deny(decision, "session-state-unknown", "session active state is unavailable");
                return 0;
        }
        if (input->active == 0) {
                deny(decision, "session-inactive", "session is not active");
                return 0;
        }
        if (input->lock_state < 0) {
                deny(decision, "lock-state-unknown", "session lock state is unavailable");
                return 0;
        }
        if (input->lock_state > 0) {
                deny(decision, "session-locked", "session is locked");
                return 0;
        }
        if (input->seconds_since_verification < 0) {
                deny(decision, "verification-missing", "no qualifying verification was recorded");
                return 0;
        }
        if ((uint64_t) input->seconds_since_verification > input->freshness_window_sec) {
                deny(decision, "verification-stale", "the last verification is outside the freshness window");
                return 0;
        }

        if (streq(policy, "fresh-user-verification")) {
                satisfy(
                                decision,
                                "verification-fresh",
                                "session has a fresh qualifying verification");
                return 0;
        }

        if (input->remote < 0) {
                deny(decision, "session-locality-unknown", "session locality is unavailable");
                return 0;
        }
        if (input->remote > 0) {
                deny(decision, "session-remote", "session is remote");
                return 0;
        }
        if (!input->user_verified) {
                deny(decision, "identity-not-verified", "user identity is not verified");
                return 0;
        }
        if (!input->boot_verified) {
                deny(decision, "boot-not-verified", "boot does not match a provisioned reference");
                return 0;
        }

        satisfy(
                        decision,
                        "local-trusted-session",
                        "local session, user identity, boot, and verification satisfy policy");
        return 0;
}
