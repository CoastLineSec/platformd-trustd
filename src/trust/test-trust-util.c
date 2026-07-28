/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "trust-util.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

static void expect(
                const char *policy,
                TrustPolicyInput input,
                bool satisfied,
                const char *reason_code) {

        TrustPolicyDecision decision;

        assert(trust_evaluate_policy(policy, &input, &decision) == 0);
        assert(decision.satisfied == satisfied);
        assert(strcmp(decision.reason_code, reason_code) == 0);
        assert(decision.reason && *decision.reason);
}

int main(void) {
        TrustSessionState state = { .lock_state = -1 };
        TrustPolicyInput input = {
                .session_exists = true,
                .active = 1,
                .class_eligible = 1,
                .lock_state = 0,
                .remote = 0,
                .seconds_since_verification = 0,
                .user_verified = true,
                .boot_verified = true,
                .freshness_window_sec = 300,
        };
        TrustPolicyDecision decision;

        trust_session_set_lock(&state, 0);
        assert(state.lock_state == 0);
        assert(state.last_verification_boottime_usec == 0);
        trust_session_set_lock(&state, 1);
        trust_session_record_verification(&state, 1000000U, 2000000U);
        assert(state.lock_state == 1);
        assert(trust_seconds_since_verification(&state, 3000000U) == 2);
        trust_session_set_lock(&state, 0);
        assert(state.last_verification_boottime_usec == 1000000U);
        trust_session_invalidate_verification(&state);
        assert(trust_seconds_since_verification(&state, 4000000U) == -1);

        assert(trust_auth_event_qualifies(
                       "platformd-verify", "verify", "platformd-verify", "success"));
        assert(!trust_auth_event_qualifies(
                       "login", "session", "password", "success"));
        assert(!trust_auth_event_qualifies(
                       "platformd-verify", "verify", "platformd-verify", "failure"));

        expect("verified-boot", input, true, "boot-verified");
        input.boot_verified = false;
        expect("verified-boot", input, false, "boot-not-verified");
        input.boot_verified = true;

        input.session_exists = false;
        expect("fresh-user-verification", input, false, "session-not-found");
        input.session_exists = true;
        input.class_eligible = -1;
        expect("fresh-user-verification", input, false, "session-class-unknown");
        input.class_eligible = 0;
        expect("fresh-user-verification", input, false, "session-class-ineligible");
        input.class_eligible = 1;
        input.active = -1;
        expect("fresh-user-verification", input, false, "session-state-unknown");
        input.active = 0;
        expect("fresh-user-verification", input, false, "session-inactive");
        input.active = 1;
        input.lock_state = -1;
        expect("fresh-user-verification", input, false, "lock-state-unknown");
        input.lock_state = 1;
        expect("fresh-user-verification", input, false, "session-locked");
        input.lock_state = 0;
        input.seconds_since_verification = -1;
        expect("fresh-user-verification", input, false, "verification-missing");
        input.seconds_since_verification = 301;
        expect("fresh-user-verification", input, false, "verification-stale");
        input.seconds_since_verification = 300;
        expect("fresh-user-verification", input, true, "verification-fresh");

        input.remote = -1;
        expect("local-trusted-session", input, false, "session-locality-unknown");
        input.remote = 1;
        expect("local-trusted-session", input, false, "session-remote");
        input.remote = 0;
        input.user_verified = false;
        expect("local-trusted-session", input, false, "identity-not-verified");
        input.user_verified = true;
        input.boot_verified = false;
        expect("local-trusted-session", input, false, "boot-not-verified");
        input.boot_verified = true;
        expect("local-trusted-session", input, true, "local-trusted-session");

        assert(trust_evaluate_policy("unknown", &input, &decision) == -EOPNOTSUPP);
        assert(trust_text_valid("valid", 16));
        assert(!trust_text_valid("invalid\n", 16));
        assert(trust_session_class_allowed("user"));
        assert(trust_session_class_allowed("user-light"));
        assert(!trust_session_class_allowed("manager"));
        return 0;
}
