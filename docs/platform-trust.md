# Platform trust

## Scope

`platformd-trustd` collects local evidence about the current boot, logind
sessions, user records, and authentication events. It evaluates named policies
over this state and can produce TPM attestation.

The service does not authenticate users, verify PAM responses, release secrets,
or authorize operations. Callers remain responsible for enforcing a policy
result.

## Interface

The system service listens on
`/run/platformd-trustd/io.platformd.Trust`. The socket implements the
`io.platformd.Trust` Varlink interface.

The following methods read collected state:

* `GetBootEvidence`
* `GetMeasuredBoot`
* `ListSessions`
* `GetSessionTrust`
* `GetUserIdentity`
* `ListAuthEvents`
* `GetRuntimeLog`

`EvaluatePolicy` evaluates a named policy. `SubmitAuthEvent` accepts an
authentication event from a caller with user ID 0. `Attest`,
`GetAttestationToken`, `GetEnrollment`, and `ActivateCredential` perform TPM
operations and also require user ID 0.

No secret or PAM response is accepted or returned by this interface.

## Evidence

Boot identity and operating system metadata are observed from local system
interfaces. Secure Boot state is observed from EFI variables. The measured boot
record contains the TPM SHA-256 PCR bank and indicates whether the TCG event log
is present.

The boot quality is `verified-local` only when PCR 11 matches a reference under
`/var/lib/platformd-trustd/boot-references/`. These references are generated
from installed unified kernel images by `systemd-measure`. They are local
reference values and do not establish an external trust root.

User information is resolved through the User/Group Record Lookup API. A
systemd-homed record is reported as `verified` only after an Ed25519 signature
has been checked and the record's UID and name match the requested identity.
Any applicable signature may satisfy this check. The root-owned homed endpoint
is the identity authority; a key embedded in an arbitrary record is not an
independent trust root. Other user records are reported as `declared`.

Identity lookups run in bounded workers with a two-second overall deadline.
Policy results are evaluated against current session state after lookup completes.

Authentication events are declared evidence. Restricting submission to user ID
0 and measuring events into a TPM NV index protects the local collection and
attestation path. It does not turn a declared authentication method into
cryptographically verified evidence.

## Session state

Each session record corresponds to a current logind session. Only the following
classes are eligible for verification freshness:

* `user`
* `user-early`
* `user-light`
* `user-early-light`

Lock state and verification freshness have separate sources and update rules.

The `lockState` field is read from the logind `LockedHint` property. Its value is
`locked`, `unlocked`, or `unknown`. Locking or losing authoritative lock state
invalidates verification freshness. Unlocking never establishes freshness.
Subscriptions precede enumeration. Failed, missing, malformed, or obsolete
enumeration replies are retried asynchronously after two seconds. Only one
enumeration request or retry is pending at a time. A logind owner change discards
cached session state; a system-bus disconnect terminates the service for automatic
restart.

A new session has no verification timestamp. Creating or unlocking a session
does not establish freshness. A successful authentication event establishes
freshness only when all of these fields match:

| Field | Required value |
| --- | --- |
| `pamService` | `platformd-verify` |
| `phase` | `verify` |
| `declaredMethod` | `platformd-verify` |
| `result` | `success` |

The event must name an existing eligible session owned by the declared user ID.
The declared user name must match logind's name for that session. Verification events do
not change lock state.

Freshness is measured with `CLOCK_BOOTTIME`. Sleep preparation and its completion
both clear freshness, including canceled sleep attempts. Authentication events
received while preparation is active or its state is unavailable do not establish
freshness. The preparation state is queried at startup and after logind owner
changes; unavailable state is retried.
The default freshness window is 300 seconds. It may be changed with
`$PLATFORMD_TRUST_FRESH_WINDOW_SEC` in the service environment, from 1 to 86400.

The session record exposes the monotonic age and the realtime timestamp of the
last qualifying event. `verificationSource` is `platformd-verifyd` and
`verificationQuality` is `declared` when such an event is present.

## Authentication events

`SubmitAuthEvent` validates the peer, field types, field lengths, control
characters, user identity, session existence, and session ownership. The
accepted phases are `session` and `verify`. The accepted results are `success`
and `failure`.

Session records submitted by `pam_platformd.so` use the `session` phase. They
are retained for audit and runtime measurement but never establish
verification freshness.

Accepted events are kept in a bounded in-memory list and are submitted to the
runtime measurement log. The event list is lost when the daemon exits.
Acknowledgement records the event and freshness state; it does not wait for TPM
measurement. TPM work is serialized in a bounded queue with a twenty-second
overall deadline. A failed or dropped measurement marks the runtime log incomplete.

## Policies

`verified-boot` succeeds when the current PCR 11 value matches a provisioned
local reference. It does not require a session.

`fresh-user-verification` requires an existing eligible session, an available
active state, an active session, an available lock state, an unlocked session,
and a qualifying verification within the freshness window.

`local-trusted-session` adds a local session, a verified user record, and a
`verified-local` boot to the requirements of
`fresh-user-verification`.

Every result contains `policyId`, `sessionId`, `result`, `reasonCode`, `reason`,
and `windowSec`. `result` is `policy-satisfied` or `denied`. `reasonCode` is a
stable machine-readable value. The currently returned reason codes are:

* `boot-verified`
* `boot-not-verified`
* `session-not-found`
* `session-class-unknown`
* `session-class-ineligible`
* `session-state-unknown`
* `session-inactive`
* `lock-state-unknown`
* `session-locked`
* `verification-missing`
* `verification-stale`
* `verification-fresh`
* `session-locality-unknown`
* `session-remote`
* `identity-not-verified`
* `local-trusted-session`

Unknown policy names return `io.platformd.Trust.UnknownPolicy`.

## PAM policy enforcement

`pam_platformd.so` accepts policy replies only from the fixed system-service
endpoint with peer user ID 0. A successful reply must contain the requested
policy and session identifiers, a complete typed result, and the corresponding
positive reason code.

For session policies, `PAM_USER` must resolve to the owner of the calling
process's logind session. Environment-supplied session identifiers are not
used. A missing session or a different target account denies the gate. The
`verified-boot` gate evaluates the boot without selecting a user session.
These rules also prevent session records from naming another account's session.

## Attestation

When TPM2-TSS and a usable TPM are available, `Attest` returns a nonce-bound
TPM quote over the boot PCRs. Runtime events are extended into an NV index and
certified with the same attestation key. `GetAttestationToken` combines the
quote, measurements, and runtime log in an unsigned, platformd-specific JSON
envelope. Its media type is `application/vnd.platformd.attestation+json` and
its profile is `io.platformd.Trust.Attestation.v1`. The legacy Varlink output
field `eat` contains this envelope for interface compatibility. This is not an
RFC 9711 Entity Attestation Token.

TPM signatures protect only the embedded quote and NV certification structures.
`localAssertions`, including machine ID, time, and Secure Boot observation, are
unsigned. Secure Boot state is not evidence about debug facilities. A verifier
must compare the signed nonce, quoted PCR digest, NV name and value against the
returned data. `nvPublicHex` contains the marshaled `TPM2B_NV_PUBLIC` needed to
validate the index name and attributes.

The runtime log uses NV index `0x01800001`, with SHA-256, the extend type, a
32-byte value, and the fixed attributes checked by the implementation. Reads
never create an index. The administrative command
`platformd-trustd --initialize-runtime-log` creates a missing index and rejects
a conflicting definition. It does not replace or delete an existing index.
Restart the service after initializing the index.

The retained log is a window of at most 1024 events from the current service
instance. Evicting an event advances `baseline` to its resulting digest. Replay
starts at that baseline and computes `SHA256(previous || description)` over
each description's UTF-8 bytes, without a terminating NUL. A restart establishes
a new baseline and does not recover earlier event descriptions. Completeness
applies to this retained window, not the entire boot. It requires a matching
live NV value and no measurement failure during the service instance.

`GetEnrollment` returns the Endorsement Key and Attestation Key public data.
`ActivateCredential` completes a TPM credential activation exchange. A remote
verifier must validate the Endorsement Key certificate when present, bind the
Attestation Key with credential activation, verify the quote, check the nonce,
and appraise the supplied measurements.

Attestation methods return `io.platformd.Trust.AttestationUnsupported` when
TPM support was not built or no TPM device is available. TPM command, authorization,
or malformed-evidence failures return `AttestationFailed`. An incomplete runtime
measurement log is not emitted as complete attestation evidence.

## Limitations

Policy evaluation is local and reflects the evidence sources described above.
A `verified-local` boot uses references stored on the same host. Session lock
state depends on the desktop or locker maintaining logind `LockedHint`.
Authentication method fields are declarations from privileged local
components. The service does not provide a policy administration interface.
