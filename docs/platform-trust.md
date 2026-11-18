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
its profile is `io.platformd.Trust.Attestation.v2`. The legacy Varlink output
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

At startup, the service prepares an existing index whose `TPMA_NV_WRITTEN` bit
is clear. It extends `SHA256("io.platformd.Trust.RuntimeLog.v2:initial")`, using
the ASCII string without a terminating NUL. The initial baseline is
`SHA256(32 zero bytes || seedDigest)`, where `seedDigest` is that string's
SHA-256 digest. Explicit initialization uses the same baseline. A written index
retains its current value. Startup preparation does not create an index, record
authentication, or establish freshness. Runtime-log queries and certification
remain read-only.

The runtime log format is `io.platformd.Trust.RuntimeLog.v2`. Each event's
`description` contains the exact compact JSON record measured by the service.
Its `format` is `io.platformd.Trust.RuntimeEvent.v2`. The record includes the
boot ID, `CLOCK_BOOTTIME` and `CLOCK_REALTIME` timestamps in microseconds, event
type, source, evidence quality, and typed payload. Authentication payloads
include all accepted event fields and the peer UID. The source identifies the
submission interface, not an independently authenticated executable. Lock and
sleep records identify the corresponding logind interface. Each event's clocks
are sampled once; verification freshness uses the same authentication sample.

Replay starts at `baseline`. For each event, compute `eventDigest =
SHA256(description)` over the UTF-8 bytes of the returned JSON string, without a
terminating NUL, then `next = SHA256(previous || eventDigest)`. Do not parse and
reserialize the record before hashing. Records are limited to 8192 bytes; each
NV extension contains the 32-byte event digest. A verifier must check the
record and log versions. The outer `realtimeUSec` is a convenience copy, not
independent evidence; the timestamp inside the measured record is authoritative
and a verifier must reject a mismatch. Version 1 extended the description bytes directly and
did not bind event timestamps. Its replay rule must not be used for version 2.

The retained log is a window of at most 1024 events from the current service
instance. Evicting an event advances `baseline` to its resulting digest. A
restart establishes a new baseline from the existing NV value and does not
recover earlier records. This also applies when upgrading from version 1; the
index is neither replaced nor cleared. Completeness applies to the retained
window, not the entire boot. It requires a matching live NV value and no
measurement failure during the service instance.

The measured timestamps and boot ID remain host assertions. Their integrity
does not establish an independently trusted clock or prove that authentication
was recent. A fresh quote proves possession of the attestation key when the
challenge was answered, not the age or method of an authentication event.

`GetEnrollment` returns the Endorsement Key and Attestation Key public data.
`ActivateCredential` completes a TPM credential activation exchange. A remote
verifier must validate the Endorsement Key certificate when present, bind the
Attestation Key with credential activation, verify the quote, check the nonce,
and appraise the supplied measurements.

Attestation methods return `io.platformd.Trust.AttestationUnsupported` when
TPM support was not built or no TPM device is available. TPM command, authorization,
or malformed-evidence failures return `AttestationFailed`. An incomplete runtime
measurement log is not emitted as complete attestation evidence.

## Remote verification

The verifier operates independently of the attester. `trustctl enrollment-begin`
uses an independently provisioned Endorsement Key pin and a bounded credential
activation challenge to bind an Attestation Key. The verifier owns the private
enrollment directory, expiry, and revocation. No manufacturer trust anchor or
account association is supplied. A revoked key remains revoked; key replacement
requires a new enrollment. `tpm2_makecredential` is required only for enrollment.

`trustctl appraise-attestation` compares verified SHA-256 PCR 11 against an
explicitly approved `systemd-measure` JSON reference and phase. It does not read
the attester's local reference directory. Approval of PCR 11 is not approval of
firmware, Secure Boot policy, or every component of the running system.

`trustctl request-begin` creates a verifier-owned challenge for an enrolled key,
UID, session, audience, and operation digest. `VerifyUserWithContext` in verifyd
performs PAM verification with that immutable context. Successful completion
submits `SubmitVerificationEvent` as root. The receiver checks session ownership,
activity, locality, lock state, and invalidation ordering. Completion timestamps
follow worker cleanup and final session validation, not the PAM return instant.
The record timestamps identify receipt; the payload retains
`verificationBoottimeUSec` and `verificationRealtimeUSec`.

The submission reply precedes the asynchronous NV extension. PAM success is not
proof of measurement or remote acceptance. The token remains restricted to root
and contains the global retained history. No unprivileged export permission is
implied by a contextual verification request. A version 2 verifier that does not
recognize `SubmitVerificationEvent` rejects that record; it must not ignore it.

`trustctl request-complete` consumes the matching request before appraisal and
holds the enrollment lock through verification. It requires the exact context
in the certified retained history, with no later session lock or sleep
invalidation. The application must explicitly accept root-declared PAM evidence.
The unpredictable challenge and verifier-owned expiry establish the request
window; device clocks do not. A failed appraisal consumes the request as well.
Restarting the verifier's process retains state; rebooting invalidates pending
requests. Revocation invalidates outstanding requests.

The result is not a bearer credential or an authorization decision. The remote
service owns authenticated transport, account-to-device mapping, approved
references, operation encoding, and authorization. The measured declaration
does not prove user consent or a particular factor. Root can submit declarations
and controls the runtime NV index; measurement does not remove that trust boundary.

## Limitations

`trustctl verify-attestation` verifies an evidence envelope offline against an
independently supplied Attestation Key and expected challenge. Its JSON result
reports cryptographic consistency, not enrollment, accepted boot state, or
authentication freshness. The requester owns challenge expiry and single-use
enforcement. See `trustctl(1)` for the input format and verification limits.

Policy evaluation is local and reflects the evidence sources described above.
A `verified-local` boot uses references stored on the same host. Session lock
state depends on the desktop or locker maintaining logind `LockedHint`.
Authentication method fields are declarations from privileged local
components. The service does not provide a policy administration interface.
