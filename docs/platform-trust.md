# The platformd Trust Authority

`platformd-trustd` maintains **local platform-authentication state** for a Linux
system. It binds the evidence that today lives scattered across the boot chain,
PAM, `systemd-logind`, `systemd-homed`, the compositor's lock screen, and D-Bus
peer credentials into a single set of inspectable records, and it answers, for any
session or caller, *how did this state come to be, and what named local policy
does it satisfy right now*. Its purpose is not to authenticate — PAM, logind,
homed, and polkit already do that — but to be the **connecting authority** that
none of them is: the place where login stops being the end of authentication and
becomes one event in a longer, inspectable chain.

This document describes the daemon, the interfaces it serves, the `trustctl`
client, the state and policy models, and the security properties it does and does
not provide. Terms follow the `platformd` claim vocabulary — `observed`,
`declared`, `measured`, `verified`, `policy-satisfied`, `trusted` — and default to
`policy-satisfied`. Nothing here is `trusted` unless a trust root, policy, threat
model, and enforcement mechanism are all named, and — because no code exists yet —
nothing here is a current fact. This is a design reference; the
[roadmap](#implementation-status) marks what any future build has actually
delivered.

## Overview

Linux already has the raw parts of platform authentication. Firmware exposes
Secure Boot state; the TPM and measured boot record what produced the running
system; LUKS and `systemd-homed` protect user state; PAM proves a user to a
service; `systemd-logind` tracks sessions, seats, and lock state; `systemd-homed`
and `userdbd` resolve identity; polkit authorizes privileged actions; the Secret
Service releases credentials; the kernel keyring, cgroups, and D-Bus peer
credentials describe processes. Each is a good boundary in isolation.

What Linux lacks is the *connecting authority*. No component can answer, coherently
and in one place:

- what boot produced this running system, and was it measured or verified;
- which user authenticated, by what method, and how recently;
- what session that authentication created, and whether it is active, locked,
  idle, remote, or stale after a suspend;
- whether the user's home is unlocked and available;
- which process is asking, and how strong that caller's identity is;
- and therefore, what named local policy the current state satisfies.

Each mechanism knows its own slice. Nothing binds the slices into a record a shell,
an administrator, or a local policy can read. `platformd-trustd` is that binding.
It does not authenticate, encrypt, or gate anything on its own; it observes the
existing mechanisms, records their evidence with honest quality labels, and
exposes the result. The first real goal is not to make Linux "trusted" — it is to
make Linux authentication state **explicit, inspectable, and policy-addressable**.

## Why you would run it

`platformd-trustd` is designed to be useful on any Linux desktop or server, well
before the full platform-authentication chain exists, and independently of the
rest of platformd:

- **One place to ask "what state is this session in."** `trustctl status`
  reports, for the current or any session: which boot, whether Secure Boot is on
  and a TPM is present, whether the home is active, whether the session is active
  / locked / idle / remote, how recently the user authenticated, and whether the
  session resumed from suspend and may be stale.
- **A session-freshness source for local policy.** Any service that wants to act
  "only if the user verified recently" can ask `platformd-trustd` instead of
  reinventing lock tracking and freshness windows. `platformd-secretd` is the
  first such consumer — today it carries that logic privately; trustd is where it
  belongs and can be shared.
- **A desktop-neutral authentication audit trail.** By observing PAM events across
  greeters, lockers, `run0`, and polkit, trustd gives administrators and local
  tools a single, honest "recent authentication happened, by this declared
  method" signal that no per-desktop keyring provides.
- **Security-state reporting that does not lie.** trustd labels every record
  `observed`, `declared`, `measured`, `verified`, or `policy-satisfied`, and shows
  `degraded` or `unsupported` where evidence is missing. It never renders a
  session "trusted" for a badge.

It is **observability-first**: it does not gate your login, and it does not hold or
release any secret. Enforcement is something *other* components opt into by asking
trustd a policy question — trustd answers; the caller decides.

## Non-goals

`platformd-trustd` does not, and is not intended to:

- replace PAM, polkit, `systemd-logind`, `systemd-homed`, NSS, or a package
  manager;
- act as a login manager, greeter, lock screen, or keyring;
- authenticate passwords, verify biometrics, or check secrets itself;
- claim hardware-backed trust before a TPM policy, recovery story, and threat
  model exist;
- pretend that same-user Linux process isolation is solved;
- gate login or secret release in its first form.

## Architecture

The component is two programs, in the manner of a systemd daemon and its companion
tool (compare `systemd-logind` and `loginctl`, or `systemd-homed` and `homectl`):

- **`platformd-trustd`** — the daemon. A **system** service (unlike
  `platformd-secretd`, which is per-user), because the evidence it binds — boot
  measurement, PAM events, logind sessions across seats, homed activation — is
  system-wide. It runs an `sd-event` loop, connects to the system bus with
  `sd-bus`, listens on a Varlink socket with `sd-varlink`, and audits to the
  journal with `sd-journal`. It announces readiness with `sd_notify(3)`.
- **`trustctl`** — the command-line client, used to inspect boot, session,
  caller, and policy state.

trustd sits between the mechanisms it *consumes* and the state it *emits*:

```
   inputs (observed)                       platformd-trustd                 outputs
   ------------------                      ----------------                 -------
   boot chain / TPM / Secure Boot  ─┐
   systemd-logind (sessions, lock) ─┤                                  ┌─ Varlink  io.platformd.Trust
   systemd-homed / userdb          ─┼──▶  evidence  ──▶  records  ──▶  ├─ D-Bus    org.freedesktop.platform1
   PAM (via pam_platformd.so)      ─┤     + quality      + policy      ├─ journald  audit events
   compositor / locker lock events ─┤                                  └─ trustctl
   pacd / update facts (later)     ─┘
```

trustd owns none of the inputs. It reads them, stamps each with an evidence
quality, binds them into the [records](#state-model) below, and serves those
records read-only. The one privileged input is the PAM bridge, which *submits*
authentication events; every other input is polled or subscribed.

## The interfaces

Following the split the platform-auth chain plan calls for: a Varlink surface for
systemd-style administrative and programmatic access (the first and primary
interface, matching `platformd-secretd`'s `io.platformd.Secret`), and a D-Bus
surface for desktop- and session-facing integration where signals and existing
bus consumers matter.

### Varlink — `io.platformd.Trust`

Read-only introspection and state, served on a system socket. Metadata and state
only; no secret material ever crosses it. Sketch:

| Method | Returns |
| --- | --- |
| `GetBootEvidence()` | the [boot-evidence record](#boot-evidence-record) for the running boot |
| `ListSessions()` | the tracked sessions and a summary of each |
| `GetSessionTrust(sessionId)` | the full [session-trust record](#session-trust-record) |
| `GetCallerIdentity(pid)` | the [caller-identity record](#caller-identity-record) for a process |
| `EvaluatePolicy(policy, sessionId?, pid?)` | a [policy-result record](#policy-result-record): satisfied or denied, with the reason |
| `ListAuthEvents(sessionId?)` | recent [authentication-event records](#authentication-event-record) |

A single privileged method, `SubmitAuthEvent`, accepts records from the PAM bridge
and is restricted to callers that can prove they are the bridge (see below).

### D-Bus — `org.freedesktop.platform1`

The desktop-facing surface, added once a graphical consumer needs change signals
rather than polling (the shell showing live lock/trust state; a polkit rule
querying session freshness). A `Manager` object exposes boot evidence and session
enumeration; per-session objects expose `Active`, `Locked`, `LastVerification`,
and `PolicyResults` properties with `PropertiesChanged` signals on transition. The
exact well-known name is an open decision (see [Naming](#naming)).

### The PAM bridge — `pam_platformd.so`

A PAM module, the one component that *writes* to trustd. Placed in the greeter and
locker PAM stacks, it converts successful (and, where useful, failed) PAM
authentication, account, and session events into structured records and submits
them over a private Varlink socket. It is observability-first: it does not verify
passwords, does not replace `pam_unix` or `pam_systemd`, and declares the
authentication method honestly (`password-pam-declared`, `fido2-pam-declared`,
`fingerprint-pam-declared`, `unknown-pam-success`) rather than asserting a strength
it cannot prove.

### `trustctl`

The inspector, in the shape of `loginctl` / `homectl`:

| Command | Purpose |
| --- | --- |
| `trustctl status` | boot, TPM/Secure Boot, and the caller's own session at a glance |
| `trustctl boot` | the full boot-evidence record and its quality |
| `trustctl list-sessions` | tracked sessions with state and freshness |
| `trustctl session <id>` | one session's full trust record |
| `trustctl explain <policy> [<id>]` | why a named policy is or is not satisfied |
| `trustctl events` | recent authentication events |

## Evidence and claim language

Every record carries an `evidence_quality`, and every field is only ever as strong
as its source. trustd uses one vocabulary, and defaults to the weakest word that
fits:

| Term | Meaning |
| --- | --- |
| `unknown` | not enough information |
| `observed` | read from the local system, not independently validated |
| `declared` | a component reported it; trustd did not verify it |
| `measured` | a TPM, IMA, or measured-boot mechanism recorded it |
| `verified` | a signature or policy validated it against an accepted key |
| `policy-satisfied` | enough evidence exists to satisfy a *named* local policy |
| `degraded` | state conflicts with a policy's expectations |

`trusted` is deliberately absent from routine output. It is valid only where a
trust root, policy, threat model, and enforcement mechanism are all documented —
which, for most desktop state, they are not. The correct sentence is "session 3
satisfies `local-console-password-after-accepted-boot`", never "session 3 is
trusted".

## State model

trustd tracks records, not impressions. The five record types below are the
concrete shape of the state it binds; fields are illustrative and will be pinned
during implementation.

### Boot-evidence record

```
boot_evidence_id   boot_id          machine_id
secure_boot_state  tpm_state        pcr_summary
uki_identity       kernel_identity  initramfs_identity
os_release         boot_policy_id   evidence_quality   warnings   created_at
```

Sourced from `sd_id128_get_boot`/`_machine`, `os-release`, `bootctl` / systemd-boot
state, EFI variables for Secure Boot, and — where present — the TPM event log and
PCRs. First form records `observed`/`measured` and asserts nothing verified.

### Authentication-event record

```
auth_event_id  user   uid    pam_service   pam_phase   declared_method
auth_strength  result seat   tty   remote_host   evidence_quality   created_at
```

Submitted by `pam_platformd.so`. `declared_method` is honest by construction; trustd
does not upgrade a declaration to a verification.

### Session-trust record

```
session_id       user           uid        seat     session_type   session_class
logind_state     boot_evidence_id  auth_event_id   home_state
lock_state       last_verification_at   stale_reason   policy_results
created_at       updated_at
```

The heart of trustd: a logind session, bound to the boot that produced it and the
authentication event that created it, annotated with home activation, lock state,
and freshness. This is the record `platformd-secretd` would consult in place of
its private lock/freshness tracking.

### Caller-identity record

```
caller_id  uid  gid  pid  process_start_time  cgroup  systemd_unit
dbus_name  executable  flatpak_app_id  portal_app_id  lsm_label  identity_quality
```

Graded from D-Bus peer credentials, `/proc`, cgroup and unit membership, and — where
present — Flatpak/portal app identity. `identity_quality` runs
`unknown` < `same-user-weak` < `systemd-unit` < `dbus-subject` < `sandboxed-app`.
This generalizes the caller grading `platformd-secretd` already performs.

### Policy-result record

```
policy_id  subject  session_id  caller_id  inputs  result  reason  created_at  expires_at
```

The answer to an `EvaluatePolicy` query: which named policy, what it was given,
whether it is satisfied, and — always — why.

## Policy model

Policies are named, explainable, and composed from records. A policy never returns
a bare boolean; it returns a result plus the reason. Illustrative set:

- **`local-console-basic`** — an active local logind session, a successful PAM
  authentication event, and (for a homed user) an active home. Requires no boot
  evidence. Use: early shell state, low-risk local decisions.
- **`local-console-after-accepted-boot`** — `local-console-basic`, plus boot
  evidence satisfying an accepted boot policy and no boot-affecting update pending
  reboot. Use: higher-value desktop actions.
- **`fresh-user-verification`** — an active, unlocked session with a successful
  authentication or unlock event inside a time window, not stale after
  suspend/resume. Use: secret access, sensitive settings. **This is the policy
  `platformd-secretd`'s trust gate is a local prototype of.**
- **`credential-release-basic`** — `fresh-user-verification`, plus a caller
  identity meeting a quality floor. Use: a future credential broker, or
  `platformd-secretd` querying trustd instead of grading callers itself.

## Relationship to systemd and platformd

trustd owns nothing systemd already owns. It does not create sessions (logind
does), authenticate users (PAM does), manage homes (homed does), or authorize
actions (polkit does). It consumes their evidence and binds it — the one local
authority that reads across all of them. Under the project's guiding constraint
that `platformd` is a placeholder for `systemd`, `platformd-trustd` is the daemon
systemd would ship to make Linux authentication state explicit, sitting beside
`systemd-logind` and `systemd-homed` and speaking the same idioms (sd-bus,
Varlink, journal audit, a `*ctl` companion).

Within platformd, trustd is the **trust oracle** the other components consume:

- **`platformd-secretd`** is the first consumer. Its trust gate already tracks the
  logind lock, grades caller identity, and enforces a freshness window — *locally*.
  That logic is precisely the slice trustd centralizes; secretd's gate becomes a
  thin client of trustd's `fresh-user-verification` / `credential-release-basic`
  policies, and the seam it was built with (a single decision point in front of
  every release) is where trustd plugs in.
- Later consumers are polkit rules and `run0` (session-freshness-aware
  authorization), and QuickGlassShell (displaying honest session and boot state).

## Threat model and known limits

trustd exposes limits; it does not paper over them. It cannot, and will not
pretend to, fix:

- weak same-user process isolation on a mutable desktop;
- a missing or low-quality TPM, or disabled Secure Boot;
- local root compromise, untrusted firmware, or a malicious compositor;
- a spoofed authentication prompt before a trusted-UI path exists;
- attestation without a verifier policy and device-identity lifecycle.

Where these hold, the affected records read `degraded` or `unsupported`, and any
policy that depended on the missing property returns denied with that reason. A
recovery boot, a LUKS recovery key, or a homed password reset marks the session
state accordingly and does not silently inherit a normal session's standing.

## Naming

Open decisions to settle before code:

- the D-Bus well-known name (`org.freedesktop.platform1` is the working
  placeholder; it should read as the name systemd would use);
- whether the first build ships the Varlink surface only (matching the
  observability-first milestone) and defers D-Bus until a graphical consumer
  exists;
- the Varlink interface name (`io.platformd.Trust`, renaming to `io.systemd.Trust`
  under the project's rename test, consistent with systemd's `io.systemd.*`
  Varlink interfaces).

## Implementation status

No code exists yet; this document is the design that precedes it, exactly as
`docs/secret-service.md` preceded `platformd-secretd`.

| Milestone | Scope | State |
| --- | --- | --- |
| T1 | observability core: `platformd-trustd` claims the bus, records boot-id / machine-id / os-release, enumerates logind sessions, serves them over `io.platformd.Trust`, and `trustctl status` / `list-sessions` print them | planned |
| T2 | session-trust records: lock state and freshness (the logind tracking generalized from `platformd-secretd`), the `fresh-user-verification` policy, and `platformd-secretd` consuming it | planned |
| T3 | `pam_platformd.so` and authentication-event records; `trustctl events` | planned |
| T4 | boot evidence: Secure Boot and TPM/PCR state recorded as `observed` / `measured`; the `*-after-accepted-boot` policy inputs | planned |
| T5 | the D-Bus `org.freedesktop.platform1` state API and QuickGlassShell integration | planned |
| T6+ | caller-identity generalization, a named policy engine, recovery-state handling, and (much later, only with a verifier) attestation | deferred |

The discipline is the platform-auth chain plan's: build observability before
enforcement, never claim `trusted` without a documented basis, and let each record
be only as strong as its evidence.
