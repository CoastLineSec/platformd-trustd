# platformd-trustd

platformd-trustd is a platform-authentication state and attestation service for
Linux systems — it reports the boot state, login sessions, user identity, and
authentication events, and produces TPM-based attestation over them. It is a
component of platformd (see `centricd-os`), written in C against libsystemd
(sd-bus, sd-event, sd-login, sd-journal, sd-varlink, sd-json), the TPM2 Software
Stack (tss2), and OpenSSL, and built with meson.

It is a RATS Attester and local Verifier: it observes systemd-logind, PAM,
systemd-homed, and the boot chain, appraises the result against reference values,
and never asserts that the platform is trusted. It replaces none of the components
it observes.

It provides three programs:

| Program | Role |
| --- | --- |
| `platformd-trustd` | the daemon; maintains the state and serves it over the `io.platformd.Trust` Varlink interface |
| `trustctl` | command-line client to inspect the state and produce attestation |
| `pam_platformd.so` | PAM module that submits authentication events to the daemon |

## Requirements

- libsystemd ≥ 257 — sd-bus, sd-event, sd-login, sd-journal, sd-varlink, sd-json
- OpenSSL (libcrypto) ≥ 3.0 — in-process verification of systemd-homed's Ed25519 signatures
- tss2-esys and tss2-mu (the TPM2 Software Stack) — optional; without them attestation is unavailable
- libpam — optional; builds the authentication-event PAM module
- meson ≥ 1.1, ninja, and a C11 compiler
- systemd-ukify (`systemd-measure`), at runtime — used by `trustctl provision` to compute the boot reference

## Build

```sh
meson setup build --prefix=/usr
ninja -C build
sudo meson install -C build
sudo systemctl enable --now platformd-trustd.service
```

`--prefix=/usr` installs as a system component would expect (the daemon under
`/usr/lib`, `trustctl` in `/usr/bin`, and the `kernel-install` plugin where
`kernel-install` looks for it). Binaries are produced under `build/src/trust/`.

## Documentation

- [`docs/platform-trust.md`](docs/platform-trust.md) — scope, the interface reference, the state model, and the policy model.
- `platformd-trustd.service(8)` and `trustctl(1)` — the manual pages.

## Status

The daemon reports boot evidence (firmware, Secure Boot, and the measured PCRs), a
TPM quote over the boot PCRs, the tracked logind sessions with their lock and
verification state, and the authentication events that established them. It
verifies systemd-homed identities in-process against their Ed25519 signatures,
folds runtime authentication events into an extend-only TPM NV index, and produces
an Entity Attestation Token bundling the boot and runtime evidence. It evaluates
the `fresh-user-verification` and `local-trusted-session` policies, grades the boot
against a reference provisioned by a `kernel-install` plugin, and supports binding
the attestation key to the TPM by credential activation. The state is served over
the `io.platformd.Trust` Varlink interface and inspected with `trustctl`.

## License

LGPL-2.1-or-later
