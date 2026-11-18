# platformd-trustd

platformd-trustd collects boot, login session, user identity, and authentication
evidence. It evaluates local policies and, when a TPM is available, produces
attestation over the collected state.

The package provides:

* `platformd-trustd`, the system service and `io.platformd.Trust` Varlink
  interface
* `trustctl`, the command line client and offline attestation verifier
* `pam_platformd.so`, a PAM module for submitting session records and evaluating
  trust policies

The service does not authenticate users, store credentials, or grant access.

## Requirements

The build requires libsystemd 257 or newer, OpenSSL 3.0 or newer, Meson 1.1 or
newer, Ninja, and a C11 compiler. TPM attestation additionally requires
tss2-esys, tss2-mu, and tss2-tctildr. The PAM module requires libpam. Boot reference
provisioning requires `systemd-measure`.

## Building

```sh
meson setup build --prefix=/usr
meson compile -C build
meson test -C build
sudo meson install -C build
```

`-Dpammoduledir=PATH` selects the PAM module directory. The default is taken
from `pam.pc`, with `${libdir}/security` as the fallback.

## Usage

```sh
trustctl status
trustctl list-sessions
trustctl session SESSION
trustctl explain fresh-user-verification SESSION
trustctl events
```

Session lock state is obtained from the logind `LockedHint` property.
Verification freshness is established only by an accepted successful
`platformd-verify` event for an existing eligible session. Session creation,
unlock notifications, and records submitted by `pam_platformd.so` do not
establish freshness.

Attestation production is unavailable when the package is built without TPM2-TSS
or the system has no usable TPM. Offline verification requires an independently
supplied attestation key and challenge, but no TPM or running service.
Authentication events remain declared evidence even
when they are included in a TPM protected runtime measurement log.

The runtime log requires explicit NV index initialization. Attestation uses a
platformd-specific JSON envelope, not an IETF Entity Attestation Token.

See [Platform Trust](docs/platform-trust.md),
`platformd-trustd.service(8)`, `trustctl(1)`, and `pam_platformd(8)`.

## License

LGPL-2.1-or-later
