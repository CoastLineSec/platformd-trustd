# platformd-trustd

platformd-trustd collects boot, login session, user identity, and authentication
evidence. It evaluates local policies and, when a TPM is available, produces
attestation over the collected state.

The package provides:

* `platformd-trustd`, the system service and `io.platformd.Trust` Varlink
  interface
* `trustctl`, the command line client
* `pam_platformd.so`, a PAM module for submitting session records and evaluating
  trust policies

The service does not authenticate users, store credentials, or grant access.

## Requirements

The build requires libsystemd 257 or newer, OpenSSL 3.0 or newer, Meson 1.1 or
newer, Ninja, and a C11 compiler. TPM attestation additionally requires
tss2-esys and tss2-mu. The PAM module requires libpam. Boot reference
provisioning requires `systemd-measure`.

## Building

```sh
meson setup build --prefix=/usr
meson compile -C build
meson test -C build
sudo meson install -C build
```

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

Attestation is unavailable when the package is built without TPM2-TSS or the
system has no usable TPM. Authentication events remain declared evidence even
when they are included in a TPM protected runtime measurement log.

See [Platform Trust](docs/platform-trust.md),
`platformd-trustd.service(8)`, `trustctl(1)`, and `pam_platformd(8)`.

## License

LGPL-2.1-or-later
