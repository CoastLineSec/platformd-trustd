# SPDX-License-Identifier: LGPL-2.1-or-later

trustctl = executable(
        'trustctl',
        'trustctl.c', 'pe.c',
        dependencies : libsystemd,
        install : true,
)

# TPM2 attestation uses a stub when TPM2-TSS is unavailable.
tss2_esys = dependency('tss2-esys', required : false)
tss2_mu = dependency('tss2-mu', required : false)
tss2_tctildr = dependency('tss2-tctildr', required : false)
# libcrypto verifies signed systemd-homed user records.
libcrypto = dependency('libcrypto', version : '>= 3.0')
have_tpm2 = tss2_esys.found() and tss2_mu.found() and tss2_tctildr.found()
attest_src = have_tpm2 ? 'attest.c' : 'attest-stub.c'
trustd_deps = have_tpm2 ? [libsystemd, tss2_esys, tss2_mu, tss2_tctildr, libcrypto] : [libsystemd, libcrypto]

trustd = executable(
        'platformd-trustd',
        'trustd.c', attest_src, 'trust-util.c', 'verify.c',
        dependencies : trustd_deps,
        install : true,
        install_dir : get_option('libexecdir'),
)

# Build the PAM module when libpam is available.
cc = meson.get_compiler('c')
libpam = cc.find_library('pam', required : false)
if libpam.found() and cc.has_header('security/pam_modules.h')
        # PAM uses a fixed module directory below the systemd prefix.
        pam_moduledir = systemd.found() ? systemd.get_variable(pkgconfig : 'prefix') / 'lib/security' : get_option('libdir') / 'security'
        shared_library(
                'pam_platformd',
                'pam_platformd.c',
                name_prefix : '',
                dependencies : [libsystemd, libpam],
                install : true,
                install_dir : pam_moduledir,
        )
endif

test('smoke', find_program('sh'),
     args : [meson.current_source_dir() / 'test-smoke.sh', trustd, trustctl],
     timeout : 60)

test('integration', find_program('sh'),
     args : [meson.current_source_dir() / 'test-integration.sh', trustd, trustctl],
     timeout : 60)

test('environment', find_program('sh'),
     args : [meson.current_source_dir() / 'test-environment.sh', trustd, trustctl],
     timeout : 60)

test('pe', executable('test-pe', 'test-pe.c', 'pe.c'))
test('verify', executable('test-verify', 'test-verify.c', 'verify.c',
     dependencies : [libsystemd, libcrypto]))
test('trust-util', executable(
        'test-trust-util',
        'test-trust-util.c',
        'trust-util.c',
))
