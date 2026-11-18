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
        'trustd.c', attest_src, 'trust-util.c', 'verify.c', 'worker.c',
        dependencies : trustd_deps,
        install : true,
        install_dir : get_option('libexecdir'),
)

test_trustd = executable(
        'platformd-trustd-test',
        'trustd.c', attest_src, 'trust-util.c', 'verify.c', 'worker.c', 'test-session.c',
        dependencies : trustd_deps,
        c_args : '-DTRUSTD_TESTING',
        link_args : [
                '-Wl,--wrap=getpwuid',
                '-Wl,--wrap=sd_get_sessions',
                '-Wl,--wrap=sd_session_get_uid',
                '-Wl,--wrap=sd_session_get_username',
                '-Wl,--wrap=sd_session_get_seat',
                '-Wl,--wrap=sd_session_get_type',
                '-Wl,--wrap=sd_session_get_class',
                '-Wl,--wrap=sd_session_get_state',
                '-Wl,--wrap=sd_session_get_tty',
                '-Wl,--wrap=sd_session_get_leader',
                '-Wl,--wrap=sd_session_is_active',
                '-Wl,--wrap=sd_session_is_remote',
        ],
)

# Build the PAM module when libpam is available.
cc = meson.get_compiler('c')
libpam = cc.find_library('pam', required : false)
if libpam.found() and cc.has_header('security/pam_modules.h')
        pam_moduledir = get_option('pammoduledir')
        if pam_moduledir == ''
                pam = dependency('pam', required : false)
                pam_moduledir = pam.found() ? pam.get_variable(pkgconfig : 'securedir', default_value : '') : ''
                if pam_moduledir == ''
                        pam_moduledir = get_option('libdir') / 'security'
                endif
        endif
        shared_library(
                'pam_platformd',
                'pam_platformd.c', 'pam-transport.c',
                name_prefix : '',
                dependencies : [libsystemd, libpam],
                install : true,
                install_dir : pam_moduledir,
        )

        test('pam-policy', executable(
                'test-pam-policy',
                'test-pam-policy.c', 'pam_platformd.c',
                dependencies : [libsystemd, libpam],
                link_args : [
                        '-Wl,--wrap=pam_get_item',
                        '-Wl,--wrap=pam_getenv',
                        '-Wl,--wrap=pam_modutil_getpwnam',
                        '-Wl,--wrap=sd_pid_get_session',
                        '-Wl,--wrap=sd_session_get_uid',
                ],
        ))

        test_pam_transport = executable(
                'test-pam-transport',
                'test-pam-transport.c', 'pam-transport.c',
                dependencies : libsystemd,
                link_args : [
                        '-Wl,--wrap=connect',
                        '-Wl,--wrap=getsockopt',
                        '-Wl,--wrap=send',
                        '-Wl,--wrap=recv',
                        '-Wl,--wrap=poll',
                ],
        )
        test('pam-transport', find_program('sh'),
             args : [meson.current_source_dir() / 'test-env.sh', test_pam_transport],
             timeout : 30)
endif

test('smoke', find_program('sh'),
     args : [meson.current_source_dir() / 'test-smoke.sh', test_trustd, trustctl],
     timeout : 60)

test('integration', find_program('sh'),
     args : [meson.current_source_dir() / 'test-integration.sh', test_trustd, trustctl],
     timeout : 60)

test('environment', find_program('sh'),
     args : [meson.current_source_dir() / 'test-environment.sh', test_trustd, trustctl],
     timeout : 60)

test('pe', executable('test-pe', 'test-pe.c', 'pe.c'))
test_provision = executable('test-provision', 'test-provision.c', 'pe.c', dependencies : libsystemd)
test('provision', find_program('sh'),
     args : [meson.current_source_dir() / 'test-env.sh', test_provision], timeout : 60)
test('kernel-install', find_program('sh'),
     args : [meson.current_source_dir() / 'test-kernel-install.sh',
             meson.project_source_root() / 'units/70-platformd-trustd.install', trustctl])
test('worker', executable('test-worker', 'test-worker.c', 'worker.c', dependencies : libsystemd))
test_logind = executable('test-logind', 'test-logind.c', 'attest-stub.c', 'trust-util.c', 'verify.c', 'worker.c',
                        dependencies : [libsystemd, libcrypto])
test('logind', find_program('sh'), args : [meson.current_source_dir() / 'test-logind.sh', test_logind])
test_suspend = executable('test-suspend',
        'test-suspend.c', 'test-session.c', 'attest-stub.c', 'trust-util.c', 'verify.c', 'worker.c',
        dependencies : [libsystemd, libcrypto],
        link_args : [
                '-Wl,--wrap=sd_varlink_get_peer_uid',
                '-Wl,--wrap=sd_varlink_reply',
                '-Wl,--wrap=sd_varlink_error',
                '-Wl,--wrap=sd_journal_send',
                '-Wl,--wrap=sd_session_get_uid',
                '-Wl,--wrap=sd_session_get_username',
                '-Wl,--wrap=sd_session_get_class',
                '-Wl,--wrap=sd_session_is_active',
                '-Wl,--wrap=sd_session_is_remote',
        ])
test('suspend', find_program('sh'), args : [meson.current_source_dir() / 'test-logind.sh', test_suspend])
if have_tpm2
        test_attest = executable('test-attest', 'test-attest.c', 'attest.c', dependencies : trustd_deps)
        test('attest', find_program('sh'),
             args : [meson.current_source_dir() / 'test-attest.sh', test_attest], timeout : 60)
endif
test('verify', executable('test-verify', 'test-verify.c', 'verify.c',
     dependencies : [libsystemd, libcrypto]))
test_identity = executable('test-identity',
        'test-identity.c', 'attest-stub.c', 'trust-util.c', 'verify.c', 'worker.c',
        dependencies : [libsystemd, libcrypto],
        link_args : [
                '-Wl,--wrap=getpwuid',
                '-Wl,--wrap=sd_varlink_connect_address',
                '-Wl,--wrap=sd_varlink_get_peer_uid',
                '-Wl,--wrap=sd_varlink_call',
        ])
test('identity', test_identity)
test('trust-util', executable(
        'test-trust-util',
        'test-trust-util.c',
        'trust-util.c',
))
