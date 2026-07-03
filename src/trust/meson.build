# platformd-trustd — the platform-authentication state authority.
# (Sources live in src/trust/, as systemd keeps src/login/, src/home/, etc.)

trustctl = executable(
        'trustctl',
        'trustctl.c', 'pe.c',
        dependencies : libsystemd,
        install : true,
)

# TPM2 attestation (T5b): built with tss2-esys when present, a stub otherwise.
tss2_esys = dependency('tss2-esys', required : false)
tss2_mu = dependency('tss2-mu', required : false)
# libcrypto: in-process Ed25519 verification of homed's signed user records.
libcrypto = dependency('libcrypto', version : '>= 3.0')
have_tpm2 = tss2_esys.found() and tss2_mu.found()
attest_src = have_tpm2 ? 'attest.c' : 'attest-stub.c'
trustd_deps = have_tpm2 ? [libsystemd, tss2_esys, tss2_mu, libcrypto] : [libsystemd, libcrypto]

trustd = executable(
        'platformd-trustd',
        'trustd.c', attest_src, 'verify.c',
        dependencies : trustd_deps,
        install : true,
        install_dir : get_option('libexecdir'),
)

# The PAM authentication-event bridge, built when libpam is present.
cc = meson.get_compiler('c')
libpam = cc.find_library('pam', required : false)
if libpam.found() and cc.has_header('security/pam_modules.h')
        # PAM searches a fixed module directory (…/lib/security), so derive it from
        # systemd's prefix, not the build prefix (as the kernel-install plugin does).
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

# --- tests (meson test) ---
test('smoke', find_program('sh'),
     args : [meson.current_source_dir() / 'test-smoke.sh', trustd, trustctl],
     timeout : 60)

test('integration', find_program('sh'),
     args : [meson.current_source_dir() / 'test-integration.sh', trustd, trustctl],
     timeout : 60)

# Unit tests for the fragile pure functions (no TPM / daemon needed).
test('pe', executable('test-pe', 'test-pe.c', 'pe.c'))
test('verify', executable('test-verify', 'test-verify.c', 'verify.c',
     dependencies : [libsystemd, libcrypto]))
