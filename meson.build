# platformd — Linux-first platform-authentication components, built as systemd
# would build them (libsystemd + meson). `platformd` is a placeholder for
# `systemd`: the rename test is `s/platformd/systemd/`.
project('platformd', 'c',
        version : '0.1.2',
        license : 'LGPL-2.1-or-later',
        meson_version : '>= 1.1',
        default_options : [
                'c_std=gnu11',
                'warning_level=2',
        ])

# systemd builds with _GNU_SOURCE, and silences -Wunused-parameter (its Varlink
# and sd-event callbacks have fixed signatures, so unused params are normal).
add_project_arguments('-D_GNU_SOURCE', '-Wno-unused-parameter', language : 'c')

# sd-event / sd-login / sd-journal, and sd-varlink / sd-json (>= 257).
libsystemd = dependency('libsystemd', version : '>= 257')

# systemd's pkg-config supplies the fixed system paths (unit dir, kernel-install
# directory, PAM module dir) so installed integration lands where systemd and PAM
# look, independent of the build prefix.
systemd = dependency('systemd', required : false)

subdir('src/trust')
subdir('man')

# --- installed integration: the systemd system unit
conf = configuration_data()
conf.set('LIBEXECDIR', get_option('prefix') / get_option('libexecdir'))

systemd_system_unit_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'systemdsystemunitdir') : get_option('prefix') / 'lib/systemd/system'
configure_file(
        input : 'units/platformd-trustd.service.in',
        output : 'platformd-trustd.service',
        configuration : conf,
        install : true,
        install_dir : systemd_system_unit_dir,
)

# kernel-install plugin: record the boot reference on every UKI update, so
# `trustctl provision` runs the systemd-measure prediction and trustd can grade
# the boot verified-local. Runs after the UKI generator (lexicographic order).
# kernel-install scans a fixed system path, so derive the directory from systemd's
# own prefix (like the unit dir) rather than the build prefix.
kernel_install_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'prefix') / 'lib/kernel/install.d' : get_option('prefix') / 'lib/kernel/install.d'
install_data(
        'units/70-platformd-trustd.install',
        install_dir : kernel_install_dir,
        install_mode : 'rwxr-xr-x',
)

# Reference authentication-gate stack, installed as documentation only — never
# into /etc/pam.d, where it could lock out an administrator. See the file's header.
install_data(
        'pam/platformd-gate.example',
        install_dir : get_option('datadir') / 'doc' / 'platformd-trustd',
)
