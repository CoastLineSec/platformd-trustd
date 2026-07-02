# platformd — Linux-first platform-authentication components, built as systemd
# would build them (libsystemd + meson). `platformd` is a placeholder for
# `systemd`: the rename test is `s/platformd/systemd/`.
project('platformd', 'c',
        version : '0.0.1',
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

subdir('src/trust')
subdir('man')

# --- installed integration: the systemd system unit
conf = configuration_data()
conf.set('LIBEXECDIR', get_option('prefix') / get_option('libexecdir'))

systemd = dependency('systemd', required : false)
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
install_data(
        'units/70-platformd-trustd.install',
        install_dir : get_option('prefix') / 'lib/kernel/install.d',
        install_mode : 'rwxr-xr-x',
)
