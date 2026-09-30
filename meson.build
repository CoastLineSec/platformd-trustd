# SPDX-License-Identifier: LGPL-2.1-or-later
project('platformd', 'c',
        version : '0.1.5',
        license : 'LGPL-2.1-or-later',
        meson_version : '>= 1.1',
        default_options : [
                'c_std=gnu11',
                'warning_level=2',
        ])

# Varlink and sd-event callbacks have fixed signatures.
add_project_arguments('-D_GNU_SOURCE', '-Wno-unused-parameter',
                      '-DPROGRAM_VERSION="@0@"'.format(meson.project_version()), language : 'c')

libsystemd = dependency('libsystemd', version : '>= 257')

systemd = dependency('systemd', required : false)

subdir('src/trust')
subdir('man')
install_data('src/trust/io.platformd.Trust.varlink', install_dir : get_option('datadir') / 'varlink')

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

# kernel-install uses a fixed directory below the systemd prefix.
kernel_install_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'prefix') / 'lib/kernel/install.d' : get_option('prefix') / 'lib/kernel/install.d'
install_data(
        'units/70-platformd-trustd.install',
        install_dir : kernel_install_dir,
        install_mode : 'rwxr-xr-x',
)
