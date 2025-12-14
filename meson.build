project('libpamtpmpin', 'c', version: '0.0.1')

pam_dep = dependency('pam', required: true)
tpm_dep = dependency('tss2-esys', required: true)

common_incdir = include_directories('include/common')
lib_incdir = include_directories('include/lib')

libtpmpin_common = static_library(
    'tpmpin_common',
    'src/common/tpmpin_common.c',
    dependencies: [tpm_dep],
    include_directories: common_incdir
)

pam_modules_dir = get_option('pam_modules_dir')
if pam_modules_dir == ''
    pam_modules_dir = get_option('libdir') / 'security'
endif

libpam_tpmpin = shared_library(
    'pam_tpmpin', 
    'src/lib/pamtpmpin.c',
    dependencies: [pam_dep, tpm_dep],
    include_directories: [lib_incdir, common_incdir],
    link_with: libtpmpin_common,
    c_args: ['-DTPMPIN_DEFAULT_UNBLOCK_HELPER="@0@"'.format(get_option('libexecdir') / 'tpmpin-unblock-self')],
    install: true,
    install_dir: pam_modules_dir
)

tpmpin_unblock_self = executable(
    'tpmpin-unblock-self',
    'src/bin/tpmpin-unblock-self.c',
    dependencies: [tpm_dep],
    include_directories: common_incdir,
    link_with: libtpmpin_common,
    install: true,
    install_dir: get_option('libexecdir'),
    install_mode: 'rwsr-xr-x'
)

tpmpin_exe = executable(
    'tpmpin',
    'src/bin/tpmpin.c',
    dependencies: [pam_dep, tpm_dep],
    include_directories: common_incdir,
    link_with: libtpmpin_common,
    install: true
)

pam_test_harness = executable(
    'pam_test_harness',
    'tests/pam_test_harness.c',
    dependencies: [pam_dep],
    install: false
)

test('integration_test',
    find_program('tests/integration_test.sh'),
    args: [meson.project_build_root()],
    depends: [pam_test_harness, libpam_tpmpin, tpmpin_exe, tpmpin_unblock_self],
    timeout: 60
)