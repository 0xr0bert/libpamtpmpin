project('libpamtpmpin', 'c')

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

shared_library(
    'pamtpmpin', 
    'src/lib/pamtpmpin.c',
    dependencies: [pam_dep, tpm_dep],
    include_directories: [lib_incdir, common_incdir],
    link_with: libtpmpin_common
)

executable(
    'tpmpin',
    'src/bin/tpmpin.c',
    dependencies: [pam_dep, tpm_dep],
    include_directories: common_incdir,
    link_with: libtpmpin_common
)