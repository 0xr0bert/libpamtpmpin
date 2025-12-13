project('libpamtpmpin', 'c')

pam_dep = dependency('pam', required: true)
tpm_dep = dependency('tss2-esys', required: true)

lib_incdir = include_directories('include/lib')
shared_library(
    'pamtpmpin', 
    'src/lib/pamtpmpin.c',
    dependencies: [pam_dep, tpm_dep],
    include_directories: lib_incdir
)

executable(
    'tpmpin',
    'src/bin/tpmpin.c',
    dependencies: [pam_dep, tpm_dep]
)