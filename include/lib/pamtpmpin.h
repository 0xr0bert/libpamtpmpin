#ifndef PAMTPMPIN_H
#define PAMTPMPIN_H

#include "tss2_tpm2_types.h"
#include <security/_pam_types.h>
#include <security/pam_modules.h>
#include <stdint.h>

/**
 * PAM module authentication entry point
 * @param pamh The PAM handle
 * @param flags PAM flags
 * @param argc Argument count
 * @param argv Argument vector
 * @return PAM_SUCCESS on success, or appropriate PAM error code on failure
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv);

/**
 * PAM module set credentials entry point
 * @param pamh The PAM handle
 * @param flags PAM flags
 * @param argc Argument count
 * @param argv Argument vector
 * @return PAM_SUCCESS on success, or appropriate PAM error code on failure
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);

/**
 * Get the UID of the user being authenticated
 * @param pamh The PAM handle
 * @return The UID on success, or negative PAM error code on failure
 */
int64_t get_uid(pam_handle_t *pamh);

/**
 * Prompt the user for input via PAM conversation
 * @param pamh The PAM handle
 * @param prompt The prompt message to display
 * @return The user input string (must be freed by caller), or NULL on error
 */
char *ask_user(pam_handle_t *pamh, char *prompt);

int32_t verify_nv_pin(pam_handle_t *pamh, const char *pin,
                      TPM2_HANDLE pin_index_val, TPM2_HANDLE counter_index_val);

#endif // PAMTPMPIN_H