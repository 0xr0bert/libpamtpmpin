#define _DEFAULT_SOURCE
#include "pamtpmpin.h"
#include "tpmpin_common.h"

#include <pwd.h>
#include <security/_pam_types.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

#ifndef TPMPIN_DEFAULT_UNBLOCK_HELPER
#define TPMPIN_DEFAULT_UNBLOCK_HELPER "/usr/libexec/tpmpin-unblock-self"
#endif

#define TPMPIN_PAM_DATA_NEEDS_UNBLOCK "tpmpin_needs_unblock"

typedef struct {
  uint32_t pin_base;
  uint64_t max_tries;
  bool unblock_on_success;
  const char *helper_path;
} module_options;

static module_options parse_options(int argc, const char **argv) {
  module_options opts = {
      .pin_base = NV_PIN_INDEX_BASE,
      .max_tries = MAX_PIN_FAILURES,
      .unblock_on_success = false,
      .helper_path = TPMPIN_DEFAULT_UNBLOCK_HELPER,
  };

  for (int i = 0; i < argc; ++i) {
    if (strncmp(argv[i], "base=", 5) == 0) {
      opts.pin_base = (uint32_t)strtoul(argv[i] + 5, NULL, 0);
    } else if (strncmp(argv[i], "max_tries=", 10) == 0) {
      opts.max_tries = (uint64_t)strtoul(argv[i] + 10, NULL, 0);
    } else if (strcmp(argv[i], "unblock_on_success") == 0) {
      opts.unblock_on_success = true;
    } else if (strncmp(argv[i], "helper=", 7) == 0) {
      opts.helper_path = argv[i] + 7;
    }
  }
  return opts;
}

static void free_pam_data(pam_handle_t *pamh, void *data, int error_status) {
  (void)pamh;
  (void)error_status;
  free(data);
}

static int run_unblock_helper(pam_handle_t *pamh, const module_options *opts,
                              int64_t uid) {
  if (opts->helper_path == NULL || opts->helper_path[0] != '/') {
    pam_syslog(pamh, LOG_ERR, "tpmpin: helper path must be absolute");
    return -1;
  }

  char uid_arg[32];
  char base_arg[32];
  snprintf(uid_arg, sizeof(uid_arg), "%ld", (long)uid);
  snprintf(base_arg, sizeof(base_arg), "0x%x", opts->pin_base);

  char *const child_argv[] = {
      (char *)opts->helper_path, (char *)"--uid", uid_arg,
      (char *)"--base",          base_arg,        NULL,
  };

  char *const child_envp[] = {
      (char *)"TSS2_LOG=all+NONE",
      NULL,
  };

  pid_t pid = fork();
  if (pid < 0) {
    pam_syslog(pamh, LOG_ERR, "tpmpin: fork failed: %m");
    return -1;
  }

  if (pid == 0) {
    execve(opts->helper_path, child_argv, child_envp);
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    pam_syslog(pamh, LOG_ERR, "tpmpin: waitpid failed: %m");
    return -1;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return 0;
  }

  if (WIFEXITED(status)) {
    pam_syslog(pamh, LOG_ERR, "tpmpin: unblock helper exited %d",
               WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    pam_syslog(pamh, LOG_ERR, "tpmpin: unblock helper killed by signal %d",
               WTERMSIG(status));
  } else {
    pam_syslog(pamh, LOG_ERR, "tpmpin: unblock helper failed (status=0x%x)",
               status);
  }
  return -1;
}

static void log_error(pam_handle_t *pamh, const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (pamh != NULL) {
    char *response = NULL;
    pam_prompt(pamh, PAM_ERROR_MSG, &response, "%s", buf);
    if (response != NULL) {
      free(response);
    }
  } else {
    fprintf(stderr, "Error: %s\n", buf);
  }
}

// PAM Module ------------------------------------------------------------------
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  setenv("TSS2_LOG", "all+NONE", 0);

  module_options opts = parse_options(argc, argv);

  long uid = get_uid(pamh);
  if (uid < 0) {
    return -uid;
  }

  char *pin = ask_user(pamh, "Please enter your PIN: ");
  if (pin == NULL) {
    return PAM_AUTH_ERR;
  }

  uint32_t counter_base =
      opts.pin_base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);

  uint32_t pin_index = calculate_nv_index(opts.pin_base, (uint32_t)uid);
  uint32_t counter_index = calculate_nv_index(counter_base, (uint32_t)uid);
  int verify_res =
      verify_nv_pin(pamh, pin, pin_index, counter_index, opts.max_tries);
  explicit_bzero(pin, strlen(pin));
  free(pin);
  if (verify_res == 0) {
    return PAM_SUCCESS;
  } else if (verify_res == 1) {
    return PAM_AUTH_ERR;
  } else if (verify_res == 2) {
    if (opts.unblock_on_success) {
      bool *flag = calloc(1, sizeof(bool));
      if (flag != NULL) {
        *flag = true;
        (void)pam_set_data(pamh, TPMPIN_PAM_DATA_NEEDS_UNBLOCK, flag,
                           free_pam_data);
      }
      // Let other auth mechanisms succeed; we'll unblock in open_session.
      return PAM_IGNORE;
    }
    return PAM_MAXTRIES;
  } else {
    return PAM_SYSTEM_ERR;
  }
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  (void)flags;
  setenv("TSS2_LOG", "all+NONE", 0);

  module_options opts = parse_options(argc, argv);
  if (!opts.unblock_on_success) {
    return PAM_SUCCESS;
  }

  const void *data = NULL;
  if (pam_get_data(pamh, TPMPIN_PAM_DATA_NEEDS_UNBLOCK, &data) != PAM_SUCCESS ||
      data == NULL) {
    return PAM_SUCCESS;
  }

  int64_t uid = get_uid(pamh);
  if (uid < 0) {
    pam_syslog(pamh, LOG_ERR, "tpmpin: could not resolve uid for auto-unblock");
    return PAM_SUCCESS;
  }

  (void)run_unblock_helper(pamh, &opts, uid);

  // Clear the flag so we don't re-run.
  (void)pam_set_data(pamh, TPMPIN_PAM_DATA_NEEDS_UNBLOCK, NULL, NULL);
  return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

// PAM -------------------------------------------------------------------------
int64_t get_uid(pam_handle_t *pamh) {
  const char *user = NULL;
  int user_res = pam_get_user(pamh, &user, NULL);
  if (user_res != PAM_SUCCESS || user == NULL) {
    return -PAM_AUTH_ERR;
  }

  // Allocate buffer
  long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1) {
    bufsize = 16384;
  }

  char *buf = malloc(bufsize);
  if (buf == NULL) {
    return -PAM_AUTH_ERR;
  }

  struct passwd pwd;
  struct passwd *result = NULL;
  int rc = getpwnam_r(user, &pwd, buf, bufsize, &result);
  if (result == NULL && rc == 0) {
    free(buf);
    return -PAM_USER_UNKNOWN;
  } else if (result == NULL) {
    free(buf);
    return -PAM_AUTH_ERR;
  }

  int64_t uid = (int64_t)pwd.pw_uid;
  free(buf);
  return uid;
}

char *ask_user(pam_handle_t *pamh, char *prompt) {
  // Get the pam conversation
  const void *conv_ptr = NULL;
  int status = pam_get_item(pamh, PAM_CONV, &conv_ptr);
  if (status != PAM_SUCCESS || conv_ptr == NULL) {
    return NULL;
  }

  // Cast the conversation pointer
  const struct pam_conv *conv = (const struct pam_conv *)conv_ptr;
  if (conv->conv == NULL) {
    return NULL;
  }

  // Prepare the message
  struct pam_message msg = {.msg = prompt, .msg_style = PAM_PROMPT_ECHO_OFF};
  const struct pam_message *msg_ptr = &msg;

  // Call the conversation function
  struct pam_response *resp = NULL;
  int conv_ret = conv->conv(1, &msg_ptr, &resp, conv->appdata_ptr);
  if (conv_ret != PAM_SUCCESS || resp == NULL) {
    return NULL;
  }

  // If the response is NULL, clean up and return NULL
  if (resp->resp == NULL) {
    free(resp);
    return NULL;
  }

  char *resp_str = resp->resp;
  // Cleanup the response structure but not the response string
  free(resp);

  return resp_str;
}

// TPM -------------------------------------------------------------------------

int32_t verify_nv_pin(pam_handle_t *pamh, const char *pin,
                      TPM2_HANDLE pin_index_val, TPM2_HANDLE counter_index_val,
                      uint64_t max_tries) {
  TSS2_RC rc;
  ESYS_CONTEXT *ctx = NULL;
  ESYS_TR pin_handle = ESYS_TR_NONE;
  ESYS_TR counter_handle = ESYS_TR_NONE;
  ESYS_TR policy_session = ESYS_TR_NONE;
  TPM2B_MAX_NV_BUFFER *out_data = NULL;
  TPM2B_AUTH empty_auth = {.size = 0};
  TPM2B_AUTH pin_auth = {0};
  int32_t result = -1;

  rc = Esys_Initialize(&ctx, NULL, NULL);
  if (rc != TSS2_RC_SUCCESS) {
    log_error(pamh, "Failed to initialize ESYS context: 0x%x", rc);
    return -1;
  }

  rc = Esys_TR_FromTPMPublic(ctx, pin_index_val, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, &pin_handle);
  if (rc != TSS2_RC_SUCCESS) {
    log_error(pamh, "Failed to load PIN NV index 0x%x (rc=0x%x)", pin_index_val,
              rc);
    goto cleanup;
  }

  rc = Esys_TR_FromTPMPublic(ctx, counter_index_val, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, &counter_handle);
  if (rc != TSS2_RC_SUCCESS) {
    log_error(pamh, "Failed to load counter NV index 0x%x (rc=0x%x)",
              counter_index_val, rc);
    goto cleanup;
  }

  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &empty_auth);
  Esys_TR_SetAuth(ctx, counter_handle, &empty_auth);

  TPMT_SYM_DEF symmetric = {
      .algorithm = TPM2_ALG_AES,
      .keyBits.aes = 128,
      .mode.aes = TPM2_ALG_CFB,
  };

  rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_POLICY,
                             &symmetric, TPM2_ALG_SHA256, &policy_session);
  if (rc != TSS2_RC_SUCCESS) {
    log_error(pamh, "Failed to start policy session: 0x%x", rc);
    goto cleanup;
  }

  rc = apply_policy_limit(ctx, counter_handle, policy_session, max_tries);
  if (rc != TSS2_RC_SUCCESS) {
    if (rc_is_policy_fail(rc)) {
      log_error(pamh, "User is locked due to too many failures");
      result = 2;
    } else {
      log_error(pamh, "PolicyNV failed: 0x%x", rc);
    }
    goto cleanup;
  }

  rc = Esys_PolicyAuthValue(ctx, policy_session, ESYS_TR_NONE, ESYS_TR_NONE,
                            ESYS_TR_NONE);
  if (rc != TSS2_RC_SUCCESS) {
    log_error(pamh, "PolicyAuthValue failed: 0x%x", rc);
    goto cleanup;
  }

  size_t pin_len = strlen(pin);
  if (pin_len > sizeof(pin_auth.buffer)) {
    log_error(pamh, "PIN is too long (max %lu bytes)", sizeof(pin_auth.buffer));
    goto cleanup;
  }
  pin_auth.size = (uint16_t)pin_len;
  memcpy(pin_auth.buffer, pin, pin_len);

  rc = Esys_TR_SetAuth(ctx, pin_handle, &pin_auth);
  if (rc != TSS2_RC_SUCCESS) {
    log_error(pamh, "Failed to set PIN auth value: 0x%x", rc);
    goto cleanup;
  }

  rc = Esys_NV_Read(ctx, pin_handle, pin_handle, policy_session, ESYS_TR_NONE,
                    ESYS_TR_NONE, PIN_NV_DATA_SIZE, 0, &out_data);

  if (rc == TSS2_RC_SUCCESS) {
    reset_counter(ctx, counter_handle);
    result = 0;
  } else if (rc_is_bad_auth(rc)) {
    increment_counter(ctx, counter_handle, max_tries);
    result = 1;
  } else if (rc_is_policy_fail(rc)) {
    log_error(pamh, "User is locked due to too many failures");
    result = 2;
  } else {
    log_error(pamh, "NV Read failed with error code: 0x%x", rc);
  }

cleanup:
  explicit_bzero(&pin_auth, sizeof(pin_auth));
  if (out_data != NULL) {
    Esys_Free(out_data);
  }
  if (policy_session != ESYS_TR_NONE) {
    Esys_FlushContext(ctx, policy_session);
  }
  if (pin_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &pin_handle);
  }
  if (counter_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &counter_handle);
  }
  if (ctx != NULL) {
    Esys_Finalize(&ctx);
  }

  return result;
}
