#define _DEFAULT_SOURCE
#include "pamtpmpin.h"

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
#include <syslog.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

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

  long uid = get_uid(pamh);
  if (uid < 0) {
    return -uid;
  }

  char *pin = ask_user(pamh, "Please enter your PIN: ");
  if (pin == NULL) {
    return PAM_AUTH_ERR;
  }

  uint32_t pin_index = get_nv_index(NV_PIN_INDEX_BASE, (uint32_t)uid);
  uint32_t counter_index = get_nv_index(NV_COUNTER_INDEX_BASE, (uint32_t)uid);
  int verify_res = verify_nv_pin(pamh, pin, pin_index, counter_index);
  explicit_bzero(pin, strlen(pin));
  free(pin);
  if (verify_res == 0) {
    return PAM_SUCCESS;
  } else if (verify_res == 1) {
    return PAM_AUTH_ERR;
  } else if (verify_res == 2) {
    return PAM_MAXTRIES;
  } else {
    return PAM_SYSTEM_ERR;
  }
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
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
inline uint32_t get_nv_index(uint32_t mask, uint32_t uid) { return uid | mask; }

static void encode_u64_be(uint64_t value, uint8_t *buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[size - 1 - i] = (uint8_t)(value & 0xFF);
    value >>= 8;
  }
}

static uint64_t decode_u64_be(const uint8_t *buffer, size_t size) {
  uint64_t value = 0;
  for (size_t i = 0; i < size; ++i) {
    value = (value << 8) | buffer[i];
  }
  return value;
}

static bool rc_is_bad_auth(TSS2_RC rc) {
  return (rc & TPM2_RC_FMT1) && ((rc & 0x3F) == (TPM2_RC_BAD_AUTH & 0x3F));
}

static bool rc_is_policy_fail(TSS2_RC rc) {
  // Failed counters have TPM2_RC_POLICY
  return (rc & 0xFFF) == TPM2_RC_POLICY;
}

static TSS2_RC read_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                  uint64_t *value) {
  TPM2B_MAX_NV_BUFFER *out = NULL;
  TSS2_RC rc =
      Esys_NV_Read(ctx, ESYS_TR_RH_OWNER, counter_handle, ESYS_TR_PASSWORD,
                   ESYS_TR_NONE, ESYS_TR_NONE, COUNTER_NV_DATA_SIZE, 0, &out);
  if (rc == TSS2_RC_SUCCESS && out != NULL) {
    *value = decode_u64_be(out->buffer, COUNTER_NV_DATA_SIZE);
  }
  if (out != NULL) {
    Esys_Free(out);
  }
  return rc;
}

static TSS2_RC write_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                   uint64_t value) {
  TPM2B_MAX_NV_BUFFER data = {.size = COUNTER_NV_DATA_SIZE};
  encode_u64_be(value, data.buffer, COUNTER_NV_DATA_SIZE);
  return Esys_NV_Write(ctx, ESYS_TR_RH_OWNER, counter_handle, ESYS_TR_PASSWORD,
                       ESYS_TR_NONE, ESYS_TR_NONE, &data, 0);
}

static TSS2_RC reset_counter(ESYS_CONTEXT *ctx, ESYS_TR counter_handle) {
  return write_counter_value(ctx, counter_handle, 0);
}

static TSS2_RC increment_counter(ESYS_CONTEXT *ctx, ESYS_TR counter_handle) {
  uint64_t current = 0;
  TSS2_RC rc = read_counter_value(ctx, counter_handle, &current);
  if (rc != TSS2_RC_SUCCESS) {
    return rc;
  }

  if (current < UINT64_MAX) {
    current++;
  }
  if (current > MAX_PIN_FAILURES) {
    current = MAX_PIN_FAILURES;
  }
  return write_counter_value(ctx, counter_handle, current);
}

static TSS2_RC apply_policy_limit(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                  ESYS_TR policy_session) {
  TPM2B_OPERAND operand = {.size = COUNTER_NV_DATA_SIZE};
  encode_u64_be(MAX_PIN_FAILURES, operand.buffer, operand.size);
  return Esys_PolicyNV(ctx, counter_handle, counter_handle, policy_session,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &operand,
                       0, TPM2_EO_UNSIGNED_LT);
}

int32_t verify_nv_pin(pam_handle_t *pamh, const char *pin,
                      TPM2_HANDLE pin_index_val,
                      TPM2_HANDLE counter_index_val) {
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

  rc = apply_policy_limit(ctx, counter_handle, policy_session);
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
    increment_counter(ctx, counter_handle);
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
