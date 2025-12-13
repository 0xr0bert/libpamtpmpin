#define _DEFAULT_SOURCE
#include "tpmpin_common.h"
#include <string.h>

void encode_u64_be(uint64_t value, uint8_t *buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[size - 1 - i] = (uint8_t)(value & 0xFF);
    value >>= 8;
  }
}

uint64_t decode_u64_be(const uint8_t *buffer, size_t size) {
  uint64_t value = 0;
  for (size_t i = 0; i < size; ++i) {
    value = (value << 8) | buffer[i];
  }
  return value;
}

bool rc_is_bad_auth(TSS2_RC rc) {
  return (rc & TPM2_RC_FMT1) && ((rc & 0x3F) == (TPM2_RC_BAD_AUTH & 0x3F));
}

bool rc_is_policy_fail(TSS2_RC rc) {
  // Failed counters have TPM2_RC_POLICY
  return (rc & 0xFFF) == TPM2_RC_POLICY;
}

TSS2_RC read_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
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

TSS2_RC write_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                            uint64_t value) {
  TPM2B_MAX_NV_BUFFER data = {.size = COUNTER_NV_DATA_SIZE};
  encode_u64_be(value, data.buffer, COUNTER_NV_DATA_SIZE);
  return Esys_NV_Write(ctx, ESYS_TR_RH_OWNER, counter_handle, ESYS_TR_PASSWORD,
                       ESYS_TR_NONE, ESYS_TR_NONE, &data, 0);
}

TSS2_RC reset_counter(ESYS_CONTEXT *ctx, ESYS_TR counter_handle) {
  return write_counter_value(ctx, counter_handle, 0);
}

TSS2_RC increment_counter(ESYS_CONTEXT *ctx, ESYS_TR counter_handle) {
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

TSS2_RC apply_policy_limit(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                           ESYS_TR policy_session) {
  TPM2B_OPERAND operand = {.size = COUNTER_NV_DATA_SIZE};
  encode_u64_be(MAX_PIN_FAILURES, operand.buffer, operand.size);
  return Esys_PolicyNV(ctx, counter_handle, counter_handle, policy_session,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &operand,
                       0, TPM2_EO_UNSIGNED_LT);
}

TSS2_RC remove_nv_if_exists(ESYS_CONTEXT *ctx, TPM2_HANDLE index) {
  // Get the handle for the NV index
  ESYS_TR nv_handle = ESYS_TR_NONE;
  TSS2_RC rc = Esys_TR_FromTPMPublic(ctx, index, ESYS_TR_NONE, ESYS_TR_NONE,
                                     ESYS_TR_NONE, &nv_handle);
  if (rc != TSS2_RC_SUCCESS) {
    if ((rc & TPM2_RC_FMT1) && (rc & ~0xF00) == TPM2_RC_HANDLE) {
      // NV index does not exist
      return TSS2_RC_SUCCESS;
    }
    return rc;
  }

  // If found, undefine the NV space
  if (rc == TSS2_RC_SUCCESS) {
    // TODO: Allow owner auth to be set
    TPM2B_AUTH empty_auth = {.size = 0};
    Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &empty_auth);
    rc = Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nv_handle,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc == TSS2_RC_SUCCESS) {
      nv_handle = ESYS_TR_NONE; // Esys flushes the handle already
    }
  }

  if (nv_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &nv_handle);
  }
  return rc;
}

TSS2_RC define_counter_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index) {
  TPM2B_NV_PUBLIC public_info = {
      .size = 0,
      .nvPublic = {
          .nvIndex = index,
          .nameAlg = TPM2_ALG_SHA256,
          .attributes = (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD |
                         TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA),
          .authPolicy = {.size = 0},
          .dataSize = COUNTER_NV_DATA_SIZE,
      }};

  TPM2B_AUTH empty_auth = {.size = 0};
  ESYS_TR tmp_handle = ESYS_TR_NONE;

  TSS2_RC rc =
      Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                          ESYS_TR_NONE, &empty_auth, &public_info, &tmp_handle);
  if (rc == TSS2_RC_SUCCESS && tmp_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &tmp_handle);
  }
  return rc;
}

TSS2_RC define_pin_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index,
                         const TPM2B_DIGEST *policy_digest, const char *pin) {
  TPM2B_NV_PUBLIC public_info = {
      .size = 0,
      .nvPublic = {
          .nvIndex = index,
          .nameAlg = TPM2_ALG_SHA256,
          .attributes = (TPMA_NV_OWNERWRITE | TPMA_NV_POLICYREAD |
                         TPMA_NV_AUTHREAD | TPMA_NV_NO_DA),
          .authPolicy = {.size = policy_digest->size},
          .dataSize = PIN_NV_DATA_SIZE,
      }};
  memcpy(public_info.nvPublic.authPolicy.buffer, policy_digest->buffer,
         policy_digest->size);

  TPM2B_AUTH pin_auth = {.size = strlen(pin)};
  memcpy(pin_auth.buffer, pin, pin_auth.size);

  ESYS_TR tmp_handle = ESYS_TR_NONE;
  TSS2_RC rc =
      Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                          ESYS_TR_NONE, &pin_auth, &public_info, &tmp_handle);
  explicit_bzero(&pin_auth, sizeof(pin_auth));
  if (rc == TSS2_RC_SUCCESS && tmp_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &tmp_handle);
  }
  return rc;
}

TSS2_RC write_pin_placeholder(ESYS_CONTEXT *ctx, TPM2_HANDLE pin_index) {
  ESYS_TR pin_handle = ESYS_TR_NONE;
  TSS2_RC rc = Esys_TR_FromTPMPublic(ctx, pin_index, ESYS_TR_NONE, ESYS_TR_NONE,
                                     ESYS_TR_NONE, &pin_handle);
  if (rc != TSS2_RC_SUCCESS) {
    return rc;
  }

  TPM2B_MAX_NV_BUFFER nv_data = {.size = PIN_NV_DATA_SIZE};
  memset(nv_data.buffer, 0, nv_data.size);
  rc = Esys_NV_Write(ctx, ESYS_TR_RH_OWNER, pin_handle, ESYS_TR_PASSWORD,
                     ESYS_TR_NONE, ESYS_TR_NONE, &nv_data, 0);
  Esys_TR_Close(ctx, &pin_handle);
  return rc;
}

TSS2_RC compute_pin_policy_digest(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                  TPM2B_DIGEST **digest) {
  TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
  ESYS_TR trial_session = ESYS_TR_NONE;

  // Start a trial session to build the policy digest without executing it
  TSS2_RC rc = Esys_StartAuthSession(
      ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
      NULL, TPM2_SE_TRIAL, &symmetric, TPM2_ALG_SHA256, &trial_session);
  if (rc != TSS2_RC_SUCCESS) {
    return rc;
  }

  TPM2B_OPERAND operand = {.size = COUNTER_NV_DATA_SIZE};
  encode_u64_be(MAX_PIN_FAILURES, operand.buffer, operand.size);

  // Require the counter value to remain below MAX_PIN_FAILURES
  rc = Esys_PolicyNV(ctx, counter_handle, counter_handle, trial_session,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &operand, 0,
                     TPM2_EO_UNSIGNED_LT);
  if (rc == TSS2_RC_SUCCESS) {
    // Require knowledge of the PIN auth value for future access
    rc = Esys_PolicyAuthValue(ctx, trial_session, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE);
  }
  if (rc == TSS2_RC_SUCCESS) {
    // Capture the finalized digest that encodes both requirements
    rc = Esys_PolicyGetDigest(ctx, trial_session, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, digest);
  }

  if (trial_session != ESYS_TR_NONE) {
    Esys_FlushContext(ctx, trial_session);
  }

  return rc;
}
