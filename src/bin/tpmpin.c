#include "tss2_common.h"
#include "tss2_esys.h"
#include "tss2_tpm2_types.h"
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Constants -------------------------------------------------------------------

#define NV_PIN_INDEX_BASE 0x01500000
#define NV_COUNTER_INDEX_BASE 0x01600000
#define PIN_NV_DATA_SIZE 32
#define COUNTER_NV_DATA_SIZE 8
#define MAX_PIN_FAILURES 5

// Forward declarations --------------------------------------------------------

/**
 * Enroll a user by username
 * @param username The username to enroll
 * @return 0 on success, -1 on failure
 */
static bool enroll_user(const char *username);

/**
 * Get the UID of the specified username
 * @param username The username to look up
 * @return The UID on success, or negative value on failure
 */
static int64_t get_uid(const char *username);

/**
 * Encode a 64-bit unsigned integer into a big-endian byte buffer
 * @param value The 64-bit unsigned integer to encode
 * @param buffer The buffer to write the encoded bytes into
 * @param size The size of the buffer (number of bytes to write)
 */
static void encode_u64_be(uint64_t value, uint8_t *buffer, size_t size);

/**
 * Enroll a user in the TPM with the specified PIN and NV indexes
 * @param pin The PIN to enroll
 * @param pin_index_val The NV index for the PIN
 * @param counter_index_val The NV index for the failure counter
 * @return true on success, false on failure
 */
static bool enroll_user_in_tpm(const char *pin, TPM2_HANDLE pin_index_val,
                               TPM2_HANDLE counter_index_val);

/**
 * Remove an NV index if it exists
 * @param ctx The ESYS context
 * @param index The NV index to remove
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
static TSS2_RC remove_nv_if_exists(ESYS_CONTEXT *ctx, TPM2_HANDLE index);

/**
 * Define a counter NV index
 * @param ctx The ESYS context
 * @param index The NV index to define
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
static TSS2_RC define_counter_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index);

/**
 * Write a value to the counter NV index
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @param value The value to write
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
static TSS2_RC write_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                   uint64_t value);

/**
 * Write a placeholder value to the PIN NV index
 * @param ctx The ESYS context
 * @param pin_index The NV index for the PIN
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
static TSS2_RC write_pin_placeholder(ESYS_CONTEXT *ctx, TPM2_HANDLE pin_index);

/**
 * Compute the policy digest for the PIN NV index
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @param digest Output parameter for the computed policy digest
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
static TSS2_RC compute_pin_policy_digest(ESYS_CONTEXT *ctx,
                                         ESYS_TR counter_handle,
                                         TPM2B_DIGEST **digest);

/**
 * Define the PIN NV index with the specified policy and PIN
 * @param ctx The ESYS context
 * @param index The NV index for the PIN
 * @param policy_digest The policy digest to associate with the NV index
 * @param pin The PIN to set as the auth value
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
static TSS2_RC define_pin_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index,
                                const TPM2B_DIGEST *policy_digest,
                                const char *pin);

// Inlines ---------------------------------------------------------------------

/**
 * Compute the NV Index for a given UID
 * @param mask The NV index base mask
 * @param uid The user ID
 * @return The computed NV index, mask ORed with the UID
 */
static inline uint32_t get_nv_index(uint32_t mask, uint32_t uid) {
  return uid | mask;
}

// Main ------------------------------------------------------------------------

int main(int argc, char **argv) {
  if (argc < 3) {
    printf("Usage: %s enroll <username>\n", argv[0]);
    return 1;
  }
  if (strcmp(argv[1], "enroll") == 0) {
    return enroll_user(argv[2]);
  } else {
    printf("Unknown command: %s\n", argv[1]);
    return 1;
  }
}

static bool enroll_user(const char *username) {
  printf("enroll user: %s\n", username);
  int64_t uid = get_uid(username);
  printf("UID: %ld\n", uid);
  if (uid < 0) {
    fprintf(stderr, "Failed to resolve UID for %s\n", username);
    return false;
  }

  TPM2_HANDLE pin_index = get_nv_index(NV_PIN_INDEX_BASE, (uint32_t)uid);
  TPM2_HANDLE counter_index =
      get_nv_index(NV_COUNTER_INDEX_BASE, (uint32_t)uid);

  return enroll_user_in_tpm("1234", pin_index, counter_index) == 0;
}

static int64_t get_uid(const char *username) {
  // Allocate buffer
  long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1) {
    bufsize = 16384;
  }

  char *buf = malloc(bufsize);
  if (buf == NULL) {
    return -1;
  }

  struct passwd pwd;
  struct passwd *result = NULL;
  int rc = getpwnam_r(username, &pwd, buf, bufsize, &result);
  if (result == NULL && rc == 0) {
    free(buf);
    return -1;
  } else if (result == NULL) {
    free(buf);
    return -1;
  }

  int64_t uid = (int64_t)pwd.pw_uid;
  free(buf);
  return uid;
}

// TPM -------------------------------------------------------------------------

static void encode_u64_be(uint64_t value, uint8_t *buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[size - 1 - i] = (uint8_t)(value & 0xFF);
    value >>= 8;
  }
}

static TSS2_RC remove_nv_if_exists(ESYS_CONTEXT *ctx, TPM2_HANDLE index) {
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

static TSS2_RC define_counter_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index) {
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

static TSS2_RC write_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                   uint64_t value) {
  TPM2B_MAX_NV_BUFFER data = {.size = COUNTER_NV_DATA_SIZE};
  encode_u64_be(value, data.buffer, COUNTER_NV_DATA_SIZE);

  return Esys_NV_Write(ctx, ESYS_TR_RH_OWNER, counter_handle, ESYS_TR_PASSWORD,
                       ESYS_TR_NONE, ESYS_TR_NONE, &data, 0);
}

static TSS2_RC write_pin_placeholder(ESYS_CONTEXT *ctx, TPM2_HANDLE pin_index) {
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

static TSS2_RC compute_pin_policy_digest(ESYS_CONTEXT *ctx,
                                         ESYS_TR counter_handle,
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

static TSS2_RC define_pin_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index,
                                const TPM2B_DIGEST *policy_digest,
                                const char *pin) {
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
  if (rc == TSS2_RC_SUCCESS && tmp_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &tmp_handle);
  }
  return rc;
}

static bool enroll_user_in_tpm(const char *pin, TPM2_HANDLE pin_index_val,
                               TPM2_HANDLE counter_index_val) {
  TSS2_RC rc;
  ESYS_CONTEXT *ctx = NULL;
  TPM2B_AUTH empty_auth = {.size = 0};
  TPM2B_DIGEST *policy_digest = NULL;
  ESYS_TR counter_handle = ESYS_TR_NONE;

  rc = Esys_Initialize(&ctx, NULL, NULL);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to initialize ESYS context: 0x%x\n", rc);
    return -1;
  }

  // Clean up any previous enrollment artifacts
  rc = remove_nv_if_exists(ctx, pin_index_val);
  if (rc == TSS2_RC_SUCCESS) {
    rc = remove_nv_if_exists(ctx, counter_index_val);
  }
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to remove existing NV indexes: 0x%x\n", rc);
    goto cleanup;
  }

  // Define the counter index and load it for policy computation
  rc = define_counter_index(ctx, counter_index_val);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to define counter NV index: 0x%x\n", rc);
    goto cleanup;
  }

  rc = Esys_TR_FromTPMPublic(ctx, counter_index_val, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, &counter_handle);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to load counter NV index: 0x%x\n", rc);
    goto cleanup;
  }

  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &empty_auth);
  Esys_TR_SetAuth(ctx, counter_handle, &empty_auth);

  rc = write_counter_value(ctx, counter_handle, 0);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to initialize counter NV index: 0x%x\n", rc);
    goto cleanup;
  }

  rc = compute_pin_policy_digest(ctx, counter_handle, &policy_digest);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to compute PIN policy digest: 0x%x\n", rc);
    goto cleanup;
  }

  rc = define_pin_index(ctx, pin_index_val, policy_digest, pin);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to define PIN NV index: 0x%x\n", rc);
    goto cleanup;
  }

  rc = write_pin_placeholder(ctx, pin_index_val);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to initialize PIN NV data: 0x%x\n", rc);
    goto cleanup;
  }

cleanup:
  if (policy_digest != NULL) {
    Esys_Free(policy_digest);
  }
  if (counter_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &counter_handle);
  }
  if (ctx != NULL) {
    Esys_Finalize(&ctx);
  }

  return rc == TSS2_RC_SUCCESS;
}