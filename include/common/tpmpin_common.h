#ifndef TPMPIN_COMMON_H
#define TPMPIN_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

// Constants -------------------------------------------------------------------

#define NV_PIN_INDEX_BASE 0x01500000
#define NV_COUNTER_INDEX_BASE 0x01600000
#define PIN_NV_DATA_SIZE 32
#define COUNTER_NV_DATA_SIZE 8
#define MAX_PIN_FAILURES 5

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

// Functions -------------------------------------------------------------------

/**
 * Encode a 64-bit unsigned integer into a big-endian byte buffer
 * @param value The 64-bit unsigned integer to encode
 * @param buffer The buffer to write the encoded bytes into
 * @param size The size of the buffer (number of bytes to write)
 */
void encode_u64_be(uint64_t value, uint8_t *buffer, size_t size);

/**
 * Decode a 64-bit unsigned integer from a big-endian byte buffer
 * @param buffer The buffer to read the encoded bytes from
 * @param size The size of the buffer
 * @return The decoded 64-bit unsigned integer
 */
uint64_t decode_u64_be(const uint8_t *buffer, size_t size);

/**
 * Check if the return code indicates a bad auth error
 * @param rc The return code
 * @return true if it is a bad auth error, false otherwise
 */
bool rc_is_bad_auth(TSS2_RC rc);

/**
 * Check if the return code indicates a policy failure
 * @param rc The return code
 * @return true if it is a policy failure, false otherwise
 */
bool rc_is_policy_fail(TSS2_RC rc);

/**
 * Read the value from the counter NV index
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @param value Output parameter for the read value
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC read_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                           uint64_t *value);

/**
 * Write a value to the counter NV index
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @param value The value to write
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC write_counter_value(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                            uint64_t value);

/**
 * Reset the counter to 0
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC reset_counter(ESYS_CONTEXT *ctx, ESYS_TR counter_handle);

/**
 * Increment the counter value
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC increment_counter(ESYS_CONTEXT *ctx, ESYS_TR counter_handle);

/**
 * Apply the policy limit to the session
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @param policy_session The policy session handle
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC apply_policy_limit(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                           ESYS_TR policy_session);

/**
 * Remove an NV index if it exists
 * @param ctx The ESYS context
 * @param index The NV index to remove
 * @param owner_password The TPM owner password (optional, can be NULL)
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC remove_nv_if_exists(ESYS_CONTEXT *ctx, TPM2_HANDLE index,
                            const char *owner_password);

/**
 * Define a counter NV index
 * @param ctx The ESYS context
 * @param index The NV index to define
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC define_counter_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index);

/**
 * Define the PIN NV index with the specified policy and PIN
 * @param ctx The ESYS context
 * @param index The NV index for the PIN
 * @param policy_digest The policy digest to associate with the NV index
 * @param pin The PIN to set as the auth value
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC define_pin_index(ESYS_CONTEXT *ctx, TPM2_HANDLE index,
                         const TPM2B_DIGEST *policy_digest, const char *pin);

/**
 * Write a placeholder value to the PIN NV index
 * @param ctx The ESYS context
 * @param pin_index The NV index for the PIN
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC write_pin_placeholder(ESYS_CONTEXT *ctx, TPM2_HANDLE pin_index);

/**
 * Compute the policy digest for the PIN NV index
 * @param ctx The ESYS context
 * @param counter_handle The ESYS_TR handle for the counter NV index
 * @param digest Output parameter for the computed policy digest
 * @return TSS2_RC_SUCCESS on success, or error code on failure
 */
TSS2_RC compute_pin_policy_digest(ESYS_CONTEXT *ctx, ESYS_TR counter_handle,
                                  TPM2B_DIGEST **digest);

#endif // TPMPIN_COMMON_H
