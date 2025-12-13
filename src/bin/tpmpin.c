#define _DEFAULT_SOURCE
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <tpmpin_common.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

// Forward declarations --------------------------------------------------------

/**
 * Enroll a user by username
 * @param username The username to enroll
 * @param owner_password The TPM owner password (optional, can be NULL)
 * @return 0 on success, -1 on failure
 */
static bool enroll_user(const char *username, const char *owner_password);

/**
 * Get the UID of the specified username
 * @param username The username to look up
 * @return The UID on success, or negative value on failure
 */
static int64_t get_uid(const char *username);

/**
 * Enroll a user in the TPM with the specified PIN and NV indexes
 * @param pin The PIN to enroll
 * @param pin_index_val The NV index for the PIN
 * @param counter_index_val The NV index for the failure counter
 * @param owner_password The TPM owner password (optional, can be NULL)
 * @return true on success, false on failure
 */
static bool enroll_user_in_tpm(const char *pin, TPM2_HANDLE pin_index_val,
                               TPM2_HANDLE counter_index_val,
                               const char *owner_password);

static char *ask_pin(const char *prompt);

// Main ------------------------------------------------------------------------

int main(int argc, char **argv) {
  setenv("TSS2_LOG", "all+NONE", 0);
  if (argc < 3) {
    printf("Usage: %s enroll <username> [owner_password]\n", argv[0]);
    return 1;
  }
  if (strcmp(argv[1], "enroll") == 0) {
    const char *owner_password = NULL;
    if (argc >= 4) {
      owner_password = argv[3];
    }
    bool result = enroll_user(argv[2], owner_password);
    if (result) {
      printf("User %s enrolled successfully.\n", argv[2]);
      return 0;
    } else {
      printf("Failed to enroll user %s.\n", argv[2]);
      return 1;
    }
  } else {
    printf("Unknown command: %s\n", argv[1]);
    return 1;
  }
}

static bool enroll_user(const char *username, const char *owner_password) {
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

  char *pin = ask_pin("Enter pin: ");
  if (pin == NULL) {
    fprintf(stderr, "Failed to read PIN from user\n");
    return false;
  }

  char *pin_confirm = ask_pin("Confirm pin: ");
  if (pin_confirm == NULL) {
    fprintf(stderr, "Failed to read PIN confirmation from user\n");
    explicit_bzero(pin, strlen(pin));
    free(pin);
    return false;
  }
  if (strcmp(pin, pin_confirm) != 0) {
    fprintf(stderr, "PIN and confirmation do not match\n");
    explicit_bzero(pin, strlen(pin));
    free(pin);
    explicit_bzero(pin_confirm, strlen(pin_confirm));
    free(pin_confirm);
    return false;
  }
  explicit_bzero(pin_confirm, strlen(pin_confirm));
  free(pin_confirm);
  printf("Pin OK\n");

  bool result =
      enroll_user_in_tpm(pin, pin_index, counter_index, owner_password);
  explicit_bzero(pin, strlen(pin));
  free(pin);
  return result;
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

static char *ask_pin(const char *prompt) {
  char *pin = NULL;
  size_t len = 0;
  struct termios old_terminal;
  bool echo_disabled = false;

  while (true) {
    printf("%s", prompt);

    if (tcgetattr(STDIN_FILENO, &old_terminal) == 0) {
      struct termios no_echo_terminal = old_terminal;
      no_echo_terminal.c_lflag &= ~ECHO;
      if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo_terminal) == 0) {
        echo_disabled = true;
      }
    }

    ssize_t read = getline(&pin, &len, stdin);

    if (echo_disabled) {
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_terminal);
      printf("\n");
    }

    if (read == -1) {
      free(pin);
      return NULL;
    }
    // Remove trailing newline
    if (read > 0 && pin[read - 1] == '\n') {
      pin[read - 1] = '\0';
      read--;
    }

    if (read < 6) {
      printf("PIN must be at least 6 characters long.\n");
      continue;
    }

    return pin;
  }
}

// TPM -------------------------------------------------------------------------

static bool enroll_user_in_tpm(const char *pin, TPM2_HANDLE pin_index_val,
                               TPM2_HANDLE counter_index_val,
                               const char *owner_password) {
  TSS2_RC rc;
  ESYS_CONTEXT *ctx = NULL;
  TPM2B_AUTH owner_auth = {.size = 0};
  TPM2B_DIGEST *policy_digest = NULL;
  ESYS_TR counter_handle = ESYS_TR_NONE;

  if (owner_password != NULL) {
    owner_auth.size = strlen(owner_password);
    if (owner_auth.size > sizeof(owner_auth.buffer)) {
      owner_auth.size = sizeof(owner_auth.buffer);
    }
    memcpy(owner_auth.buffer, owner_password, owner_auth.size);
  }

  rc = Esys_Initialize(&ctx, NULL, NULL);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to initialize ESYS context: 0x%x\n", rc);
    return -1;
  }

  // Clean up any previous enrollment artifacts
  rc = remove_nv_if_exists(ctx, pin_index_val, owner_password);
  if (rc == TSS2_RC_SUCCESS) {
    rc = remove_nv_if_exists(ctx, counter_index_val, owner_password);
  }
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to remove existing NV indexes: 0x%x\n", rc);
    goto cleanup;
  }

  // Define the counter index and load it for policy computation
  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &owner_auth);
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

  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &owner_auth);
  Esys_TR_SetAuth(ctx, counter_handle, &owner_auth);

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

  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &owner_auth);
  rc = define_pin_index(ctx, pin_index_val, policy_digest, pin);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to define PIN NV index: 0x%x\n", rc);
    goto cleanup;
  }

  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &owner_auth);
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