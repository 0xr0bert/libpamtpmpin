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
 * @param base The NV index base
 * @param max_tries The maximum number of tries allowed
 * @return 0 on success, -1 on failure
 */
static bool enroll_user(const char *username, const char *owner_password,
                        uint32_t base, uint64_t max_tries);

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
 * @param max_tries The maximum number of tries allowed
 * @return true on success, false on failure
 */
static bool enroll_user_in_tpm(const char *pin, TPM2_HANDLE pin_index_val,
                               TPM2_HANDLE counter_index_val,
                               const char *owner_password, uint64_t max_tries);

/**
 * Unblock a user by resetting their failure counter
 * @param username The username to unblock
 * @param owner_password The TPM owner password (optional, can be NULL)
 * @param base The NV index base
 * @return true on success, false on failure
 */
static bool unblock_user(const char *username, const char *owner_password,
                         uint32_t base);

/**
 * Unblock a user in the TPM by resetting the counter NV index
 * @param counter_index_val The NV index for the failure counter
 * @param owner_password The TPM owner password (optional, can be NULL)
 * @return true on success, false on failure
 */
static bool unblock_user_in_tpm(TPM2_HANDLE counter_index_val,
                                const char *owner_password);

static char *ask_pin(const char *prompt);

// Main ------------------------------------------------------------------------

int main(int argc, char **argv) {
  setenv("TSS2_LOG", "all+NONE", 0);
  if (argc < 3) {
    printf("Usage: %s <command> <username> [options]\n", argv[0]);
    printf("Commands:\n");
    printf("  enroll <username> [owner_password] [--base <hex>] [--max-tries "
           "<number>]\n");
    printf("  unblock <username> [owner_password] [--base <hex>]\n");
    return 1;
  }
  if (strcmp(argv[1], "enroll") == 0) {
    const char *username = NULL;
    const char *owner_password = NULL;
    uint32_t base = NV_PIN_INDEX_BASE;
    uint64_t max_tries = MAX_PIN_FAILURES;

    for (int i = 2; i < argc; ++i) {
      if (strcmp(argv[i], "--base") == 0) {
        if (i + 1 < argc) {
          base = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else {
          fprintf(stderr, "--base requires an argument\n");
          return 1;
        }
      } else if (strcmp(argv[i], "--max-tries") == 0) {
        if (i + 1 < argc) {
          max_tries = (uint64_t)strtoul(argv[++i], NULL, 0);
        } else {
          fprintf(stderr, "--max-tries requires an argument\n");
          return 1;
        }
      } else if (username == NULL) {
        username = argv[i];
      } else if (owner_password == NULL) {
        owner_password = argv[i];
      }
    }

    if (username == NULL) {
      printf("Usage: %s enroll <username> [owner_password] [--base <hex>] "
             "[--max-tries <number>]\n",
             argv[0]);
      return 1;
    }

    bool result = enroll_user(username, owner_password, base, max_tries);
    if (result) {
      printf("User %s enrolled successfully.\n", username);
      return 0;
    } else {
      printf("Failed to enroll user %s.\n", username);
      return 1;
    }
  } else if (strcmp(argv[1], "unblock") == 0) {
    const char *username = NULL;
    const char *owner_password = NULL;
    uint32_t base = NV_PIN_INDEX_BASE;

    for (int i = 2; i < argc; ++i) {
      if (strcmp(argv[i], "--base") == 0) {
        if (i + 1 < argc) {
          base = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else {
          fprintf(stderr, "--base requires an argument\n");
          return 1;
        }
      } else if (username == NULL) {
        username = argv[i];
      } else if (owner_password == NULL) {
        owner_password = argv[i];
      }
    }

    if (username == NULL) {
      printf("Usage: %s unblock <username> [owner_password] [--base <hex>]\n",
             argv[0]);
      return 1;
    }

    bool result = unblock_user(username, owner_password, base);
    if (result) {
      printf("User %s unblocked successfully.\n", username);
      return 0;
    } else {
      printf("Failed to unblock user %s.\n", username);
      return 1;
    }
  } else {
    printf("Unknown command: %s\n", argv[1]);
    return 1;
  }
}

static bool enroll_user(const char *username, const char *owner_password,
                        uint32_t base, uint64_t max_tries) {
  printf("enroll user: %s\n", username);
  int64_t uid = get_uid(username);
  printf("UID: %ld\n", uid);
  if (uid < 0) {
    fprintf(stderr, "Failed to resolve UID for %s\n", username);
    return false;
  }

  uint32_t counter_base = base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
  TPM2_HANDLE pin_index = calculate_nv_index(base, (uint32_t)uid);
  TPM2_HANDLE counter_index = calculate_nv_index(counter_base, (uint32_t)uid);

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

  bool result = enroll_user_in_tpm(pin, pin_index, counter_index,
                                   owner_password, max_tries);
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
                               const char *owner_password, uint64_t max_tries) {
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

  rc =
      compute_pin_policy_digest(ctx, counter_handle, max_tries, &policy_digest);
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

static bool unblock_user(const char *username, const char *owner_password,
                         uint32_t base) {
  printf("Unblocking user: %s\n", username);
  int64_t uid = get_uid(username);
  if (uid < 0) {
    fprintf(stderr, "Failed to resolve UID for %s\n", username);
    return false;
  }

  uint32_t counter_base = base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
  TPM2_HANDLE counter_index = calculate_nv_index(counter_base, (uint32_t)uid);

  return unblock_user_in_tpm(counter_index, owner_password);
}

static bool unblock_user_in_tpm(TPM2_HANDLE counter_index_val,
                                const char *owner_password) {
  TSS2_RC rc;
  ESYS_CONTEXT *ctx = NULL;
  TPM2B_AUTH owner_auth = {.size = 0};
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
    return false;
  }

  // Load the counter NV index
  rc = Esys_TR_FromTPMPublic(ctx, counter_index_val, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, &counter_handle);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr,
            "Failed to load counter NV index (User might not be enrolled): "
            "0x%x\n",
            rc);
    goto cleanup;
  }

  // Set owner auth for the operation
  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &owner_auth);

  // Reset the counter
  rc = reset_counter(ctx, counter_handle);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to reset counter: 0x%x\n", rc);
  }

cleanup:
  if (counter_handle != ESYS_TR_NONE) {
    Esys_TR_Close(ctx, &counter_handle);
  }
  if (ctx != NULL) {
    Esys_Finalize(&ctx);
  }

  return rc == TSS2_RC_SUCCESS;
}
