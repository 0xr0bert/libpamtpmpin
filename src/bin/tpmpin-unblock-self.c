#define _DEFAULT_SOURCE

#include "tpmpin_common.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <unistd.h>

static void close_extra_fds(void) {
  long max_fd = sysconf(_SC_OPEN_MAX);
  if (max_fd < 0) {
    max_fd = 1024;
  }
  for (int fd = 3; fd < max_fd; fd++) {
    close(fd);
  }
}

static bool parse_u32(const char *s, uint32_t *out) {
  if (s == NULL || *s == '\0') {
    return false;
  }
  char *endptr = NULL;
  errno = 0;
  unsigned long val = strtoul(s, &endptr, 0);
  if (errno != 0 || endptr == s || *endptr != '\0' || val > UINT32_MAX) {
    return false;
  }
  *out = (uint32_t)val;
  return true;
}

static bool parse_uid(const char *s, uid_t *out) {
  if (s == NULL || *s == '\0') {
    return false;
  }
  char *endptr = NULL;
  errno = 0;
  unsigned long val = strtoul(s, &endptr, 10);
  if (errno != 0 || endptr == s || *endptr != '\0' || val > UINT32_MAX) {
    return false;
  }
  *out = (uid_t)val;
  return true;
}

int main(int argc, char **argv) {
  // Must be installed setuid-root.
  if (geteuid() != 0) {
    fprintf(stderr, "tpmpin-unblock-self: must run with euid=0\n");
    return 2;
  }

  // Harden the execution environment (setuid context).
  clearenv();
  setenv("TSS2_LOG", "all+NONE", 0);
  close_extra_fds();

  uint32_t base = NV_PIN_INDEX_BASE;
  bool uid_specified = false;
  uid_t requested_uid = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--base") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--base requires an argument\n");
        return 2;
      }
      if (!parse_u32(argv[++i], &base)) {
        fprintf(stderr, "Invalid value for --base\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--uid") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--uid requires an argument\n");
        return 2;
      }
      if (!parse_uid(argv[++i], &requested_uid)) {
        fprintf(stderr, "Invalid value for --uid\n");
        return 2;
      }
      uid_specified = true;
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 2;
    }
  }

  uid_t real_uid = getuid();
  uid_t target_uid = real_uid;

  // In the normal self-service case, real_uid is the user and euid is 0.
  // Only allow targeting arbitrary uids when the *real* uid is also root.
  if (real_uid == 0) {
    if (uid_specified) {
      target_uid = requested_uid;
    }
  } else {
    if (uid_specified) {
      fprintf(stderr, "--uid is only allowed when invoked by root\n");
      return 2;
    }
  }

  uint32_t counter_base = base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
  TPM2_HANDLE counter_index =
      calculate_nv_index(counter_base, (uint32_t)target_uid);

  ESYS_CONTEXT *ctx = NULL;
  ESYS_TR counter_handle = ESYS_TR_NONE;
  TPM2B_AUTH empty_auth = {.size = 0};

  TSS2_RC rc = Esys_Initialize(&ctx, NULL, NULL);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to initialize ESYS context: 0x%x\n", rc);
    return 1;
  }

  rc = Esys_TR_FromTPMPublic(ctx, counter_index, ESYS_TR_NONE, ESYS_TR_NONE,
                             ESYS_TR_NONE, &counter_handle);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr,
            "Failed to load counter NV index 0x%x (user not enrolled?): 0x%x\n",
            counter_index, rc);
    Esys_Finalize(&ctx);
    return 1;
  }

  Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &empty_auth);
  rc = reset_counter(ctx, counter_handle);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "Failed to reset counter: 0x%x\n", rc);
  }

  Esys_TR_Close(ctx, &counter_handle);
  Esys_Finalize(&ctx);

  return rc == TSS2_RC_SUCCESS ? 0 : 1;
}
