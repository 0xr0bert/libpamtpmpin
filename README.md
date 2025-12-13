# libpamtpmpin

[![Build](https://github.com/0xr0bert/libpamtpmpin/actions/workflows/build.yml/badge.svg)](https://github.com/0xr0bert/libpamtpmpin/actions/workflows/build.yml)

A PAM module allowing authentication via a PIN backed by a TPM 2.0 device.

## Overview

`libpamtpmpin` provides a secure way to authenticate users using a PIN. Unlike standard password authentication, the security of the PIN is enforced by the TPM hardware. This includes:

*   **Hardware-bound security**: The PIN verification happens within the TPM.
*   **Anti-hammering**: A monotonic counter in the TPM limits the number of incorrect attempts.

## Installation

### Prerequisites

*   `cmake`
*   `gcc` or `clang`
*   `libpam0g-dev`
*   `libtss2-dev` (TPM2 TSS ESAPI)

### Build and Install

```bash
meson setup build
meson compile -C build
sudo meson install -C build
```

By default, the PAM module is installed to `/usr/lib/security` (or `/usr/local/lib/security` depending on prefix). If your distribution uses a different path (like `/lib/security`), you can specify it:

```bash
meson configure build -Dpam_modules_dir=/lib/security
sudo meson install -C build
```

## Configuration

### 1. Enrol a User

Before using the PAM module, the user must be enrolled in the TPM. This provisions the necessary NV (Non-Volatile) indexes.

```bash
# Syntax: tpmpin enroll <username> [owner_password] [options]
sudo tpmpin enroll myuser
```

*   You will be prompted to set a PIN.
*   **Options**:
    *   `--max-tries <N>`: Set the maximum number of failed attempts (default: 5).
    *   `--base <hex>`: Specify the starting NV index (advanced usage).

### 2. Configure PAM

Edit the appropriate PAM configuration file (e.g., `/etc/pam.d/sudo`, `/etc/pam.d/gdm-password`, or `/etc/pam.d/common-auth`).

Add the following line before the standard unix authentication:

```pam
auth    sufficient      pam_tpmpin.so
```

#### Module Options

You can pass options to the PAM module to customize its behaviour:

*   `max_tries=<N>`: Overrides the default maximum attempts allowed before fallback (default: 5). Note: This is distinct from the hardware-enforced limit set during enrollment.
*   `base=<hex>`: Specifies the base NV index if a non-default range was used during enrolment.

**Example with options**:

```pam
auth    sufficient      pam_tpmpin.so max_tries=5 base=0x1000000
```

**Example `/etc/pam.d/sudo`**:

```pam
#%PAM-1.0
auth    sufficient      pam_tpmpin.so
auth    include         system-auth
account include         system-auth
session include         system-auth
```

With `sufficient`, if the PIN is correct, sudo is granted. If the PIN is incorrect, it falls back to the system password.

## Management

### Unblocking a User

If a user exceeds the maximum number of tries, their PIN is locked. To unblock them, the TPM Owner password is required (if set) or the operation must be done by root/owner.

```bash
sudo tpmpin unblock myuser
```

## Security Model

The security relies on TPM 2.0 NV Indexes and Policy Sessions.

1.  **Two NV Indexes per User**:
    *   **Counter Index**: Stores the number of failed attempts.
    *   **PIN Index**: Protected by the PIN (AuthValue) and a Policy.

2.  **Policy Check**:
    *   Accessing the PIN Index requires satisfying a `PolicyNV` check against the Counter Index.
    *   The policy enforces that `CounterValue < MaxTries`.

3.  **Authentication Flow**:
    *   The PAM module attempts to satisfy the policy.
    *   If the PIN is wrong, the module increments the Counter Index.
    *   If the Counter reaches `MaxTries`, the TPM policy prevents any further attempts to verify the PIN, effectively locking the account.

4.  **Reset**:
    *   The `tpmpin unblock` command resets the counter to 0 using the TPM Owner authorization.
