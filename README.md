# libpamtpmpin

[![Build](https://github.com/0xr0bert/libpamtpmpin/actions/workflows/build.yml/badge.svg)](https://github.com/0xr0bert/libpamtpmpin/actions/workflows/build.yml)

A PAM module allowing authentication via a PIN backed by a TPM 2.0 device.

## Overview

`libpamtpmpin` provides a secure way to authenticate users using a PIN. Unlike standard password authentication, the security of the PIN is enforced by the TPM hardware. This includes:

*   **Hardware-bound security**: The PIN verification happens within the TPM.
*   **Anti-hammering**: A monotonic counter in the TPM limits the number of incorrect attempts.

## Installation

### Prerequisites

*   Rust (stable)
*   `clang` (required for bindgen)
*   `pkg-config`
*   `libpam0g-dev` (PAM development headers)
*   `libtss2-dev` (TPM2 TSS ESAPI development headers)

### Build and Install

```bash
cargo build --release
```

This will produce the following artifacts in `target/release/`:

*   `libpam_tpmpin.so`: The PAM module.
*   `tpmpin`: The administration tool.
*   `tpmpin-unblock-self`: The setuid helper for auto-unblocking.

#### Manual Installation

1.  **Install the PAM module**:
    ```bash
    sudo cp target/release/libpam_tpmpin.so /lib/security/
    ```
    *(Note: Adjust the path to `/usr/lib/security` or `/usr/lib64/security` depending on your distribution.)*

2.  **Install the administration tool**:
    ```bash
    sudo cp target/release/tpmpin /usr/local/bin/
    ```

3.  **Install the unblock helper**:
    ```bash
    sudo cp target/release/tpmpin-unblock-self /usr/local/libexec/
    sudo chown root:root /usr/local/libexec/tpmpin-unblock-self
    sudo chmod u+s /usr/local/libexec/tpmpin-unblock-self
    ```
    *(Note: The helper **must** be setuid root to function correctly when called by the PAM module.)*

### Arch Linux / AUR

This package is available on the Arch User Repository (AUR): https://aur.archlinux.org/packages/libpamtpmpin

Install with an AUR helper (example using `paru`):

```bash
paru -S libpamtpmpin
```

## Configuration

### 1. Enrol a User

Before using the PAM module, the user must be enrolled in the TPM. This provisions the necessary NV (Non-Volatile) indexes.

```bash
# Syntax: tpmpin enroll <username> [options]
sudo tpmpin enroll myuser
```

*   You will be prompted to set a PIN.
*   **Options**:
    *   `--ask-password`: Prompt for the TPM owner password securely.
    *   `--max-tries <N>`: Set the maximum number of failed attempts (default: 5).
    *   `--base <hex>`: Specify the starting NV index (advanced usage).

### 2. Configure PAM

Edit the appropriate PAM configuration file (e.g., `/etc/pam.d/sudo`, `/etc/pam.d/gdm-password`, or `/etc/pam.d/common-auth`).

Add the following line before the standard unix authentication:

```pam
auth    sufficient      libpam_tpmpin.so
```

#### Module Options

You can pass options to the PAM module to customize its behaviour:

*   `max_tries=<N>`: Overrides the default maximum attempts allowed before fallback (default: 5). Note: This is distinct from the hardware-enforced limit set during enrollment.
*   `base=<hex>`: Specifies the base NV index if a non-default range was used during enrolment.
*   `unblock_on_success`: If the PIN is locked, return `PAM_IGNORE` during `auth` (allowing other auth modules to succeed). If a login/session is successfully established, the module will run a setuid helper during `session` to reset the TPM failure counter for that user.
*   `helper=/absolute/path`: Set the path to the unblock helper.

**Example with options**:

```pam
auth    sufficient      libpam_tpmpin.so max_tries=5 base=0x1000000 unblock_on_success helper=/usr/local/libexec/tpmpin-unblock-self

# Auto-unblock only after successful non-TPM auth
auth    optional        libpam_tpmpin.so unblock_on_success helper=/usr/local/libexec/tpmpin-unblock-self
session optional        libpam_tpmpin.so unblock_on_success helper=/usr/local/libexec/tpmpin-unblock-self
```

**Example `/etc/pam.d/sudo`**:

```pam
#%PAM-1.0
auth    sufficient      libpam_tpmpin.so
auth    include         system-auth
account include         system-auth
session include         system-auth
```

With `sufficient`, if the PIN is correct, sudo is granted. If the PIN is incorrect, it falls back to the system password.

## Management

### Unblocking a User

If a user exceeds the maximum number of tries, their PIN is locked. To unblock them, the TPM Owner password is required (if set) or the operation must be done by root/owner.

```bash
# Syntax: tpmpin unblock <username> [options]
sudo tpmpin unblock myuser --ask-password
```

### Self-unblock helper (setuid)

When installed with the setuid bit, the helper can reset the caller's TPM failure counter without needing admin access:

```bash
/usr/local/libexec/tpmpin-unblock-self
```

This is also what `unblock_on_success` uses (invoked by PAM as root, targeting the authenticated user).

Security note: enabling auto-unblock without re-authentication reduces the effectiveness of lockout as a deterrent. Consider using it only in stacks where another strong factor (password/FIDO/etc.) is required.

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
