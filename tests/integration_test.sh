#!/bin/bash
set -e

# Arguments
BUILD_DIR=${1:-build}
PAM_MODULE_PATH="$BUILD_DIR/libpam_tpmpin.so"
TPMPIN_BIN="$BUILD_DIR/tpmpin"
TEST_HARNESS="$BUILD_DIR/pam_test_harness"
SERVICE_NAME="tpmpin-test"
USERNAME=$(whoami)
PIN="123456"

# Check if files exist
if [ ! -f "$PAM_MODULE_PATH" ]; then
    echo "Error: PAM module not found at $PAM_MODULE_PATH"
    exit 1
fi

if [ ! -f "$TPMPIN_BIN" ]; then
    echo "Error: tpmpin binary not found at $TPMPIN_BIN"
    exit 1
fi

if [ ! -f "$TEST_HARNESS" ]; then
    echo "Error: Test harness not found at $TEST_HARNESS"
    exit 1
fi

# Setup SWTPM
echo "Setting up SWTPM..."
TPM_DIR=$(mktemp -d)
swtpm socket --tpm2 --tpmstate dir=$TPM_DIR --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init &
SWTPM_PID=$!

# Cleanup trap
cleanup() {
    echo "Cleaning up..."
    kill $SWTPM_PID
    rm -rf $TPM_DIR
    sudo rm -f /etc/pam.d/$SERVICE_NAME
}
trap cleanup EXIT

# Wait for SWTPM to start
sleep 1

# Configure TCTI
export TSS2_TCTI="swtpm:host=localhost,port=2321"

# Initialize TPM
echo "Initializing TPM..."
tpm2_startup -c
tpm2_clear -c p

# Setup PAM Service
echo "Setting up PAM service..."
# We need absolute path for the module in PAM config
ABS_MODULE_PATH=$(readlink -f $PAM_MODULE_PATH)
echo "auth required $ABS_MODULE_PATH" | sudo tee /etc/pam.d/$SERVICE_NAME > /dev/null

# Test 1: Enroll
echo "Test 1: Enrollment"
# tpmpin enroll expects interactive input, or we can pipe it?
# The code uses simple scanf or similar? Let's check tpmpin.c later.
# Assuming we can pipe input.
echo -e "$PIN\n$PIN" | $TPMPIN_BIN enroll $USERNAME

# Test 2: Authentication Success
echo "Test 2: Authentication Success"
$TEST_HARNESS $SERVICE_NAME $USERNAME $PIN

# Test 3: Authentication Failure
echo "Test 3: Authentication Failure"
if $TEST_HARNESS $SERVICE_NAME $USERNAME "wrongpin"; then
    echo "Error: Authentication should have failed!"
    exit 1
else
    echo "Authentication failed as expected."
fi

echo "All tests passed!"
