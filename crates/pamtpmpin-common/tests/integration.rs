use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

use pamtpmpin_common::*;
use serial_test::serial;
use tss_esapi::constants::tss::{TPM2_ALG_NULL, TPM2_ALG_SHA256, TPM2_RC_SUCCESS, TPM2_SE_POLICY};
use tss_esapi::tss2_esys::{
    ESYS_CONTEXT, ESYS_TR_NONE, Esys_Finalize, Esys_Free, Esys_Initialize, Esys_NV_Read,
    Esys_PolicyAuthValue, Esys_StartAuthSession, Esys_TR_Close, Esys_TR_FromTPMPublic,
    Esys_TR_SetAuth, TPM2B_AUTH, TPM2B_MAX_NV_BUFFER, TPMT_SYM_DEF, TPMU_SYM_KEY_BITS,
    TPMU_SYM_MODE,
};
use tss_esapi_sys::{TSS2_TCTI_CONTEXT, Tss2_TctiLdr_Finalize, Tss2_TctiLdr_Initialize};

struct TpmSimulator {
    process: Child,
    _temp_dir: TempDir,
    tcti_context: *mut TSS2_TCTI_CONTEXT,
}

impl TpmSimulator {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();

        let socket_base = temp_dir.path().join("swtpm-sock");
        let ctrl_sock = PathBuf::from(format!("{}.ctrl", socket_base.display()));

        println!(
            "Starting swtpm: swtpm socket --tpmstate dir={} --ctrl type=unixio,path={} --tpm2 --server type=unixio,path={} --seccomp action=none --flags not-need-init,startup-clear",
            temp_dir.path().display(),
            ctrl_sock.display(),
            socket_base.display()
        );

        // Start swtpm
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpmstate")
            .arg(format!("dir={}", temp_dir.path().display()))
            .arg("--ctrl")
            .arg(format!("type=unixio,path={}", ctrl_sock.display()))
            .arg("--tpm2")
            .arg("--server")
            .arg(format!("type=unixio,path={}", socket_base.display()))
            .arg("--seccomp")
            .arg("action=none")
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("Failed to start swtpm. Make sure 'swtpm' is installed.");

        // Wait for swtpm to be ready
        thread::sleep(Duration::from_millis(2000));

        // Initialize TCTI
        let conf = std::ffi::CString::new(format!("swtpm:path={}", socket_base.display())).unwrap();
        let mut tcti_context: *mut TSS2_TCTI_CONTEXT = std::ptr::null_mut();
        unsafe {
            let rc = Tss2_TctiLdr_Initialize(conf.as_ptr(), &mut tcti_context);
            assert_eq!(rc, TPM2_RC_SUCCESS, "Tss2_TctiLdr_Initialize failed");
        }

        Self {
            process: child,
            _temp_dir: temp_dir,
            tcti_context,
        }
    }
}

impl Drop for TpmSimulator {
    fn drop(&mut self) {
        if !self.tcti_context.is_null() {
            unsafe { Tss2_TctiLdr_Finalize(&mut self.tcti_context) };
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

unsafe fn authenticate(
    context: *mut ESYS_CONTEXT,
    pin_index: u32,
    counter_index: u32,
    pin: &str,
    max_tries: u64,
) -> Result<(), u32> {
    let mut pin_handle = ESYS_TR_NONE;
    let mut counter_handle = ESYS_TR_NONE;

    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            pin_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut pin_handle,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        return Err(rc);
    }

    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            counter_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        unsafe { Esys_TR_Close(context, &mut pin_handle) };
        return Err(rc);
    }

    // Start policy session
    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_NULL,
        keyBits: TPMU_SYM_KEY_BITS { sym: 0 },
        mode: TPMU_SYM_MODE { sym: TPM2_ALG_NULL },
    };
    let mut policy_session = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_StartAuthSession(
            context,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            std::ptr::null(),
            TPM2_SE_POLICY,
            &symmetric,
            TPM2_ALG_SHA256,
            &mut policy_session,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        unsafe {
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
        }
        return Err(rc);
    }

    // Apply policy limit (check counter < max_tries)
    let rc = unsafe { apply_policy_limit(context, counter_handle, policy_session, max_tries) };
    if let Err(e) = rc {
        // If policy fails here, it means counter >= max_tries (Lockout)
        // Or some other error
        unsafe {
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
            // Flush session
            tss_esapi::tss2_esys::Esys_FlushContext(context, policy_session);
        }
        return Err(e);
    }

    // Provide PIN auth
    let rc = unsafe {
        Esys_PolicyAuthValue(
            context,
            policy_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        unsafe {
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
            tss_esapi::tss2_esys::Esys_FlushContext(context, policy_session);
        }
        return Err(rc);
    }

    let mut pin_auth = TPM2B_AUTH {
        size: pin.len() as u16,
        buffer: [0u8; 64],
    };
    pin_auth.buffer[..pin.len()].copy_from_slice(pin.as_bytes());
    unsafe { Esys_TR_SetAuth(context, pin_handle, &pin_auth) };

    // Try to read the PIN index (this verifies the PIN and the policy)
    let mut data: *mut TPM2B_MAX_NV_BUFFER = std::ptr::null_mut();
    let rc = unsafe {
        Esys_NV_Read(
            context,
            pin_handle,
            pin_handle,
            policy_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            PIN_NV_DATA_SIZE as u16,
            0,
            &mut data,
        )
    };

    if rc != TPM2_RC_SUCCESS {
        // If auth failed, increment counter
        if is_bad_auth(rc) {
            let _ = increment_counter(context, counter_handle, max_tries);
        }
    } else {
        // Success, reset counter
        let _ = unsafe { reset_counter_value(context, counter_handle) };
        unsafe { Esys_Free(data as *mut std::ffi::c_void) };
    }

    unsafe {
        Esys_TR_Close(context, &mut pin_handle);
        Esys_TR_Close(context, &mut counter_handle);
        tss_esapi::tss2_esys::Esys_FlushContext(context, policy_session);
    }

    if rc != TPM2_RC_SUCCESS {
        Err(rc)
    } else {
        Ok(())
    }
}

#[test]
#[serial]
fn test_enrollment_authentication_lockout() {
    let tpm = TpmSimulator::new();

    let mut context: *mut ESYS_CONTEXT = std::ptr::null_mut();
    unsafe {
        let rc = Esys_Initialize(&mut context, tpm.tcti_context, std::ptr::null_mut());
        assert_eq!(rc, TPM2_RC_SUCCESS, "Esys_Initialize failed");
    }

    let uid = 1000;
    let pin_base = NV_PIN_INDEX_BASE;
    let counter_base = NV_COUNTER_INDEX_BASE;
    let pin_index = calculate_nv_index(pin_base, uid);
    let counter_index = calculate_nv_index(counter_base, uid);
    let max_tries = 3;
    let pin = "123456";

    // --- Enrollment ---
    println!("Enrolling user...");
    unsafe {
        let rc = define_counter_index(context, counter_index);
        assert!(rc.is_ok(), "define_counter_index failed");
    }

    let mut counter_handle = ESYS_TR_NONE;
    unsafe {
        let rc = Esys_TR_FromTPMPublic(
            context,
            counter_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        );
        assert_eq!(rc, TPM2_RC_SUCCESS);
    }

    // Initialize counter to 0
    unsafe {
        let rc = reset_counter_value(context, counter_handle);
        assert!(rc.is_ok(), "reset_counter_value failed");
    }

    let policy_digest =
        unsafe { compute_pin_policy_digest(context, counter_handle, max_tries).unwrap() };

    unsafe {
        let rc = define_pin_index(context, pin_index, policy_digest.as_ptr(), Box::from(pin));
        assert!(rc.is_ok(), "define_pin_index failed");
    }

    unsafe {
        let rc = write_pin_placeholder(context, pin_index);
        assert!(rc.is_ok());
    }
    println!("Enrollment complete.");

    // --- Authentication Success ---
    println!("Testing successful authentication...");
    unsafe {
        let rc = authenticate(context, pin_index, counter_index, pin, max_tries);
        assert_eq!(rc, Ok(()), "Authentication with correct PIN failed");
    }

    // --- Authentication Failure (Wrong PIN) ---
    println!("Testing wrong PIN...");
    unsafe {
        let rc = authenticate(context, pin_index, counter_index, "wrong", max_tries);
        assert!(rc.is_err(), "Authentication with wrong PIN should fail");
        assert!(is_bad_auth(rc.unwrap_err()), "Error should be BAD_AUTH");
    }

    // Check counter incremented
    unsafe {
        let val = read_counter_value(context, counter_handle).unwrap();
        assert_eq!(val, 1, "Counter should be 1");
    }

    // --- Lockout ---
    println!("Testing lockout...");
    // Fail 2 more times (total 3 failures = max_tries)
    unsafe {
        let _ = authenticate(context, pin_index, counter_index, "wrong", max_tries);
        let _ = authenticate(context, pin_index, counter_index, "wrong", max_tries);
        let val = read_counter_value(context, counter_handle).unwrap();
        assert_eq!(val, 3, "Counter should be 3 (max_tries)");
    }

    // Now try again, should fail with Policy Failure (Lockout)
    unsafe {
        let rc = authenticate(context, pin_index, counter_index, pin, max_tries); // Even correct PIN fails
        assert!(rc.is_err(), "Authentication should fail when locked out");
        let err = rc.unwrap_err();
        assert!(
            is_policy_fail(err) || err == 0x99D, // 0x99D is TPM2_RC_POLICY_FAIL sometimes depending on layer
            "Error should be related to policy failure. Got: 0x{:X}",
            err
        );
    }

    // --- Unblock ---
    println!("Testing unblock...");
    unsafe {
        let rc = reset_counter_value(context, counter_handle);
        assert!(rc.is_ok(), "Reset counter failed");
    }

    // Auth should work again
    unsafe {
        let rc = authenticate(context, pin_index, counter_index, pin, max_tries);
        assert_eq!(rc, Ok(()), "Authentication after unblock failed");
    }

    unsafe {
        Esys_TR_Close(context, &mut counter_handle);
        Esys_Finalize(&mut context);
    }
}
