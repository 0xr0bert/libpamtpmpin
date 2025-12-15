use std::ffi::{CStr, CString, c_void};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use libc::{LOG_ERR, c_char, c_int, free};
use nix::unistd::{User, getuid};
use pam_sys::raw::pam_get_item;
use pam_sys::{PamConversation, PamMessage, PamResponse};
use pam_sys::{
    PamHandle, PamReturnCode,
    raw::{pam_get_data, pam_get_user, pam_set_data},
};
use pamtpmpin_common::{
    EsysPtr, NV_COUNTER_INDEX_BASE, NV_PIN_INDEX_BASE, PIN_NV_DATA_SIZE, apply_policy_limit,
    calculate_nv_index, increment_counter, is_bad_auth, is_policy_fail, reset_counter_value,
};
use tss_esapi::constants::tss::{
    TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_SHA256, TPM2_RC_SUCCESS, TPM2_SE_POLICY,
};
use tss_esapi_sys::{
    ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER, Esys_Finalize, Esys_FlushContext,
    Esys_Initialize, Esys_NV_Read, Esys_PolicyAuthValue, Esys_StartAuthSession, Esys_TR_Close,
    Esys_TR_FromTPMPublic, Esys_TR_SetAuth, TPM2_HANDLE, TPM2B_AUTH, TPM2B_MAX_NV_BUFFER,
    TPMT_SYM_DEF, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE,
};
use zeroize::{Zeroize, Zeroizing};

pub const TPMPIN_PAM_DATA_NEEDS_UNBLOCK: &str = "tpmpin_needs_unblock";

#[link(name = "pam")]
unsafe extern "C" {
    unsafe fn pam_syslog(pamh: *mut PamHandle, priority: c_int, fmt: *const c_char, ...);
}

struct ModuleOptions {
    pin_base: u32,
    max_tries: u64,
    unblock_on_success: bool,
    helper_path: Option<String>,
}

#[unsafe(no_mangle)]
pub extern "C" fn free_pam_data(_pamh: *mut PamHandle, data: *mut c_void, _flags: c_int) {
    let _ = std::panic::catch_unwind(|| {
        if !data.is_null() {
            unsafe {
                let _boxed: Box<bool> = Box::from_raw(data as *mut bool);
            }
        }
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if std::env::var_os("TSS2_LOG") == None {
            // Disable logging by default
            unsafe {
                std::env::set_var("TSS2_LOG", "all+NONE");
            }
        }

        let options = parse_module_options(argc, argv);
        let uid = match get_uid(pamh) {
            Ok(u) => u,
            Err(code) => return code as c_int,
        };

        let counter_base = options.pin_base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
        let counter_index = calculate_nv_index(counter_base, uid);
        let pin_index = calculate_nv_index(options.pin_base, uid);

        match unsafe { is_counter_locked(pamh, counter_index, options.max_tries) } {
            Ok(locked) => {
                if locked {
                    if options.unblock_on_success {
                        let flag = Box::into_raw(Box::new(true));
                        let module_data_name = CString::new(TPMPIN_PAM_DATA_NEEDS_UNBLOCK)
                            .expect("CString::new failed");
                        unsafe {
                            pam_set_data(
                                pamh,
                                module_data_name.as_ptr(),
                                flag as *mut c_void,
                                Some(free_pam_data),
                            );
                        }
                        return PamReturnCode::IGNORE as c_int;
                    } else {
                        return PamReturnCode::MAXTRIES as c_int;
                    }
                }
            }
            Err(_) => {
                return PamReturnCode::SYSTEM_ERR as c_int;
            }
        }

        let pin = match unsafe { ask_user(pamh, "Please enter your pin: ") } {
            Ok(p) => Zeroizing::new(p),
            Err(code) => return code as c_int,
        };

        let verify_result =
            unsafe { verify_nv_pin(pamh, &pin, pin_index, counter_index, options.max_tries) };

        match verify_result {
            Ok(_) => PamReturnCode::SUCCESS as c_int,
            Err(code) => code as c_int,
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => PamReturnCode::SYSTEM_ERR as c_int,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    return PamReturnCode::SUCCESS as c_int;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if std::env::var_os("TSS2_LOG") == None {
            // Disable logging by default
            unsafe {
                std::env::set_var("TSS2_LOG", "all+NONE");
            }
        }

        let opts = parse_module_options(argc, argv);
        if !opts.unblock_on_success {
            return PamReturnCode::SUCCESS as c_int;
        }

        let mut data: *const c_void = std::ptr::null();
        let module_data_name =
            CString::new(TPMPIN_PAM_DATA_NEEDS_UNBLOCK).expect("CString::new failed");
        if unsafe { pam_get_data(pamh, module_data_name.as_ptr(), &mut data) }
            != PamReturnCode::SUCCESS as c_int
            || data.is_null()
        {
            return PamReturnCode::SUCCESS as c_int;
        }

        let uid = match get_uid(pamh) {
            Ok(u) => u,
            Err(_) => {
                unsafe {
                    pam_syslog(
                        pamh,
                        LOG_ERR,
                        CString::new("tpmpin: could not resolve uid for auto-unblock")
                            .expect("CString::new failed")
                            .as_ptr(),
                    );
                }
                return PamReturnCode::SUCCESS as c_int;
            }
        };

        let _ = unsafe { run_unblock_helper(pamh, &opts, uid) };

        // Clear the flag so we don't try again
        unsafe {
            pam_set_data(pamh, module_data_name.as_ptr(), std::ptr::null_mut(), None);
        }
        return PamReturnCode::SUCCESS as c_int;
    }));

    match result {
        Ok(code) => code,
        Err(_) => PamReturnCode::SYSTEM_ERR as c_int,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    return PamReturnCode::SUCCESS as c_int;
}

fn parse_module_options(argc: c_int, argv: *const *const c_char) -> ModuleOptions {
    let mut options = ModuleOptions {
        pin_base: 0x01500000,
        max_tries: 5,
        unblock_on_success: false,
        helper_path: None,
    };
    for i in 0..argc {
        let arg_ptr = unsafe { *argv.offset(i as isize) };
        if arg_ptr.is_null() {
            continue;
        }
        let arg_cstr = unsafe { std::ffi::CStr::from_ptr(arg_ptr) };
        let arg_str = match arg_cstr.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };

        if let Some(value) = arg_str.strip_prefix("base=") {
            if let Ok(base) = u32::from_str_radix(value, 16) {
                options.pin_base = base;
            }
        } else if let Some(value) = arg_str.strip_prefix("max_tries=") {
            if let Ok(tries) = value.parse::<u64>() {
                options.max_tries = tries;
            }
        } else if arg_str == "unblock_on_success" {
            options.unblock_on_success = true;
        } else if let Some(value) = arg_str.strip_prefix("helper=") {
            options.helper_path = Some(value.to_string());
        }
    }

    options
}

fn get_uid(pamh: *mut PamHandle) -> Result<u32, PamReturnCode> {
    let mut user: *const c_char = std::ptr::null();
    let ret = unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) };
    if ret != PamReturnCode::SUCCESS as c_int || user.is_null() {
        return Err(PamReturnCode::AUTH_ERR);
    }

    let username = unsafe { CStr::from_ptr(user) }.to_str().unwrap();
    match User::from_name(username) {
        Ok(Some(u)) => Ok(u.uid.as_raw() as u32),
        Ok(None) => Err(PamReturnCode::USER_UNKNOWN),
        Err(_) => Err(PamReturnCode::AUTH_ERR),
    }
}

unsafe fn run_unblock_helper(
    pamh: *mut PamHandle,
    opts: &ModuleOptions,
    uid: u32,
) -> Result<(), ()> {
    let helper_path = match &opts.helper_path {
        Some(p) if p.starts_with('/') => p,
        _ => {
            let fmt = CString::new("tpmpin: helper path must be absolute").unwrap();
            unsafe { pam_syslog(pamh, LOG_ERR, fmt.as_ptr()) };
            return Err(());
        }
    };

    let base_arg = format!("0x{:x}", opts.pin_base);
    let uid_arg = uid.to_string();

    let mut cmd = Command::new(helper_path);
    cmd.env_clear();
    cmd.env("TSS2_LOG", "all+NONE");

    if getuid().is_root() {
        cmd.arg("--uid").arg(uid_arg);
    }
    cmd.arg("--base").arg(base_arg);

    match cmd.status() {
        Ok(status) => {
            if status.success() {
                return Ok(());
            }

            let fmt = CString::new("%s").unwrap();
            if let Some(code) = status.code() {
                let msg = CString::new(format!("tpmpin: unblock helper exited {}", code)).unwrap();
                unsafe { pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), msg.as_ptr()) };
            } else if let Some(signal) = status.signal() {
                let msg = CString::new(format!(
                    "tpmpin: unblock helper killed by signal {}",
                    signal
                ))
                .unwrap();
                unsafe { pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), msg.as_ptr()) };
            } else {
                let msg = CString::new("tpmpin: unblock helper failed (unknown status)").unwrap();
                unsafe { pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), msg.as_ptr()) };
            }
            Err(())
        }
        Err(e) => {
            let fmt = CString::new("%s").unwrap();
            let msg = CString::new(format!("tpmpin: failed to execute helper: {}", e)).unwrap();
            unsafe { pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), msg.as_ptr()) };
            Err(())
        }
    }
}

unsafe fn is_counter_locked(
    pamh: *mut PamHandle,
    counter_index: TPM2_HANDLE,
    max_tries: u64,
) -> Result<bool, ()> {
    let mut context: *mut ESYS_CONTEXT = std::ptr::null_mut();
    let rc_init =
        unsafe { Esys_Initialize(&mut context, std::ptr::null_mut(), std::ptr::null_mut()) };
    if rc_init != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_Initialize failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_init);
        }
        return Err(());
    }

    let mut counter_handle: ESYS_TR = ESYS_TR_NONE;
    let rc_load_counter = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            counter_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        )
    };
    if rc_load_counter != TPM2_RC_SUCCESS {
        let fmt = CString::new(
            "tpmpin: Esys_TR_FromTPMPublic failed to load counter NV index 0x{:X} (user not enroled?): 0x{:X}",
        )
        .unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), counter_index, rc_load_counter);
            Esys_Finalize(&mut context);
        }
        return Err(());
    }

    let auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0; 64],
    };

    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &auth);
        Esys_TR_SetAuth(context, counter_handle, &auth);
    }

    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_AES,
        keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
        mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
    };

    let mut policy_session: ESYS_TR = ESYS_TR_NONE;
    let rc_start_auth = unsafe {
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

    if rc_start_auth != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_StartAuthSession failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_start_auth);
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(());
    }

    let rc_policy_limit =
        unsafe { apply_policy_limit(context, counter_handle, policy_session, max_tries) };

    match rc_policy_limit {
        Ok(_) => {
            unsafe {
                Esys_FlushContext(context, policy_session);
                Esys_TR_Close(context, &mut counter_handle);
                Esys_Finalize(&mut context);
            }
            return Ok(false);
        }
        Err(rc) => {
            if is_policy_fail(rc) {
                unsafe {
                    Esys_FlushContext(context, policy_session);
                    Esys_TR_Close(context, &mut counter_handle);
                    Esys_Finalize(&mut context);
                }
                return Ok(true);
            } else {
                let fmt = CString::new("tpmpin: apply_policy_limit failed: 0x{:X}").unwrap();
                unsafe {
                    pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc);
                    Esys_FlushContext(context, policy_session);
                    Esys_TR_Close(context, &mut counter_handle);
                    Esys_Finalize(&mut context);
                }
                return Err(());
            }
        }
    }
}

const PAM_CONV: c_int = 5;

unsafe fn ask_user(pamh: *mut PamHandle, prompt: &str) -> Result<String, PamReturnCode> {
    let mut conv: *const c_void = std::ptr::null();
    let status = unsafe { pam_get_item(pamh, PAM_CONV, &mut conv) };
    if status != PamReturnCode::SUCCESS as c_int || conv.is_null() {
        return Err(PamReturnCode::SYSTEM_ERR);
    }
    let conv_ptr = conv as *const PamConversation;
    if unsafe { (*conv_ptr).conv.is_none() } {
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let mut msg = PamMessage {
        msg_style: 1, // PAM_PROMPT_ECHO_OFF
        msg: CString::new(prompt)
            .expect("CString::new failed")
            .into_raw(),
    };
    let mut msg_ptr: *mut PamMessage = &mut msg as *mut PamMessage;
    let mut resp: *mut PamResponse = std::ptr::null_mut();
    let ret =
        unsafe { (*conv_ptr).conv.unwrap() }(1, &mut msg_ptr, &mut resp, conv_ptr as *mut c_void);
    // Reclaim the prompt string
    let _ = unsafe { CString::from_raw(msg.msg as *mut c_char) };
    if ret != PamReturnCode::SUCCESS as c_int || resp.is_null() {
        return Err(PamReturnCode::SYSTEM_ERR);
    }
    let c_str = unsafe { CStr::from_ptr((*resp).resp) };
    let response = c_str
        .to_str()
        .map_err(|_| PamReturnCode::SYSTEM_ERR)?
        .to_string();

    // Zeroize and free the response string
    let len = c_str.to_bytes_with_nul().len();
    unsafe {
        let ptr = (*resp).resp as *mut u8;
        std::ptr::write_bytes(ptr, 0, len);
        free((*resp).resp as *mut c_void);
    }

    // Free the response structure
    unsafe { free(resp as *mut c_void) };
    Ok(response)
}

unsafe fn verify_nv_pin(
    pamh: *mut PamHandle,
    pin: &str,
    pin_index: TPM2_HANDLE,
    counter_index: TPM2_HANDLE,
    max_tries: u64,
) -> Result<(), PamReturnCode> {
    let mut context: *mut ESYS_CONTEXT = std::ptr::null_mut();
    let rc_init =
        unsafe { Esys_Initialize(&mut context, std::ptr::null_mut(), std::ptr::null_mut()) };
    if rc_init != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_Initialize failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_init);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let mut pin_handle: ESYS_TR = ESYS_TR_NONE;
    let rc_load_pin = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            pin_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut pin_handle,
        )
    };
    if rc_load_pin != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_TR_FromTPMPublic failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_load_pin);
        }
        unsafe {
            Esys_Finalize(&mut context);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let mut counter_handle: ESYS_TR = ESYS_TR_NONE;
    let rc_load_counter = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            counter_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        )
    };
    if rc_load_counter != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_TR_FromTPMPublic failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_load_counter);
            Esys_TR_Close(context, &mut pin_handle);
            Esys_Finalize(&mut context);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let empty_auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0; 64],
    };

    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &empty_auth);
        Esys_TR_SetAuth(context, counter_handle, &empty_auth);
    }

    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_AES,
        keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
        mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
    };

    let mut policy_session: ESYS_TR = ESYS_TR_NONE;
    let rc_start_auth = unsafe {
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
    if rc_start_auth != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_StartAuthSession failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_start_auth);
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let rc_policy_limit =
        unsafe { apply_policy_limit(context, counter_handle, policy_session, max_tries) };

    if let Err(rc) = rc_policy_limit {
        if is_policy_fail(rc) {
            let fmt = CString::new("tpmpin: maximum PIN attempts exceeded").unwrap();
            unsafe {
                pam_syslog(pamh, LOG_ERR, fmt.as_ptr());
                Esys_FlushContext(context, policy_session);
                Esys_TR_Close(context, &mut pin_handle);
                Esys_TR_Close(context, &mut counter_handle);
                Esys_Finalize(&mut context);
            }
            return Err(PamReturnCode::MAXTRIES);
        } else {
            let fmt = CString::new("tpmpin: apply_policy_limit failed: 0x{:X}").unwrap();
            unsafe {
                pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc);
                Esys_FlushContext(context, policy_session);
                Esys_TR_Close(context, &mut pin_handle);
                Esys_TR_Close(context, &mut counter_handle);
                Esys_Finalize(&mut context);
            }
            return Err(PamReturnCode::SYSTEM_ERR);
        }
    }

    let rc_policy_auth_value = unsafe {
        Esys_PolicyAuthValue(
            context,
            policy_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
        )
    };
    if rc_policy_auth_value != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_PolicyAuthValue failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_policy_auth_value);
            Esys_FlushContext(context, policy_session);
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    if pin.len() > 64 {
        let fmt = CString::new("tpmpin: PIN too long").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr());
            Esys_FlushContext(context, policy_session);
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let mut pin_auth = TPM2B_AUTH {
        size: pin.len() as u16,
        buffer: {
            let mut buf = [0u8; 64];
            buf[..pin.len()].copy_from_slice(pin.as_bytes());
            buf
        },
    };

    let rc_set_auth = unsafe { Esys_TR_SetAuth(context, pin_handle, &pin_auth) };
    if rc_set_auth != TPM2_RC_SUCCESS {
        let fmt = CString::new("tpmpin: Esys_TR_SetAuth failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_set_auth);
            Esys_FlushContext(context, policy_session);
            Esys_TR_Close(context, &mut pin_handle);
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(PamReturnCode::SYSTEM_ERR);
    }

    let mut out_data: *mut TPM2B_MAX_NV_BUFFER = std::ptr::null_mut();
    let rc_get_nv = unsafe {
        Esys_NV_Read(
            context,
            pin_handle,
            pin_handle,
            policy_session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            PIN_NV_DATA_SIZE as u16,
            0,
            &mut out_data,
        )
    };

    // Wrap out_data immediately to ensure cleanup
    let _out_data_ptr = unsafe { EsysPtr::new(out_data) };

    let result = if rc_get_nv == TPM2_RC_SUCCESS {
        let _ = unsafe { reset_counter_value(context, counter_handle) };
        Ok(())
    } else if is_bad_auth(rc_get_nv) {
        let _ = increment_counter(context, counter_handle, max_tries);
        Err(PamReturnCode::AUTH_ERR)
    } else if is_policy_fail(rc_get_nv) {
        let fmt = CString::new("tpmpin: maximum PIN attempts exceeded").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr());
        }
        Err(PamReturnCode::MAXTRIES)
    } else {
        let fmt = CString::new("tpmpin: Esys_NV_Read failed: 0x{:X}").unwrap();
        unsafe {
            pam_syslog(pamh, LOG_ERR, fmt.as_ptr(), rc_get_nv);
        }
        Err(PamReturnCode::SYSTEM_ERR)
    };

    pin_auth.buffer.zeroize();
    pin_auth.size.zeroize();

    unsafe {
        Esys_FlushContext(context, policy_session);
        Esys_TR_Close(context, &mut pin_handle);
        Esys_TR_Close(context, &mut counter_handle);
        Esys_Finalize(&mut context);
    }

    result
}
