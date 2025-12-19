use clap::{Parser, Subcommand, command};
use clap_num::maybe_hex;
use nix::unistd::User;
use pamtpmpin_common::{
    MAX_PIN_FAILURES, NV_COUNTER_INDEX_BASE, NV_PIN_INDEX_BASE, calculate_nv_index,
    compute_pin_policy_digest, define_counter_index, define_pin_index, remove_nv_if_exists,
    reset_counter_value, write_counter_value, write_pin_placeholder,
};
use tss_esapi::constants::tss::TPM2_RC_SUCCESS;
use tss_esapi_sys::{
    ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER, Esys_Finalize, Esys_Initialize,
    Esys_TR_Close, Esys_TR_FromTPMPublic, Esys_TR_SetAuth, TPM2_HANDLE, TPM2B_AUTH,
};
use zeroize::{Zeroize, Zeroizing};

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll {
            username,
            ask_password,
            base,
            max_tries,
        } => {
            let owner_pw = if ask_password {
                Some(Zeroizing::new(
                    rpassword::prompt_password("Enter TPM owner password: ").unwrap(),
                ))
            } else {
                None
            };
            match enroll_user(
                &username,
                owner_pw.as_deref().map(|s| s.as_str()),
                base,
                max_tries,
            ) {
                Ok(()) => {
                    println!("User '{}' enrolled successfully", username);
                    drop(owner_pw);
                    std::process::exit(0);
                }
                Err(err) => {
                    eprintln!("Error enrolling user '{}': {}", username, err);
                    drop(owner_pw);
                    std::process::exit(1);
                }
            }
        }
        Command::Unblock {
            username,
            ask_password,
            base,
        } => {
            let owner_pw = if ask_password {
                Some(Zeroizing::new(
                    rpassword::prompt_password("Enter TPM owner password: ").unwrap(),
                ))
            } else {
                None
            };
            match unblock_user(&username, owner_pw.as_deref().map(|s| s.as_str()), base) {
                Ok(()) => {
                    println!("User '{}' unblocked successfully", username);
                    drop(owner_pw);
                    std::process::exit(0);
                }
                Err(err) => {
                    eprintln!("Error unblocking user '{}': {}", username, err);
                    drop(owner_pw);
                    std::process::exit(1);
                }
            }
        }
    }
}

#[derive(Parser)]
#[command(name = "tpmpin", about = "TPM PIN management utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Enroll {
        username: String,
        #[arg(long)]
        ask_password: bool,
        #[arg(long, default_value_t = NV_PIN_INDEX_BASE, value_parser = maybe_hex::<u32>)]
        base: u32,
        #[arg(long, default_value_t = MAX_PIN_FAILURES)]
        max_tries: u64,
    },
    Unblock {
        username: String,
        #[arg(long)]
        ask_password: bool,
        #[arg(long, default_value_t = NV_PIN_INDEX_BASE)]
        base: u32,
    },
}

fn get_uid(username: &str) -> Option<u32> {
    User::from_name(username)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw() as u32)
}

fn ask_pin(prompt: &str) -> Box<str> {
    loop {
        match rpassword::prompt_password(prompt) {
            Ok(mut pin) => {
                if pin.len() < 6 {
                    eprintln!("PIN must be at least 6 characters long");
                    pin.zeroize();
                    continue;
                }
                return pin.into_boxed_str();
            }
            Err(err) => {
                eprintln!("Error reading PIN: {}", err);
            }
        };
    }
}

fn enroll_user(
    username: &str,
    owner_pw: Option<&str>,
    base: u32,
    max_tries: u64,
) -> Result<(), String> {
    println!("enrol user: {}", username);
    let uid = match get_uid(username) {
        Some(u) => u,
        None => return Err(format!("User '{}' not found", username)),
    };
    println!("uid: {}", uid);
    let counter_base = base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
    let pin_index = calculate_nv_index(base, uid);
    let counter_index = calculate_nv_index(counter_base, uid);

    let mut pin = ask_pin("Enter new PIN: ");
    let mut pin_confirm = ask_pin("Confirm new PIN: ");
    if pin.as_ref() != pin_confirm.as_ref() {
        pin.zeroize();
        pin_confirm.zeroize();
        return Err("PINs do not match".to_string());
    }
    pin_confirm.zeroize();
    println!("Pin OK");
    unsafe {
        enroll_user_in_tpm(pin, pin_index, counter_index, owner_pw, max_tries)?;
    }

    Ok(())
}

unsafe fn enroll_user_in_tpm(
    pin: Box<str>,
    pin_index_val: TPM2_HANDLE,
    counter_index_val: TPM2_HANDLE,
    owner_pw: Option<&str>,
    max_tries: u64,
) -> Result<(), String> {
    let mut auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0; 64],
    };
    if let Some(pw) = owner_pw {
        let pw_bytes = pw.as_bytes();
        if pw_bytes.len() > auth.buffer.len() {
            return Err("Owner password too long".to_string());
        }
        auth.size = pw_bytes.len() as u16;
        auth.buffer[..pw_bytes.len()].copy_from_slice(pw_bytes);
    }

    let mut context: *mut ESYS_CONTEXT = std::ptr::null_mut();
    let rc_initialize =
        unsafe { Esys_Initialize(&mut context, std::ptr::null_mut(), std::ptr::null_mut()) };
    if rc_initialize != TPM2_RC_SUCCESS {
        return Err(format!(
            "Esys_Initialize failed: 0x{:X}\nDo you have admin rights?",
            rc_initialize
        ));
    }

    // Clean up any previous enrolment artifacts
    let rc_remove = unsafe { remove_nv_if_exists(context, pin_index_val, owner_pw) };
    if let Err(rc) = rc_remove {
        unsafe {
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "failed to remove existing PIN NV index 0x{:X}: 0x{:X}",
            pin_index_val, rc
        ));
    } else {
        let rc_remove_counter =
            unsafe { remove_nv_if_exists(context, counter_index_val, owner_pw) };
        if let Err(rc) = rc_remove_counter {
            unsafe {
                Esys_Finalize(&mut context);
            }
            return Err(format!(
                "failed to remove existing counter NV index 0x{:X}: 0x{:X}",
                counter_index_val, rc
            ));
        }
    }

    // Define the counter index and load it for policy computation
    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &auth);
    }
    let rc_define_counter = unsafe { define_counter_index(context, counter_index_val) };
    if let Err(rc) = rc_define_counter {
        unsafe {
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "failed to define counter NV index 0x{:X}: 0x{:X}",
            counter_index_val, rc
        ));
    }

    let mut counter_handle: ESYS_TR = ESYS_TR_NONE;

    let rc_load_counter = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            counter_index_val,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        )
    };

    if rc_load_counter != TPM2_RC_SUCCESS {
        if counter_handle != ESYS_TR_NONE {
            unsafe {
                Esys_TR_Close(context, &mut counter_handle);
            }
        }
        unsafe {
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "Esys_TR_FromTPMPublic failed to load counter NV index 0x{:X}: 0x{:X}",
            counter_index_val, rc_load_counter
        ));
    }

    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &auth);
        Esys_TR_SetAuth(context, counter_handle, &auth);
    }

    let rc_write_counter = unsafe { write_counter_value(context, counter_handle, 0) };
    if let Err(rc) = rc_write_counter {
        unsafe {
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "failed to initialize counter NV index 0x{:X}: 0x{:X}",
            counter_index_val, rc
        ));
    }

    let res_compute_pin_policy =
        unsafe { compute_pin_policy_digest(context, counter_handle, max_tries) };
    let pin_policy_digest = match res_compute_pin_policy {
        Ok(digest) => digest,
        Err(rc) => {
            unsafe {
                Esys_TR_Close(context, &mut counter_handle);
                Esys_Finalize(&mut context);
            }
            return Err(format!("failed to compute PIN policy digest: 0x{:X}", rc));
        }
    };

    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &auth);
    }

    let rc_define_pin =
        unsafe { define_pin_index(context, pin_index_val, pin_policy_digest.as_ptr(), pin) };

    if let Err(rc) = rc_define_pin {
        unsafe {
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "failed to define PIN NV index 0x{:X}: 0x{:X}",
            pin_index_val, rc
        ));
    }

    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &auth);
    }
    let rc_write_pin = unsafe { write_pin_placeholder(context, pin_index_val) };
    if let Err(rc) = rc_write_pin {
        unsafe {
            Esys_TR_Close(context, &mut counter_handle);
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "failed to write PIN NV index 0x{:X}: 0x{:X}",
            pin_index_val, rc
        ));
    }
    unsafe {
        Esys_TR_Close(context, &mut counter_handle);
        Esys_Finalize(&mut context);
    }

    Ok(())
}

fn unblock_user(username: &str, owner_pw: Option<&str>, base: u32) -> Result<(), String> {
    let uid = match get_uid(username) {
        Some(u) => u,
        None => return Err(format!("User '{}' not found", username)),
    };
    let counter_base = base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
    let counter_index = calculate_nv_index(counter_base, uid);
    unsafe { unblock_user_in_tpm(counter_index, owner_pw) }
}

unsafe fn unblock_user_in_tpm(
    counter_index_val: TPM2_HANDLE,
    owner_pw: Option<&str>,
) -> Result<(), String> {
    let mut auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0; 64],
    };
    if let Some(pw) = owner_pw {
        let pw_bytes = pw.as_bytes();
        if pw_bytes.len() > auth.buffer.len() {
            return Err("Owner password too long".to_string());
        }
        auth.size = pw_bytes.len() as u16;
        auth.buffer[..pw_bytes.len()].copy_from_slice(pw_bytes);
    }

    let mut context: *mut ESYS_CONTEXT = std::ptr::null_mut();

    let rc_initialize =
        unsafe { Esys_Initialize(&mut context, std::ptr::null_mut(), std::ptr::null_mut()) };

    if rc_initialize != TPM2_RC_SUCCESS {
        return Err(format!(
            "Esys_Initialize failed: 0x{:X}\nDo you have admin rights?",
            rc_initialize
        ));
    }

    // Load the counter NV index
    let mut counter_handle: ESYS_TR = ESYS_TR_NONE;
    let rc_load_counter = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            counter_index_val,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        )
    };

    if rc_load_counter != TPM2_RC_SUCCESS {
        unsafe {
            Esys_Finalize(&mut context);
        }
        return Err(format!(
            "Esys_TR_FromTPMPublic failed to load counter NV index 0x{:X} (user not enroled?): 0x{:X}",
            counter_index_val, rc_load_counter
        ));
    }

    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &auth);
    }
    let rc_reset = unsafe { reset_counter_value(context, counter_handle) };

    unsafe {
        Esys_TR_Close(context, &mut counter_handle);
        Esys_Finalize(&mut context);
    }

    return match rc_reset {
        Ok(()) => Ok(()),
        Err(rc) => Err(format!(
            "failed to reset counter NV index 0x{:X}: 0x{:X}",
            counter_index_val, rc
        )),
    };
}
