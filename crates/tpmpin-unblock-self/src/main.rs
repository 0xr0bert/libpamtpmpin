use clap::{Parser, command};
use nix::{
    libc::{clearenv, geteuid, getuid},
    unistd::{SysconfVar, sysconf},
};
use pamtpmpin_common::{
    NV_COUNTER_INDEX_BASE, NV_PIN_INDEX_BASE, calculate_nv_index, reset_counter_value,
};
use tss_esapi::constants::tss::TPM2_RC_SUCCESS;
use tss_esapi_sys::{
    ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER, Esys_Finalize, Esys_Initialize,
    Esys_TR_Close, Esys_TR_FromTPMPublic, Esys_TR_SetAuth, TPM2B_AUTH,
};

fn main() {
    if unsafe { geteuid() } != 0 {
        eprintln!("tpmpin-unblock-self: must be run with euid=0");
        std::process::exit(2);
    }

    // Harden the execution environment (setuid context)
    unsafe {
        clearenv();
    }

    if std::env::var_os("TSS2_LOG") == None {
        // Disable logging by default
        unsafe {
            std::env::set_var("TSS2_LOG", "all+NONE");
        }
    }
    close_extra_fds();

    let args = Cli::parse();
    let uid = match args.uid {
        Some(u) => u,
        None => (unsafe { getuid() } as u32),
    };
    let real_uid = unsafe { getuid() } as u32;
    if real_uid != 0 && uid != real_uid {
        eprintln!("--uid may only be specified when run as root");
        std::process::exit(2);
    }
    let counter_base = args.base + (NV_COUNTER_INDEX_BASE - NV_PIN_INDEX_BASE);
    let counter_index = calculate_nv_index(counter_base, uid);

    let mut esys_context: *mut ESYS_CONTEXT = std::ptr::null_mut();
    let rc_init = unsafe {
        Esys_Initialize(
            &mut esys_context,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc_init != TPM2_RC_SUCCESS {
        eprintln!(
            "tpmpin-unblock-self: Esys_Initialize failed: 0x{:X}",
            rc_init
        );
        std::process::exit(1);
    }

    let mut counter_handle: ESYS_TR = ESYS_TR_NONE;

    let rc_load_counter = unsafe {
        Esys_TR_FromTPMPublic(
            esys_context,
            counter_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut counter_handle,
        )
    };

    if rc_load_counter != TPM2_RC_SUCCESS {
        eprintln!(
            "tpmpin-unblock-self: Esys_TR_FromTPMPublic failed to load counter NV index 0x{:X} (user not enroled?): 0x{:X}",
            counter_index, rc_load_counter
        );
        unsafe {
            Esys_Finalize(&mut esys_context);
        }
        std::process::exit(1);
    }

    let auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0; 64],
    };

    unsafe {
        Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &auth);
    }
    let rc_reset = unsafe { reset_counter_value(esys_context, counter_handle) };
    if let Err(rc) = rc_reset {
        eprintln!(
            "tpmpin-unblock-self: failed to reset counter NV index 0x{:X}: 0x{:X}",
            counter_index, rc
        );
    }

    unsafe {
        Esys_TR_Close(esys_context, &mut counter_handle);
        Esys_Finalize(&mut esys_context);
    }
    if let Err(_) = rc_reset {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    uid: Option<u32>,
    #[arg(long, default_value_t = NV_PIN_INDEX_BASE)]
    base: u32,
}

fn close_extra_fds() {
    let max_fd = sysconf(SysconfVar::OPEN_MAX).ok().flatten().unwrap_or(1024);
    for fd in 3..max_fd as i32 {
        let _ = nix::unistd::close(fd);
    }
}
