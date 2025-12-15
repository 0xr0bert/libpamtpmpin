use std::ffi::c_void;
use std::ops::{Deref, DerefMut};
use tss_esapi::{
    constants::tss::{
        TPM2_ALG_NULL, TPM2_ALG_SHA256, TPM2_EO_UNSIGNED_LT, TPM2_RC_BAD_AUTH, TPM2_RC_FMT1,
        TPM2_RC_HANDLE, TPM2_RC_POLICY, TPM2_RC_SUCCESS, TPM2_SE_TRIAL,
    },
    tss2_esys::{
        ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE, ESYS_TR_PASSWORD, ESYS_TR_RH_OWNER, Esys_Free,
        Esys_NV_DefineSpace, Esys_NV_Read, Esys_NV_Write, Esys_PolicyAuthValue,
        Esys_PolicyGetDigest, Esys_PolicyNV, Esys_StartAuthSession, Esys_TR_Close,
        Esys_TR_FromTPMPublic, Esys_TR_SetAuth, TPM2_HANDLE, TPM2B_AUTH, TPM2B_DIGEST,
        TPM2B_MAX_NV_BUFFER, TPM2B_NV_PUBLIC, TPM2B_OPERAND, TPMS_NV_PUBLIC, TPMT_SYM_DEF,
        TPMU_SYM_KEY_BITS, TPMU_SYM_MODE, TSS2_RC,
    },
};
use zeroize::Zeroize;

/// A safe wrapper around a pointer allocated by the TSS library.
///
/// This struct ensures that the memory is freed using `Esys_Free` when it goes out of scope.
pub struct EsysPtr<T> {
    ptr: *mut T,
}

impl<T> EsysPtr<T> {
    /// Creates a new `EsysPtr` from a raw pointer.
    ///
    /// # Safety
    ///
    /// The pointer must have been allocated by the TSS library (e.g., via `Esys_NV_Read` or `Esys_PolicyGetDigest`).
    /// The caller must ensure that the pointer is valid and that ownership is transferred to this `EsysPtr`.
    pub unsafe fn new(ptr: *mut T) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Returns the underlying raw pointer.
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    /// Returns the underlying mutable raw pointer.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }
}

impl<T> Drop for EsysPtr<T> {
    fn drop(&mut self) {
        unsafe {
            Esys_Free(self.ptr as *mut c_void);
        }
    }
}

impl<T> Deref for EsysPtr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> DerefMut for EsysPtr<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

/// Size of counter NV data in bytes (u64)
pub const COUNTER_NV_DATA_SIZE: u16 = 8;
pub const PIN_NV_DATA_SIZE: usize = 32;

pub const NV_INDEX_RANGE: u32 = 0x000FFFFF;
pub const COUNTER_SIZE: usize = 8;

pub const TPMA_NV_OWNERWRITE: u32 = 0x00000002;
pub const TPMA_NV_OWNERREAD: u32 = 0x00020000;
pub const TPMA_NV_AUTHWRITE: u32 = 0x00000004;
pub const TPMA_NV_AUTHREAD: u32 = 0x00040000;
pub const TPMA_NV_NO_DA: u32 = 0x02000000;
pub const TPMA_NV_POLICYREAD: u32 = 0x00080000;

pub const NV_PIN_INDEX_BASE: u32 = 0x01500000;
pub const NV_COUNTER_INDEX_BASE: u32 = 0x01600000;

pub const MAX_PIN_FAILURES: u64 = 5;

pub fn calculate_nv_index(base: u32, uid: u32) -> u32 {
    // FNV-1a 32-bit hash algorithm
    let mut hash: u32 = 2166136261u32;
    for &byte in &uid.to_ne_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    base + (hash % NV_INDEX_RANGE)
}

pub unsafe fn read_counter_value(
    context: *mut ESYS_CONTEXT,
    counter_handle: ESYS_TR,
) -> Result<u64, TSS2_RC> {
    let mut data: *mut TPM2B_MAX_NV_BUFFER = std::ptr::null_mut();
    let rc: TSS2_RC = unsafe {
        Esys_NV_Read(
            context,
            ESYS_TR_RH_OWNER,
            counter_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            COUNTER_NV_DATA_SIZE,
            0,
            &mut data,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        Err(rc)
    } else {
        let data_ptr = unsafe { EsysPtr::new(data) }.ok_or(TPM2_RC_SUCCESS)?;
        let buffer = data_ptr.buffer;
        let mut bytes = [0u8; COUNTER_NV_DATA_SIZE as usize];
        bytes.copy_from_slice(&buffer[..COUNTER_NV_DATA_SIZE as usize]);
        Ok(u64::from_be_bytes(bytes))
    }
}

pub unsafe fn write_counter_value(
    context: *mut ESYS_CONTEXT,
    counter_handle: ESYS_TR,
    value: u64,
) -> Result<(), TSS2_RC> {
    let mut data: TPM2B_MAX_NV_BUFFER = TPM2B_MAX_NV_BUFFER {
        size: COUNTER_NV_DATA_SIZE,
        buffer: [0u8; 2048],
    };
    let be_bytes = value.to_be_bytes();
    data.buffer[..COUNTER_NV_DATA_SIZE as usize].copy_from_slice(&be_bytes);
    let rc: TSS2_RC = unsafe {
        Esys_NV_Write(
            context,
            ESYS_TR_RH_OWNER,
            counter_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut data,
            0,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        Err(rc)
    } else {
        Ok(())
    }
}

pub unsafe fn reset_counter_value(
    context: *mut ESYS_CONTEXT,
    counter_handle: ESYS_TR,
) -> Result<(), TSS2_RC> {
    unsafe { write_counter_value(context, counter_handle, 0) }
}

pub fn increment_counter(
    context: *mut ESYS_CONTEXT,
    counter_handle: ESYS_TR,
    max_tries: u64,
) -> Result<(), TSS2_RC> {
    let mut current_value = unsafe { read_counter_value(context, counter_handle)? };
    if current_value < u64::MAX {
        current_value += 1;
    }
    if current_value > max_tries {
        current_value = max_tries;
    }
    unsafe { write_counter_value(context, counter_handle, current_value) }
}

pub fn is_bad_auth(rc: TSS2_RC) -> bool {
    (rc & TPM2_RC_FMT1 != 0) && (rc & 0x3F) == (TPM2_RC_BAD_AUTH & 0x3F)
}

pub fn is_policy_fail(rc: TSS2_RC) -> bool {
    // Failed counters have TPM2_RC_POLICY as the low byte
    (rc & 0xFFF) == TPM2_RC_POLICY
}

pub unsafe fn apply_policy_limit(
    context: *mut ESYS_CONTEXT,
    counter_handle: ESYS_TR,
    policy_session: ESYS_TR,
    max_tries: u64,
) -> Result<(), TSS2_RC> {
    let mut operand = TPM2B_OPERAND {
        size: COUNTER_NV_DATA_SIZE,
        buffer: [0u8; 64],
    };
    let be_bytes = max_tries.to_be_bytes();
    operand.buffer[..COUNTER_NV_DATA_SIZE as usize].copy_from_slice(&be_bytes);
    let rc: TSS2_RC = unsafe {
        tss_esapi::tss2_esys::Esys_PolicyNV(
            context,
            counter_handle,
            counter_handle,
            policy_session,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut operand,
            0,
            tss_esapi::constants::tss::TPM2_EO_UNSIGNED_LT,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        Err(rc)
    } else {
        Ok(())
    }
}

pub unsafe fn remove_nv_if_exists(
    context: *mut ESYS_CONTEXT,
    nv_index: TPM2_HANDLE,
    owner_password: Option<&str>,
) -> Result<(), TSS2_RC> {
    let mut nv_handle: ESYS_TR = ESYS_TR_NONE;
    let rc_lookup: TSS2_RC = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            nv_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut nv_handle,
        )
    };

    if rc_lookup != TPM2_RC_SUCCESS {
        if (rc_lookup & TPM2_RC_FMT1 != 0) && (rc_lookup & !0xF00) == TPM2_RC_HANDLE {
            // NV index does not exist, nothing to do
            return Ok(());
        } else {
            // Some other error occurred
            return Err(rc_lookup);
        }
    }

    // If found, undefine the NV space
    let mut auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0u8; 64],
    };
    if let Some(pw) = owner_password {
        auth.size = pw.len() as u16;
        if auth.size > 64 {
            auth.size = 64;
        }
        auth.buffer[..auth.size as usize].copy_from_slice(&pw.as_bytes()[..auth.size as usize]);
    }
    unsafe {
        Esys_TR_SetAuth(context, ESYS_TR_RH_OWNER, &mut auth);
    }
    let rc_undefine: TSS2_RC = unsafe {
        tss_esapi::tss2_esys::Esys_NV_UndefineSpace(
            context,
            ESYS_TR_RH_OWNER,
            nv_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
        )
    };
    if rc_undefine == TPM2_RC_SUCCESS {
        Ok(())
    } else {
        unsafe {
            Esys_TR_Close(context, &mut nv_handle);
        }
        Err(rc_undefine)
    }
}

pub unsafe fn define_counter_index(
    context: *mut ESYS_CONTEXT,
    index: TPM2_HANDLE,
) -> Result<(), TSS2_RC> {
    let mut public_info: TPM2B_NV_PUBLIC = TPM2B_NV_PUBLIC {
        size: 0,
        nvPublic: TPMS_NV_PUBLIC {
            nvIndex: index,
            nameAlg: TPM2_ALG_SHA256,
            attributes: TPMA_NV_OWNERWRITE
                | TPMA_NV_OWNERREAD
                | TPMA_NV_AUTHWRITE
                | TPMA_NV_AUTHREAD
                | TPMA_NV_NO_DA,
            authPolicy: tss_esapi::structures::Digest::default().into(),
            dataSize: COUNTER_NV_DATA_SIZE,
        },
    };
    let mut auth: TPM2B_AUTH = TPM2B_AUTH {
        size: 0,
        buffer: [0u8; 64],
    };
    let mut tmp_handle = ESYS_TR_NONE;
    let rc: TSS2_RC = unsafe {
        Esys_NV_DefineSpace(
            context,
            ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut auth,
            &mut public_info,
            &mut tmp_handle,
        )
    };
    if rc == TPM2_RC_SUCCESS && tmp_handle != ESYS_TR_NONE {
        unsafe {
            Esys_TR_Close(context, &mut tmp_handle);
        }
        Ok(())
    } else {
        Err(rc)
    }
}

pub unsafe fn define_pin_index(
    context: *mut ESYS_CONTEXT,
    index: TPM2_HANDLE,
    policy_digest: *const TPM2B_DIGEST,
    mut pin: Box<str>,
) -> Result<(), TSS2_RC> {
    let mut public_info: TPM2B_NV_PUBLIC = TPM2B_NV_PUBLIC {
        size: 0,
        nvPublic: TPMS_NV_PUBLIC {
            nvIndex: index,
            nameAlg: TPM2_ALG_SHA256,
            attributes: TPMA_NV_OWNERWRITE | TPMA_NV_AUTHREAD | TPMA_NV_POLICYREAD | TPMA_NV_NO_DA,
            authPolicy: unsafe { (*policy_digest).clone() },
            dataSize: PIN_NV_DATA_SIZE as u16,
        },
    };
    let mut auth: TPM2B_AUTH = TPM2B_AUTH {
        size: pin.len() as u16,
        buffer: [0u8; 64],
    };
    auth.buffer[..pin.len()].copy_from_slice(pin.as_bytes());
    let mut tmp_handle = ESYS_TR_NONE;
    let rc: TSS2_RC = unsafe {
        Esys_NV_DefineSpace(
            context,
            ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut auth,
            &mut public_info,
            &mut tmp_handle,
        )
    };
    pin.zeroize();
    if rc == TPM2_RC_SUCCESS && tmp_handle != ESYS_TR_NONE {
        unsafe {
            Esys_TR_Close(context, &mut tmp_handle);
        }
        Ok(())
    } else {
        Err(rc)
    }
}

pub unsafe fn write_pin_placeholder(
    context: *mut ESYS_CONTEXT,
    pin_index: TPM2_HANDLE,
) -> Result<(), TSS2_RC> {
    let mut pin_handle: ESYS_TR = ESYS_TR_NONE;
    let rc_lookup: TSS2_RC = unsafe {
        Esys_TR_FromTPMPublic(
            context,
            pin_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut pin_handle,
        )
    };
    if rc_lookup != TPM2_RC_SUCCESS {
        return Err(rc_lookup);
    }
    let mut data: TPM2B_MAX_NV_BUFFER = TPM2B_MAX_NV_BUFFER {
        size: PIN_NV_DATA_SIZE as u16,
        buffer: [0u8; 2048],
    };

    let rc_write: TSS2_RC = unsafe {
        Esys_NV_Write(
            context,
            ESYS_TR_RH_OWNER,
            pin_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut data,
            0,
        )
    };
    unsafe {
        Esys_TR_Close(context, &mut pin_handle);
    }
    if rc_write != TPM2_RC_SUCCESS {
        Err(rc_write)
    } else {
        Ok(())
    }
}

pub unsafe fn compute_pin_policy_digest(
    context: *mut ESYS_CONTEXT,
    counter_handle: ESYS_TR,
    max_tries: u64,
) -> Result<EsysPtr<TPM2B_DIGEST>, TSS2_RC> {
    let symmetric: TPMT_SYM_DEF = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_NULL,
        keyBits: TPMU_SYM_KEY_BITS { sym: 0 },
        mode: TPMU_SYM_MODE { sym: TPM2_ALG_NULL },
    };
    let mut trial_session = ESYS_TR_NONE;
    let mut rc: TSS2_RC = unsafe {
        Esys_StartAuthSession(
            context,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            std::ptr::null(),
            TPM2_SE_TRIAL,
            &symmetric,
            TPM2_ALG_SHA256,
            &mut trial_session,
        )
    };
    if rc != TPM2_RC_SUCCESS {
        return Err(rc);
    }

    let mut operand = TPM2B_OPERAND {
        size: COUNTER_NV_DATA_SIZE,
        buffer: [0u8; 64],
    };
    let be_bytes = max_tries.to_be_bytes();
    operand.buffer[..COUNTER_NV_DATA_SIZE as usize].copy_from_slice(&be_bytes);

    // Require the counter value to remain below MAX_PIN_FAILURES
    rc = unsafe {
        Esys_PolicyNV(
            context,
            counter_handle,
            counter_handle,
            trial_session,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &operand,
            0,
            TPM2_EO_UNSIGNED_LT,
        )
    };

    if rc == TPM2_RC_SUCCESS {
        // Require knowledege of the PIN auth value for future access
        rc = unsafe {
            Esys_PolicyAuthValue(
                context,
                trial_session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
            )
        };
    };
    let mut policy_digest: *mut TPM2B_DIGEST = std::ptr::null_mut();

    if rc == TPM2_RC_SUCCESS {
        // Capture the finalized digest that encodes both requirements
        rc = unsafe {
            Esys_PolicyGetDigest(
                context,
                trial_session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &mut policy_digest,
            )
        };
    }

    if rc != TPM2_RC_SUCCESS || policy_digest.is_null() {
        Err(rc)
    } else {
        Ok(unsafe { EsysPtr::new(policy_digest).unwrap() })
    }
}
