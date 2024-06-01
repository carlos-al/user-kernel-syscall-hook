use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::AtomicPtr;

use windows_kernel::headers::{
    ZwTraceControl, CKCL_TRACE_PROPERTIES, ETWTRACECONTROLCODE, EVENT_TRACE_PROPERTIES,
};
use windows_kernel::Error;
use windows_kernel_sys::base::{
    NTSTATUS, PAGE_SIZE, STATUS_UNSUCCESSFUL, ULONG, UNICODE_STRING, _GUID,
};

use macros::unicode_string;

use crate::{get_image_section_by_name, get_kernel_module_by_name, scan_pattern};

unicode_string!(CKCL = "Circular Kernel Context Logger");
pub(crate) static CIRCULAR_KERNEL_CONTEXT_LOGGER: AtomicPtr<usize> = AtomicPtr::new(null_mut());

pub(crate) fn get_ckcl_context() -> Result<*mut usize, Error> {
    let mut ntoskrnl_base = null_mut();
    let mut ntoskrnl_size = 0;

    get_kernel_module_by_name("ntoskrnl.exe", &mut ntoskrnl_base, &mut ntoskrnl_size)?;

    let (ntoskrnl_data, ntoskrnl_data_size) = get_image_section_by_name(".data", ntoskrnl_base)?;

    if let Some(mut etwp_debugger_data) = scan_pattern(
        ntoskrnl_data,
        ntoskrnl_data_size as usize,
        &[0x2C_u8, 0x08, 0x04, 0x38, 0x0C],
        "xxxxx".as_bytes(),
    ) {
        unsafe {
            etwp_debugger_data = etwp_debugger_data.byte_offset(-2);
            etwp_debugger_data = *(etwp_debugger_data.byte_add(0x10) as *mut *mut usize);
        }

        let cirular_kernel_context_logger = unsafe { *etwp_debugger_data.add(2) } as *mut usize;
        if cirular_kernel_context_logger as usize <= 1 {
            Err(Error::UNSUCCESSFUL)
        } else {
            Ok(cirular_kernel_context_logger)
        }
    } else {
        Err(Error::UNSUCCESSFUL)
    }
}

pub(crate) fn modify_ckcl(function_code: ETWTRACECONTROLCODE, enable_flags: u32) -> NTSTATUS {
    if let Ok(mut properties) = CKCLTracePropertiesWrapper::new() {
        properties.Wnode.BufferSize = PAGE_SIZE;
        properties.Wnode.Guid = _GUID {
            Data1: 0x54DEA73A,
            Data2: 0xED1F,
            Data3: 0x42A4,
            Data4: [0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74],
        };
        properties.Wnode.ClientContext = 0x3;
        properties.Wnode.Flags = 0x20000;
        properties.BufferSize = size_of::<u32>() as ULONG;
        properties.MinimumBuffers = 2;
        properties.MaximumBuffers = 2;
        properties.LogFileMode = 0x400;
        properties.EnableFlags = enable_flags;
        *properties.provider_name_mut() = unsafe { CKCL.clone() };

        let mut ret_size = 0;

        unsafe {
            ZwTraceControl(
                function_code as u32,
                properties.ptr.as_ptr() as _,
                PAGE_SIZE,
                properties.ptr.as_ptr() as _,
                PAGE_SIZE,
                &mut ret_size,
            )
        }
    } else {
        STATUS_UNSUCCESSFUL
    }
}

struct CKCLTracePropertiesWrapper {
    ptr: NonNull<CKCL_TRACE_PROPERTIES>,
    layout: Layout,
}

impl CKCLTracePropertiesWrapper {
    fn new() -> Result<Self, Error> {
        unsafe {
            let layout = Layout::from_size_align_unchecked(PAGE_SIZE as usize, PAGE_SIZE as usize);
            let ptr = alloc_zeroed(layout) as *mut CKCL_TRACE_PROPERTIES;

            if ptr.is_null() {
                Err(Error::NO_MEMORY)
            } else {
                let non_null_ptr = NonNull::new_unchecked(ptr);

                Ok(CKCLTracePropertiesWrapper {
                    ptr: non_null_ptr,
                    layout,
                })
            }
        }
    }
    pub fn unknown(&self) -> &[u64; 3] {
        unsafe { &(*self.ptr.as_ptr()).Unknown }
    }

    pub fn unknown_mut(&mut self) -> &mut [u64; 3] {
        unsafe { &mut (*self.ptr.as_ptr()).Unknown }
    }

    // Immutable accessor for the `ProviderName`
    pub fn provider_name(&self) -> &UNICODE_STRING {
        unsafe { &(*self.ptr.as_ptr()).ProviderName }
    }

    // Mutable accessor for the `ProviderName`
    pub fn provider_name_mut(&mut self) -> &mut UNICODE_STRING {
        unsafe { &mut (*self.ptr.as_ptr()).ProviderName }
    }
}

impl Drop for CKCLTracePropertiesWrapper {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr() as *mut u8, self.layout);
        }
    }
}

impl Deref for CKCLTracePropertiesWrapper {
    type Target = EVENT_TRACE_PROPERTIES;

    fn deref(&self) -> &Self::Target {
        // Safety: We know this is safe because we ensure `ptr` is always valid while the wrapper exists.
        unsafe { &(*self.ptr.as_ptr()).Base }
    }
}

impl DerefMut for CKCLTracePropertiesWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: Similar to `deref`, we know this mutation is safe under the same conditions.
        unsafe { &mut (*self.ptr.as_ptr()).Base }
    }
}
