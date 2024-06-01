use alloc::vec;
use core::ffi::CStr;
use core::mem::size_of;
use core::ptr::null_mut;
use core::slice;

use windows_kernel::headers::_SYSTEM_INFORMATION_CLASS::SystemModuleInformation;
use windows_kernel::headers::{
    ZwQuerySystemInformation, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    STATUS_INFO_LENGTH_MISMATCH, SYSTEM_MODULE_INFORMATION,
};
use windows_kernel::{nt_success, Error};
use windows_kernel_sys::c_void;

pub(crate) fn scan_pattern(
    base: *mut u8,
    size: usize,
    pattern: &[u8],
    mask: &[u8],
) -> Option<*mut usize> {
    //TODO: https://dearxxj.github.io/post/4/
    let pattern_size = mask.len();

    if pattern_size == 0 || size < pattern_size {
        return None;
    }

    unsafe {
        for i in 0..=size - pattern_size {
            let mut is_match = true;
            for j in 0..pattern_size {
                if mask[j] != b'?' && *base.add(i + j) != pattern[j] {
                    is_match = false;
                    break;
                }
            }
            if is_match {
                return Some((base as usize + i) as *mut usize);
            }
        }
    }

    None
}

pub(crate) fn calculate_instruction_offset(scan_address: u64) -> u64 {
    // Read the 4-byte displacement value at pattern_address + 3
    let displacement = unsafe { *((scan_address as *mut u8).add(3) as *mut u32) };

    // Calculate the address of pHalpTimerQueryHostPerformanceCounter
    let address = (scan_address as usize + 7 + displacement as usize) as _;

    // Convert the offset from bytes to a signed 32-bit integer
    address
}

pub(crate) fn get_kernel_module_by_name(
    module_name: &str,
    module_start: &mut *mut c_void,
    module_size: &mut i32,
) -> Result<(), Error> {
    let mut size = 0_u32;
    let status = unsafe {
        ZwQuerySystemInformation(SystemModuleInformation, null_mut(), 0, &mut size as *mut _)
    };
    if status != STATUS_INFO_LENGTH_MISMATCH as i32 {
        return Err(Error::from_ntstatus(status));
    }

    let mut module_info = vec![0; size as usize];
    let status = unsafe {
        ZwQuerySystemInformation(
            SystemModuleInformation,
            module_info.as_mut_ptr() as _,
            size,
            &mut size as *mut _,
        )
    };

    if !nt_success!(status) {
        return Err(Error::from_ntstatus(status));
    }

    let list_header = module_info.as_ptr() as *const SYSTEM_MODULE_INFORMATION;
    let module_count = unsafe { (*list_header).ModulesCount };
    let modules =
        unsafe { slice::from_raw_parts((*list_header).Modules.as_ptr(), module_count as usize) };
    unsafe {
        for module in modules {
            let current_module_name =
                CStr::from_ptr(module.Name.as_ptr().byte_add(module.NameOffset as usize) as _) //
                    .to_str()
                    .unwrap_or("");
            if module_name == current_module_name {
                *module_start = module.ImageBaseAddress as _;
                *module_size = module.ImageSize as _;
                return Ok(());
            }
        }
    }

    drop(module_info);
    Err(Error::from_ntstatus(status))
}

pub(crate) fn get_image_section_by_name(
    section_name: &str,
    module_address: *mut c_void,
) -> Result<(*mut u8, u32), Error> {
    let dos_header: *const IMAGE_DOS_HEADER = module_address as *const IMAGE_DOS_HEADER;

    let nt_headers_offset = unsafe { (*dos_header).e_lfanew as isize };
    let nt_headers_ptr =
        (unsafe { module_address.offset(nt_headers_offset) }) as *const IMAGE_NT_HEADERS64;
    let nt_headers64: &IMAGE_NT_HEADERS64 = unsafe { &*nt_headers_ptr };

    let sections_start = (nt_headers64 as *const _ as usize + size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;
    let sections = unsafe {
        slice::from_raw_parts(
            sections_start,
            nt_headers64.FileHeader.NumberOfSections as usize,
        )
    };

    for section in sections {
        let name = core::str::from_utf8(&section.Name).expect("Section name is not valid UTF-8");
        if name.starts_with(section_name) {
            let section_base =
                (section.VirtualAddress as usize + module_address as usize) as *mut u8;
            let size = section.VirtualSize;
            return Ok((section_base, size));
        }
    }

    Err(Error::UNSUCCESSFUL)
}
