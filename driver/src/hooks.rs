use core::cell::SyncUnsafeCell;

use windows_kernel::sync::dashmap::DashMap;
use windows_kernel::sync::once_lock::OnceLock;
use windows_kernel_sys::base::{
    ACCESS_MASK, HANDLE, IO_STATUS_BLOCK, LARGE_INTEGER, NTSTATUS, OBJECT_ATTRIBUTES, PVOID,
};
use windows_kernel_sys::ntoskrnl::NtCreateFile;

static HOOK_MAP: OnceLock<SyncUnsafeCell<Option<DashMap<usize, usize>>>> = OnceLock::new();

#[inline]
pub fn init_process_map() {
    HOOK_MAP.get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())));
}

#[inline]
fn get_process_map() -> &'static DashMap<usize, usize> {
    unsafe {
        HOOK_MAP
            .get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())))
            .get()
            .as_ref()
            .unwrap_unchecked()
            .as_ref()
            .unwrap_unchecked()
    }
}

pub fn deinit_process_map() {
    unsafe {
        *HOOK_MAP.get().unwrap_unchecked().get() = None;
    }
}

pub(crate) unsafe extern "system" fn nt_create_file_hook(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *mut LARGE_INTEGER,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: PVOID,
    ea_length: u32,
) -> NTSTATUS {
    //println!("nt_create_file_hook");

    NtCreateFile(
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        allocation_size,
        file_attributes,
        share_access,
        create_disposition,
        create_options,
        ea_buffer,
        ea_length,
    )
}
