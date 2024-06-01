use core::alloc::{GlobalAlloc, Layout};
use core::cell::OnceCell;
use core::ffi::c_ulong;
use core::ptr::null_mut;

use winapi::shared::ntdef::{HANDLE, ULONG};
use winapi::um::winnt::{HEAP_GROWABLE, PVOID};

unsafe impl Sync for UserlandAllocator {}
pub struct UserlandAllocator {
    handle: OnceCell<HANDLE>,
}

impl UserlandAllocator {
    pub const fn new() -> Self {
        Self {
            handle: OnceCell::new(),
        }
    }
}

unsafe impl GlobalAlloc for UserlandAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let handle = self.handle.get_or_init(|| {
            RtlCreateHeap(
                //
                HEAP_GROWABLE,
                null_mut(),
                0,
                0,
                null_mut() as _,
                null_mut() as _,
            )
        });

        let ptr = RtlAllocateHeap(*handle, 0, layout.size());

        if ptr.is_null() {
            panic!("[userland-alloc] failed to allocate pool.");
        }

        ptr as _
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let handle = self.handle.get_or_init(|| {
            RtlCreateHeap(
                HEAP_GROWABLE,
                null_mut(),
                0,
                0,
                null_mut() as _,
                null_mut() as _,
            )
        });
        RtlFreeHeap(*handle, 0, null_mut());
    }
}

impl UserlandAllocator {
    pub(crate) fn deinit(&self) {
        let handle = self.handle.get_or_init(|| unsafe {
            RtlCreateHeap(
                HEAP_GROWABLE,
                null_mut(),
                0,
                0,
                null_mut() as _,
                null_mut() as _,
            )
        });
        unsafe {
            RtlDestroyHeap(*handle);
        }
    }
}

extern "system" {
    pub fn RtlCreateHeap(
        Flags: ULONG,
        HeapBase: PVOID,
        ReserveSize: usize,
        CommitSize: usize,
        Lock: PVOID,
        Parameters: PVOID,
    ) -> HANDLE;
    pub fn RtlAllocateHeap(HeapHandle: HANDLE, Flags: c_ulong, Size: usize) -> PVOID;

    pub fn RtlDestroyHeap(HeapHandle: HANDLE) -> HANDLE;
    pub fn RtlFreeHeap(HeapHandle: HANDLE, Flags: c_ulong, HeapBase: PVOID) -> c_ulong;
}
