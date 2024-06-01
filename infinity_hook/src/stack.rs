use core::ptr::null_mut;

use smallvec::SmallVec;
use windows_kernel::headers::{
    RtlLookupFunctionEntry, RtlVirtualUnwind, KNONVOLATILE_CONTEXT_POINTERS, UNWIND_HISTORY_TABLE,
};
use windows_kernel_sys::base::{CONTEXT, PVOID, ULONG64};
use windows_kernel_sys::ntoskrnl::RtlCaptureContext;

pub(crate) struct StackFrame {
    pub(crate) rbp: *mut usize,
    pub(crate) rsp: *mut usize,
}

pub(crate) fn stack_trace_64() -> SmallVec<[StackFrame; 10]> {
    let mut context = unsafe { core::mem::zeroed::<CONTEXT>() };
    let mut unwind_history_table = unsafe { core::mem::zeroed::<UNWIND_HISTORY_TABLE>() };
    let mut image_base = 0u64;
    let mut handler_data: PVOID = null_mut();
    let mut establisher_frame = 0u64;
    let nv_context = unsafe { core::mem::zeroed::<KNONVOLATILE_CONTEXT_POINTERS>() };

    unsafe {
        RtlCaptureContext(&mut context);
    }

    let mut frame = 0u64;
    let mut res = SmallVec::new();

    unsafe {
        loop {
            let runtime_function =
                RtlLookupFunctionEntry(context.Rip, &mut image_base, &mut unwind_history_table);

            if runtime_function.is_null() {
                if context.Rsp < 0x7FFF_FFFF_FFFFu64 {
                    break;
                }
                context.Rip = *(context.Rsp as *const ULONG64);
                context.Rsp += 8;
            } else {
                RtlVirtualUnwind(
                    0,
                    image_base,
                    context.Rip,
                    runtime_function,
                    &mut context,
                    &mut handler_data,
                    &mut establisher_frame,
                    null_mut(),
                );
            }

            let reg_names = [
                "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9", "R10", "R11",
                "R12", "R13", "R14", "R15",
            ];

            // println!("FRAME {:02}: Rip={:x} Rsp={:x} Rbp={:x}", frame, context.Rip, context.Rsp, context.Rbp);
            for i in 0..16 {
                if let Some(reg) = nv_context.Anonymous2.IntegerContext[i].as_ref() {
                    /* println!(
                        " -> Saved register '{}' on stack at {:x} (=> {:x})",
                        reg_names[i], reg, *reg
                    );*/
                }
            }
            res.push(StackFrame {
                rbp: context.Rbp as _,
                rsp: context.Rsp as _,
            });
            if context.Rip == 0 {
                break;
            }
            frame += 1;
        }
    }
    res
}
