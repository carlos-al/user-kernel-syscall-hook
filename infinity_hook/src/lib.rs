#![no_std]
#![feature(optimize_attribute)]

extern crate alloc;

use core::mem::transmute;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use windows_kernel::headers::EventTraceFlags;
use windows_kernel::headers::ETWTRACECONTROLCODE::{
    EtwStartLoggerCode, EtwStopLoggerCode, EtwUpdateLoggerCode,
};
use windows_kernel::{nt_success, Error};
use windows_kernel_sys::base::{LONG, ULONGLONG};

use crate::ckcl::{get_ckcl_context, modify_ckcl, CIRCULAR_KERNEL_CONTEXT_LOGGER};
use crate::scan::{
    calculate_instruction_offset, get_image_section_by_name, get_kernel_module_by_name,
    scan_pattern,
};
use crate::stack::stack_trace_64;

mod ckcl;
mod scan;
mod stack;

// Syscall function to hook
static TARGET: AtomicPtr<usize> = AtomicPtr::new(null_mut());

// Hook for the syscall above
static HOOK_TARGET: AtomicPtr<usize> = AtomicPtr::new(null_mut());

// Original timer function we hook to allow the syscall hooking to happen.
static ORIGINAL_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER: AtomicPtr<usize> =
    AtomicPtr::new(null_mut());
static OFFSET_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER: AtomicPtr<usize> =
    AtomicPtr::new(null_mut());

// Keep the original value of wmiGetCpuClock to unhook later
static ORIGINAL_CLOCK_TYPE: AtomicU64 = AtomicU64::new(5); //invalid value, don't set

#[allow(non_upper_case_globals)]
const wmiGetCpuClockOffset: usize = 0x018;

type HalTimerQueryHostPerformanceCounter = Option<fn(arg1: *mut ULONGLONG) -> LONG>;

pub fn hook_syscall(hook_fn: *const usize, system_fn: *const usize) -> Result<(), Error> {
    TARGET.store(system_fn as _, Ordering::Release);
    HOOK_TARGET.store(hook_fn as _, Ordering::Release);

    modify_ckcl(
        EtwStartLoggerCode,
        EventTraceFlags::EVENT_TRACE_FLAG_SYSTEMCALL.bits(),
    );

    CIRCULAR_KERNEL_CONTEXT_LOGGER.store(get_ckcl_context()?, Ordering::Release);
    if CIRCULAR_KERNEL_CONTEXT_LOGGER
        .load(Ordering::Acquire)
        .is_null()
    {
        return Err(Error::UNSUCCESSFUL);
    }

    // Start up CKCL if not already running
    if !nt_success!(modify_ckcl(
        EtwUpdateLoggerCode,
        EventTraceFlags::EVENT_TRACE_FLAG_SYSTEMCALL.bits()
    )) {
        if !nt_success!(modify_ckcl(
            EtwStartLoggerCode,
            EventTraceFlags::EVENT_TRACE_FLAG_SYSTEMCALL.bits()
        )) {
            return Err(Error::UNSUCCESSFUL);
        } else if !nt_success!(modify_ckcl(
            EtwUpdateLoggerCode,
            EventTraceFlags::EVENT_TRACE_FLAG_SYSTEMCALL.bits()
        )) {
            return Err(Error::UNSUCCESSFUL);
        }
    }

    // Locate ntoskrnl.exe's .text section address in-memory
    let mut ntoskrnl_base = null_mut();
    let mut ntoskrnl_size = 0;
    get_kernel_module_by_name("ntoskrnl.exe", &mut ntoskrnl_base, &mut ntoskrnl_size)?;

    let (ntoskrnl_text, ntoskrnl_text_size) = get_image_section_by_name(".text", ntoskrnl_base)?;

    // pHalpTimerQueryHostPerformanceCounter is referenced by `mov qword ptr [rip+0x888a7a], rax` somewhere in (my version of) ntoskrnl.exe
    // we scan the .text section to locate it, then translate to the actual address this pointer is located on
    // this depends on where the mov instruction is placed in memory
    if let Some(hal_private_dispatch_table) = scan_pattern(
        ntoskrnl_text,
        ntoskrnl_text_size as usize,
        //&[0x48, 0x89, 0x05, 0x4a, 0x95, 0x88, 0x00],
        &[0x48, 0x89, 0x05, 0x7a, 0x8a, 0x88, 0x00],
        "xxxxxxx".as_bytes(),
    ) {
        let hal_timer_query_host_performance_counter =
            calculate_instruction_offset(hal_private_dispatch_table as _) as *mut *mut usize;

        OFFSET_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER.store(
            hal_timer_query_host_performance_counter as _,
            Ordering::Release,
        );

        // store tje original perfcounter for later use / unhooking
        let original_fn = unsafe { *hal_timer_query_host_performance_counter };
        ORIGINAL_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER.store(original_fn, Ordering::Release);

        unsafe {
            *hal_timer_query_host_performance_counter =
                hooked_hal_timer_query_host_performance_counter as _;
        }

        // Change CKCL logging type so that
        unsafe {
            ORIGINAL_CLOCK_TYPE.store(
                *(CIRCULAR_KERNEL_CONTEXT_LOGGER
                    .load(Ordering::Acquire)
                    .byte_add(wmiGetCpuClockOffset) as *mut u64),
                Ordering::Release,
            );

            *(CIRCULAR_KERNEL_CONTEXT_LOGGER
                .load(Ordering::Acquire)
                .byte_add(wmiGetCpuClockOffset) as *mut u64) = 2
        }

        Ok(())
    } else {
        Err(Error::UNSUCCESSFUL)
    }
}

pub fn unhook_syscall() -> bool {
    if !nt_success!(
        (modify_ckcl(
            EtwStopLoggerCode,
            EventTraceFlags::EVENT_TRACE_FLAG_SYSTEMCALL.bits()
        ))
    ) {
        return false;
    }
    unsafe {
        if !OFFSET_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER
            .load(Ordering::Acquire)
            .is_null()
            && !ORIGINAL_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER
                .load(Ordering::Acquire)
                .is_null()
        {
            let original_clock = ORIGINAL_CLOCK_TYPE.load(Ordering::Acquire);
            if original_clock != 5 {
                *(CIRCULAR_KERNEL_CONTEXT_LOGGER
                    .load(Ordering::Acquire)
                    .byte_add(wmiGetCpuClockOffset) as *mut u64) = original_clock;
            }
            *(OFFSET_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER.load(Ordering::Acquire)
                as *mut *const usize) =
                ORIGINAL_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER.load(Ordering::Acquire);

            return true;
        }
    }

    false
}

#[optimize(speed)]
unsafe extern "C" fn hooked_hal_timer_query_host_performance_counter(arg1: *mut ULONGLONG) -> LONG {
    let res = transmute::<*mut usize, HalTimerQueryHostPerformanceCounter>(
        ORIGINAL_HAL_TIMER_QUERY_HOST_PERFORMANCE_COUNTER.load(Ordering::Acquire),
    )
    .unwrap_unchecked()(arg1);

    let hook_id = *((arg1 as *const u32).offset(10));
    if hook_id == 0x00501802 {
        let backtrace = stack_trace_64();
        if backtrace.len() <= 3 {
            return res;
        }
        let frame = &backtrace[3];
        let next_frame = &backtrace[4];

        for j in 0..((next_frame.rsp as u64 - frame.rsp as u64) / 8) {
            if *((frame.rsp as *mut u32).offset((j + 2) as isize)) == 0x00501802
                && *((frame.rsp as *mut u32).offset(j as isize)) & 0xFFFF == 0xf33
            {
                let target = *(next_frame.rsp.offset(8) as *mut *mut usize);
                //println!("is this your card? 0x{:x}", target as usize);
                //KeBugCheck(0xdeadbeef);
                if target == TARGET.load(Ordering::Acquire) {
                    *(next_frame.rsp.offset(8) as *mut *mut usize) =
                        HOOK_TARGET.load(Ordering::Acquire);
                }
                break;
            }
        }
    }

    res
}
