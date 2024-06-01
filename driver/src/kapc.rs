use alloc::boxed::Box;
use core::intrinsics::transmute;
use core::ptr::null_mut;

use windows_kernel::headers::_KAPC_ENVIRONMENT::OriginalApcEnvironment;
use windows_kernel::headers::{
    KeInitializeApc, KeInsertQueueApc, KeTestAlertThread, PKKERNEL_ROUTINE, PKNORMAL_ROUTINE,
    PKRUNDOWN_ROUTINE,
};
use windows_kernel::mdl::AccessMode::KernelMode;
use windows_kernel::Error;
use windows_kernel_sys::base::_MODE::UserMode;
use windows_kernel_sys::base::{
    _KAPC_STATE__bindgen_ty_1, _KAPC_STATE__bindgen_ty_2, BOOLEAN, HANDLE, KAPC, KAPC_STATE,
    KPROCESSOR_MODE, LIST_ENTRY, PKAPC, PKTHREAD, PVOID, TRUE, UCHAR,
};
use windows_kernel_sys::c_void;
use windows_kernel_sys::ntoskrnl::{
    _ObDereferenceObject as ObDereferenceObject, _ObReferenceObject as ObReferenceObject,
    _PsGetCurrentThread as PsGetCurrentThread,
};

use crate::injector::UserApcArgs;
use crate::section::{DllStats, SectionType};
use crate::__MOD;

#[allow(non_snake_case)]
pub fn new_KAPC_STATE() -> KAPC_STATE {
    KAPC_STATE {
        ApcListHead: [LIST_ENTRY {
            Flink: null_mut(),
            Blink: null_mut(),
        }; 2],
        Process: null_mut(),
        __bindgen_anon_1: _KAPC_STATE__bindgen_ty_1 { InProgressFlags: 0 },
        KernelApcPending: 0,
        __bindgen_anon_2: _KAPC_STATE__bindgen_ty_2 {
            UserApcPendingAll: 0,
        },
    }
}

#[no_mangle]
#[inline(never)]
#[optimize(speed)]
pub unsafe extern "system" fn apc_kernel_routine(
    apc: *mut KAPC,
    normal_routine: *mut PKNORMAL_ROUTINE,
    normal_context: *mut PVOID,
    system_argument1: *mut PVOID,
    system_argument2: *mut PVOID,
) {
    match apc_kernel_routine_helper(
        apc,
        normal_routine,
        normal_context,
        system_argument1,
        system_argument2,
    ) {
        true => ObDereferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _),
        false => (),
    }
}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
fn apc_kernel_routine_helper(
    apc: *mut KAPC,
    normal_routine: *mut PKNORMAL_ROUTINE,
    normal_context: *mut PVOID,
    system_argument1: *mut PVOID,
    system_argument2: *mut PVOID,
) -> bool {
    let mut dereference_driver = true;

    if !apc.is_null() {
        unsafe {
            if (*apc).ApcMode == KernelMode as _ {
                // Still pending to get to UserMode execution
                dereference_driver = false;
            } else if (*apc).ApcMode == UserMode as _ {
                let kapc = Box::from_raw(apc);
                drop(kapc);
            } else {
                panic!()
            }
        }
    }

    dereference_driver
}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
pub unsafe extern "system" fn apc_normal_routine(
    normal_context: *mut c_void,
    system_argument1: PVOID,
    system_argument2: PVOID,
) {
    match thunkless_apc_normal_routine_helper(normal_context, system_argument1, system_argument2) {
        true => ObDereferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _),
        false => (),
    }
}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn apc_normal_routine_helper(
    mut normal_context: *mut c_void,
    system_argument1: PVOID,
    system_argument2: PVOID,
) -> bool {
    let dll_stats = system_argument1 as *const DllStats;
    let pid = system_argument2 as HANDLE;
    let apc = normal_context as *mut KAPC;

    if !apc.is_null() && !dll_stats.is_null() && (*dll_stats).is_valid() {
        ObDereferenceObject((*dll_stats).section);
        let (shellcode, user_apc_args) =
            crate::injector::map_shellcode_into_process(pid, dll_stats).unwrap();

        if cfg!(target_arch = "x86_64") && (*dll_stats).section_type == SectionType::WoW {
            // PsWrapApcWow64Thread(&mut normal_context as _, &shellcode as *const _ as _);
        }

        call_user_apc(
            apc,
            PsGetCurrentThread(),
            Some(apc_kernel_routine),
            Some(apc_rundown_routine),
            Some(transmute(shellcode)),
            user_apc_args as _,
        );
    }

    true
}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn thunkless_apc_normal_routine_helper(
    mut normal_context: *mut c_void,
    system_argument1: PVOID,
    system_argument2: PVOID,
) -> bool {
    let dll_stats = system_argument1 as *const DllStats;
    let pid = system_argument2 as HANDLE;
    let apc = normal_context as *mut KAPC;

    if !apc.is_null() && !dll_stats.is_null() && (*dll_stats).is_valid() {
        ObDereferenceObject((*dll_stats).section);

        let (shellcode, user_apc_args) =
            crate::injector::map_shellcode_into_process_thunkless(pid).unwrap();

        if cfg!(target_arch = "x86_64") && (*dll_stats).section_type == SectionType::WoW {
            //PsWrapApcWow64Thread(&mut normal_context as _, &shellcode as *const _ as _);
        }

        call_user_apc_thunkless(
            apc,
            PsGetCurrentThread(),
            Some(apc_kernel_routine),
            Some(apc_rundown_routine),
            Some(transmute(shellcode)),
            user_apc_args as _,
        );
    }

    true
}

fn call_user_apc(
    kapc: PKAPC,
    target_thread: PKTHREAD,
    kernel_routine: PKKERNEL_ROUTINE,
    rundown_routine: PKRUNDOWN_ROUTINE,
    normal_routine: PKNORMAL_ROUTINE,
    params: *const c_void,
) -> Result<(), Error> {
    unsafe {
        KeInitializeApc(
            kapc,
            target_thread,
            OriginalApcEnvironment,
            kernel_routine,
            rundown_routine,
            normal_routine,
            UserMode as KPROCESSOR_MODE,
            params as _,
        );
        ObReferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _)
    }

    unsafe {
        let res = KeInsertQueueApc(kapc, null_mut(), null_mut(), 0);
        if 0 == res {
            ObDereferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _);
            return Err(Error::UNSUCCESSFUL);
        }

        KeTestAlertThread(UserMode as KPROCESSOR_MODE);
    }

    Ok(())
}

fn call_user_apc_thunkless(
    kapc: PKAPC,
    target_thread: PKTHREAD,
    kernel_routine: PKKERNEL_ROUTINE,
    rundown_routine: PKRUNDOWN_ROUTINE,
    normal_routine: PKNORMAL_ROUTINE,
    params: *const c_void,
) -> Result<(), Error> {
    unsafe {
        KeInitializeApc(
            kapc,
            target_thread,
            OriginalApcEnvironment,
            kernel_routine,
            rundown_routine,
            normal_routine,
            UserMode as KPROCESSOR_MODE,
            null_mut(),
        );
        ObReferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _)
    }

    unsafe {
        let res = KeInsertQueueApc(kapc, null_mut(), params as _, 0);
        if 0 == res {
            ObDereferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _);
            return Err(Error::UNSUCCESSFUL);
        }

        KeTestAlertThread(UserMode as KPROCESSOR_MODE);
    }

    Ok(())
}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
#[optimize(speed)]
pub unsafe extern "system" fn apc_rundown_routine(apc: *mut KAPC) {
    let f: UCHAR = 0 as UCHAR;
    match apc_rundown_routine_helper(apc) {
        TRUE => ObDereferenceObject(__MOD.as_ref().unwrap_unchecked()._device.as_raw_mut() as _), //must be JMP. Can't return to driver itself
        f => (),
    }
}

// Cleanup when the APC is not called (i.e. when the thread is closed before it can run it)
// rundown routine executes <=> kernel&normal routines do not execute
#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn apc_rundown_routine_helper(apc: *mut KAPC) -> BOOLEAN {
    //println!("rundown helper");
    if !apc.is_null() {
        let kapc = Box::from_raw(apc);
        drop(kapc)
    }
    TRUE
}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
pub unsafe fn user_mode_apc_callback2(args: PVOID, _: PVOID, _: PVOID) {
    ((*(args as *mut UserApcArgs))
        .load_library
        .unwrap_unchecked())(
        null_mut(),
        null_mut(),
        &(*(args as *mut UserApcArgs)).dll_path as *const _ as _,
        &mut (*(args as *mut UserApcArgs)).retval as *mut _,
    );
}

// Dummy function to mark the end of user_mode_apc_callback
#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
pub unsafe fn user_mode_apc_callback_end2() {}

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe extern "stdcall" fn user_mode_apc_callback_wow(args: PVOID, _: PVOID, _: PVOID) {
    ((*(args as *mut UserApcArgs))
        .load_library
        .unwrap_unchecked())(
        null_mut(),
        null_mut(),
        &(*(args as *mut UserApcArgs)).dll_path as *const _ as _,
        &mut (*(args as *mut UserApcArgs)).retval as *mut _,
    );
}

// Dummy function to mark the end of user_mode_apc_callback
#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn user_mode_apc_callback_end_wow() {}
