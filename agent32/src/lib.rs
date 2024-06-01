#![feature(fn_traits)]
#![feature(naked_functions)]
#![no_std]
#![no_main]

extern crate alloc;
extern crate compiler_builtins;

use alloc::ffi::{CString, NulError};
use alloc::format;
use alloc::string::String;
use core::arch::asm;
use core::ffi::{c_char, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::{addr_of_mut, null_mut, slice_from_raw_parts};

use macros::unicode_string;
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntexapi::NtQuerySystemTime;
use ntapi::ntioapi::{
    FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, IO_STATUS_BLOCK, IO_STATUS_BLOCK_u, NtCreateFile,
    NtWriteFile,
};
use ntapi::ntldr::LdrLoadDll;
use ntapi::ntmmapi::NtUnmapViewOfSection;
use ntapi::ntobapi::NtClose;
use ntapi::ntpebteb::{PPEB, PTEB};
use ntapi::ntpsapi::NtCurrentProcess;
use ntapi::ntrtl::{
    RtlDosPathNameToNtPathName_U_WithStatus, RtlFreeUnicodeString, RtlSystemTimeToLocalTime,
    RtlTimeToTimeFields, TIME_FIELDS,
};
use ntapi::ntzwapi::ZwQueueApcThread;
use ntapi::winapi::um::winnt::{FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, SYNCHRONIZE};
use ntapi::winapi_local::um::winnt::__readfsdword;
#[cfg(target_arch = "x86_64")]
use ntapi::winapi_local::um::winnt::__readgsqword;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::ntdef::{
    HANDLE, NT_SUCCESS, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJECT_ATTRIBUTES, PULONG, PUNICODE_STRING,
    PVOID, PWSTR, ULONG, ULONGLONG, UNICODE_STRING,
};
use winapi::shared::ntstatus::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, NT_TIB, PNT_TIB,
    SECURITY_DESCRIPTOR,
};

mod allocator;

#[global_allocator]
static ALLOCATOR: allocator::KernelAllocator = allocator::KernelAllocator::new();

pub type PLARGE_INTEGER = *mut LARGE_INTEGER;

#[repr(C)]
union LARGE_INTEGER {
    dummystructname: DUMMYSTRUCTNAME,
    u: U,
    QuadPart: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct DUMMYSTRUCTNAME {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct U {
    low_part: u32,
    high_part: i32,
}

unicode_string!(LOG_FILE_PATH = "C:\\Inject\\log.txt");

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            let teb = get_teb();
            let peb = get_peb();

            let cid = (unsafe { *teb }).ClientId;
            let pid = cid.UniqueProcess as u32;

            let mut time = LARGE_INTEGER { QuadPart: 0 };
            let mut time_fields = TIME_FIELDS {
                Year: 0,
                Month: 0,
                Day: 0,
                Hour: 0,
                Minute: 0,
                Second: 0,
                Milliseconds: 0,
                Weekday: 0,
            };

            unsafe {
                NtQuerySystemTime(&mut time as *mut _ as _);
                RtlSystemTimeToLocalTime(&mut time as *mut _ as _, &mut time as *mut _ as _);
                RtlTimeToTimeFields(&mut time as *mut _ as _, &mut time_fields as *mut _ as _);
            }

            unsafe {
                if !(*peb).ProcessParameters.is_null() {
                    let name = String::from_utf16_lossy(
                        slice_from_raw_parts(
                            (*(*peb).ProcessParameters).ImagePathName.Buffer,
                            (*(*peb).ProcessParameters).ImagePathName.Length as usize / 2,
                        )
                        .as_ref()
                        .unwrap(),
                    );

                    println!(
                        "{}-{}-{} {}:{}:{}.{} > PID={} \"{}\" \n",
                        time_fields.Year,
                        time_fields.Month,
                        time_fields.Day,
                        time_fields.Hour,
                        time_fields.Minute,
                        time_fields.Second,
                        time_fields.Milliseconds,
                        pid,
                        name.as_str()
                    );
                }
            }
        }
        DLL_PROCESS_DETACH => {
            ALLOCATOR.deinit();
        }
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => {}
    };

    true
}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn _DllMainCRTStartup(
    dll_module: *mut c_void,
    call_reason: u32,
    c: *mut (),
) -> bool {
    DllMain(dll_module as _, call_reason, c)
}

extern "system" {
    //pub fn RtlDosPathNameToNtPathName_U_WithStatus(alert_mode: KPROCESSOR_MODE) -> BOOLEAN;
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    // Format the string using the `alloc::format!` as this is guaranteed to return a `String`
    // instead of a `Result` that we would have to `unwrap`. This ensures that this code stays
    // panic-free.
    let s = alloc::format!("{}", args);
    let c = CString::new(s.as_str());

    match c {
        Ok(c) => {
            log_to_file(c.as_ptr() as _, unsafe { LOG_FILE_PATH.Buffer });
        }
        Err(_) => {
            let name = CString::new("KO\n").unwrap();
            log_to_file(name.as_ptr() as _, unsafe { LOG_FILE_PATH.Buffer });
        }
    }
}

fn log_to_file(output: *const c_char, file: PWSTR) -> NTSTATUS {
    let mut status = STATUS_INVALID_PARAMETER;

    if !output.is_null() && unsafe { *output } != 0 {
        let mut size = 0;
        while unsafe { *output.offset(size) } != 0 {
            size += 1
        }

        let mut file_unicode = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: null_mut(),
        };
        unsafe {
            status = RtlDosPathNameToNtPathName_U_WithStatus(
                file,
                &mut file_unicode as *mut _,
                null_mut(),
                null_mut(),
            );
        }

        if status == STATUS_SUCCESS {
            let mut handle = null_mut();
            let mut oa = OBJECT_ATTRIBUTES {
                Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                RootDirectory: null_mut(),
                ObjectName: addr_of_mut!(file_unicode),
                Attributes: OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: null_mut(),
                SecurityQualityOfService: null_mut(),
            };
            let mut iosb = IO_STATUS_BLOCK {
                u: IO_STATUS_BLOCK_u {
                    Status: STATUS_SUCCESS,
                },
                Information: 0,
            };

            unsafe {
                status = NtCreateFile(
                    &mut handle,
                    FILE_APPEND_DATA | SYNCHRONIZE,
                    &mut oa,
                    &mut iosb,
                    null_mut(),
                    FILE_ATTRIBUTE_NORMAL,
                    0,
                    FILE_OPEN_IF,
                    FILE_SYNCHRONOUS_IO_NONALERT,
                    null_mut(),
                    0,
                );
            }

            if NT_SUCCESS(status) {
                unsafe {
                    status = NtWriteFile(
                        handle,
                        null_mut(),
                        None,
                        null_mut(),
                        &mut iosb,
                        output as _,
                        size as ULONG,
                        null_mut(),
                        null_mut(),
                    );
                }

                unsafe {
                    NtClose(handle);
                }
            }

            unsafe {
                RtlFreeUnicodeString(&mut file_unicode);
            }
        }
    }

    status
}

fn get_teb() -> PTEB {
    unsafe { __readfsdword(0x18) as PTEB }
}

fn get_peb() -> PPEB {
    unsafe { __readfsdword(0x30) as PPEB }
}

#[repr(C)]
struct UserApcArgs {
    dll_path: [u16; 256],
    base_address: *mut c_void,
    load_library: LdrLoadDll,
    nt_unmap: NtUnmapViewOfSection,
}

type LdrLoadDll = Option<
    unsafe extern "system" fn(
        DllPath: PWSTR,
        DllCharacteristics: PULONG,
        DllName: PUNICODE_STRING,
        DllHandle: *mut PVOID,
    ) -> NTSTATUS,
>;
type NtUnmapViewOfSection =
    Option<unsafe extern "system" fn(ProcessHandle: HANDLE, BaseAddress: PVOID) -> NTSTATUS>;

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe extern "C" fn user_mode_apc_callback(args: PVOID, _: PVOID, _: PVOID) {
    ((*(args as *mut UserApcArgs))
        .load_library
        .unwrap_unchecked())(
        &(*(args as *mut UserApcArgs)).dll_path as *const _ as _,
        null_mut(),
        null_mut(),
        null_mut(),
    );
}

// Dummy function to mark the end of user_mode_apc_callback
#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn user_mode_apc_callback_end() {}

unsafe extern "C" fn dummy_cfg_callback(ptr: *mut c_void) {
    //TODO: taggity tag
    ZwQueueApcThread(
        null_mut(),
        Some(user_mode_apc_callback),
        null_mut(),
        null_mut(),
        null_mut(),
    );
}

#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

//making the linker happy ☺️

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, count: usize) -> *mut u8 {
    let mut d = dest;
    let mut s = src;

    for _ in 0..count {
        *d = *s;
        d = d.offset(1);
        s = s.offset(1);
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn strlen(mut s: *const u8) -> usize {
    let mut result = 0;
    while *s != 0 {
        s = s.offset(1);
        result += 1;
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *s.offset(i as isize) = c as u8;
        i += 1;
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.offset(i as isize);
        let b = *s2.offset(i as isize);
        if a != b {
            return a as i32 - b as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dest {
        // Copy from end to start if there is potential overlap with dest being higher in memory
        for i in (0..n).rev() {
            *dest.add(i) = *src.add(i);
        }
    } else {
        for i in 0..n {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[no_mangle]
pub static mut _fltused: u8 = 0;

#[no_mangle]
pub extern "system" fn ___CxxFrameHandler3() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn __CxxFrameHandler3() -> i32 {
    0
}

#[naked]
#[no_mangle]
unsafe extern "C" fn _aullrem(dividend: u64, divisor: u64) -> u64 {
    asm!(
        "
        push ebx

        mov  eax, dword ptr [esp + 0x14]
        or   eax, eax
        jnz  2f

        mov  ecx, dword ptr [esp + 0x10]
        mov  eax, dword ptr [esp + 0xC]
        xor  edx, edx
        div  ecx
        mov  eax, dword ptr [esp + 0x8]
        div  ecx
        mov  eax, edx
        xor  edx, edx
        jmp  6f

        2:
        mov  ecx, eax
        mov  ebx, dword ptr [esp + 0x10]
        mov  edx, dword ptr [esp + 0xC]
        mov  eax, dword ptr [esp + 0x8]

        3:
        shr  ecx, 1
        rcr  ebx, 1
        shr  edx, 1
        rcr  eax, 1
        or   ecx, ecx
        jnz  3b

        div  ebx
        mov  ecx, eax
        mul  dword ptr [esp + 0x14]
        xchg eax, ecx
        mul  dword ptr [esp + 0x10]
        add  edx, ecx
        jb   4f

        cmp  edx, dword ptr [esp + 0xC]
        ja   4f
        jb   5f

        cmp  eax, dword ptr [esp + 0x8]
        jbe  5f

        4:
        sub  eax, dword ptr [esp + 0x10]
        sbb  edx, dword ptr [esp + 0x14]

        5:
        sub  eax, dword ptr [esp + 0x8]
        sbb  edx, dword ptr [esp + 0xC]
        neg  edx
        neg  eax
        sbb  edx, 0

        6:
        pop  ebx
        ret  2*8
        ",
        options(noreturn)
    );
}
#[naked]
#[no_mangle]
unsafe extern "C" fn _aulldiv(dividend: u64, divisor: u64) -> u64 {
    asm!(
        "
        push ebx
        push esi

        mov  eax, dword ptr [esp + 0x18]
        or   eax, eax
        jnz  2f

        mov  ecx, dword ptr [esp + 0x14]
        mov  eax, dword ptr [esp + 0x10]
        xor  edx, edx
        div  ecx
        mov  ebx, eax
        mov  eax, dword ptr [esp + 0xC]
        div  ecx
        mov  edx, ebx
        jmp  6f

        2:
        mov  ecx, eax
        mov  ebx, dword ptr [esp + 0x14]
        mov  edx, dword ptr [esp + 0x10]
        mov  eax, dword ptr [esp + 0xC]

        3:
        shr  ecx, 1
        rcr  ebx, 1
        shr  edx, 1
        rcr  eax, 1
        or   ecx, ecx
        jnz  3b

        div  ebx
        mov  esi, eax
        mul  dword ptr [esp + 0x18]
        mov  ecx, eax
        mov  eax, dword ptr [esp + 0x14]
        mul  esi
        add  edx, ecx
        jb   4f

        cmp  edx, dword ptr [esp + 0x10]
        ja   4f
        jb   5f

        cmp  eax, dword ptr [esp + 0xC]
        jbe  5f

        4:
        dec  esi

        5:
        xor  edx, edx
        mov  eax, esi

        6:
        pop  esi
        pop  ebx
        ret  2*8
        ",
        options(noreturn)
    )
}
