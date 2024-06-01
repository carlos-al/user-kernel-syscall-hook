#![no_std]
#![feature(optimize_attribute)]
#![feature(sync_unsafe_cell)]

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use core::mem::{align_of, size_of};
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::Ordering::Release;

use common::{InjectCommand, IOCTL_KIT_PROCESS_CALLBACK_PATCH};
use postcard::from_bytes;
use windows_kernel::asynk::executor::WakeRef;
use windows_kernel::headers::{
    MyProbeForRead, PsGetProcessPeb, PsIsProcessBeingDebugged, ZwQueryInformationProcess,
    IMAGE_NT_HEADERS64, PIMAGE_DOS_HEADER, PPEB,
};
use windows_kernel::mdl::AccessMode::KernelMode;
use windows_kernel::nt_success;
use windows_kernel::process::{Process, ProcessId};
use windows_kernel::{
    allocator, kernel_module, println, Access, Completion, Device, DeviceDoFlags, DeviceFlags,
    DeviceOperations, DeviceType, Driver, Error, IoControlRequest, KernelModule, Mutex,
    RequestError, SymbolicLink, U16CString, __DEVICE,
};
use windows_kernel_sys::base::_PROCESSINFOCLASS::ProcessImageFileName;
use windows_kernel_sys::base::{
    PsProcessType, ACCESS_MASK, BOOLEAN, HANDLE, IO_STATUS_BLOCK, LARGE_INTEGER, MAXSHORT,
    NTSTATUS, OBJECT_ATTRIBUTES, OBJ_KERNEL_HANDLE, PEPROCESS, PLOAD_IMAGE_NOTIFY_ROUTINE, PNT_TIB,
    PROCESS_ALL_ACCESS, PULONG, PUNICODE_STRING, PVOID, PWSTR, ULONG, UNICODE_STRING, USHORT,
    WCHAR, _IMAGE_INFO, _UNICODE_STRING,
};
use windows_kernel_sys::c_void;
use windows_kernel_sys::netio::{wcsnlen, RtlEqualUnicodeString, ZwClose};
use windows_kernel_sys::ntoskrnl::{
    MmGetSystemRoutineAddress, ObDereferenceObject, ObOpenObjectByPointer, PsGetCurrentProcessId,
    PsGetCurrentThreadTeb, PsLookupProcessByProcessId, PsRemoveLoadImageNotifyRoutine,
    PsSetLoadImageNotifyRoutine,
};

use macros::unicode_string;

use crate::injector::inject_by_pid;
use crate::section::Section;
use crate::section::SectionType::{Native, WoW};

mod hooks;
mod injector;
mod kapc;
mod section;

#[global_allocator]
static ALLOCATOR: allocator::KernelAllocator =
    allocator::KernelAllocator::new(u32::from_ne_bytes(*b"EBNG"));

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

unicode_string!(TEST_PROC = "notepad.exe");

unicode_string!(INJECTED_DLL_NAME_32 = "\\KnownDlls32\\agent.dll"); //TODO: replace with https://github.com/ColinFinck/nt-string
unicode_string!(KERNEL_32_PATH_32 = "\\KnownDlls32\\kernel32.dll");

unicode_string!(INJECTED_DLL_NT_PATH_NTV = "\\systemroot\\system32\\agent.dll");
unicode_string!(INJECTED_DLL_NT_PATH_WOW = "\\systemroot\\syswow64\\agent.dll");

unicode_string!(DLL_NAME = "agent.dll");

#[cfg(target_arch = "x86_64")]
unicode_string!(INJECTED_DLL_NAME = "\\KnownDlls\\agent.dll");
#[cfg(target_arch = "x86_64")]
unicode_string!(INJECTED_DLL_NAME_PROTECTED = "\\BaseNamedObjects\\agent.dll");
#[cfg(target_arch = "x86_64")]
unicode_string!(KERNEL_32_PATH = "\\KnownDlls\\kernel32.dll");

#[cfg(target_arch = "x86")]
unicode_string!(INJECTED_DLL_NAME = "\\KnownDlls32\\agent.dll");
#[cfg(target_arch = "x86")]
unicode_string!(KERNEL_32_PATH = "\\KnownDlls32\\kernel32.dll");

static mut SEC: Section = Section::new(Native);
static mut SEC_WOW: Section = Section::new(WoW);

#[derive(Default)]
struct MyDevice {}

impl MyDevice {
    fn inject_by_pid(&self, request: &IoControlRequest) -> Result<u32, Error> {
        let buffer = request.user_ptr();
        let content = buffer.as_slice();
        let size = content.len();

        let command = content[0..size].to_vec();
        let command: InjectCommand = from_bytes(command.as_slice()).unwrap();

        inject_by_pid(
            command.pid as HANDLE,
            string_to_u16_array(command.dll_path.as_str()),
        );

        Ok(0)
    }
}

impl DeviceOperations for MyDevice {
    fn ioctl(
        &mut self,
        _device: &Device,
        request: IoControlRequest,
    ) -> Result<Completion, RequestError> {
        let result = match request.function() {
            (_, IOCTL_KIT_PROCESS_CALLBACK_PATCH) => self.inject_by_pid(&request),
            _ => Err(Error::INVALID_PARAMETER),
        };

        match result {
            Ok(size) => Ok(Completion::Complete(size, request.into())),
            Err(e) => Err(RequestError(e, request.into())),
        }
    }
}

struct Module {
    _device: Device,
    _symbolic_link: SymbolicLink,
}

impl KernelModule for Module {
    fn init(mut driver: Driver, _registry_path: &str) -> Result<Self, Error> {
        let device = driver.create_device(
            "\\Device\\Example",
            DeviceType::Unknown,
            DeviceFlags::SECURE_OPEN,
            DeviceDoFlags::DO_BUFFERED_IO,
            Access::NonExclusive,
            MyDevice::default(),
        )?;
        let symbolic_link = SymbolicLink::new("\\??\\Example", "\\Device\\Example")?;

        unsafe {
            PsSetLoadImageNotifyRoutine(IMAGE_CALLBACK);

            __DEVICE = Some(device.as_raw_mut());
        }

        unicode_string!(CREATEFILE = "NtCreateFile");
        let target = unsafe { MmGetSystemRoutineAddress(addr_of_mut!(CREATEFILE)) };
        match infinity_hook::hook_syscall(
            hooks::nt_create_file_hook as *const _,
            target as *const _,
        ) {
            Ok(_) => Ok(Module {
                _device: device,
                _symbolic_link: symbolic_link,
            }),
            Err(e) => {
                unsafe {
                    PsRemoveLoadImageNotifyRoutine(IMAGE_CALLBACK);
                    let _ = SEC.free_section();
                    if cfg!(target_arch = "x86_64") {
                        let _ = SEC_WOW.free_section();
                    }
                }

                Err(e)
            }
        }
    }

    fn cleanup(self, _driver: Driver) {
        unsafe {
            PsRemoveLoadImageNotifyRoutine(IMAGE_CALLBACK);
            SEC.free_section();
            if cfg!(target_arch = "x86_64") {
                SEC_WOW.free_section();
            }
        }
        infinity_hook::unhook_syscall();

        drop(self._device)
    }
}
kernel_module!(Module);
const IMAGE_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

#[allow(non_snake_case)]
type LdrLoadDll = Option<
    unsafe extern "system" fn(
        DllPath: PWSTR,
        DllCharacteristics: PULONG,
        DllName: PUNICODE_STRING,
        DllHandle: *mut PVOID,
    ) -> NTSTATUS,
>;

static IMAGE_CALLBACK: PLOAD_IMAGE_NOTIFY_ROUTINE = Some(on_image_load);
unsafe extern "C" fn on_image_load(
    full_image_name: *mut _UNICODE_STRING,
    process_id: HANDLE,
    image_info: *mut _IMAGE_INFO,
) {
    if image_info.is_null() || full_image_name.is_null() {
        return;
    }

    unicode_string!(KERNEL32 = "\\kernel32.dll");

    if (0
        == (*image_info)
        .__bindgen_anon_1
        .__bindgen_anon_1
        .SystemModeImage())                                                     // No kernel images
        && process_id == PsGetCurrentProcessId()                                    
        && is_suffixed_unicode_string(full_image_name, addr_of_mut!(KERNEL32), true) // Just looking for kernel32.dll
        && is_mapped_by_LdrLoadDll(addr_of_mut!(KERNEL32))
    // being mapped by ntdll
        && is_process_name_w(process_id, TEST_PROC.Buffer, false)
    {
        let wow_flag = if cfg!(target_arch = "x86_64") {
            //TODO replace with IoIs32BitProcess() call
            let dos_header = (*image_info).ImageBase as PIMAGE_DOS_HEADER;
            let nt_headers = (*image_info)
                .ImageBase
                .byte_offset((*dos_header).e_lfanew as isize)
                as *const IMAGE_NT_HEADERS64;
            (*nt_headers).OptionalHeader.Magic != IMAGE_OPTIONAL_HDR64_MAGIC
        } else {
            false
        };

        let process = Process::by_id(process_id as ProcessId).unwrap();
        let peb = unsafe { PsGetProcessPeb(process.process) };
        let process_id = process_id as ProcessId;

        let section = if cfg!(target_arch = "x86_64") && wow_flag {
            println!("got wow");
            &mut SEC_WOW
        } else {
            &mut SEC
        };

        let dll_stats = match section.get_section(false) {
            Ok(stats) => stats,
            Err(_) => return,
        };

        match section.inject_dll(dll_stats, process_id as HANDLE) {
            Ok(_) => {}
            Err(_) => {
                println!("APC injection failed")
            }
        }
    }
}

fn is_suffixed_unicode_string(
    full_name: *mut UNICODE_STRING,
    short_name: *mut UNICODE_STRING,
    case_insensitive: bool,
) -> bool {
    unsafe {
        if full_name.is_null() || short_name.is_null() || (*full_name).Length < (*short_name).Length
        {
            return false;
        }
    }

    let str = UNICODE_STRING {
        Length: (unsafe { *short_name }).Length,
        MaximumLength: (unsafe { *short_name }).MaximumLength,
        Buffer: unsafe {
            RtlOffsetToPointer(
                (*full_name).Buffer,
                ((*full_name).Length - (*short_name).Length) as usize,
            )
        } as _,
    };

    1 == unsafe { RtlEqualUnicodeString(&str, short_name, BOOLEAN::from(case_insensitive)) }
}

#[allow(non_snake_case)]
fn is_mapped_by_LdrLoadDll(short_name: *mut UNICODE_STRING) -> bool {
    let teb = unsafe { PsGetCurrentThreadTeb() } as PNT_TIB;

    unsafe {
        if teb.is_null() || (*teb).ArbitraryUserPointer.is_null() {
            return false;
        }
    }

    let mut name = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: (unsafe { *teb }).ArbitraryUserPointer as _,
    };

    if !MyProbeForRead(
        name.Buffer as _,
        size_of::<WCHAR>(),
        align_of::<WCHAR>() as u64,
    ) {
        return false;
    }

    unsafe {
        name.Length = wcsnlen(name.Buffer, MAXSHORT as usize) as USHORT;
    }
    if name.Length == MAXSHORT as u16 {
        return false;
    }

    name.Length *= size_of::<WCHAR>() as u16;
    name.MaximumLength = name.Length;

    is_suffixed_unicode_string(&mut name, short_name, true)
}

unsafe fn is_process_name_w(
    process_id: HANDLE,
    image_name: *const WCHAR,
    is_debugged: bool,
) -> bool {
    let mut res = false;
    let mut process: PEPROCESS = null_mut();

    if nt_success!(PsLookupProcessByProcessId(process_id, &mut process)) {
        if !is_debugged || PsIsProcessBeingDebugged(process) == 0 {
            let mut handle_proc: HANDLE = null_mut();

            if nt_success!(ObOpenObjectByPointer(
                process as _,
                OBJ_KERNEL_HANDLE,
                null_mut(),
                PROCESS_ALL_ACCESS,
                *PsProcessType,
                KernelMode as _,
                &mut handle_proc
            )) {
                let mut buff = [0_u16; 500];

                let mut name = UNICODE_STRING {
                    Length: 0,
                    MaximumLength: (buff.len() * size_of::<u16>()) as USHORT,
                    Buffer: buff.as_mut_ptr(),
                };

                if nt_success!(ZwQueryInformationProcess(
                    handle_proc,
                    ProcessImageFileName,
                    &mut name as *mut _ as _,
                    (buff.len() * size_of::<u16>()) as ULONG,
                    null_mut()
                )) && name.Length + size_of::<u16>() as u16 <= name.MaximumLength
                {
                    let target = U16CString::from_ptr_str(name.Buffer).to_string_lossy();
                    let base = U16CString::from_ptr_str(image_name).to_string_lossy();

                    res = is_filename_match(&target, &base, false);
                }

                ZwClose(handle_proc);
            }
        }

        ObDereferenceObject(process as _);
    }

    res
}

#[allow(non_snake_case)]
unsafe fn RtlOffsetToPointer<T>(base: *const T, offset: usize) -> *const c_char {
    let base_ptr = base as *const c_void as *const c_char;
    base_ptr.add(offset)
}

fn is_filename_match(path: &str, filename: &str, case_sensitive: bool) -> bool {
    //TODO compare with a standard c-style pointer mambojambo loop. Check nt-string crate
    if let Some(last_component) = path.rsplit('\\').next() {
        if case_sensitive {
            last_component == filename
        } else {
            last_component.eq_ignore_ascii_case(filename)
        }
    } else {
        false
    }
}

fn string_to_u16_array(s: &str) -> [u16; 256] {
    let mut array = [0u16; 256];
    let encoded: Vec<u16> = s.encode_utf16().collect();
    for (i, &item) in encoded.iter().enumerate().take(255) {
        array[i] = item;
    }
    array
}
