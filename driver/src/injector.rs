use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::mem::{size_of, transmute};
use core::ptr::{addr_of_mut, null_mut};
use core::{mem, slice};

use windows_kernel::check_nt_status;
use windows_kernel::headers::_KAPC_ENVIRONMENT::OriginalApcEnvironment;
use windows_kernel::headers::{
    KeInitializeApc, KeInsertQueueApc, KeTestAlertThread, NtCurrentProcess, ObGetObjectType,
    PsGetProcessPeb, ZwQuerySystemInformation, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER,
    IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, LDR_DATA_TABLE_ENTRY,
    PKNORMAL_ROUTINE, STATUS_INFO_LENGTH_MISMATCH, SYSTEM_HANDLE_INFORMATION,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO, SYSTEM_INFORMATION_CLASS, SYSTEM_PROCESS_INFORMATION,
};
use windows_kernel::process::{Process, ProcessId};
use windows_kernel::{nt_success, println, Error};
use windows_kernel_sys::base::_MODE::UserMode;
use windows_kernel_sys::base::{
    HANDLE, KAPC, KAPC_STATE, KPROCESSOR_MODE, MEM_COMMIT, MEM_RELEASE, OBJECT_NAME_INFORMATION,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PEPROCESS, PKTHREAD, PUNICODE_STRING, PVOID, SIZE_T,
    STATUS_SUCCESS, TRUE, ULONG, UNICODE_STRING, WCHAR, _KAPC, _LIST_ENTRY,
};
use windows_kernel_sys::netio::RtlCopyMemoryNonTemporal;
use windows_kernel_sys::ntoskrnl::{
    KeStackAttachProcess, KeUnstackDetachProcess, ObDereferenceObject, ObQueryNameString,
    PsGetCurrentProcess, PsLookupProcessByProcessId, PsLookupThreadByThreadId,
    RtlEqualUnicodeString, ZwAllocateVirtualMemory, ZwFreeVirtualMemory,
};
use windows_kernel_sys::{c_char, c_void};

use macros::unicode_string;

use crate::kapc::new_KAPC_STATE;
use crate::section::DllStats;
use crate::section::SectionType::WoW;
use crate::{kapc, LdrLoadDll};

// APC stuff

#[repr(C)]
struct UserApcArgsByPid {
    dll_path: [u16; 256],
    load_library: LoadLibraryW,
}

type LoadLibraryW = Option<unsafe extern "system" fn(*const u16) -> *mut u8>;

#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn user_mode_apc_callback(args: *mut UserApcArgsByPid, _: PVOID, _: PVOID) {
    ((*args).load_library.unwrap_unchecked())(&(*args).dll_path as *const _);
}

// Dummy function to mark the end of user_mode_apc_callback
#[no_mangle]
#[allow(unused)]
#[link_section = ".text"]
#[inline(never)]
unsafe fn user_mode_apc_callback_end() {}

#[allow(non_snake_case)]
#[no_mangle]
unsafe extern "system" fn kernel_apc(
    _Apc: *mut KAPC,
    _NormalRoutine: *mut PKNORMAL_ROUTINE,
    _NormalContext: *mut PVOID,
    _SystemArgument1: *mut PVOID,
    _SystemArgument2: *mut PVOID,
) {
    KeTestAlertThread(UserMode as _);
}

fn call_apc(
    target_thread: PKTHREAD,
    target_function: *mut c_void,
    params: *mut c_void,
) -> Result<(), Error> {
    let mut apc: Box<KAPC> = Box::new(_KAPC {
        Type: 0,
        AllFlags: 0,
        Size: 0,
        SpareByte1: 0,
        SpareLong0: 0,
        Thread: null_mut(),
        ApcListEntry: _LIST_ENTRY {
            Flink: null_mut(),
            Blink: null_mut(),
        },
        Reserved: [null_mut(); 3],
        NormalContext: null_mut(),
        SystemArgument1: null_mut(),
        SystemArgument2: null_mut(),
        ApcStateIndex: 0,
        ApcMode: 0,
        Inserted: 0,
    });

    unsafe {
        KeInitializeApc(
            &mut *apc,
            target_thread,
            OriginalApcEnvironment,
            Some(kernel_apc),
            None,
            Some(transmute(target_function)),
            UserMode as KPROCESSOR_MODE,
            params,
        )
    }

    unsafe {
        let res = KeInsertQueueApc(apc.as_mut() as _, null_mut(), null_mut(), 0);
        if 0 == res {
            return Err(Error::UNSUCCESSFUL);
        }
    }

    mem::forget(apc);
    Ok(())
}

//Attached process stuff

pub(crate) struct ProcessReference {
    process: PEPROCESS,
    apc_state: Box<KAPC_STATE>,
}

impl ProcessReference {
    pub(crate) fn attach(pid: HANDLE) -> Result<Self, Error> {
        let mut process = ProcessReference {
            process: null_mut(),
            apc_state: Box::new(new_KAPC_STATE()),
        };

        let res = unsafe { PsLookupProcessByProcessId(pid, &mut process.process) };
        if res != 0 || process.process.is_null() {
            return Err(Error::from_ntstatus(res));
        }

        println!("attaching to process");
        unsafe { KeStackAttachProcess(process.process, process.apc_state.as_mut() as _) }

        Ok(process)
    }
}

impl Drop for ProcessReference {
    fn drop(&mut self) {
        unsafe {
            ObDereferenceObject(self.process as _);
            KeUnstackDetachProcess(self.apc_state.as_mut() as _)
        }
        println!("dettached from process");
    }
}

pub(crate) fn get_module_symbol_address(
    module_name: &str,
    symbol_name: &str,
) -> Result<*mut c_void, Error> {
    let peb = unsafe { PsGetProcessPeb(PsGetCurrentProcess()) };

    if peb.is_null() {
        return Err(Error::UNSUCCESSFUL);
    }

    let module_entry =
        unsafe { *(*peb).Ldr }.InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
    let mut next = module_entry;

    while !next.is_null() {
        let name = unsafe { (*next.cast::<LDR_DATA_TABLE_ENTRY>()).BaseDllName };
        let name = unsafe {
            String::from_utf16_lossy(slice::from_raw_parts(name.Buffer, name.Length as usize / 2))
        };

        if name == module_name {
            unsafe {
                return find_symbol_address(
                    (*next.cast::<LDR_DATA_TABLE_ENTRY>()).DllBase,
                    symbol_name,
                );
            }
        }
        unsafe {
            next = (*next).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }
    }

    Err(Error::UNSUCCESSFUL)
}
fn find_symbol_address(
    module_address: *mut c_void,
    symbol_name: &str,
) -> Result<*mut c_void, Error> {
    let dos_header: &IMAGE_DOS_HEADER = unsafe { &*(module_address as *const IMAGE_DOS_HEADER) };

    // Calculate the address of IMAGE_NT_HEADERS64
    let nt_headers_offset = dos_header.e_lfanew as isize;
    let nt_headers_ptr =
        (unsafe { module_address.offset(nt_headers_offset) }) as *const IMAGE_NT_HEADERS64;
    let nt_headers64: &IMAGE_NT_HEADERS64 = unsafe { &*nt_headers_ptr };

    // Access the OptionalHeader
    let optional_header_ptr = &nt_headers64.OptionalHeader as *const IMAGE_OPTIONAL_HEADER64;
    let optional_header: &IMAGE_OPTIONAL_HEADER64 = unsafe { &*optional_header_ptr };

    // Access the Export Directory
    let export_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    let export_table_ptr =
        (unsafe { module_address.offset(export_directory.VirtualAddress as isize) })
            as *const IMAGE_EXPORT_DIRECTORY;
    let export_table: &IMAGE_EXPORT_DIRECTORY = unsafe { &*export_table_ptr };

    unsafe {
        for i in 0..export_table.NumberOfNames {
            let function_name_offset_ptr = module_address.offset(
                export_table.AddressOfNames as isize + (size_of::<ULONG>() * i as usize) as isize,
            ) as *const ULONG;
            let function_name_offset = *function_name_offset_ptr;

            let function_name_ptr =
                (module_address.offset(function_name_offset as isize)) as *const c_char;
            let function_name = CStr::from_ptr(function_name_ptr).to_str().unwrap();

            if function_name == symbol_name {
                let function_address_ptr = module_address.offset(
                    export_table.AddressOfFunctions as isize
                        + (size_of::<ULONG>() * (i + 1) as usize) as isize,
                ) as *const ULONG;
                let function_address = *function_address_ptr;

                return Ok(module_address.offset(function_address as isize));
            }
        }
    }

    Err(Error::UNSUCCESSFUL)
}

// Process/Handle info

#[derive(Clone)]
pub(crate) struct ProcessInfo {
    pub(crate) process_id: HANDLE,
    pub(crate) number_of_threads: usize,
    pub(crate) threads_id: Vec<HANDLE>,
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self {
            process_id: null_mut(),
            number_of_threads: 0,
            threads_id: vec![],
        }
    }
}

fn get_all_processes() -> Vec<SYSTEM_PROCESS_INFORMATION> {
    let mut capacity = 0;
    loop {
        capacity += 0x10_000;
        let mut processes_pool: Vec<SYSTEM_PROCESS_INFORMATION> =
            vec![SYSTEM_PROCESS_INFORMATION::default(); capacity];

        let mut ret_len = 0;

        let res = unsafe {
            ZwQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS::SystemProcessInformation,
                processes_pool.as_mut_ptr(),
                capacity as ULONG,
                &mut ret_len,
            )
        };

        if res == STATUS_INFO_LENGTH_MISMATCH as i32 {
            continue;
        } else {
            break processes_pool;
        }
    }
}

fn get_processes_info() -> Vec<ProcessInfo> {
    let mut number_of_processes = 0;
    let all_processes = get_all_processes();

    let mut process = all_processes.as_ptr();
    unsafe {
        while (*process).NextEntryOffset != 0 {
            number_of_processes += 1;
            process = process.byte_add((*process).NextEntryOffset as usize);
        }
    }

    let mut processes_info: Vec<ProcessInfo> = vec![ProcessInfo::default(); number_of_processes];
    let mut processes_ptr = all_processes.as_ptr();

    for process in processes_info.iter_mut() {
        unsafe {
            if (*processes_ptr).NextEntryOffset != 0 {
                process.process_id = (*processes_ptr).UniqueProcessId;
                process.number_of_threads = (*processes_ptr).NumberOfThreads as usize;

                if (*processes_ptr).NumberOfThreads == 0 {
                    continue;
                }

                process.threads_id = vec![null_mut(); (*processes_ptr).NumberOfThreads as usize];

                for j in 0..((*processes_ptr).NumberOfThreads as usize - 1) {
                    let thread_info = (*processes_ptr).Threads.as_ptr().add(j);
                    process.threads_id[j] = (*thread_info).ClientId.UniqueThread;
                }

                processes_ptr = processes_ptr.byte_add((*processes_ptr).NextEntryOffset as usize);
            }
        }
    }
    processes_info
}

pub(crate) fn get_process_info_by_pid(pid: HANDLE) -> ProcessInfo {
    let mut process_info = ProcessInfo {
        process_id: null_mut(),
        number_of_threads: 0,
        threads_id: Vec::new(),
    };
    let processes = get_processes_info();

    for process in processes {
        if pid == process.process_id {
            process_info.process_id = pid;
            process_info.number_of_threads = process.number_of_threads;
            process_info.threads_id = process.threads_id;
        }
    }

    process_info
}

fn get_all_handles() -> Vec<SYSTEM_HANDLE_INFORMATION> {
    let mut capacity = 0;
    loop {
        capacity += 0x10_000;
        let mut processes_pool: Vec<SYSTEM_HANDLE_INFORMATION> = vec![
            SYSTEM_HANDLE_INFORMATION {
                NumberOfHandles: 0,
                Handles: null_mut(),
            };
            capacity
        ];

        let mut ret_len = 0;

        let res = unsafe {
            ZwQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS::SystemHandleInformation,
                processes_pool.as_mut_ptr() as _,
                capacity as ULONG,
                &mut ret_len,
            )
        };

        if res == STATUS_INFO_LENGTH_MISMATCH as i32 {
            continue;
        } else {
            break processes_pool;
        }
    }
}

fn get_handle_info<'a>() -> (
    Vec<SYSTEM_HANDLE_INFORMATION>,
    &'a [SYSTEM_HANDLE_TABLE_ENTRY_INFO],
) {
    let mut all_handles = get_all_handles();

    let a = unsafe {
        slice::from_raw_parts(
            addr_of_mut!(all_handles[0].Handles) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO,
            all_handles[0].NumberOfHandles as usize,
        )
    };

    (all_handles, a) //TODO: not so ugly
}

pub(crate) fn get_handle_info_by_pid(pid: HANDLE) -> HANDLE {
    let (v, all_handles) = get_handle_info();
    let mut ret_handle = null_mut();
    let mut process: PEPROCESS = null_mut();
    unsafe {
        PsLookupProcessByProcessId(pid, &mut process);
    }
    let unique_process_id = unsafe { *(process.byte_add(0x440) as usize as *mut u16) } as HANDLE;

    'outer: for handle in all_handles {
        unsafe {
            if handle.UniqueProcessId == unique_process_id as _ {
                let object_tpye = ObGetObjectType(handle.Object as _);
                let object_type_name = object_tpye.byte_add(0x10) as PUNICODE_STRING;

                'inner: for i in 0..16 {
                    // Dereference the pointer offset by `i` and check if it is not null
                    if *(handle.Object as *mut u8).byte_add(i) != 0 {
                        continue 'inner;
                    }
                    continue 'outer;
                }

                unicode_string!(DIRECTORY = "Directory");
                println!("check: 0x{:x}", object_type_name as usize);
                println!("check: 0x{:x}", addr_of_mut!(DIRECTORY) as usize);
                let name = unsafe {
                    let unicode_name = object_type_name;
                    let slice = slice::from_raw_parts(
                        (*unicode_name).Buffer,
                        (*unicode_name).Length as usize / 2,
                    );
                    String::from_utf16_lossy(slice)
                };
                println!("checking for {name}");

                unsafe {
                    if RtlEqualUnicodeString(addr_of_mut!(DIRECTORY), object_type_name, TRUE)
                        == TRUE
                    {
                        let mut return_length = 0;

                        let status = unsafe {
                            ObQueryNameString(handle.Object, null_mut(), 0, &mut return_length)
                        };

                        if status != STATUS_INFO_LENGTH_MISMATCH as i32 {
                            continue 'outer;
                        }

                        let mut buffer = vec![0u8; return_length as usize];

                        let status = unsafe {
                            ObQueryNameString(
                                handle.Object,
                                buffer.as_mut_ptr() as *mut _,
                                buffer.len() as ULONG,
                                &mut return_length,
                            )
                        };

                        if status != STATUS_SUCCESS {
                            println!("neverhere 0x{:x}", status);
                        }

                        // Safe to assume buffer now contains OBJECT_NAME_INFORMATION. We need to cast it.
                        // This is still unsafe because we're assuming the Vec's buffer is properly aligned
                        // and that the  call was successful.
                        let object_name_info =
                            unsafe { &*(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION) };

                        let name = {
                            let unicode_name = &object_name_info.Name;
                            let slice = slice::from_raw_parts(
                                unicode_name.Buffer,
                                unicode_name.Length as usize / 2,
                            );
                            String::from_utf16_lossy(slice)
                        };
                        println!("chhhecking for {name}");
                        unicode_string!(NAMED_OBJECTS = "\\BaseNamedObjects");

                        if RtlEqualUnicodeString(
                            addr_of_mut!(NAMED_OBJECTS),
                            &object_name_info.Name,
                            TRUE,
                        ) == TRUE
                        {
                            println!("encontramos la handle");
                            println!("@ 0x{:x}", handle.Object as usize);

                            ret_handle = handle.HandleValue as _;
                            return ret_handle;
                        }
                    }
                }
            }
        }
    }
    println!("no handle no pary");
    drop(v);
    ret_handle
}

type SectionBase = usize;
type SecionSize = u32;
type GlobalVariableAddress = *mut c_void;

pub(crate) fn find_ldrp_known_dll_directory_handle(
) -> Result<(GlobalVariableAddress, (SectionBase, SecionSize)), Error> {
    let peb = unsafe { PsGetProcessPeb(PsGetCurrentProcess()) };
    let module_name = "ntdll.dll";

    if peb.is_null() {
        return Err(Error::UNSUCCESSFUL);
    }
    //peb may be paged out

    let module_entry =
        unsafe { *(*peb).Ldr }.InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
    let mut next = module_entry;

    while next != null_mut() {
        let name = unsafe { (*next.cast::<LDR_DATA_TABLE_ENTRY>()).BaseDllName };
        let name = unsafe {
            String::from_utf16_lossy(slice::from_raw_parts(name.Buffer, name.Length as usize / 2))
        };

        println!("{}", name);
        if name == module_name {
            unsafe {
                return find_global_address((*next.cast::<LDR_DATA_TABLE_ENTRY>()).DllBase);
            }
        }
        unsafe {
            next = (*next).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }
    }

    Err(Error::UNSUCCESSFUL)
}

fn find_global_address(
    module_address: *mut c_void,
) -> Result<(GlobalVariableAddress, (SectionBase, SecionSize)), Error> {
    let dos_header: &IMAGE_DOS_HEADER = unsafe { &*(module_address as *const IMAGE_DOS_HEADER) };

    // Calculate the address of IMAGE_NT_HEADERS64
    let nt_headers_offset = dos_header.e_lfanew as isize;
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
        if name.starts_with(".mrdata\0") {
            println!("ntdll @ 0x{:x}", module_address as usize);
            let section_base = section.VirtualAddress as usize + module_address as usize;
            let size = section.VirtualSize;
            let mut addr = section_base + 0x280;
            let mut res: *mut c_void = null_mut();
            for i in 0..10 {
                unsafe {
                    if *(addr as *const usize) == section_base {
                        res = addr as _; // ntdll!LdrpMrdataBase
                        break;
                    }
                    addr += 0x8;
                }
            }
            unsafe { return Ok((res.byte_add(0x10), (section_base, size))) }
        }
    }

    Err(Error::UNSUCCESSFUL)
}

// Thunk(less) shellcode

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
pub(crate) struct UserApcArgs {
    pub(crate) dll_path: UNICODE_STRING,
    pub(crate) retval: PVOID,
    pub(crate) load_library: LdrLoadDll,
    buffer: [WCHAR; 256],
}

type InjectedApcCallback = PVOID;
type InjectedApcArgs = PVOID;

pub unsafe fn map_shellcode_into_process(
    process_id: HANDLE,
    dll_stats: *const DllStats,
) -> Result<(InjectedApcCallback, InjectedApcArgs), Error> {
    let process_reference = ProcessReference::attach(process_id)?;
    let load_library = get_module_symbol_address("ntdll.dll", "LdrLoadDll");

    let mut user_apc_args = UserApcArgs {
        dll_path: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: null_mut(),
        },
        buffer: [0; 256],
        retval: null_mut(),
        load_library: unsafe { transmute::<*mut c_void, LdrLoadDll>(load_library.unwrap()) },
    };

    //make the contents of dll_path.Buffer be contained on a field on the same struct, avoiding references to kernel memory
    let path: Vec<WCHAR> = "agent.dll".encode_utf16().collect();
    let len = path.len().min(255);
    user_apc_args.buffer[..len].copy_from_slice(&path[..len]);

    user_apc_args.dll_path.Length = (len * 2) as u16;
    user_apc_args.dll_path.MaximumLength = user_apc_args.dll_path.Length + 2; // + null-terminator
    user_apc_args.dll_path.Buffer = user_apc_args.buffer.as_mut_ptr();

    // Allocate and copy the user apc args to target process

    let mut injected_apc_args = null_mut();
    let mut injected_apc_args_size = size_of::<UserApcArgs>() as SIZE_T;

    unsafe {
        if !nt_success!(ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut injected_apc_args,
            0,
            &mut injected_apc_args_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )) {
            return Err(Error::UNSUCCESSFUL);
        };
        RtlCopyMemoryNonTemporal(
            injected_apc_args,
            &user_apc_args as *const _ as _,
            size_of::<UserApcArgs>() as SIZE_T,
        )
    }
    //Still need to update the dll_path.Buffer field, as it points to kernel memory

    // Calculate the new buffer address in user space, which is the address of `injected_apc_args` plus the offset of `buffer`
    let new_buffer_address = injected_apc_args as usize + 32; // `buffer` starts at offset 32

    // Access the UNICODE_STRING within the copied struct to adjust the `Buffer` pointer
    let args = &mut *((injected_apc_args as usize) as *mut UserApcArgs);
    args.dll_path.Buffer = new_buffer_address as *mut _;

    // Allocate and copy the apc user mode callback code to target process

    let (mut injected_apc_callback, mut code_size) =
        if cfg!(target_arch = "x86_64") && (*dll_stats).section_type == WoW {
            let injected_apc_callback: PVOID = null_mut();
            let code_size =
                kapc::user_mode_apc_callback_end2 as usize - kapc::user_mode_apc_callback2 as usize;
            (injected_apc_callback, code_size)
        } else {
            let injected_apc_callback = null_mut();
            let code_size =
                kapc::user_mode_apc_callback_end2 as usize - kapc::user_mode_apc_callback2 as usize;
            (injected_apc_callback, code_size)
        };

    unsafe {
        let res = ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut injected_apc_callback,
            0,
            &mut code_size as *mut _ as _,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if res != 0 {
            ZwFreeVirtualMemory(
                NtCurrentProcess(),
                &mut injected_apc_args as _,
                &mut injected_apc_args_size,
                MEM_RELEASE,
            );
            return Err(Error::UNSUCCESSFUL);
        }
        RtlCopyMemoryNonTemporal(
            injected_apc_callback,
            kapc::user_mode_apc_callback2 as usize as _,
            code_size as SIZE_T,
        )
    }
    drop(process_reference);

    Ok((injected_apc_callback, injected_apc_args))
}

pub unsafe fn map_shellcode_into_process_thunkless(
    process_id: HANDLE,
) -> Result<(InjectedApcCallback, InjectedApcArgs), Error> {
    let process_reference = ProcessReference::attach(process_id)?;
    let load_library = get_module_symbol_address("ntdll.dll", "LdrLoadDll");

    let process = Process::by_id(process_id as ProcessId).unwrap();
    let peb = unsafe { PsGetProcessPeb(process.process) };

    let mut user_apc_args = UserApcArgs {
        dll_path: UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: null_mut(),
        },
        buffer: [0; 256],
        retval: null_mut(),
        load_library: unsafe { transmute::<*mut c_void, LdrLoadDll>(load_library.unwrap()) },
    };

    //make the contents of dll_path.Buffer be contained on a field on the same struct, avoiding references to kernel memory
    let path: Vec<WCHAR> = "agent.dll".encode_utf16().collect();
    let len = path.len().min(255);
    user_apc_args.buffer[..len].copy_from_slice(&path[..len]);

    user_apc_args.dll_path.Length = (len * 2) as u16;
    user_apc_args.dll_path.MaximumLength = user_apc_args.dll_path.Length + 2; // + null-terminator
    user_apc_args.dll_path.Buffer = user_apc_args.buffer.as_mut_ptr();

    // Allocate and copy the user apc args to target process

    let mut injected_apc_args = null_mut();
    let mut injected_apc_args_size = size_of::<UserApcArgs>() as SIZE_T;

    unsafe {
        if !nt_success!(ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut injected_apc_args,
            0,
            &mut injected_apc_args_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        )) {
            return Err(Error::UNSUCCESSFUL);
        };
        RtlCopyMemoryNonTemporal(
            injected_apc_args,
            &user_apc_args as *const _ as _,
            size_of::<UserApcArgs>() as SIZE_T,
        )
    }

    //Still need to update the dll_path.Buffer field, as it points to kernel memory

    // Calculate the new buffer address in user space, which is the address of `injected_apc_args` plus the offset of `buffer`
    let new_buffer_address = injected_apc_args as usize + 32; // `buffer` starts at offset 32

    // Access the UNICODE_STRING within the copied struct to adjust the `Buffer` pointer
    let args = &mut *((injected_apc_args as usize) as *mut UserApcArgs);
    args.dll_path.Buffer = new_buffer_address as *mut _;

    // Allocate and copy the apc user mode callback code to target process
    drop(process_reference);

    Ok((
        user_apc_args.load_library.unwrap_unchecked() as *mut c_void,
        injected_apc_args,
    ))
}

pub fn inject_by_pid(pid: HANDLE, dll_path: [u16; 256]) {
    let process_reference = ProcessReference::attach(pid);

    let load_library = get_module_symbol_address("KERNEL32.DLL", "LoadLibraryW");

    let user_apc_args = UserApcArgsByPid {
        dll_path,
        load_library: unsafe { transmute::<*mut c_void, LoadLibraryW>(load_library.unwrap()) },
    };

    let mut injected_apc_args = null_mut();
    let mut injected_apc_args_size = size_of::<UserApcArgsByPid>() as SIZE_T;

    // Allocate and copy the dll path to target process
    unsafe {
        check_nt_status!(ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut injected_apc_args,
            0,
            &mut injected_apc_args_size,
            MEM_COMMIT,
            PAGE_READWRITE,
        ));
        RtlCopyMemoryNonTemporal(
            injected_apc_args,
            &user_apc_args as *const _ as _,
            size_of::<UserApcArgsByPid>() as SIZE_T,
        )
    }

    // Allocate and copy the apc user mode callback code to target process
    let mut injected_apc_callback = null_mut();
    let mut code_size = user_mode_apc_callback_end as usize - user_mode_apc_callback as usize;

    unsafe {
        let res = ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut injected_apc_callback,
            0,
            &mut code_size as *mut _ as _,
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if res != 0 {
            ZwFreeVirtualMemory(
                NtCurrentProcess(),
                &mut injected_apc_args as _,
                &mut injected_apc_args_size,
                MEM_RELEASE,
            );
            return;
        }
        RtlCopyMemoryNonTemporal(
            injected_apc_callback,
            user_mode_apc_callback as usize as _,
            (user_mode_apc_callback_end as usize - user_mode_apc_callback as usize) as SIZE_T,
        )
    }
    drop(process_reference);

    let process_info = get_process_info_by_pid(pid);

    let mut target_thread: PKTHREAD = null_mut();

    for i in 0..process_info.number_of_threads {
        unsafe {
            let thread = process_info.threads_id[i];
            let res = PsLookupThreadByThreadId(thread, &mut target_thread);
            if res != 0 {
                println!("[-] APC injection wont do 0x{:x}", res);
                return;
            }
        }

        let ret = call_apc(target_thread, injected_apc_callback, injected_apc_args);
        if ret.is_err() {
            println!("[!] failed 0x{:x}", ret.err().unwrap().to_ntstatus());
        }

        unsafe {
            ObDereferenceObject(target_thread as _);
        }
    }
}
