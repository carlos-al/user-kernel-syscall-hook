#![feature(fn_traits)]
#![no_std]
#![no_main]

extern crate alloc;

use alloc::ffi::CString;
use alloc::string::String;
use core::ffi::{c_char, c_void};
use core::mem::size_of;
use core::ptr::{addr_of_mut, null_mut, slice_from_raw_parts};

use bitflags::bitflags;
use ntapi::ntexapi::NtQuerySystemTime;
use ntapi::ntioapi::{
    IO_STATUS_BLOCK_u, NtCreateFile, NtWriteFile, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT,
    IO_STATUS_BLOCK,
};
use ntapi::ntobapi::NtClose;
use ntapi::ntpebteb::{PPEB, PTEB};
use ntapi::ntrtl::{
    RtlDosPathNameToNtPathName_U_WithStatus, RtlFreeUnicodeString, RtlSystemTimeToLocalTime,
    RtlTimeToTimeFields, TIME_FIELDS,
};
use ntapi::ntzwapi::ZwQueueApcThread;
use ntapi::winapi::um::winnt::{FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, SYNCHRONIZE};
use ntapi::winapi_local::um::winnt::__readgsqword;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::ntdef::{
    HANDLE, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, PULONG, PUNICODE_STRING,
    PVOID, PWSTR, ULONG, UNICODE_STRING,
};
use winapi::shared::ntstatus::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use winapi::um::winioctl::{
    FILE_ANY_ACCESS, METHOD_BUFFERED, METHOD_IN_DIRECT, METHOD_NEITHER, METHOD_OUT_DIRECT,
};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, FILE_READ_DATA,
    FILE_WRITE_DATA,
};

use macros::unicode_string;

mod allocator;

#[global_allocator]
static ALLOCATOR: allocator::UserlandAllocator = allocator::UserlandAllocator::new();

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
            log_dll_process_attach();
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

fn log_dll_process_attach() {
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
    unsafe { __readgsqword(0x30) as PTEB }
}

fn get_peb() -> PPEB {
    unsafe { __readgsqword(0x60) as PPEB }
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
pub extern "system" fn __CxxFrameHandler3() -> i32 {
    0
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Port8042,
    Acpi,
    Battery,
    Beep,
    BusExtender,
    Cdrom,
    CdromFileSystem,
    Changer,
    Controller,
    DataLink,
    Dfs,
    DfsFileSystem,
    DfsVolume,
    Disk,
    DiskFileSystem,
    Dvd,
    FileSystem,
    Fips,
    FullscreenVideo,
    InportPort,
    Keyboard,
    Ks,
    Ksec,
    Mailslot,
    MassStorage,
    MidiIn,
    MidiOut,
    Modem,
    Mouse,
    MultiUncProvider,
    NamedPipe,
    Network,
    NetworkBrowser,
    NetworkFileSystem,
    NetworkRedirector,
    Null,
    ParallelPort,
    PhysicalNetcard,
    Printer,
    Scanner,
    Screen,
    Serenum,
    SerialPort,
    SerialMousePort,
    Smartcard,
    Smb,
    Sound,
    Streams,
    Tape,
    TapeFileSystem,
    Termsrv,
    Transport,
    Unknown,
    Vdm,
    Video,
    VirtualDisk,
    WaveIn,
    WaveOut,
}

impl Into<u32> for DeviceType {
    fn into(self) -> u32 {
        match self {
            DeviceType::Port8042 => winapi::um::winioctl::FILE_DEVICE_8042_PORT,
            DeviceType::Acpi => winapi::um::winioctl::FILE_DEVICE_ACPI,
            DeviceType::Battery => winapi::um::winioctl::FILE_DEVICE_BATTERY,
            DeviceType::Beep => winapi::um::winioctl::FILE_DEVICE_BEEP,
            DeviceType::BusExtender => winapi::um::winioctl::FILE_DEVICE_BUS_EXTENDER,
            DeviceType::Cdrom => winapi::um::winioctl::FILE_DEVICE_CD_ROM,
            DeviceType::CdromFileSystem => winapi::um::winioctl::FILE_DEVICE_CD_ROM_FILE_SYSTEM,
            DeviceType::Changer => winapi::um::winioctl::FILE_DEVICE_CHANGER,
            DeviceType::Controller => winapi::um::winioctl::FILE_DEVICE_CONTROLLER,
            DeviceType::DataLink => winapi::um::winioctl::FILE_DEVICE_DATALINK,
            DeviceType::Dfs => winapi::um::winioctl::FILE_DEVICE_DFS,
            DeviceType::DfsFileSystem => winapi::um::winioctl::FILE_DEVICE_DFS_FILE_SYSTEM,
            DeviceType::DfsVolume => winapi::um::winioctl::FILE_DEVICE_DFS_VOLUME,
            DeviceType::Disk => winapi::um::winioctl::FILE_DEVICE_DISK,
            DeviceType::DiskFileSystem => winapi::um::winioctl::FILE_DEVICE_DISK_FILE_SYSTEM,
            DeviceType::Dvd => winapi::um::winioctl::FILE_DEVICE_DVD,
            DeviceType::FileSystem => winapi::um::winioctl::FILE_DEVICE_FILE_SYSTEM,
            DeviceType::Fips => winapi::um::winioctl::FILE_DEVICE_FIPS,
            DeviceType::FullscreenVideo => winapi::um::winioctl::FILE_DEVICE_FULLSCREEN_VIDEO,
            DeviceType::InportPort => winapi::um::winioctl::FILE_DEVICE_INPORT_PORT,
            DeviceType::Keyboard => winapi::um::winioctl::FILE_DEVICE_KEYBOARD,
            DeviceType::Ks => winapi::um::winioctl::FILE_DEVICE_KS,
            DeviceType::Ksec => winapi::um::winioctl::FILE_DEVICE_KSEC,
            DeviceType::Mailslot => winapi::um::winioctl::FILE_DEVICE_MAILSLOT,
            DeviceType::MassStorage => winapi::um::winioctl::FILE_DEVICE_MASS_STORAGE,
            DeviceType::MidiIn => winapi::um::winioctl::FILE_DEVICE_MIDI_IN,
            DeviceType::MidiOut => winapi::um::winioctl::FILE_DEVICE_MIDI_OUT,
            DeviceType::Modem => winapi::um::winioctl::FILE_DEVICE_MODEM,
            DeviceType::Mouse => winapi::um::winioctl::FILE_DEVICE_MOUSE,
            DeviceType::MultiUncProvider => winapi::um::winioctl::FILE_DEVICE_MULTI_UNC_PROVIDER,
            DeviceType::NamedPipe => winapi::um::winioctl::FILE_DEVICE_NAMED_PIPE,
            DeviceType::Network => winapi::um::winioctl::FILE_DEVICE_NETWORK,
            DeviceType::NetworkBrowser => winapi::um::winioctl::FILE_DEVICE_NETWORK_BROWSER,
            DeviceType::NetworkFileSystem => winapi::um::winioctl::FILE_DEVICE_NETWORK_FILE_SYSTEM,
            DeviceType::NetworkRedirector => winapi::um::winioctl::FILE_DEVICE_NETWORK_REDIRECTOR,
            DeviceType::Null => winapi::um::winioctl::FILE_DEVICE_NULL,
            DeviceType::ParallelPort => winapi::um::winioctl::FILE_DEVICE_PARALLEL_PORT,
            DeviceType::PhysicalNetcard => winapi::um::winioctl::FILE_DEVICE_PHYSICAL_NETCARD,
            DeviceType::Printer => winapi::um::winioctl::FILE_DEVICE_PRINTER,
            DeviceType::Scanner => winapi::um::winioctl::FILE_DEVICE_SCANNER,
            DeviceType::Screen => winapi::um::winioctl::FILE_DEVICE_SCREEN,
            DeviceType::Serenum => winapi::um::winioctl::FILE_DEVICE_SERENUM,
            DeviceType::SerialMousePort => winapi::um::winioctl::FILE_DEVICE_SERIAL_MOUSE_PORT,
            DeviceType::SerialPort => winapi::um::winioctl::FILE_DEVICE_SERIAL_PORT,
            DeviceType::Smartcard => winapi::um::winioctl::FILE_DEVICE_SMARTCARD,
            DeviceType::Smb => winapi::um::winioctl::FILE_DEVICE_SMB,
            DeviceType::Sound => winapi::um::winioctl::FILE_DEVICE_SOUND,
            DeviceType::Streams => winapi::um::winioctl::FILE_DEVICE_STREAMS,
            DeviceType::Tape => winapi::um::winioctl::FILE_DEVICE_TAPE,
            DeviceType::TapeFileSystem => winapi::um::winioctl::FILE_DEVICE_TAPE_FILE_SYSTEM,
            DeviceType::Termsrv => winapi::um::winioctl::FILE_DEVICE_TERMSRV,
            DeviceType::Transport => winapi::um::winioctl::FILE_DEVICE_TRANSPORT,
            DeviceType::Unknown => winapi::um::winioctl::FILE_DEVICE_UNKNOWN,
            DeviceType::Vdm => winapi::um::winioctl::FILE_DEVICE_VDM,
            DeviceType::Video => winapi::um::winioctl::FILE_DEVICE_VIDEO,
            DeviceType::VirtualDisk => winapi::um::winioctl::FILE_DEVICE_VIRTUAL_DISK,
            DeviceType::WaveIn => winapi::um::winioctl::FILE_DEVICE_WAVE_IN,
            DeviceType::WaveOut => winapi::um::winioctl::FILE_DEVICE_WAVE_OUT,
        }
    }
}

impl From<u32> for DeviceType {
    fn from(value: u32) -> Self {
        match value {
            winapi::um::winioctl::FILE_DEVICE_8042_PORT => DeviceType::Port8042,
            winapi::um::winioctl::FILE_DEVICE_ACPI => DeviceType::Acpi,
            winapi::um::winioctl::FILE_DEVICE_BATTERY => DeviceType::Battery,
            winapi::um::winioctl::FILE_DEVICE_BEEP => DeviceType::Beep,
            winapi::um::winioctl::FILE_DEVICE_BUS_EXTENDER => DeviceType::BusExtender,
            winapi::um::winioctl::FILE_DEVICE_CD_ROM => DeviceType::Cdrom,
            winapi::um::winioctl::FILE_DEVICE_CD_ROM_FILE_SYSTEM => DeviceType::CdromFileSystem,
            winapi::um::winioctl::FILE_DEVICE_CHANGER => DeviceType::Changer,
            winapi::um::winioctl::FILE_DEVICE_CONTROLLER => DeviceType::Controller,
            winapi::um::winioctl::FILE_DEVICE_DATALINK => DeviceType::DataLink,
            winapi::um::winioctl::FILE_DEVICE_DFS => DeviceType::Dfs,
            winapi::um::winioctl::FILE_DEVICE_DFS_FILE_SYSTEM => DeviceType::DfsFileSystem,
            winapi::um::winioctl::FILE_DEVICE_DFS_VOLUME => DeviceType::DfsVolume,
            winapi::um::winioctl::FILE_DEVICE_DISK => DeviceType::Disk,
            winapi::um::winioctl::FILE_DEVICE_DISK_FILE_SYSTEM => DeviceType::DiskFileSystem,
            winapi::um::winioctl::FILE_DEVICE_DVD => DeviceType::Dvd,
            winapi::um::winioctl::FILE_DEVICE_FILE_SYSTEM => DeviceType::FileSystem,
            winapi::um::winioctl::FILE_DEVICE_FIPS => DeviceType::Fips,
            winapi::um::winioctl::FILE_DEVICE_FULLSCREEN_VIDEO => DeviceType::FullscreenVideo,
            winapi::um::winioctl::FILE_DEVICE_INPORT_PORT => DeviceType::InportPort,
            winapi::um::winioctl::FILE_DEVICE_KEYBOARD => DeviceType::Keyboard,
            winapi::um::winioctl::FILE_DEVICE_KS => DeviceType::Ks,
            winapi::um::winioctl::FILE_DEVICE_KSEC => DeviceType::Ksec,
            winapi::um::winioctl::FILE_DEVICE_MAILSLOT => DeviceType::Mailslot,
            winapi::um::winioctl::FILE_DEVICE_MASS_STORAGE => DeviceType::MassStorage,
            winapi::um::winioctl::FILE_DEVICE_MIDI_IN => DeviceType::MidiIn,
            winapi::um::winioctl::FILE_DEVICE_MIDI_OUT => DeviceType::MidiOut,
            winapi::um::winioctl::FILE_DEVICE_MODEM => DeviceType::Modem,
            winapi::um::winioctl::FILE_DEVICE_MOUSE => DeviceType::Mouse,
            winapi::um::winioctl::FILE_DEVICE_MULTI_UNC_PROVIDER => DeviceType::MultiUncProvider,
            winapi::um::winioctl::FILE_DEVICE_NAMED_PIPE => DeviceType::NamedPipe,
            winapi::um::winioctl::FILE_DEVICE_NETWORK => DeviceType::Network,
            winapi::um::winioctl::FILE_DEVICE_NETWORK_BROWSER => DeviceType::NetworkBrowser,
            winapi::um::winioctl::FILE_DEVICE_NETWORK_FILE_SYSTEM => DeviceType::NetworkFileSystem,
            winapi::um::winioctl::FILE_DEVICE_NETWORK_REDIRECTOR => DeviceType::NetworkRedirector,
            winapi::um::winioctl::FILE_DEVICE_NULL => DeviceType::Null,
            winapi::um::winioctl::FILE_DEVICE_PARALLEL_PORT => DeviceType::ParallelPort,
            winapi::um::winioctl::FILE_DEVICE_PHYSICAL_NETCARD => DeviceType::PhysicalNetcard,
            winapi::um::winioctl::FILE_DEVICE_PRINTER => DeviceType::Printer,
            winapi::um::winioctl::FILE_DEVICE_SCANNER => DeviceType::Scanner,
            winapi::um::winioctl::FILE_DEVICE_SCREEN => DeviceType::Screen,
            winapi::um::winioctl::FILE_DEVICE_SERENUM => DeviceType::Serenum,
            winapi::um::winioctl::FILE_DEVICE_SERIAL_MOUSE_PORT => DeviceType::SerialMousePort,
            winapi::um::winioctl::FILE_DEVICE_SERIAL_PORT => DeviceType::SerialPort,
            winapi::um::winioctl::FILE_DEVICE_SMARTCARD => DeviceType::Smartcard,
            winapi::um::winioctl::FILE_DEVICE_SMB => DeviceType::Smb,
            winapi::um::winioctl::FILE_DEVICE_SOUND => DeviceType::Sound,
            winapi::um::winioctl::FILE_DEVICE_STREAMS => DeviceType::Streams,
            winapi::um::winioctl::FILE_DEVICE_TAPE => DeviceType::Tape,
            winapi::um::winioctl::FILE_DEVICE_TAPE_FILE_SYSTEM => DeviceType::TapeFileSystem,
            winapi::um::winioctl::FILE_DEVICE_TERMSRV => DeviceType::Termsrv,
            winapi::um::winioctl::FILE_DEVICE_TRANSPORT => DeviceType::Transport,
            winapi::um::winioctl::FILE_DEVICE_UNKNOWN => DeviceType::Unknown,
            winapi::um::winioctl::FILE_DEVICE_VDM => DeviceType::Vdm,
            winapi::um::winioctl::FILE_DEVICE_VIDEO => DeviceType::Video,
            winapi::um::winioctl::FILE_DEVICE_VIRTUAL_DISK => DeviceType::VirtualDisk,
            winapi::um::winioctl::FILE_DEVICE_WAVE_IN => DeviceType::WaveIn,
            winapi::um::winioctl::FILE_DEVICE_WAVE_OUT => DeviceType::WaveOut,
            _ => DeviceType::Unknown,
        }
    }
}

bitflags! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RequiredAccess: u32 {
        const ANY_ACCESS = FILE_ANY_ACCESS;
        const READ_DATA = FILE_READ_DATA;
        const WRITE_DATA = FILE_WRITE_DATA;
        const READ_WRITE_DATA = FILE_READ_DATA | FILE_WRITE_DATA;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TransferMethod {
    Neither = METHOD_NEITHER,
    InputDirect = METHOD_IN_DIRECT,
    OutputDirect = METHOD_OUT_DIRECT,
    Buffered = METHOD_BUFFERED,
}

impl From<u32> for TransferMethod {
    fn from(value: u32) -> Self {
        match value & 0x3 {
            METHOD_NEITHER => Self::Neither,
            METHOD_IN_DIRECT => Self::InputDirect,
            METHOD_OUT_DIRECT => Self::OutputDirect,
            METHOD_BUFFERED => Self::Buffered,
            _ => unreachable!(),
        }
    }
}

impl Into<u32> for TransferMethod {
    fn into(self) -> u32 {
        match self {
            Self::Neither => METHOD_NEITHER,
            Self::InputDirect => METHOD_IN_DIRECT,
            Self::OutputDirect => METHOD_OUT_DIRECT,
            Self::Buffered => METHOD_BUFFERED,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlCode(
    pub DeviceType,
    pub RequiredAccess,
    pub u32,
    pub TransferMethod,
);

impl ControlCode {
    const METHOD_BITS: usize = 2;
    const NUM_BITS: usize = 12;
    const ACCESS_BITS: usize = 2;
    const TYPE_BITS: usize = 16;

    const METHOD_SHIFT: usize = 0;
    const NUM_SHIFT: usize = Self::METHOD_SHIFT + Self::METHOD_BITS;
    const ACCESS_SHIFT: usize = Self::NUM_SHIFT + Self::NUM_BITS;
    const TYPE_SHIFT: usize = Self::ACCESS_SHIFT + Self::ACCESS_BITS;

    const METHOD_MASK: u32 = (1 << Self::METHOD_BITS) - 1;
    const NUM_MASK: u32 = (1 << Self::NUM_BITS) - 1;
    const ACCESS_MASK: u32 = (1 << Self::ACCESS_BITS) - 1;
    const TYPE_MASK: u32 = (1 << Self::TYPE_BITS) - 1;
}

impl From<u32> for ControlCode {
    fn from(value: u32) -> Self {
        let method = (value >> Self::METHOD_SHIFT) & Self::METHOD_MASK;
        let num = (value >> Self::NUM_SHIFT) & Self::NUM_MASK;
        let access = (value >> Self::ACCESS_SHIFT) & Self::ACCESS_MASK;
        let ty = (value >> Self::TYPE_SHIFT) & Self::TYPE_MASK;

        Self(
            ty.into(),
            RequiredAccess::from_bits(access).unwrap_or(RequiredAccess::READ_DATA),
            num,
            method.into(),
        )
    }
}

impl Into<u32> for ControlCode {
    fn into(self) -> u32 {
        let method = Into::<u32>::into(self.3) << Self::METHOD_SHIFT;
        let num = self.2 << Self::NUM_SHIFT;
        let access = self.1.bits() << Self::ACCESS_SHIFT;
        let ty = Into::<u32>::into(self.0) << Self::TYPE_SHIFT;

        ty | access | num | method
    }
}

struct Error(usize);
