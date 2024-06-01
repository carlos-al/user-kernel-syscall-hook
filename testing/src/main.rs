use std::ffi::{c_void, CString};
use std::ptr::null_mut;
use std::thread::sleep;
use std::time::Duration;

use windows::core::imp::{CloseHandle, LoadLibraryExA};
use windows::core::PCSTR;
use windows::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, WRITE_DAC, WRITE_OWNER,
};

fn main() {
    println!("Hello, world!");

    //
    //let s = CString::new("C:\\Inject").unwrap();
    //set_security_descriptor(PCSTR {
    //    0: s.as_ptr() as *const u8 as _,
    //});

    let dll = to_c_lpcstr("C:\\Users\\dev\\Desktop\\agent.dll").unwrap();
    sleep(Duration::from_secs(5));

    let res = unsafe { LoadLibraryExA(dll.into_raw() as _, 0, 0) };

    println!("0x{:x}", res);
}

fn to_c_lpcstr(rust_string: &str) -> Result<CString, std::ffi::NulError> {
    let c_str = CString::new(rust_string)?;
    Ok(c_str)
}

fn set_security_descriptor(path: PCSTR) {
    let mut sd = null_mut();
    let mut size = 0_u32;
    let str_sd = CString::new(
        "D:(A;;GA;;;WD)(A;;GA;;;AN)(A;;GA;;;S-1-15-2-1)(A;;GA;;;S-1-15-2-2)S:(ML;;;;;S-1-16-0)",
    )
    .unwrap();
    let pcstr = PCSTR {
        0: str_sd.as_ptr() as _,
    };

    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorA(
            pcstr,
            SDDL_REVISION_1,
            &mut sd as *mut *mut c_void as _,
            Some(&mut size as _),
        )
        .is_ok()
        {
            let handle = CreateFileA(
                path,
                WRITE_DAC.0 | WRITE_OWNER.0,
                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            );

            match handle {
                Ok(handle) => {
                    if !handle.is_invalid() {
                        match SetKernelObjectSecurity(
                            handle.clone(),
                            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                            PSECURITY_DESCRIPTOR {
                                0: sd as *mut _ as _,
                            },
                        ) {
                            Ok(_) => {
                                println!("OK")
                            }
                            Err(_) => {
                                println!("KO kerobj {:#?}", GetLastError())
                            }
                        };

                        CloseHandle(handle.0);
                    } else {
                        println!("KO createfile {:#?}", GetLastError())
                    }
                }
                Err(_) => {
                    println!("KO handle {:#?}", GetLastError())
                }
            };

            LocalFree(HLOCAL { 0: sd });
        } else {
            println!("KO Convert {:#?}", GetLastError())
        }
    }
}
