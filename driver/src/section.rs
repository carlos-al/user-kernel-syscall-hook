use alloc::boxed::Box;
use alloc::vec;
use core::mem::size_of;
use core::ptr::{addr_of_mut, null_mut};

use windows_kernel::headers::_KAPC_ENVIRONMENT::OriginalApcEnvironment;
use windows_kernel::headers::{KeInitializeApc, KeInsertQueueApc};
use windows_kernel::mdl::AccessMode::KernelMode;
use windows_kernel::{nt_success, println, Error};
use windows_kernel_sys::base::{
    _IO_STATUS_BLOCK__bindgen_ty_1, DACL_SECURITY_INFORMATION, FILE_EXECUTE, FILE_GENERIC_READ,
    FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT, HANDLE, IO_STATUS_BLOCK, KAPC, KPROCESSOR_MODE,
    LABEL_SECURITY_INFORMATION, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, OBJ_PERMANENT,
    OWNER_SECURITY_INFORMATION, PAGE_EXECUTE, PEPROCESS, PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
    READ_CONTROL, RTL_RUN_ONCE, SECTION_MAP_EXECUTE, SECTION_QUERY, SEC_IMAGE, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL, ULONG, _LIST_ENTRY,
};
use windows_kernel_sys::c_void;
use windows_kernel_sys::netio::{
    ObReferenceObjectByHandle, ZwClose, ZwCreateSection, ZwMakeTemporaryObject,
};
use windows_kernel_sys::ntoskrnl::{
    KeStackAttachProcess, KeUnstackDetachProcess, ObDereferenceObject, ObMakeTemporaryObject,
    ObReferenceObject, PsGetCurrentThread, PsLookupProcessByProcessId, RtlRunOnceBeginInitialize,
    RtlRunOnceComplete, RtlRunOnceInitialize, ZwOpenFile, ZwOpenSection, ZwQuerySecurityObject,
};

use crate::kapc::{apc_kernel_routine, apc_normal_routine, apc_rundown_routine, new_KAPC_STATE};
use crate::{
    INJECTED_DLL_NAME, INJECTED_DLL_NAME_32, INJECTED_DLL_NAME_PROTECTED, INJECTED_DLL_NT_PATH_NTV,
    INJECTED_DLL_NT_PATH_WOW, KERNEL_32_PATH, KERNEL_32_PATH_32, __MOD,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum SectionType {
    Native,
    WoW,
}

pub(crate) struct Section {
    section_type: SectionType,
    singleton_state: RTL_RUN_ONCE,
}

impl Section {
    pub(crate) const fn new(section_type: SectionType) -> Self {
        Self {
            section_type,
            singleton_state: RTL_RUN_ONCE { Ptr: null_mut() },
        }
    }

    pub(crate) fn get_section(&mut self, protected: bool) -> Result<*mut DllStats, Error> {
        let mut context: *mut DllStats = null_mut();
        let status = unsafe {
            RtlRunOnceBeginInitialize(&mut self.singleton_state, 0, &mut context as *mut _ as _)
        };

        if status == 0x00000103 {
            let mut dll_stats = Box::new(DllStats {
                section_type: SectionType::Native,
                section: null_mut(),
            });

            context = null_mut();

            // Attach to the process and create a KnownDll(CIG bypass) section

            let mut apc_state = new_KAPC_STATE();

            unsafe {
                let mut pproc: PEPROCESS = null_mut();
                PsLookupProcessByProcessId(4 as _, &mut pproc);
                KeStackAttachProcess(pproc, &mut apc_state);
            }

            if protected {
                if self.create_protected_section(&mut dll_stats).is_err() {
                    unsafe {
                        KeUnstackDetachProcess(&mut apc_state);
                    }
                    return Err(Error::UNSUCCESSFUL);
                }
            } else if self.create_KnownDll_section(&mut dll_stats).is_err() {
                unsafe {
                    KeUnstackDetachProcess(&mut apc_state);
                }
                return Err(Error::UNSUCCESSFUL);
            }

            unsafe {
                KeUnstackDetachProcess(&mut apc_state);
            }

            //This then becomes our singleton variable

            context = Box::into_raw(dll_stats);

            if !nt_success!(unsafe {
                RtlRunOnceComplete(&mut self.singleton_state, 0, context as *mut _ as _)
            }) {
                let _dll_stats = unsafe { Box::from_raw(context) };
                return Err(Error::UNSUCCESSFUL);
            }

            // Else the memory on context will be deallocated at function return. To be deallocated with free_section()
        } else if status != STATUS_SUCCESS {
            return Err(Error::UNSUCCESSFUL);
        }

        if !context.is_null() {
            Ok(context)
        } else {
            Err(Error::UNSUCCESSFUL)
        }
    }

    #[allow(clippy::ifs_same_cond)]
    pub(crate) fn free_section(&mut self) -> Result<(), Error> {
        let mut context: *mut DllStats = null_mut();
        let status = unsafe {
            RtlRunOnceBeginInitialize(&mut self.singleton_state, 0, &mut context as *mut _ as _)
        };

        if nt_success!(status) {
            // Singleton already intitialized

            if !context.is_null() {
                let dll_stats = unsafe { Box::from_raw(context) };

                //Remove permanence tag
                unsafe {
                    ObMakeTemporaryObject(dll_stats.section);
                    ObDereferenceObject(dll_stats.section)
                }

                drop(dll_stats);
                println!("[+] Freed section");
            }

            unsafe {
                RtlRunOnceInitialize(&mut self.singleton_state);
            } // Reinit singleton for new use

            Ok(())
        } else if nt_success!(status) {
            return Ok(());
        } else {
            println!("free section KO 0x{:x}", status);
            return Err(Error::from_ntstatus(status));
        }
    }
    #[allow(non_snake_case)]
    fn create_KnownDll_section(&self, dll_stats: &mut Box<DllStats>) -> Result<(), Error> {
        let mut status = STATUS_SUCCESS;
        let mut section_k32: HANDLE = null_mut();
        let mut attr_k32 = unsafe {
            match self.section_type {
                SectionType::Native => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(KERNEL_32_PATH),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
                SectionType::WoW => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(KERNEL_32_PATH_32),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
            }
        };
        let mut attr_fake_dll_path = unsafe {
            match self.section_type {
                SectionType::Native => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(INJECTED_DLL_NT_PATH_NTV),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
                SectionType::WoW => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(INJECTED_DLL_NT_PATH_WOW),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
            }
        };

        if nt_success!(unsafe { ZwOpenSection(&mut section_k32, READ_CONTROL, &mut attr_k32) }) {
            let mut mem_size = 0;

            let mut sd = vec![0; 0x1000];

            let mut attr_fake_dll = unsafe {
                match self.section_type {
                    SectionType::Native => OBJECT_ATTRIBUTES {
                        Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                        RootDirectory: null_mut(),
                        ObjectName: addr_of_mut!(INJECTED_DLL_NAME),
                        Attributes: OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                        SecurityDescriptor: sd.as_mut_ptr() as _,
                        SecurityQualityOfService: null_mut(),
                    },
                    SectionType::WoW => OBJECT_ATTRIBUTES {
                        Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                        RootDirectory: null_mut(),
                        ObjectName: addr_of_mut!(INJECTED_DLL_NAME_32),
                        Attributes: OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                        SecurityDescriptor: sd.as_mut_ptr() as _,
                        SecurityQualityOfService: null_mut(),
                    },
                }
            };

            loop {
                let mut current_size = 0;

                unsafe {
                    status = ZwQuerySecurityObject(
                        section_k32,
                        PROCESS_TRUST_LABEL_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION
                            | LABEL_SECURITY_INFORMATION
                            | OWNER_SECURITY_INFORMATION,
                        attr_fake_dll.SecurityDescriptor,
                        mem_size,
                        &mut current_size,
                    );
                }

                if nt_success!(status) {
                    break;
                } else if status == 0xC0000023u32 as i32 {
                    sd = vec![0; current_size as usize];
                    attr_fake_dll.SecurityDescriptor = sd.as_mut_ptr() as _;
                    mem_size = current_size;
                } else {
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            unsafe {
                ZwClose(section_k32);
            }

            if nt_success!(status) {
                // create section
                let mut file = null_mut();
                let mut iosb = IO_STATUS_BLOCK {
                    __bindgen_anon_1: _IO_STATUS_BLOCK__bindgen_ty_1 {
                        Pointer: null_mut(),
                    },
                    Information: 0,
                };

                unsafe {
                    status = ZwOpenFile(
                        &mut file,
                        FILE_GENERIC_READ | FILE_EXECUTE,
                        &mut attr_fake_dll_path,
                        &mut iosb,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT,
                    );
                }
                if nt_success!(status) {
                    let mut fake_section = null_mut();

                    unsafe {
                        status = ZwCreateSection(
                            &mut fake_section,
                            SECTION_MAP_EXECUTE | SECTION_QUERY,
                            &mut attr_fake_dll,
                            null_mut(),
                            PAGE_EXECUTE,
                            SEC_IMAGE,
                            file,
                        );
                    }
                    if nt_success!(status) {
                        unsafe {
                            status = ObReferenceObjectByHandle(
                                fake_section,
                                0,
                                null_mut(),
                                KernelMode as _,
                                &mut dll_stats.section,
                                null_mut(),
                            );
                        }
                        if nt_success!(status) {
                            //set ret params
                            dll_stats.section_type = self.section_type;

                            println!("KnownDll created @0x{:x}", dll_stats.section as usize);

                            status = STATUS_SUCCESS;
                        } else {
                            println!("obref KO");
                        }
                    } else {
                        println!("createsection KO");
                    }

                    if !nt_success!(status) {
                        //dll_stats section not set OK. Won't be used. Make it non-permanent to remove it
                        unsafe {
                            ZwMakeTemporaryObject(fake_section);
                        }
                    }

                    unsafe {
                        ZwClose(fake_section);
                    }
                } else {
                    println!("openfile KO");
                    return Err(Error::UNSUCCESSFUL);
                }
            }
        } else {
            println!("query KO");
            return Err(Error::UNSUCCESSFUL);
        }

        if nt_success!(status) {
            return Ok(());
        }
        Err(Error::from_ntstatus(status))
    }

    fn create_protected_section(&self, dll_stats: &mut Box<DllStats>) -> Result<(), Error> {
        let mut status = STATUS_SUCCESS;
        let mut section_k32: HANDLE = null_mut();
        let mut attr_k32 = unsafe {
            match self.section_type {
                SectionType::Native => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(KERNEL_32_PATH),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
                SectionType::WoW => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(KERNEL_32_PATH_32),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
            }
        };
        let mut attr_fake_dll_path = unsafe {
            match self.section_type {
                SectionType::Native => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(INJECTED_DLL_NT_PATH_NTV),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
                SectionType::WoW => OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                    RootDirectory: null_mut(),
                    ObjectName: addr_of_mut!(INJECTED_DLL_NT_PATH_WOW),
                    Attributes: OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor: null_mut(),
                    SecurityQualityOfService: null_mut(),
                },
            }
        };

        if nt_success!(unsafe { ZwOpenSection(&mut section_k32, READ_CONTROL, &mut attr_k32) }) {
            let mut mem_size = 0;

            let mut sd = vec![0; 0x1000];

            let mut attr_fake_dll = unsafe {
                match self.section_type {
                    SectionType::Native => OBJECT_ATTRIBUTES {
                        Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                        RootDirectory: null_mut(),
                        ObjectName: addr_of_mut!(INJECTED_DLL_NAME_PROTECTED),
                        Attributes: OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                        SecurityDescriptor: sd.as_mut_ptr() as _,
                        SecurityQualityOfService: null_mut(),
                    },
                    SectionType::WoW => OBJECT_ATTRIBUTES {
                        Length: size_of::<OBJECT_ATTRIBUTES>() as ULONG,
                        RootDirectory: null_mut(),
                        ObjectName: addr_of_mut!(INJECTED_DLL_NAME_32),
                        Attributes: OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                        SecurityDescriptor: sd.as_mut_ptr() as _,
                        SecurityQualityOfService: null_mut(),
                    },
                }
            };

            loop {
                let mut current_size = 0;

                unsafe {
                    status = ZwQuerySecurityObject(
                        section_k32,
                        PROCESS_TRUST_LABEL_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION
                            | LABEL_SECURITY_INFORMATION
                            | OWNER_SECURITY_INFORMATION,
                        attr_fake_dll.SecurityDescriptor,
                        mem_size,
                        &mut current_size,
                    );
                }

                if nt_success!(status) {
                    break;
                } else if status == 0xC0000023u32 as i32 {
                    sd = vec![0; current_size as usize];
                    attr_fake_dll.SecurityDescriptor = sd.as_mut_ptr() as _;
                    mem_size = current_size;
                } else {
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }
            }

            unsafe {
                ZwClose(section_k32);
            }

            if nt_success!(status) {
                // create section
                let mut file = null_mut();
                let mut iosb = IO_STATUS_BLOCK {
                    __bindgen_anon_1: _IO_STATUS_BLOCK__bindgen_ty_1 {
                        Pointer: null_mut(),
                    },
                    Information: 0,
                };

                unsafe {
                    status = ZwOpenFile(
                        &mut file,
                        FILE_GENERIC_READ | FILE_EXECUTE,
                        &mut attr_fake_dll_path,
                        &mut iosb,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT,
                    );
                }
                if nt_success!(status) {
                    let mut fake_section = null_mut();

                    unsafe {
                        status = ZwCreateSection(
                            &mut fake_section,
                            SECTION_MAP_EXECUTE | SECTION_QUERY,
                            &mut attr_fake_dll,
                            null_mut(),
                            PAGE_EXECUTE,
                            SEC_IMAGE,
                            file,
                        );
                    }
                    if nt_success!(status) {
                        unsafe {
                            status = ObReferenceObjectByHandle(
                                fake_section,
                                0,
                                null_mut(),
                                KernelMode as _,
                                &mut dll_stats.section,
                                null_mut(),
                            );
                        }
                        if nt_success!(status) {
                            //set ret params
                            dll_stats.section_type = self.section_type;

                            println!(
                                "BaseNamedObject created @0x{:x}",
                                dll_stats.section as usize
                            );

                            status = STATUS_SUCCESS;
                        } else {
                            println!("obref KO");
                        }
                    } else {
                        println!("createsection KO");
                    }

                    if !nt_success!(status) {
                        //dll_stats section not set OK. Won't be used. Make it non-permanent to remove it
                        unsafe {
                            ZwMakeTemporaryObject(fake_section);
                        }
                    }

                    unsafe {
                        ZwClose(fake_section);
                    }
                } else {
                    println!("openfile KO");
                    return Err(Error::UNSUCCESSFUL);
                }
            }
        } else {
            println!("query KO");
            return Err(Error::UNSUCCESSFUL);
        }

        if nt_success!(status) {
            return Ok(());
        }
        Err(Error::from_ntstatus(status))
    }

    pub(crate) fn inject_dll(&self, dll_stats: *mut DllStats, pid: HANDLE) -> Result<(), Error> {
        if !dll_stats.is_null() && !unsafe { dll_stats.as_ref() }.unwrap().is_valid() {
            return Err(Error::INVALID_PARAMETER);
        }
        let mut kapc = Box::new(KAPC {
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
                &mut *kapc,
                PsGetCurrentThread(),
                OriginalApcEnvironment,
                Some(apc_kernel_routine),
                Some(apc_rundown_routine),
                Some(apc_normal_routine),
                KernelMode as KPROCESSOR_MODE,
                &mut *kapc as *mut _ as _,
            );
            ObReferenceObject(__MOD.as_mut().unwrap()._device.as_raw_mut() as _);
            ObReferenceObject((*dll_stats).section);
        }

        unsafe {
            let res = KeInsertQueueApc(kapc.as_mut() as _, dll_stats as _, pid as *const _ as _, 0);
            if 0 == res {
                ObDereferenceObject(__MOD.as_mut().unwrap()._device.as_raw_mut() as _);
                ObDereferenceObject((*dll_stats).section);
                return Err(Error::UNSUCCESSFUL);
            }
        }
        Box::into_raw(kapc);

        Ok(())
    }
}

pub struct DllStats {
    pub(crate) section_type: SectionType,
    pub(crate) section: *mut c_void,
}

impl DllStats {
    pub(crate) fn is_valid(&self) -> bool {
        !self.section.is_null()
    }
}
