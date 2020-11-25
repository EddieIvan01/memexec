pub mod def;
pub mod error;
pub mod winapi;

use crate::peparser::def::*;
use crate::peparser::PE;
use def::{DllMain, DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RESERVE};
use error::{Error, Result};
use std::ffi::CStr;
use std::mem;
use std::os::raw::c_void;
use std::ptr;

#[cfg(feature = "hook")]
use hook::{ProcDesc, Thunk};
#[cfg(feature = "hook")]
use std::collections::HashMap;
#[cfg(feature = "hook")]
pub mod hook;

unsafe fn patch_reloc_table(pe: &PE, base_addr: *const c_void) -> Result<()> {
    let reloc_entry = &pe.pe_header.nt_header.get_data_directory()[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    let image_base_offset = base_addr as isize - pe.pe_header.nt_header.get_image_base() as isize;

    if image_base_offset != 0 && reloc_entry.VirtualAddress != 0 && reloc_entry.Size != 0 {
        let mut reloc_table_ptr =
            base_addr.offset(reloc_entry.VirtualAddress as isize) as *const u8;

        loop {
            let reloc_block =
                &*mem::transmute::<*const u8, *const IMAGE_BASE_RELOCATION>(reloc_table_ptr);
            if reloc_block.SizeOfBlock == 0 && reloc_block.VirtualAddress == 0 {
                break;
            }

            for i in 0..(reloc_block.SizeOfBlock as isize - 8) / 2 {
                let item = *(reloc_table_ptr.offset(8 + i * 2) as *const u16);
                if (item >> 12) == IMAGE_REL_BASED {
                    let patch_addr = base_addr
                        .offset(reloc_block.VirtualAddress as isize + (item & 0xfff) as isize)
                        as *mut isize;
                    *patch_addr = *patch_addr + image_base_offset;
                }
            }

            reloc_table_ptr = reloc_table_ptr.offset(reloc_block.SizeOfBlock as isize);
        }
    }
    Ok(())
}

unsafe fn resolve_import_symbols(
    pe: &PE,
    base_addr: *const c_void,
    #[cfg(feature = "hook")] hooks: Option<&HashMap<ProcDesc, *const c_void>>,
) -> Result<()> {
    let import_entry = &pe.pe_header.nt_header.get_data_directory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_entry.Size != 0 && import_entry.VirtualAddress != 0 {
        let mut import_desc_ptr = base_addr.offset(import_entry.VirtualAddress as isize)
            as *const IMAGE_IMPORT_DESCRIPTOR;
        loop {
            let import_desc = &*import_desc_ptr;
            if 0 == import_desc.Name
                && 0 == import_desc.FirstThunk
                && 0 == import_desc.OriginalFirstThunk
                && 0 == import_desc.TimeDateStamp
                && 0 == import_desc.ForwarderChain
            {
                break;
            }

            let dll_name = CStr::from_ptr(base_addr.offset(import_desc.Name as isize) as *const i8)
                .to_str()?;
            // TODO: implement loading module by calling self recursively
            let hmod = winapi::load_library(&dll_name)?;

            // Whether the ILT (called INT in IDA) exists? (some linkers didn't generate the ILT)
            let (mut iat_ptr, mut ilt_ptr) = if import_desc.OriginalFirstThunk != 0 {
                (
                    base_addr.offset(import_desc.FirstThunk as isize) as *mut IMAGE_THUNK_DATA,
                    base_addr.offset(import_desc.OriginalFirstThunk as isize)
                        as *const IMAGE_THUNK_DATA,
                )
            } else {
                (
                    base_addr.offset(import_desc.FirstThunk as isize) as *mut IMAGE_THUNK_DATA,
                    base_addr.offset(import_desc.FirstThunk as isize) as *const IMAGE_THUNK_DATA,
                )
            };

            loop {
                let thunk_data = *ilt_ptr as isize;
                if thunk_data == 0 {
                    break;
                }

                if thunk_data & IMAGE_ORDINAL_FLAG != 0 {
                    // Import by ordinal number

                    #[cfg(not(feature = "hook"))]
                    let proc_addr = winapi::get_proc_address_by_ordinal(hmod, thunk_data & 0xffff)?;
                    #[cfg(feature = "hook")]
                    let proc_addr = match hooks {
                        Some(hooks) => {
                            match hooks.get(&ProcDesc::new(
                                dll_name,
                                Thunk::Ordinal(thunk_data & 0xffff),
                            )) {
                                Some(addr) => *addr,
                                None => {
                                    winapi::get_proc_address_by_ordinal(hmod, thunk_data & 0xffff)?
                                }
                            }
                        }
                        None => winapi::get_proc_address_by_ordinal(hmod, thunk_data & 0xffff)?,
                    };

                    // rust-lang/rust/issues/15701
                    *iat_ptr = proc_addr as IMAGE_THUNK_DATA;
                } else {
                    // TODO: implement resolving proc address by `IMAGE_IMPORT_BY_NAME.Hint`
                    let hint_name_table = &*mem::transmute::<
                        *const c_void,
                        *const IMAGE_IMPORT_BY_NAME,
                    >(base_addr.offset(thunk_data));
                    if 0 == hint_name_table.Name {
                        break;
                    }

                    #[cfg(not(feature = "hook"))]
                    let proc_addr = winapi::get_proc_address_by_name(
                        hmod,
                        CStr::from_ptr(&hint_name_table.Name as _).to_str()?,
                    )?;
                    #[cfg(feature = "hook")]
                    let proc_addr = match hooks {
                        Some(hooks) => match hooks.get(&ProcDesc::new(
                            dll_name,
                            Thunk::Name(CStr::from_ptr(&hint_name_table.Name as _).to_str()?),
                        )) {
                            Some(addr) => *addr,
                            None => winapi::get_proc_address_by_name(
                                hmod,
                                CStr::from_ptr(&hint_name_table.Name as _).to_str()?,
                            )?,
                        },
                        None => winapi::get_proc_address_by_name(
                            hmod,
                            CStr::from_ptr(&hint_name_table.Name as _).to_str()?,
                        )?,
                    };

                    *iat_ptr = proc_addr as IMAGE_THUNK_DATA;
                }

                iat_ptr = iat_ptr.offset(1);
                ilt_ptr = ilt_ptr.offset(1);
            }

            import_desc_ptr = import_desc_ptr.offset(1);
        }
    }
    Ok(())
}

unsafe fn call_tls_callback(pe: &PE, base_addr: *const c_void) -> Result<()> {
    let tls_entry = &pe.pe_header.nt_header.get_data_directory()[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_entry.Size != 0 && tls_entry.VirtualAddress != 0 {
        let tls = &*mem::transmute::<*const c_void, *const IMAGE_TLS_DIRECTORY>(
            base_addr.offset(tls_entry.VirtualAddress as isize),
        );
        let mut tls_callback_addr = tls.AddressOfCallBacks as *const *const c_void;

        loop {
            if *tls_callback_addr == 0 as _ {
                break;
            }

            mem::transmute::<*const c_void, PIMAGE_TLS_CALLBACK>(*tls_callback_addr)(
                base_addr,
                DLL_PROCESS_ATTACH,
                0 as _,
            );
            tls_callback_addr = tls_callback_addr.offset(1);
        }
    }
    Ok(())
}

unsafe fn load_pe_into_mem(
    pe: &PE,
    #[cfg(feature = "hook")] hooks: Option<&HashMap<ProcDesc, *const c_void>>,
) -> Result<*const c_void> {
    // Step1: allocate memory for image
    let mut base_addr = pe.pe_header.nt_header.get_image_base();
    let size = pe.pe_header.nt_header.get_size_of_image();

    // ASLR
    if winapi::nt_alloc_vm(
        &base_addr as _,
        &size as _,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .is_err()
    {
        base_addr = 0 as *const c_void;
        winapi::nt_alloc_vm(
            &base_addr as _,
            &size as _,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )?;
    }

    // Step2: copy sections
    for section in pe.section_area.section_table {
        ptr::copy_nonoverlapping(
            pe.raw.as_ptr().offset(section.PointerToRawData as isize),
            base_addr.offset(section.VirtualAddress as isize) as *mut u8,
            section.SizeOfRawData as usize,
        );
    }

    // Step3: handle base relocataion table
    patch_reloc_table(pe, base_addr)?;

    // Step4: resolve import symbols
    #[cfg(feature = "hook")]
    resolve_import_symbols(pe, base_addr, hooks)?;
    #[cfg(not(feature = "hook"))]
    resolve_import_symbols(pe, base_addr)?;

    // Step5: restore sections' protection
    for section in pe.section_area.section_table {
        let size = section.SizeOfRawData as usize;
        if size == 0 {
            continue;
        }

        winapi::nt_protect_vm(
            &(base_addr.offset(section.VirtualAddress as isize)) as _,
            &size as _,
            section.get_protection(),
        )?;
    }

    // Step6: call TLS callback
    call_tls_callback(pe, base_addr)?;

    Ok(base_addr)
}

fn check_platform(pe: &PE) -> Result<()> {
    if (mem::size_of::<usize>() == 4 && pe.is_x86())
        || (mem::size_of::<usize>() == 8 && pe.is_x64())
    {
        Ok(())
    } else {
        Err(Error::MismatchedArch)
    }
}

pub struct ExeLoader {
    entry_point_va: *const c_void,
}

impl ExeLoader {
    pub unsafe fn new(
        pe: &PE,
        #[cfg(feature = "hook")] hooks: Option<&HashMap<ProcDesc, *const c_void>>,
    ) -> Result<ExeLoader> {
        check_platform(pe)?;
        if pe.is_dll() {
            return Err(Error::MismatchedLoader);
        }

        if pe.is_dot_net() {
            return Err(Error::UnsupportedDotNetExecutable);
        }

        let entry_point = pe.pe_header.nt_header.get_address_of_entry_point();
        if entry_point == 0 {
            Err(Error::NoEntryPoint)
        } else {
            #[cfg(feature = "hook")]
            let entry_point_va = load_pe_into_mem(pe, hooks)?.offset(entry_point);
            #[cfg(not(feature = "hook"))]
            let entry_point_va = load_pe_into_mem(pe)?.offset(entry_point);
            Ok(ExeLoader {
                entry_point_va: entry_point_va,
            })
        }
    }

    pub unsafe fn invoke_entry_point(&self) {
        mem::transmute::<*const c_void, extern "system" fn()>(self.entry_point_va)()
    }
}

pub struct DllLoader {
    entry_point_va: *const c_void,
}

impl DllLoader {
    pub unsafe fn new(
        pe: &PE,
        #[cfg(feature = "hook")] hooks: Option<&HashMap<ProcDesc, *const c_void>>,
    ) -> Result<DllLoader> {
        check_platform(pe)?;
        if !pe.is_dll() {
            return Err(Error::MismatchedLoader);
        }

        if pe.is_dot_net() {
            return Err(Error::UnsupportedDotNetExecutable);
        }

        let entry_point = pe.pe_header.nt_header.get_address_of_entry_point();
        if entry_point == 0 {
            Err(Error::NoEntryPoint)
        } else {
            #[cfg(feature = "hook")]
            let entry_point_va = load_pe_into_mem(pe, hooks)?.offset(entry_point);
            #[cfg(not(feature = "hook"))]
            let entry_point_va = load_pe_into_mem(pe)?.offset(entry_point);
            Ok(DllLoader {
                entry_point_va: entry_point_va,
            })
        }
    }

    pub unsafe fn invoke_entry_point(
        &self,
        hmod: *const c_void,
        reason_for_call: u32,
        lp_reserved: *const c_void,
    ) -> bool {
        mem::transmute::<*const c_void, DllMain>(self.entry_point_va)(
            hmod,
            reason_for_call,
            lp_reserved,
        )
    }
}
