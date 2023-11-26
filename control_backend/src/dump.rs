use std::{
    ffi::OsString,
    mem::{size_of_val, uninitialized},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    ptr::addr_of,
};

use log::{debug, warn};
use windows::Win32::{
    Foundation::{CloseHandle, FALSE, HANDLE, MAX_PATH},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER},
        ProcessStatus::{EnumProcessModules, GetModuleFileNameExW, GetModuleInformation},
        SystemServices::IMAGE_DOS_HEADER,
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

pub mod general;
pub mod overwatch;

pub struct Process {
    pub handle: HANDLE,
    pub modules: Vec<Module>,
}

impl Process {
    pub fn new(process_id: u32) -> Self {
        let process;
        let mut modules = Vec::new();
        unsafe {
            debug!("Opening process {process_id}");
            process = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                process_id,
            )
            .unwrap();

            let mut hmodule_buffer: [_; 128] = uninitialized();
            let mut hmodule_buffer_used = uninitialized();
            EnumProcessModules(
                process,
                hmodule_buffer.as_mut_ptr(),
                size_of_val(&hmodule_buffer) as u32,
                &mut hmodule_buffer_used,
            )
            .unwrap();
            let hmodules =
                &hmodule_buffer[..hmodule_buffer_used as usize / size_of_val(&hmodule_buffer[0])];

            let mut path_buffer: [_; MAX_PATH as usize] = uninitialized();
            for &hmodule in hmodules {
                GetModuleFileNameExW(process, hmodule, &mut path_buffer);
                let path = PathBuf::from(OsString::from_wide(
                    &path_buffer[..path_buffer.iter().position(|&c| c == 0).unwrap()],
                ));
                let mut module_info = uninitialized();
                GetModuleInformation(
                    process,
                    hmodule,
                    &mut module_info,
                    size_of_val(&module_info) as u32,
                )
                .unwrap();

                debug!(
                    "Copying image of module {} 0x{:x}-0x{:x}",
                    path.to_str().unwrap(),
                    module_info.lpBaseOfDll as usize,
                    module_info.lpBaseOfDll as usize + module_info.SizeOfImage as usize
                );
                let mut image = vec![0u8; module_info.SizeOfImage as usize];
                if ReadProcessMemory(
                    process,
                    module_info.lpBaseOfDll,
                    image.as_mut_ptr() as *mut _,
                    image.len(),
                    None,
                )
                .is_err()
                {
                    warn!("Failed to copy image");
                    continue;
                }

                modules.push(Module {
                    path,
                    image_base: module_info.lpBaseOfDll as usize,
                    image,
                    image_file: None,
                });
            }

            // First module is the executable
            modules[0].image_file = Some(std::fs::read(&modules[0].path).unwrap());
        }

        Self {
            handle: process,
            modules,
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let module = &self.modules[0];
        let image_file = module.image_file.as_ref().unwrap();
        let image_file_ptr = image_file.as_ptr() as usize;

        let mut result = vec![];
        unsafe {
            let image = &module.image;
            let image_ptr = image.as_ptr() as usize;
            let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

            // Use image file header because image header might be altered
            let file_dos_headers = &*(image_file_ptr as *const IMAGE_DOS_HEADER);
            let file_nt_headers = &*((image_file_ptr + file_dos_headers.e_lfanew as usize)
                as *const IMAGE_NT_HEADERS64);
            let sections = std::slice::from_raw_parts(
                addr_of!(*file_nt_headers).add(1) as *const IMAGE_SECTION_HEADER,
                file_nt_headers.FileHeader.NumberOfSections as usize,
            );

            // Copy header
            result.extend_from_slice(
                &image_file[..file_nt_headers.OptionalHeader.SizeOfHeaders as usize],
            );

            // Copy sections
            for section in sections {
                // Preserve sections which are intended and expected to be changed
                result.extend_from_slice(
                    &module.image[section.VirtualAddress as usize..]
                        [..section.SizeOfRawData as usize],
                )
            }

            // Fix base address in preserved header
            let result_ptr = result.as_ptr() as usize;
            let result_dos_headers = &*(result_ptr as *const IMAGE_DOS_HEADER);
            let mut result_nt_headers = &mut *((result_ptr + result_dos_headers.e_lfanew as usize)
                as *mut IMAGE_NT_HEADERS64);
            result_nt_headers.OptionalHeader.ImageBase = nt_headers.OptionalHeader.ImageBase;
        }
        result
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

pub struct Module {
    pub path: PathBuf,
    pub image_base: usize,
    pub image: Vec<u8>,
    pub image_file: Option<Vec<u8>>,
}

pub trait Fixup {
    fn fixup(&self, process: &Process);
}
