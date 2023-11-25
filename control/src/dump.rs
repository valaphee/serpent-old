use std::{
    ffi::OsString,
    mem::{size_of_val, uninitialized},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    ptr::addr_of,
};

use eframe::egui;
use windows::Win32::{
    Foundation::{FALSE, HANDLE, MAX_PATH},
    System::{
        Diagnostics::Debug::{
            ReadProcessMemory, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT,
            IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
        },
        ProcessStatus::{EnumProcessModules, GetModuleFileNameExW, GetModuleInformation},
        SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::dump::{general::GeneralDumpExt, overwatch::OverwatchDumpExt};

mod general;
mod overwatch;

#[derive(Default)]
pub struct Dump {
    process: HANDLE,
    modules: Vec<Module>,
}

impl Dump {
    pub fn open(process_id: u32) -> Self {
        let process;
        let mut modules = Vec::new();
        unsafe {
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
                    continue;
                }

                modules.push(Module {
                    path,
                    image,
                    image_file: None,
                    image_base: format!("0x{:016X}", module_info.lpBaseOfDll as usize),
                });
            }

            // First module is the executable
            modules[0].image_file = Some(std::fs::read(&modules[0].path).unwrap());
        }

        Self { process, modules }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            egui_extras::TableBuilder::new(ui)
                .striped(true)
                .auto_shrink([false, true])
                .column(egui_extras::Column::auto().resizable(true))
                .column(egui_extras::Column::auto().resizable(true))
                .column(egui_extras::Column::remainder())
                .header(12.0, |mut header| {
                    header.col(|ui| {
                        ui.label("Path");
                    });
                    header.col(|ui| {
                        ui.label("Base");
                    });
                    header.col(|ui| {
                        ui.label("Size");
                    });
                })
                .body(|body| {
                    body.rows(12.0, self.modules.len(), |i, mut row| {
                        let module = &self.modules[i];
                        row.col(|ui| {
                            ui.add(egui::Label::new(module.path.to_str().unwrap()).wrap(false));
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&module.image_base).monospace(),
                                )
                                .wrap(false),
                            );
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format!("0x{:X}", module.image.len()))
                                        .monospace(),
                                )
                                .wrap(false),
                            );
                        });
                    });
                });
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    if let Some(path) = rfd::FileDialog::new().save_file() {
                        self.relocate();
                        self.import_search();
                        self.string_obfuscation();
                        std::fs::write(path, self.build()).unwrap();
                    }
                }
            });
        });
    }

    fn build(&self) -> Vec<u8> {
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
            let file_sections = std::slice::from_raw_parts(
                addr_of!(*file_nt_headers).add(1) as *const IMAGE_SECTION_HEADER,
                file_nt_headers.FileHeader.NumberOfSections as usize,
            );

            // Preserve header, don't trust the image header
            result.extend_from_slice(
                &image_file[..file_nt_headers.OptionalHeader.SizeOfHeaders as usize],
            );

            // Copy sections
            for section in file_sections {
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

struct Module {
    path: PathBuf,
    image: Vec<u8>,
    image_file: Option<Vec<u8>>,

    image_base: String,
}

impl Module {
    fn contains(&self, address: usize) -> bool {
        unsafe {
            let image_ptr = self.image.as_ptr() as usize;
            let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            address >= nt_headers.OptionalHeader.ImageBase as usize
                && address < nt_headers.OptionalHeader.ImageBase as usize + self.image.len()
        }
    }

    fn export_name_by_address(&self, address: usize) -> Option<&[u8]> {
        unsafe {
            let image_ptr = self.image.as_ptr() as usize;
            let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            let export_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                as *const IMAGE_DATA_DIRECTORY);
            let export_directory = &*((image_ptr + export_data_directory.VirtualAddress as usize)
                as *const IMAGE_EXPORT_DIRECTORY);
            let functions = std::slice::from_raw_parts(
                (image_ptr + export_directory.AddressOfFunctions as usize) as *const u32,
                export_directory.NumberOfFunctions as usize,
            );
            let names = std::slice::from_raw_parts(
                (image_ptr + export_directory.AddressOfNames as usize) as *const u32,
                export_directory.NumberOfNames as usize,
            );
            let name_ordinals = std::slice::from_raw_parts(
                (image_ptr + export_directory.AddressOfNameOrdinals as usize) as *const u16,
                export_directory.NumberOfNames as usize,
            );

            for (&name, &name_ordinal) in names.iter().zip(name_ordinals) {
                let function = nt_headers.OptionalHeader.ImageBase as usize
                    + functions[name_ordinal as usize] as usize;
                if function != address {
                    continue;
                }

                let name_ptr = (image_ptr + name as usize) as *const u8;
                let mut name_end_ptr = name_ptr;
                while *name_end_ptr != 0 {
                    name_end_ptr = name_end_ptr.add(1)
                }
                let name_length = name_end_ptr.offset_from(name_ptr) as usize;
                let name = std::slice::from_raw_parts(name_ptr, name_length + 1);
                return Some(name);
            }

            None
        }
    }

    fn export_name_by_forward(&self, forward: &[u8]) -> Option<&[u8]> {
        unsafe {
            let image_ptr = self.image.as_ptr() as usize;
            let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            let export_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                as *const IMAGE_DATA_DIRECTORY);
            let export_directory = &*((image_ptr + export_data_directory.VirtualAddress as usize)
                as *const IMAGE_EXPORT_DIRECTORY);
            let functions = std::slice::from_raw_parts(
                (image_ptr + export_directory.AddressOfFunctions as usize) as *const u32,
                export_directory.NumberOfFunctions as usize,
            );
            let names = std::slice::from_raw_parts(
                (image_ptr + export_directory.AddressOfNames as usize) as *const u32,
                export_directory.NumberOfNames as usize,
            );
            let name_ordinals = std::slice::from_raw_parts(
                (image_ptr + export_directory.AddressOfNameOrdinals as usize) as *const u16,
                export_directory.NumberOfNames as usize,
            );

            for (&name, &name_ordinal) in names.iter().zip(name_ordinals) {
                let function = functions[name_ordinal as usize] as usize;
                if function < export_data_directory.VirtualAddress as usize
                    || function
                        >= (export_data_directory.VirtualAddress + export_data_directory.Size)
                            as usize
                {
                    continue;
                }

                let mut forward_name = std::slice::from_raw_parts(
                    (image_ptr + function) as *const u8,
                    function - export_data_directory.VirtualAddress as usize
                        + export_data_directory.Size as usize,
                );
                let forward_dll_name_end = forward_name.iter().position(|&c| c == b'.').unwrap();
                let forward_name_end = forward_name.iter().position(|&c| c == 0).unwrap();
                if forward != &forward_name[forward_dll_name_end + 1..forward_name_end + 1] {
                    continue;
                }

                let name_ptr = (image_ptr + name as usize) as *const u8;
                let mut name_end_ptr = name_ptr;
                while *name_end_ptr != 0 {
                    name_end_ptr = name_end_ptr.add(1)
                }
                let name_length = name_end_ptr.offset_from(name_ptr) as usize;
                let name = std::slice::from_raw_parts(name_ptr, name_length + 1);
                return Some(name);
            }

            None
        }
    }
}
