use std::{
    ffi::OsString,
    mem::{size_of_val, uninitialized},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
};

use eframe::egui;
use windows::Win32::{
    Foundation::{FALSE, MAX_PATH},
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        ProcessStatus::{EnumProcessModules, GetModuleFileNameExW, GetModuleInformation},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

#[derive(Default)]
pub struct DumpView {
    modules: Vec<Module>,
}

impl DumpView {
    pub fn open(process_id: u32) -> Self {
        let mut modules = Vec::new();
        unsafe {
            let process = OpenProcess(
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

        Self { modules }
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
            ui.button("Dump");
        });
    }
}

struct Module {
    path: PathBuf,
    image: Vec<u8>,
    image_file: Option<Vec<u8>>,

    image_base: String,
}
