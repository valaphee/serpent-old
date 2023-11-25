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

use crate::util::unique_id;

#[derive(Default)]
pub struct DumpView {
    modules: Vec<Module>,
}

struct Module {
    path: PathBuf,
    image: Vec<u8>,
    image_file: Option<Vec<u8>>,
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
                });
            }

            // First module is the executable
            modules[0].image_file = Some(std::fs::read(&modules[0].path).unwrap());
        }

        Self { modules }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new(unique_id!()).show(ui, |ui| {
                        for module in &self.modules {
                            ui.label(module.path.to_str().unwrap());
                            ui.end_row();
                        }
                    });
                });
            ui.button("Dump");
        });
    }
}
