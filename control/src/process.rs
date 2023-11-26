use std::{
    ffi::OsString,
    mem::{size_of_val, uninitialized},
    num::NonZeroU32,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
};

use eframe::egui;

use windows::Win32::{
    Foundation::{CloseHandle, FALSE, MAX_PATH},
    System::{
        ProcessStatus::{EnumProcessModules, EnumProcesses, GetModuleFileNameExW},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

pub struct ProcessOverview {
    items: Vec<Process>,

    pub value: Option<NonZeroU32>,
}

impl Default for ProcessOverview {
    fn default() -> Self {
        let mut _self = Self {
            items: Default::default(),
            value: Default::default(),
        };
        _self.refresh();
        _self
    }
}

impl ProcessOverview {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        if ui.input(|i| i.key_pressed(egui::Key::F5)) {
            self.refresh();
        }
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .auto_shrink([false, false])
            .column(egui_extras::Column::auto().resizable(true))
            .column(egui_extras::Column::remainder())
            .header(12.0, |mut header| {
                header.col(|ui| {
                    ui.label("PID");
                });
                header.col(|ui| {
                    ui.label("Name");
                });
            })
            .body(|body| {
                body.rows(12.0, self.items.len(), |i, mut row| {
                    let item = &self.items[i];
                    row.col(|ui| {
                        if ui.selectable_label(false, item.id.to_string()).clicked() {
                            self.value = NonZeroU32::new(item.id);
                            ui.ctx().request_repaint();
                        }
                    });
                    row.col(|ui| {
                        ui.label(item.path.file_name().unwrap().to_str().unwrap());
                    });
                });
            })
    }

    fn refresh(&mut self) {
        self.items.clear();

        unsafe {
            let mut process_id_buffer: [_; 1024] = uninitialized();
            let mut process_id_buffer_used = uninitialized();
            EnumProcesses(
                process_id_buffer.as_mut_ptr(),
                size_of_val(&process_id_buffer) as u32,
                &mut process_id_buffer_used,
            )
            .unwrap();
            let process_ids = process_id_buffer
                [..process_id_buffer_used as usize / size_of_val(&process_id_buffer[0])]
                .to_owned();

            let mut path_buffer: [_; MAX_PATH as usize] = uninitialized();
            for process_id in process_ids {
                let Ok(process) = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE,
                    process_id,
                ) else {
                    continue;
                };

                let mut module = uninitialized();
                if EnumProcessModules(process, &mut module, size_of_val(&module) as u32, &mut 0)
                    .is_err()
                {
                    continue;
                }

                GetModuleFileNameExW(process, module, &mut path_buffer);
                let process_path = OsString::from_wide(
                    &path_buffer[..path_buffer.iter().position(|&c| c == 0).unwrap()],
                )
                .into();

                CloseHandle(process).unwrap();

                self.items.push(Process {
                    id: process_id,
                    path: process_path,
                });
            }
        }
    }
}

struct Process {
    id: u32,
    path: PathBuf,
}
