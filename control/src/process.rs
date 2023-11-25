use std::{
    ffi::OsString,
    mem::{size_of_val, uninitialized},
    num::NonZeroU32,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use eframe::egui;
use windows::Win32::{
    Foundation::{CloseHandle, FALSE, MAX_PATH},
    System::{
        ProcessStatus::{EnumProcessModules, EnumProcesses, GetModuleFileNameExW},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

#[derive(Default)]
pub struct ProcessOverviewWindow {
    inner: Arc<Mutex<ProcessOverviewWindowInner>>,
}

impl ProcessOverviewWindow {
    pub fn show(&self, ctx: &egui::Context) -> Option<NonZeroU32> {
        let inner = self.inner.clone();
        ctx.show_viewport_deferred(
            egui::ViewportId::from_hash_of("ProcessOverviewWindow"),
            egui::ViewportBuilder::default()
                .with_title("Process Overview")
                .with_inner_size([400.0, 600.0]),
            move |ctx, class| {
                inner.lock().unwrap().show(ctx);
            },
        );
        self.inner.lock().unwrap().result
    }
}

struct ProcessOverviewWindowInner {
    items: Vec<ProcessOverview>,
    result: Option<NonZeroU32>,
}

struct ProcessOverview {
    id: u32,
    path: PathBuf,
}

impl Default for ProcessOverviewWindowInner {
    fn default() -> Self {
        let mut _self = Self {
            items: Default::default(),
            result: Default::default(),
        };
        _self.refresh();
        _self
    }
}

impl ProcessOverviewWindowInner {
    pub fn show(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) {
            self.result = NonZeroU32::new(u32::MAX);
        }
        if ctx.input(|i| i.key_pressed(egui::Key::F5)) {
            self.refresh();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
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
                .body(|mut body| {
                    body.rows(12.0, self.items.len(), |i, mut row| {
                        let item = &self.items[i];
                        row.col(|ui| {
                            if ui.selectable_label(false, item.id.to_string()).clicked() {
                                self.result = NonZeroU32::new(item.id);
                            }
                        });
                        row.col(|ui| {
                            ui.label(item.path.file_name().unwrap().to_str().unwrap());
                        });
                    });
                })
        });
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

                self.items.push(ProcessOverview {
                    id: process_id,
                    path: process_path,
                });
            }
        }
    }
}
