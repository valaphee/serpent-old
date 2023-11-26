use eframe::egui;

use serpent_control_backend::{dump, dump::Fixup};

pub struct DumpView {
    dump: dump::Process,
}

impl DumpView {
    pub fn new(process_id: u32) -> Self {
        Self {
            dump: dump::Process::new(process_id),
        }
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
                    body.rows(12.0, self.dump.modules.len(), |i, mut row| {
                        let module = &self.dump.modules[i];
                        row.col(|ui| {
                            ui.add(egui::Label::new(module.path.to_str().unwrap()).wrap(false));
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(format!("0x{:016X}", module.image_base))
                                        .monospace(),
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
            if ui.button("Save").clicked() {
                if let Some(path) = rfd::FileDialog::new().save_file() {
                    //dump::general::RelocateFixup.fixup(&self.dump);
                    dump::overwatch::ImportSearchFixup.fixup(&self.dump);
                    dump::overwatch::StringObfuscationFixup.fixup(&self.dump);
                    std::fs::write(path, self.build()).unwrap();
                }
            }
        });
    }
}
