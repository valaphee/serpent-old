use eframe::egui;

use serpent_control_backend::inject;

pub struct InjectView {
    process_id: u32,
}

impl InjectView {
    pub fn new(process_id: u32) -> Self {
        Self { process_id }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            if ui.button("Inject").clicked() {
                inject::load_library(self.process_id, "target\\debug\\serpent_payload.dll");
            }
        });
    }
}
