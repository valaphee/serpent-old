use eframe::egui;

pub struct Inject {
    process_id: u32,
}

impl Inject {
    pub fn new(process_id: u32) -> Self {
        Self { process_id }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {}
}
