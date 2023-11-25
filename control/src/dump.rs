use eframe::egui;

pub struct DumpWindow {

}

impl DumpWindow {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("DumpWindow").show(ui, |ui| {
            ui.label("Hello");
            ui.button("Process");
            ui.end_row();
        });
    }
}
