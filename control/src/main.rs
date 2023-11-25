#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::{egui, Frame};
use crate::dump::DumpWindow;

use crate::process::ProcessOverviewWindow;

mod process;
mod dump;

fn main() -> Result<(), eframe::Error> {
    let mut options = eframe::NativeOptions::default();
    options.viewport = egui::ViewportBuilder::default().with_inner_size([1000.0, 1000.0]);
    eframe::run_native(
        "Serpent",
        options,
        Box::new(|cc| Box::<App>::default()),
    )
}

struct App {
    process_overview_window: Option<ProcessOverviewWindow>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            process_overview_window: Some(ProcessOverviewWindow::default()),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        if let Some(window) = &self.process_overview_window {
            if let Some(result) = window.value() {
                self.process_overview_window = None;
            } else {
                window.show(ctx);
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            /*ui.vertical_centered_justified(|ui| {
                ui.button("Dump");
                ui.button("Inject");
                ui.button("Exit");
            });*/
            DumpWindow {}.show(ui);
        });
    }
}
