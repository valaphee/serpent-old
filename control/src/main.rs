#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::{egui, Frame};

use crate::process::ProcessOverviewWindow;

mod process;

fn main() -> Result<(), eframe::Error> {
    eframe::run_native(
        "Serpent",
        eframe::NativeOptions::default(),
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
            if let Some(result) = window.show(ctx) {
                if result.get() == u32::MAX {
                    self.process_overview_window = None;
                    ctx.request_repaint();
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {});
    }
}
