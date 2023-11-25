#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::{egui, Frame};

use crate::process::ProcessOverviewWindow;

mod process;

fn main() -> Result<(), eframe::Error> {
    let mut options = eframe::NativeOptions::default();
    options.viewport = egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]);
    eframe::run_native("Serpent", options, Box::new(|cc| Box::<App>::default()))
}

struct App {
    process_overview_window: Option<Box<ProcessOverviewWindow>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            process_overview_window: Some(Default::default()),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        if let Some(window) = &mut self.process_overview_window {
            if let Some(result) = window.value {
                self.process_overview_window = None;
            } else {
                window.show(ctx);
            }
        } else {
            egui::TopBottomPanel::top("main.rs:42").show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        ui.button("Open");
                        ui.button("Exit");
                    });
                    ui.menu_button("Help", |ui| {
                        ui.button("About");
                    });
                });
            });
            egui::CentralPanel::default().show(ctx, |ui| {});
        }
    }
}
