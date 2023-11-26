#![feature(str_from_utf16_endian)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

use crate::{inject::InjectView, process::ProcessOverview, util::unique_id};

mod dump;
mod inject;
mod process;
mod util;

fn main() -> Result<(), eframe::Error> {
    env_logger::init();

    let mut options = eframe::NativeOptions::default();
    options.viewport = egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]);
    eframe::run_native("Serpent", options, Box::new(|_cc| Box::<App>::default()))
}

struct App {
    process_overview_view: Option<Box<ProcessOverview>>,
    dump_view: Option<Box<InjectView>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            process_overview_view: Some(Default::default()),
            dump_view: None,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut egui::Frame) {
        egui::TopBottomPanel::top(unique_id!()).show(ctx, |ui| {
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
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(view) = &mut self.process_overview_view {
                if let Some(value) = view.value {
                    self.process_overview_view = None;
                    self.dump_view = Some(Box::new(InjectView::new(value.get())));
                } else {
                    view.show(ui);
                }
            }
            if let Some(view) = &mut self.dump_view {
                view.show(ui);
            }
        });
    }
}
