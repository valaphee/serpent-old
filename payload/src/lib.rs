mod util;

use crate::util::unique_id;
use eframe::egui;
use windows::Win32::{
    Foundation::HMODULE,
    System::{LibraryLoader::DisableThreadLibraryCalls, SystemServices::DLL_PROCESS_ATTACH},
};

#[no_mangle]
unsafe extern "system" fn DllMain(
    module: HMODULE,
    reason: u32,
    _reserved: *const std::ffi::c_void,
) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(module).ok().unwrap();

        env_logger::init();
        let mut options = eframe::NativeOptions::default();
        options.viewport = egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]);
        eframe::run_native("Serpent", options, Box::new(|_cc| Box::<App>::default()))
    }

    true
}

struct App {}

impl Default for App {
    fn default() -> Self {
        Self {}
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut egui::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {});
    }
}
