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
    }

    true
}
