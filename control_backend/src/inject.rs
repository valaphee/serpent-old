use std::path::Path;

use windows::{
    core::{s, HSTRING},
    Win32::{
        Foundation::FALSE,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
            Threading::{
                CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_CREATE_RUN_IMMEDIATELY,
            },
        },
    },
};

pub fn load_library(process_id: u32, path: impl AsRef<Path>) {
    let path = HSTRING::from(path.as_ref());
    let path = path.as_wide();
    unsafe {
        let process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            process_id,
        )
        .unwrap();
        let path_address = VirtualAllocEx(
            process,
            None,
            std::mem::size_of_val(path),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        WriteProcessMemory(
            process,
            path_address as *const std::ffi::c_void,
            path.as_ptr() as *const _,
            std::mem::size_of_val(path),
            None,
        )
        .unwrap();
        let load_library_w =
            GetProcAddress(GetModuleHandleA(s!("kernel32.dll"))?, s!("LoadLibraryW"));
        let load_library_thread = CreateRemoteThread(
            process,
            None,
            0,
            Some(std::mem::transmute(load_library_w)),
            Some(path_address),
            THREAD_CREATE_RUN_IMMEDIATELY.0,
            None,
        )
        .unwrap();
        WaitForSingleObject(load_library_thread, INFINITE);
    }
}
