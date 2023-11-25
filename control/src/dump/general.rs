use std::{
    mem::{size_of, size_of_val},
    ptr::addr_of,
};

use windows::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    },
    SystemServices::{IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_REL_BASED_DIR64},
};

use crate::dump::Dump;

pub trait GeneralDumpExt {
    fn relocate(&mut self);
}

impl GeneralDumpExt for Dump {
    fn relocate(&mut self) {
        let module = &mut self.modules[0];
        let image = &mut module.image;
        let image_ptr = image.as_ptr() as usize;
        let image_file = module.image_file.as_ref().unwrap();
        let image_file_ptr = image_file.as_ptr() as usize;

        unsafe {
            // Use image file header because image header might be altered
            let dos_headers = &*(image_file_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &*((image_file_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            let basereloc_data_directory = &nt_headers.OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize];
            let sections = std::slice::from_raw_parts(
                addr_of!(*nt_headers).add(1) as *const IMAGE_SECTION_HEADER,
                nt_headers.FileHeader.NumberOfSections as usize,
            );

            // Go through all base relocations, zero-terminated
            let mut base_relocation = &*((image_ptr
                + basereloc_data_directory.VirtualAddress as usize)
                as *const IMAGE_BASE_RELOCATION);
            while base_relocation != &IMAGE_BASE_RELOCATION::default() {
                // Get section containing the base relocation for the chunk, and convert it to
                // file offset
                let section = sections
                    .iter()
                    .find(|section| {
                        section.VirtualAddress <= base_relocation.VirtualAddress
                            && section.VirtualAddress + section.SizeOfRawData
                                > base_relocation.VirtualAddress
                    })
                    .unwrap();
                let file_offset = (base_relocation.VirtualAddress - section.VirtualAddress
                    + section.PointerToRawData) as usize;

                // Update addresses in image
                let relocations = std::slice::from_raw_parts(
                    addr_of!(*base_relocation).add(1) as *const u16,
                    (base_relocation.SizeOfBlock as usize - size_of_val(&base_relocation))
                        / size_of::<u16>(),
                );
                for &relocation in relocations {
                    let r#type = (relocation >> 12) as u8;
                    let offset = relocation & 0xFFF;
                    if r#type == IMAGE_REL_BASED_DIR64 as u8 {
                        let rva = (base_relocation.VirtualAddress + offset as u32) as usize;
                        let file_offset = file_offset + offset as usize;
                        image[rva..rva + 8]
                            .copy_from_slice(&image_file[file_offset..file_offset + 8]);
                    }
                }

                base_relocation = &*((addr_of!(*base_relocation) as usize
                    + base_relocation.SizeOfBlock as usize)
                    as *const _)
            }
        }
    }
}