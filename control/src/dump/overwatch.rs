use std::{
    collections::BTreeSet,
    ffi::c_void,
    io::Write,
    mem::{size_of, size_of_val},
    ptr::addr_of,
};

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use log::{debug, warn};
use unicorn_engine::{
    unicorn_const::{Arch, Mode, Permission},
    RegisterX86, Unicorn,
};
use windows::Win32::System::{
    Diagnostics::Debug::{
        ReadProcessMemory, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT,
        IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64,
        IMAGE_SECTION_HEADER,
    },
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
        IMAGE_IMPORT_DESCRIPTOR_0,
    },
};

use crate::dump::{Dump, Module};

pub trait OverwatchDumpExt {
    fn import_search(&mut self);

    fn string_obfuscation(&mut self);
}

impl OverwatchDumpExt for Dump {
    fn import_search(&mut self) {
        let module = &self.modules[0];
        let image_ptr = module.image.as_ptr() as usize;
        let image_file_ptr = module.image_file.as_ref().unwrap().as_ptr() as usize;

        unsafe {
            // Use image file header because image header might be altered
            let dos_headers = &*(image_file_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &mut *((image_file_ptr + dos_headers.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64);
            let sections = std::slice::from_raw_parts(
                addr_of!(*nt_headers).add(1) as *const IMAGE_SECTION_HEADER,
                nt_headers.FileHeader.NumberOfSections as usize,
            );
            let iat_data_directory =
                &mut nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT.0 as usize];

            // MSVC: import address table is always placed at the beginning of the .rdata
            // section
            iat_data_directory.VirtualAddress = sections
                .iter()
                .find(|section| &section.Name == b".rdata\0\0")
                .unwrap()
                .VirtualAddress;

            let iat = std::slice::from_raw_parts_mut(
                (image_ptr + iat_data_directory.VirtualAddress as usize) as *mut usize,
                iat_data_directory.Size as usize / size_of::<usize>(),
            );

            // Copy heap referenced by import address table
            let mut pages = BTreeSet::new();
            for &address in iat.iter() {
                if address == 0 {
                    continue;
                }

                pages.insert(address & !(0x1000 - 1));
            }
            let page_min = *pages.first().unwrap();
            let page_max = *pages.last().unwrap() + 0x1000;
            let mut heap: Vec<u8> = vec![0; page_max - page_min];
            for page in pages {
                ReadProcessMemory(
                    self.process,
                    page as *const c_void,
                    heap.as_mut_ptr().add(page - page_min) as *mut _,
                    0x1000,
                    None,
                )
                .unwrap();
            }

            // Start emulator
            let mut unicorn = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
            unicorn
                .mem_map_ptr(
                    page_min as u64,
                    heap.len(),
                    Permission::EXEC,
                    heap.as_mut_ptr() as *mut _,
                )
                .unwrap();

            // Stop decoding when indirect jmp is reached
            let mut decoder = Decoder::new(64, &heap[..], DecoderOptions::NONE);
            unicorn
                .add_code_hook(
                    page_min as u64,
                    page_max as u64,
                    move |unicorn, address, _| {
                        decoder.set_ip(address);
                        decoder.set_position(address as usize - page_min).unwrap();
                        let instruction = decoder.decode();
                        if instruction.mnemonic() != Mnemonic::Jmp
                            || instruction.op0_kind() != OpKind::Register
                        {
                            return;
                        }

                        unicorn.emu_stop().unwrap();
                    },
                )
                .unwrap();

            // Calculate addresses
            for address in &mut iat.iter_mut() {
                if *address == 0 {
                    continue;
                }

                unicorn
                    .emu_start(*address as u64, page_max as u64, 0, 0)
                    .unwrap();
                *address = unicorn.reg_read(RegisterX86::RAX).unwrap() as usize;
            }

            // Rebuild import directory
            let mut import_descriptors = vec![];
            let mut import_thunks = vec![];
            let mut import_names = vec![];
            for iat in iat.split(|&address| address == 0) {
                if iat.is_empty() {
                    continue;
                }

                // Search for module containing the given address
                let Some(module) = self.modules[1..]
                    .iter()
                    .find(|module| contains(module, iat[0]))
                else {
                    warn!("No dll exporting 0x{:x}", iat[0]);
                    continue;
                };
                debug!("Found dll {}", module.path.to_str().unwrap());

                // Add new import descriptor
                import_descriptors.push(IMAGE_IMPORT_DESCRIPTOR {
                    Anonymous: IMAGE_IMPORT_DESCRIPTOR_0 {
                        OriginalFirstThunk: (import_thunks.len() * size_of::<usize>()) as u32,
                    },
                    TimeDateStamp: 0,
                    ForwarderChain: 0,
                    Name: import_names.len() as u32,
                    FirstThunk: (iat.as_ptr() as usize - image_ptr) as u32,
                });
                import_names.extend_from_slice(
                    module
                        .path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .as_bytes(),
                );
                import_names.push(0);

                // Resolve imports by addresses pointing to exports
                for &address in iat {
                    let name = if let Some(name) = export_name_by_address(module, address) {
                        name
                    } else if let Some(forward_module) =
                        self.modules.iter().find(|module| contains(module, address))
                    {
                        if let Some(forward_name) = export_name_by_address(forward_module, address)
                        {
                            if let Some(name) = export_name_by_forward(module, forward_name) {
                                name
                            } else {
                                b"\0"
                            }
                        } else {
                            b"\0"
                        }
                    } else {
                        b"\0"
                    };
                    if name == b"\0" {
                        warn!(
                            "Dll {} not exporting 0x{:016X}",
                            module.path.to_str().unwrap(),
                            address
                        );
                    } else {
                        debug!(
                            "Found dll export {} 0x{:016X}",
                            std::str::from_utf8(&name[..name.len() - 1]).unwrap(),
                            address
                        );
                    }
                    import_thunks.push(import_names.len());
                    import_names.push(0);
                    import_names.push(0);
                    import_names.extend_from_slice(name);
                }
                import_thunks.push(0);
            }
            import_descriptors.push(IMAGE_IMPORT_DESCRIPTOR::default());

            // Cast to byte array
            let import_descriptor_bytes = std::slice::from_raw_parts(
                import_descriptors.as_ptr() as *const u8,
                size_of_val(&import_descriptors[..]),
            );
            let import_thunk_bytes = std::slice::from_raw_parts(
                import_thunks.as_ptr() as *const u8,
                size_of_val(&import_thunks[..]),
            );

            let rdata_section = sections
                .iter()
                .find(|section| &section.Name == b".rdata\0\0")
                .unwrap();

            // MSVC: import directory is always placed at the end of the .rdata section
            let import_data_directory = &mut nt_headers.OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize];
            import_data_directory.Size = import_descriptor_bytes.len() as u32;
            import_data_directory.VirtualAddress = rdata_section.VirtualAddress
                + rdata_section.SizeOfRawData
                - (import_descriptor_bytes.len() + import_thunk_bytes.len() + import_names.len())
                    as u32;

            // Fix addresses
            let import_thunks_offset =
                import_data_directory.VirtualAddress + import_descriptor_bytes.len() as u32;
            let import_names_offset = import_thunks_offset + import_thunk_bytes.len() as u32;
            for import_descriptor in &mut import_descriptors {
                if import_descriptor.FirstThunk == 0 {
                    continue;
                }
                import_descriptor.Anonymous.OriginalFirstThunk += import_thunks_offset;
                import_descriptor.Name += import_names_offset;
            }
            for import_thunk in &mut import_thunks {
                if *import_thunk == 0 {
                    continue;
                }
                *import_thunk += import_names_offset as usize;
            }

            // Overwrite import directory, thunks and names
            let mut import = std::slice::from_raw_parts_mut(
                (image_ptr + import_data_directory.VirtualAddress as usize) as *mut u8,
                import_descriptor_bytes.len() + import_thunk_bytes.len() + import_names.len(),
            );
            import.write_all(import_descriptor_bytes).unwrap();
            import.write_all(import_thunk_bytes).unwrap();
            import.write_all(&import_names).unwrap();

            let iat_data_directory =
                &mut nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT.0 as usize];
            std::slice::from_raw_parts_mut(
                (image_ptr + iat_data_directory.VirtualAddress as usize) as *mut u8,
                iat_data_directory.Size as usize,
            )
            .write_all(import_thunk_bytes)
            .unwrap();
        }
    }

    fn string_obfuscation(&mut self) {
        let module = &mut self.modules[0];
        let image = &mut module.image;

        let sections = unsafe {
            let image_ptr = image.as_ptr() as usize;
            let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
            let nt_headers =
                &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            std::slice::from_raw_parts(
                addr_of!(*nt_headers).add(1) as *const IMAGE_SECTION_HEADER,
                nt_headers.FileHeader.NumberOfSections as usize,
            )
        };
        let section = sections
            .iter()
            .find(|section| &section.Name == b".data\0\0\0")
            .unwrap();

        let begin = section.VirtualAddress as usize;
        let end = begin + section.SizeOfRawData as usize;
        let mut i = begin;
        while i < end {
            // Encrypted?
            if image[i] != 1 {
                i += 1;
                continue;
            }

            let length = (image[i - 3] as u32
                | ((image[i - 2] as u32) << 8)
                | ((image[i - 1] as u32) << 16)) as usize;

            // Empty?
            if length == 0 {
                i += 1;
                continue;
            }

            // Longer than total length?
            if i + 1 + length >= end {
                i += 1;
                continue;
            }

            // Null-terminated?
            if image[i + 1 + length] != 0 {
                i += 1;
                continue;
            }

            // Xor
            for j in 0..length {
                image[i + 1 + j] ^= image[i - 3 - 8 + (j % 8)];
            }

            // Try to decode
            let Ok(string) = std::str::from_utf8(&image[i + 1..i + 1 + length]) else {
                // Undo xor
                for j in 0..length {
                    image[i + 1 + j] ^= image[i - 3 - 8 + (j % 8)];
                }
                i += 1;
                continue;
            };

            // Contains non-whitespace control characters?
            if string
                .contains(|value: char| value.is_ascii_control() && !value.is_ascii_whitespace())
            {
                // Undo xor
                for j in 0..length {
                    image[i + 1 + j] ^= image[i - 3 - 8 + (j % 8)];
                }
                i += 1;
                continue;
            }

            image[i] = 0;
            i += length;
        }
    }
}

fn contains(module: &Module, address: usize) -> bool {
    unsafe {
        let image_ptr = module.image.as_ptr() as usize;
        let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        address >= nt_headers.OptionalHeader.ImageBase as usize
            && address < nt_headers.OptionalHeader.ImageBase as usize + module.image.len()
    }
}

fn export_name_by_address(module: &Module, address: usize) -> Option<&[u8]> {
    unsafe {
        let image_ptr = module.image.as_ptr() as usize;
        let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let export_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
            as *const IMAGE_DATA_DIRECTORY);
        let export_directory = &*((image_ptr + export_data_directory.VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY);
        let functions = std::slice::from_raw_parts(
            (image_ptr + export_directory.AddressOfFunctions as usize) as *const u32,
            export_directory.NumberOfFunctions as usize,
        );
        let names = std::slice::from_raw_parts(
            (image_ptr + export_directory.AddressOfNames as usize) as *const u32,
            export_directory.NumberOfNames as usize,
        );
        let name_ordinals = std::slice::from_raw_parts(
            (image_ptr + export_directory.AddressOfNameOrdinals as usize) as *const u16,
            export_directory.NumberOfNames as usize,
        );

        for (&name, &name_ordinal) in names.iter().zip(name_ordinals) {
            let function = nt_headers.OptionalHeader.ImageBase as usize
                + functions[name_ordinal as usize] as usize;
            if function != address {
                continue;
            }

            let name_ptr = (image_ptr + name as usize) as *const u8;
            let mut name_end_ptr = name_ptr;
            while *name_end_ptr != 0 {
                name_end_ptr = name_end_ptr.add(1)
            }
            let name_length = name_end_ptr.offset_from(name_ptr) as usize;
            let name = std::slice::from_raw_parts(name_ptr, name_length + 1);
            return Some(name);
        }

        None
    }
}

fn export_name_by_forward<'a>(module: &'a Module, forward: &[u8]) -> Option<&'a [u8]> {
    unsafe {
        let image_ptr = module.image.as_ptr() as usize;
        let dos_headers = &*(image_ptr as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*((image_ptr + dos_headers.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let export_data_directory = &*(&nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
            as *const IMAGE_DATA_DIRECTORY);
        let export_directory = &*((image_ptr + export_data_directory.VirtualAddress as usize)
            as *const IMAGE_EXPORT_DIRECTORY);
        let functions = std::slice::from_raw_parts(
            (image_ptr + export_directory.AddressOfFunctions as usize) as *const u32,
            export_directory.NumberOfFunctions as usize,
        );
        let names = std::slice::from_raw_parts(
            (image_ptr + export_directory.AddressOfNames as usize) as *const u32,
            export_directory.NumberOfNames as usize,
        );
        let name_ordinals = std::slice::from_raw_parts(
            (image_ptr + export_directory.AddressOfNameOrdinals as usize) as *const u16,
            export_directory.NumberOfNames as usize,
        );

        for (&name, &name_ordinal) in names.iter().zip(name_ordinals) {
            let function = functions[name_ordinal as usize] as usize;
            if function < export_data_directory.VirtualAddress as usize
                || function
                    >= (export_data_directory.VirtualAddress + export_data_directory.Size) as usize
            {
                continue;
            }

            let forward_name = std::slice::from_raw_parts(
                (image_ptr + function) as *const u8,
                function - export_data_directory.VirtualAddress as usize
                    + export_data_directory.Size as usize,
            );
            let forward_dll_name_end = forward_name.iter().position(|&c| c == b'.').unwrap();
            let forward_name_end = forward_name.iter().position(|&c| c == 0).unwrap();
            if forward != &forward_name[forward_dll_name_end + 1..forward_name_end + 1] {
                continue;
            }

            let name_ptr = (image_ptr + name as usize) as *const u8;
            let mut name_end_ptr = name_ptr;
            while *name_end_ptr != 0 {
                name_end_ptr = name_end_ptr.add(1)
            }
            let name_length = name_end_ptr.offset_from(name_ptr) as usize;
            let name = std::slice::from_raw_parts(name_ptr, name_length + 1);
            return Some(name);
        }

        None
    }
}
