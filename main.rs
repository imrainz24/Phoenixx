pub mod xmem_model;
pub mod xmem_model_v3;
pub mod xmem_page_runtime;
pub mod xmem_request_bridge;
pub mod xmem_physical_pages;
pub mod xmem_scatter_mapping;
pub mod xmem_memory_manager;
pub mod xmem_physical_page_abi;
pub mod xmem_virtual_alloc_abi;
pub mod xmem_compat_runtime;
pub mod xmem_dispatch_bridge;
pub mod xmem_guest_abi;
pub mod xmem_abi;
pub mod xmem_trace;
pub mod xmem_usage;
pub mod xmem_virtual_alloc;
pub mod host_virtual_memory;
pub mod physical_page_model;
pub mod xmem_runtime;
pub mod xmem_host_adapter;
pub mod xmem_allocation_registry;
pub mod guest_address_space;
pub mod pe_image_stager;
pub mod pe_import_manifest;
pub mod iat_binding_plan;
pub mod import_dispatch_registry;
pub mod loader_pipeline;
pub mod loader_lifecycle;
pub mod prepared_image;

use std::{env, fs};
use iat_binding_plan::{ExportKey, ExportResolution, BindingSymbol};
use pe_image_stager::parse_pe32_plus;
use pe_import_manifest::{parse_import_manifest, ImportSymbol};
use loader_pipeline::{prepare_pe_image, print_pipeline_summary};

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(offset..offset.checked_add(8)?)?.try_into().ok()?))
}
fn c_string(data: &[u8], offset: usize) -> Option<String> {
    let tail = data.get(offset..)?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
}

fn rva_to_file_offset(rva: u32, sections: &[Section], headers_size: u32) -> Option<usize> {
    if rva < headers_size {
        return Some(rva as usize);
    }
    for section in sections {
        if let Some(delta) = rva.checked_sub(section.virtual_address) {
            if delta < section.raw_size {
                return usize::try_from(section.raw_pointer.checked_add(delta)?).ok();
            }
        }
    }
    None
}

#[derive(Debug)]
struct ImportRecord {
    dll: String,
    symbol: String,
    iat_rva: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportClass {
    WindowsNative,
    XboxCompatibility,
    PlatformMiddleware,
    Unknown,
}

fn classify_dll(name: &str) -> ImportClass {
    let n = name.to_ascii_lowercase();
    if n.ends_with(".dll") && (n.starts_with("api-ms-win-") || n.starts_with("ext-ms-win-")) {
        return ImportClass::WindowsNative;
    }
    match n.as_str() {
        "kernel32.dll" | "kernelbase.dll" | "ntdll.dll" | "user32.dll" |
        "gdi32.dll" | "advapi32.dll" | "ws2_32.dll" | "winhttp.dll" |
        "bcrypt.dll" | "mfplat.dll" | "mfreadwrite.dll" | "ole32.dll" |
        "oleaut32.dll" | "msvcp140.dll" | "vcruntime140.dll" |
        "vcruntime140_1.dll" | "ucrtbase.dll" => ImportClass::WindowsNative,
        "d3d12_xs.dll" | "xmem.dll" | "xg_xs.dll" | "xapu.dll" |
        "acphal.dll" | "xboxbvhbuilder.dll" | "xcrdapi.dll" |
        "gameinput.dll" | "libhttpclient.gdk.dll" | "amd_fidelityfx_loader_xbox.dll" => ImportClass::XboxCompatibility,
        "bink2scarlett.dll" | "chad.dll" => ImportClass::PlatformMiddleware,
        _ => ImportClass::Unknown,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CompatibilityWorkstream {
    GraphicsAndRayTracing,
    MemoryAndVirtualAddressing,
    AudioAndDsp,
    Input,
    Storage,
    NetworkingAndOnlineServices,
    VideoPlayback,
    UnknownPlatform,
}

impl CompatibilityWorkstream {
    fn label(self) -> &'static str {
        match self {
            Self::GraphicsAndRayTracing => "Graphics / texture layout / ray tracing",
            Self::MemoryAndVirtualAddressing => "Memory / physical pages / APU address mapping",
            Self::AudioAndDsp => "Audio / DSP command processing",
            Self::Input => "Controller and input",
            Self::Storage => "Storage / DirectStorage interface",
            Self::NetworkingAndOnlineServices => "Networking / Xbox online HTTP services",
            Self::VideoPlayback => "Video playback middleware",
            Self::UnknownPlatform => "Unclassified platform interface",
        }
    }
}

fn compatibility_workstream(dll: &str) -> CompatibilityWorkstream {
    match dll.to_ascii_lowercase().as_str() {
        "d3d12_xs.dll" | "xg_xs.dll" | "xboxbvhbuilder.dll" |
        "amd_fidelityfx_loader_xbox.dll" => CompatibilityWorkstream::GraphicsAndRayTracing,
        "xmem.dll" | "acphal.dll" => CompatibilityWorkstream::MemoryAndVirtualAddressing,
        "xapu.dll" | "chad.dll" => CompatibilityWorkstream::AudioAndDsp,
        "gameinput.dll" => CompatibilityWorkstream::Input,
        "xcrdapi.dll" => CompatibilityWorkstream::Storage,
        "libhttpclient.gdk.dll" => CompatibilityWorkstream::NetworkingAndOnlineServices,
        "bink2scarlett.dll" => CompatibilityWorkstream::VideoPlayback,
        _ => CompatibilityWorkstream::UnknownPlatform,
    }
}

fn report_compatibility_work_items(records: &[ImportRecord]) {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<CompatibilityWorkstream, BTreeMap<String, Vec<&ImportRecord>>> = BTreeMap::new();
    for record in records {
        if classify_dll(&record.dll) == ImportClass::WindowsNative {
            continue;
        }
        groups.entry(compatibility_workstream(&record.dll))
            .or_default()
            .entry(record.dll.clone())
            .or_default()
            .push(record);
    }

    println!("\n=== PHOENIX COMPATIBILITY WORK ITEMS ===");
    let total: usize = groups.values()
        .flat_map(|modules| modules.values())
        .map(Vec::len)
        .sum();
    println!("Platform imports requiring compatibility or middleware review: {total}");
    println!("This is an import-based work breakdown, not proof of implementation or runtime compatibility.");

    for (workstream, modules) in groups {
        let count: usize = modules.values().map(Vec::len).sum();
        println!("\n[{}] — {} imported functions", workstream.label(), count);
        for (dll, imports) in modules {
            println!("  {dll} — {} functions", imports.len());
            for import in imports {
                println!("    {} (IAT RVA {:#010x})", import.symbol, import.iat_rva);
            }
        }
    }

    println!("\nRecommended implementation order:");
    println!("  1. Memory / virtual-address semantics — foundational for later subsystems.");
    println!("  2. Graphics / texture layout / ray tracing — largest platform-specific rendering surface.");
    println!("  3. Input and storage — isolate these behind small host-side interfaces.");
    println!("  4. Audio / DSP and video playback — build independent test harnesses.");
    println!("  5. Networking / online services — document platform dependencies before implementing replacements.");
    println!("No compatibility functions have been implemented by this report.");
}

fn inspect_imports(
    file: &[u8], sections: &[Section], headers_size: u32,
    import_rva: u32, import_size: u32, image_size: usize,
) -> Result<(), String> {
    println!("\n=== IMPORT TABLE / RESOLUTION PLAN ===");
    if import_rva == 0 || import_size == 0 {
        println!("No import directory is present.");
        return Ok(());
    }

    let mut descriptor = rva_to_file_offset(import_rva, sections, headers_size)
        .ok_or("Import directory RVA does not map to file data.")?;
    let directory_end = descriptor.checked_add(import_size as usize)
        .ok_or("Import directory range overflow.")?;
    if directory_end > file.len() {
        return Err("Import directory extends beyond the file.".into());
    }

    let mut records = Vec::<ImportRecord>::new();
    let mut modules = Vec::<(String, ImportClass)>::new();
    let mut descriptor_terminated = false;

    while descriptor.checked_add(20).map_or(false, |end| end <= directory_end) {
        let original_thunk = u32_at(file, descriptor).ok_or("Truncated import descriptor.")?;
        let name_rva = u32_at(file, descriptor + 12).ok_or("Truncated import descriptor.")?;
        let first_thunk = u32_at(file, descriptor + 16).ok_or("Truncated import descriptor.")?;
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            descriptor_terminated = true;
            break;
        }
        if first_thunk == 0 { return Err("Import descriptor has a null IAT RVA.".into()); }

        let name_offset = rva_to_file_offset(name_rva, sections, headers_size)
            .ok_or("DLL name RVA does not map to file data.")?;
        let dll_name = c_string(file, name_offset).ok_or("Invalid DLL name string.")?;
        let class = classify_dll(&dll_name);
        modules.push((dll_name.clone(), class));

        let lookup_rva = if original_thunk != 0 { original_thunk } else { first_thunk };
        let mut lookup_offset = rva_to_file_offset(lookup_rva, sections, headers_size)
            .ok_or_else(|| format!("Lookup thunk for {dll_name} does not map to file data."))?;
        let mut index = 0u32;
        let mut thunk_terminated = false;
        for _ in 0..65_536 {
            let value = u64_at(file, lookup_offset)
                .ok_or_else(|| format!("Truncated lookup thunk for {dll_name}."))?;
            if value == 0 { thunk_terminated = true; break; }
            let iat_rva = first_thunk.checked_add(index.checked_mul(8).ok_or("IAT index overflow.")?)
                .ok_or("IAT RVA overflow.")?;
            if (iat_rva as usize).checked_add(8).map_or(true, |end| end > image_size) {
                return Err(format!("IAT slot for {dll_name} at RVA {iat_rva:#x} exceeds SizeOfImage."));
            }
            let symbol = if value & (1u64 << 63) != 0 {
                format!("Ordinal {}", value & 0xffff)
            } else {
                let import_name_rva = u32::try_from(value)
                    .map_err(|_| format!("Invalid import-name RVA in {dll_name}."))?;
                let import_name_offset = rva_to_file_offset(import_name_rva, sections, headers_size)
                    .ok_or_else(|| format!("Import name for {dll_name} does not map to file data."))?;
                let function_offset = import_name_offset.checked_add(2).ok_or("Import name offset overflow.")?;
                c_string(file, function_offset).ok_or_else(|| format!("Invalid import name in {dll_name}."))?
            };
            records.push(ImportRecord { dll: dll_name.clone(), symbol, iat_rva });
            index = index.checked_add(1).ok_or("Import count overflow.")?;
            lookup_offset = lookup_offset.checked_add(8).ok_or("Lookup thunk offset overflow.")?;
        }
        if !thunk_terminated { return Err(format!("Import thunk for {dll_name} exceeded the safety limit.")); }
        descriptor = descriptor.checked_add(20).ok_or("Import descriptor offset overflow.")?;
    }
    if !descriptor_terminated {
        return Err("Import descriptor list has no terminating entry within its declared directory.".into());
    }

    for (dll, class) in &modules {
        let label = match class {
            ImportClass::WindowsNative => "WINDOWS-NATIVE CANDIDATE",
            ImportClass::XboxCompatibility => "XBOX COMPATIBILITY REQUIRED",
            ImportClass::PlatformMiddleware => "PLATFORM MIDDLEWARE REVIEW",
            ImportClass::Unknown => "UNCLASSIFIED - REVIEW REQUIRED",
        };
        println!("\n[{dll}] — {label}");
        for record in records.iter().filter(|r| r.dll.eq_ignore_ascii_case(dll)) {
            println!("  {}  (IAT RVA {:#010x})", record.symbol, record.iat_rva);
        }
    }

    let windows = modules.iter().filter(|(_, c)| *c == ImportClass::WindowsNative).count();
    let xbox = modules.iter().filter(|(_, c)| *c == ImportClass::XboxCompatibility).count();
    let middleware = modules.iter().filter(|(_, c)| *c == ImportClass::PlatformMiddleware).count();
    let unknown = modules.iter().filter(|(_, c)| *c == ImportClass::Unknown).count();
    println!("\n=== RESOLUTION SUMMARY ===");
    println!("Imported DLLs: {}", modules.len());
    println!("Imported functions: {}", records.len());
    println!("Windows-native candidates: {windows} DLLs");
    println!("Xbox compatibility modules: {xbox} DLLs");
    println!("Platform middleware modules: {middleware} DLLs");
    println!("Unclassified modules: {unknown} DLLs");
    println!("IAT slots validated against SizeOfImage: {}", records.len());
    println!("NOTE: This is static import analysis. The integrated loader pipeline runs after this report.");
    report_compatibility_work_items(&records);
    Ok(())
}

fn inspect(path: &str) -> Result<(), String> {
    let file = fs::read(path).map_err(|e| format!("Could not read file: {e}"))?;
    if file.get(0..2) != Some(b"MZ") || file.len() < 0x40 {
        return Err("Not a valid DOS/PE file.".into());
    }
    let pe = u32_at(&file, 0x3c).ok_or("Missing e_lfanew.")? as usize;
    let pe_end = pe.checked_add(4).ok_or("PE offset overflow.")?;
    if file.get(pe..pe_end) != Some(b"PE\0\0") {
        return Err("Invalid PE signature.".into());
    }
    let coff = pe.checked_add(4).ok_or("COFF offset overflow.")?;
    let machine = u16_at(&file, coff).ok_or("Truncated COFF header.")?;
    let section_count = u16_at(&file, coff + 2).ok_or("Missing section count.")? as usize;
    let optional_size = u16_at(&file, coff + 16).ok_or("Missing optional-header size.")? as usize;
    let optional = coff.checked_add(20).ok_or("Optional-header offset overflow.")?;
    let optional_end = optional.checked_add(optional_size).ok_or("Optional-header size overflow.")?;
    if optional_end > file.len() { return Err("Optional header extends beyond the file.".into()); }
    if u16_at(&file, optional) != Some(0x20b) {
        return Err("Expected a 64-bit PE32+ image.".into());
    }

    let entry_rva = u32_at(&file, optional + 16).ok_or("Missing entry-point RVA.")?;
    let image_base = u64_at(&file, optional + 24).ok_or("Missing image base.")?;
    let section_alignment = u32_at(&file, optional + 32).ok_or("Missing section alignment.")?;
    let file_alignment = u32_at(&file, optional + 36).ok_or("Missing file alignment.")?;
    let image_size = u32_at(&file, optional + 56).ok_or("Missing SizeOfImage.")? as usize;
    let headers_size = u32_at(&file, optional + 60).ok_or("Missing SizeOfHeaders.")?;
    let directory_count = u32_at(&file, optional + 108).unwrap_or(0);
    if image_size == 0 || image_size > 2 * 1024 * 1024 * 1024usize {
        return Err(format!("Unreasonable SizeOfImage: {image_size:#x}"));
    }
    if headers_size as usize > file.len() || headers_size as usize > image_size {
        return Err("Invalid SizeOfHeaders.".into());
    }

    let section_table = optional_end;
    let table_bytes = section_count.checked_mul(40).ok_or("Section table overflow.")?;
    let table_end = section_table.checked_add(table_bytes).ok_or("Section table offset overflow.")?;
    if table_end > file.len() { return Err("Section table extends beyond the file.".into()); }

    let mut sections = Vec::with_capacity(section_count);
    for i in 0..section_count {
        let o = section_table + i * 40;
        let raw_name = file.get(o..o + 8).ok_or("Truncated section name.")?;
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..name_end]).into_owned(),
            virtual_size: u32_at(&file, o + 8).ok_or("Bad section header.")?,
            virtual_address: u32_at(&file, o + 12).ok_or("Bad section header.")?,
            raw_size: u32_at(&file, o + 16).ok_or("Bad section header.")?,
            raw_pointer: u32_at(&file, o + 20).ok_or("Bad section header.")?,
            characteristics: u32_at(&file, o + 36).ok_or("Bad section header.")?,
        });
    }

    let import_rva = if directory_count > 1 && optional_size >= 128 {
        u32_at(&file, optional + 120).unwrap_or(0)
    } else { 0 };
    let import_size = if directory_count > 1 && optional_size >= 128 {
        u32_at(&file, optional + 124).unwrap_or(0)
    } else { 0 };
    let reloc_rva = if directory_count > 5 && optional_size >= 160 {
        u32_at(&file, optional + 152).unwrap_or(0)
    } else { 0 };
    let reloc_size = if directory_count > 5 && optional_size >= 160 {
        u32_at(&file, optional + 156).unwrap_or(0)
    } else { 0 };

    println!("=== PROJECT PHOENIX: PE IMAGE ANALYSIS ===");
    println!("File: {path}");
    println!("File size: {} bytes", file.len());
    println!("Machine: {machine:#06x} ({})", match machine { 0x8664 => "AMD64", 0xAA64 => "ARM64", _ => "other" });
    println!("Preferred image base: {image_base:#018x}");
    println!("Entry point RVA: {entry_rva:#010x}");
    println!("Section alignment: {section_alignment:#x}");
    println!("File alignment: {file_alignment:#x}");
    println!("SizeOfImage: {image_size:#x} bytes");
    println!("SizeOfHeaders: {headers_size:#x} bytes");

    println!("\n=== SECTIONS ===");
    for s in &sections {
        let span = s.virtual_size.max(s.raw_size);
        let end = s.virtual_address.checked_add(span).ok_or_else(|| format!("Section {} address overflow.", s.name))?;
        println!("{:<8} RVA {:#010x}..{:#010x} | virtual {:#x} | raw {:#x} | file {:#x} | flags {:#010x}",
            s.name, s.virtual_address, end, s.virtual_size, s.raw_size, s.raw_pointer, s.characteristics);
        if end as usize > image_size { return Err(format!("Section {} extends beyond SizeOfImage.", s.name)); }
        let raw_end = (s.raw_pointer as usize).checked_add(s.raw_size as usize)
            .ok_or_else(|| format!("Section {} raw range overflow.", s.name))?;
        if raw_end > file.len() { return Err(format!("Section {} raw data extends beyond the file.", s.name)); }
    }

    // Construct a non-executable analysis image. This is not an OS loader.
    let mut mapped = vec![0u8; image_size];
    mapped[..headers_size as usize].copy_from_slice(&file[..headers_size as usize]);
    for s in &sections {
        let dst = s.virtual_address as usize;
        let src = s.raw_pointer as usize;
        let len = s.raw_size as usize;
        let dst_end = dst.checked_add(len).ok_or("Mapped section range overflow.")?;
        if dst_end > mapped.len() { return Err(format!("Mapped section {} exceeds image allocation.", s.name)); }
        mapped[dst..dst_end].copy_from_slice(&file[src..src + len]);
    }
    println!("\nMapped image layout in Phoenix analysis buffer: {} bytes", mapped.len());
    println!("NOTE: Analysis buffer only; no code was executed.");

    println!("\n=== BASE RELOCATIONS ===");
    println!("Directory RVA: {reloc_rva:#010x}, size: {reloc_size:#x}");
    if reloc_rva == 0 || reloc_size == 0 {
        println!("No base relocation entries declared; image cannot be rebased by Phoenix.");
    } else {
        let mut cursor = rva_to_file_offset(reloc_rva, &sections, headers_size)
            .ok_or("Relocation directory RVA does not map to file data.")?;
        let dir_end = cursor.checked_add(reloc_size as usize).ok_or("Relocation directory overflow.")?;
        if dir_end > file.len() { return Err("Relocation directory extends beyond the file.".into()); }

        // Use a deliberately different simulated base to exercise relocation handling.
        // This only modifies the Vec<u8> analysis image; it does not reserve process memory.
        let simulated_base = image_base.checked_add(0x1000_0000)
            .ok_or("Simulated image base overflow.")?;
        let delta = simulated_base.checked_sub(image_base)
            .ok_or("Simulated relocation delta is negative or invalid.")?;
        let mut blocks = 0usize;
        let mut entries = 0usize;
        let mut applied_dir64 = 0usize;
        let mut padding = 0usize;
        let mut unsupported = 0usize;
        let mut first_target: Option<(u32, u64, u64)> = None;

        while cursor < dir_end {
            if cursor.checked_add(8).map_or(true, |end| end > dir_end) {
                return Err("Truncated relocation block header.".into());
            }
            let page_rva = u32_at(&file, cursor).ok_or("Bad relocation block.")?;
            let block_size = u32_at(&file, cursor + 4).ok_or("Bad relocation block.")? as usize;
            let block_end = cursor.checked_add(block_size).ok_or("Relocation block overflow.")?;
            if block_size < 8 || block_size % 2 != 0 || block_end > dir_end {
                return Err("Invalid relocation block size.".into());
            }

            for i in 0..((block_size - 8) / 2) {
                let item = u16_at(&file, cursor + 8 + i * 2).ok_or("Bad relocation entry.")?;
                let kind = item >> 12;
                let offset = (item & 0x0fff) as u32;
                if kind == 0 {
                    padding += 1;
                    continue;
                }
                entries += 1;
                let target_rva = page_rva.checked_add(offset).ok_or("Relocation target RVA overflow.")?;
                let target = target_rva as usize;

                match kind {
                    10 => {
                        let target_end = target.checked_add(8).ok_or("DIR64 target range overflow.")?;
                        if target_end > mapped.len() {
                            return Err(format!("DIR64 target {target_rva:#x} extends beyond SizeOfImage."));
                        }
                        let old_value = u64::from_le_bytes(mapped[target..target_end].try_into().unwrap());
                        let new_value = old_value.checked_add(delta)
                            .ok_or_else(|| format!("DIR64 value overflow at RVA {target_rva:#x}."))?;
                        mapped[target..target_end].copy_from_slice(&new_value.to_le_bytes());
                        applied_dir64 += 1;
                        if first_target.is_none() {
                            first_target = Some((target_rva, old_value, new_value));
                        }
                    }
                    3 => {
                        // HIGHLOW is not expected in this AMD64 image. Count it, but do not
                        // silently apply a 32-bit relocation using a 64-bit image delta.
                        unsupported += 1;
                    }
                    _ => unsupported += 1,
                }
            }
            blocks += 1;
            cursor = block_end;
        }

        println!("Relocation blocks: {blocks}");
        println!("Non-padding relocation entries: {entries}");
        println!("ABSOLUTE padding entries: {padding}");
        println!("DIR64 relocations applied: {applied_dir64}");
        println!("Unsupported relocation entries left untouched: {unsupported}");
        println!("Preferred image base: {image_base:#018x}");
        println!("Simulated image base: {simulated_base:#018x}");
        println!("Applied relocation delta: {delta:#x}");
        if let Some((rva, before, after)) = first_target {
            println!("First DIR64 check at RVA {rva:#010x}: {before:#018x} -> {after:#018x}");
            if after != before.checked_add(delta).ok_or("Relocation verification overflow.")? {
                return Err("DIR64 relocation verification failed.".into());
            }
            println!("First relocation verification: PASS");
        }
        if unsupported != 0 {
            println!("WARNING: Some relocation types were not applied.");
        }
        println!("Relocations were applied only to Phoenix's non-executable analysis buffer.");
    }

    inspect_imports(&file, &sections, headers_size, import_rva, import_size, image_size)?;
    Ok(())
}


#[cfg(windows)]
struct HostExportSnapshot {
    resolutions: Vec<ExportResolution>,
    handles: Vec<*mut std::ffi::c_void>,
}

#[cfg(windows)]
impl HostExportSnapshot {
    fn release(self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn FreeLibrary(module: *mut std::ffi::c_void) -> i32;
        }
        for handle in self.handles {
            if !handle.is_null() {
                unsafe { FreeLibrary(handle); }
            }
        }
    }
}

#[cfg(windows)]
fn resolve_manifest_exports(manifest: &pe_import_manifest::ImportManifest) -> HostExportSnapshot {
    use std::{collections::BTreeMap, ffi::{c_void, CString}, os::windows::ffi::OsStrExt};
    type HModule = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> HModule;
        fn GetProcAddress(module: HModule, name: *const i8) -> *mut c_void;
    }
    const FLAGS: u32 = 0x0000_0001 | 0x0000_0800; // DONT_RESOLVE_DLL_REFERENCES | SYSTEM32 only
    let mut modules: BTreeMap<String, Result<HModule, u32>> = BTreeMap::new();
    let mut resolutions = Vec::new();
    let mut handles = Vec::new();

    for module in &manifest.modules {
        if classify_dll(&module.name) != ImportClass::WindowsNative {
            continue;
        }
        let key = module.name.to_ascii_lowercase();
        if !modules.contains_key(&key) {
            let wide: Vec<u16> = std::ffi::OsStr::new(&module.name)
                .encode_wide().chain(Some(0)).collect();
            let handle = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), FLAGS) };
            let result = if handle.is_null() {
                Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
            } else {
                handles.push(handle);
                Ok(handle)
            };
            modules.insert(key.clone(), result);
        }
        let loaded = modules.get(&key).expect("module inserted above");
        let handle = match loaded {
            Ok(handle) => *handle,
            Err(_) => continue,
        };
        for function in &module.functions {
            let (symbol, address) = match &function.symbol {
                ImportSymbol::Name { name, .. } => {
                    let address = CString::new(name.as_bytes()).ok()
                        .map(|name| unsafe { GetProcAddress(handle, name.as_ptr()) })
                        .unwrap_or(std::ptr::null_mut());
                    (BindingSymbol::Name(name.clone()), address)
                }
                ImportSymbol::Ordinal(ordinal) => {
                    let address = unsafe { GetProcAddress(handle, *ordinal as usize as *const i8) };
                    (BindingSymbol::Ordinal(*ordinal), address)
                }
            };
            resolutions.push(ExportResolution {
                key: ExportKey { module: module.name.clone(), symbol },
                host_address: if address.is_null() { None } else { Some(address as usize as u64) },
            });
        }
    }
    println!("\n=== WINDOWS EXPORT SNAPSHOT ===");
    println!("Windows import entries examined: {}", resolutions.len());
    println!("System modules retained temporarily: {}", handles.len());
    println!("Xbox/middleware imports are intentionally left unresolved.");
    println!("No imported function is called and no IAT slot is modified.");
    HostExportSnapshot { resolutions, handles }
}

#[cfg(not(windows))]
fn resolve_manifest_exports(_manifest: &pe_import_manifest::ImportManifest) -> Vec<ExportResolution> {
    println!("\nWindows export snapshot skipped: Phoenix must run on Windows for System32 export inspection.");
    Vec::new()
}

fn run_integrated_pipeline(path: &str) -> Result<(), String> {
    let file = fs::read(path).map_err(|e| format!("Could not read executable for staging: {e}"))?;
    let info = parse_pe32_plus(&file).map_err(|e| format!("PE staging validation failed: {e}"))?;
    let manifest = parse_import_manifest(&file).map_err(|e| format!("Import parsing failed: {e}"))?;

    #[cfg(windows)]
    let snapshot = resolve_manifest_exports(&manifest);
    #[cfg(windows)]
    let resolutions = &snapshot.resolutions;
    #[cfg(not(windows))]
    let resolutions = &resolve_manifest_exports(&manifest);

    let guest_base = usize::try_from(info.preferred_base)
        .map_err(|_| "Preferred image base does not fit this host's address type.")?;
    let mut prepared = prepare_pe_image(&file, guest_base, resolutions)
        .map_err(|e| format!("Integrated preparation failed: {e:?}"))?;

    let patched_windows_slots = prepared.patch_windows_iat()
        .map_err(|e| format!("Safe staged Windows IAT patching failed: {e:?}"))?;
    println!("\nWindows IAT slots patched in staged guest memory: {patched_windows_slots}");
    println!("Xbox/middleware IAT slots remain unresolved and untouched.");
    print_pipeline_summary(&prepared);
    println!("\n=== UNRESOLVED IMPORTS ===");
    for entry in prepared.dispatch.entries() {
        if matches!(entry.target, import_dispatch_registry::DispatchTarget::Unresolved) {
            let symbol = match &entry.id.symbol {
                BindingSymbol::Name(name) => name.clone(),
                BindingSymbol::Ordinal(value) => format!("ordinal #{value}"),
            };
            println!("  {}!{} (IAT RVA {:#010x})", entry.id.module, symbol, entry.iat_rva);
        }
    }

    // Read back a small header signature from staged guest memory as an
    // integration check, without invoking any code in the image.
    let mut signature = [0u8; 2];
    prepared.read_guest(guest_base, &mut signature)
        .map_err(|e| format!("Staged-image readback failed: {e}"))?;
    if &signature != b"MZ" {
        return Err("Staged-image readback did not preserve the DOS signature.".into());
    }
    println!("Staged-image readback: PASS (MZ signature).");

    let lifecycle = loader_lifecycle::build_loader_lifecycle_plan(&file)
        .map_err(|e| format!("Loader lifecycle audit failed: {e}"))?;
    loader_lifecycle::print_loader_lifecycle_plan(&lifecycle);

    prepared.unload().map_err(|e| format!("Guest image unload failed: {e}"))?;
    println!("Guest image unload: PASS.");

    #[cfg(windows)]
    snapshot.release();

    Ok(())
}


fn main() {
    xmem_abi::print_contract_report();
    xmem_trace::print_observation_report();
    xmem_usage::print_usage_report();
    xmem_virtual_alloc::print_abi_report();
    host_virtual_memory::print_backend_report();
    physical_page_model::print_model_report();
    xmem_runtime::print_runtime_report();
    xmem_host_adapter::print_adapter_report();
    xmem_allocation_registry::print_registry_report();
    xmem_page_runtime::print_runtime_report();
    xmem_request_bridge::print_bridge_report();
    xmem_physical_pages::print_physical_page_report();
    xmem_scatter_mapping::print_scatter_report();
    xmem_memory_manager::print_manager_report();
    xmem_physical_page_abi::print_abi_adapter_report();
    xmem_virtual_alloc_abi::print_virtual_alloc_abi_report();
    xmem_compat_runtime::print_runtime_report();
    xmem_dispatch_bridge::print_dispatch_bridge_report();
    xmem_guest_abi::print_guest_abi_report();
    guest_address_space::print_address_space_report();
    pe_image_stager::print_stager_report();
    let args: Vec<String> = env::args().collect();
    if args.len() == 4 && args[1] == "--prepare-image" {
        let input = &args[2];
        let output = std::path::Path::new(&args[3]);
        if output.exists() {
            eprintln!("Refusing to overwrite existing output: {}", output.display());
            std::process::exit(2);
        }
        let original = match fs::read(input) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("Could not read input image: {error}");
                std::process::exit(1);
            }
        };
        let prepared = match prepared_image::prepare(&original) {
            Ok(image) => image,
            Err(error) => {
                eprintln!("Prepared-image generation failed: {error}");
                std::process::exit(1);
            }
        };
        if let Err(error) = fs::write(output, &prepared.bytes) {
            eprintln!("Could not write prepared image: {error}");
            std::process::exit(1);
        }
        println!("Prepared image written: {}", output.display());
        println!("Original image size: {} bytes", original.len());
        println!("Prepared image size: {} bytes", prepared.bytes.len());
        println!("Original imports retained for Phoenix: {}", prepared.original_import_count());
        println!("Original TLS callbacks retained for Phoenix: {}", prepared.original_tls_callback_count());
        println!("TLS callback relocation entries neutralized: {}", prepared.tls_relocations_neutralized);
        println!("Entry point cleared in prepared copy; no game code was executed.");
        return;
    }
    if args.len() != 2 {
        println!("Project Phoenix - PE staging, Windows import binding, and compatibility analysis");
        println!("Usage: phoenix <executable.exe>");
        println!("       phoenix --prepare-image <input.exe> <new-output.dll>");
        return;
    }
    if let Err(error) = inspect(&args[1]) {
        eprintln!("Phoenix error: {error}");
        std::process::exit(1);
    }
    if let Err(error) = run_integrated_pipeline(&args[1]) {
        eprintln!("Phoenix integrated pipeline error: {error}");
        std::process::exit(1);
    }
}
