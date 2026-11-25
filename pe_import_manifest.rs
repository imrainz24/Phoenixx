//! Bounded PE32+ import-directory parser for Project Phoenix.
//!
//! Produces an inspection manifest only. It does not load DLLs, resolve exports,
//! modify the IAT, or execute imported functions.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportParseError {
    Truncated(&'static str),
    Invalid(&'static str),
    Overflow,
    Unterminated(&'static str),
}

impl fmt::Display for ImportParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for ImportParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    Name { hint: u16, name: String },
    Ordinal(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFunction {
    pub symbol: ImportSymbol,
    pub lookup_rva: u32,
    pub iat_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedModule {
    pub name: String,
    pub descriptor_rva: u32,
    pub original_first_thunk_rva: u32,
    pub first_thunk_rva: u32,
    pub functions: Vec<ImportedFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportManifest {
    pub modules: Vec<ImportedModule>,
    pub function_count: usize,
}

#[derive(Debug, Clone)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, ImportParseError> {
    let end = offset.checked_add(2).ok_or(ImportParseError::Overflow)?;
    let b = data.get(offset..end).ok_or(ImportParseError::Truncated("u16"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(data: &[u8], offset: usize) -> Result<u32, ImportParseError> {
    let end = offset.checked_add(4).ok_or(ImportParseError::Overflow)?;
    let b = data.get(offset..end).ok_or(ImportParseError::Truncated("u32"))?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}
fn u64_at(data: &[u8], offset: usize) -> Result<u64, ImportParseError> {
    let end = offset.checked_add(8).ok_or(ImportParseError::Overflow)?;
    let b = data.get(offset..end).ok_or(ImportParseError::Truncated("u64"))?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}
fn c_string(data: &[u8], offset: usize, what: &'static str) -> Result<String, ImportParseError> {
    let tail = data.get(offset..).ok_or(ImportParseError::Truncated(what))?;
    let end = tail.iter().position(|b| *b == 0)
        .ok_or(ImportParseError::Unterminated(what))?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

pub fn parse_import_manifest(file: &[u8]) -> Result<ImportManifest, ImportParseError> {
    if u16_at(file, 0)? != 0x5a4d {
        return Err(ImportParseError::Invalid("MZ signature"));
    }
    let pe = u32_at(file, 0x3c)? as usize;
    if u32_at(file, pe)? != 0x00004550 {
        return Err(ImportParseError::Invalid("PE signature"));
    }
    let coff = pe.checked_add(4).ok_or(ImportParseError::Overflow)?;
    if u16_at(file, coff)? != 0x8664 {
        return Err(ImportParseError::Invalid("not AMD64"));
    }
    let section_count = u16_at(file, coff + 2)? as usize;
    let optional_size = u16_at(file, coff + 16)? as usize;
    let optional = coff.checked_add(20).ok_or(ImportParseError::Overflow)?;
    if u16_at(file, optional)? != 0x20b {
        return Err(ImportParseError::Invalid("not PE32+"));
    }
    if optional_size < 120 {
        return Err(ImportParseError::Invalid("optional header lacks import directory"));
    }
    let headers_size = u32_at(file, optional + 60)?;
    let import_rva = u32_at(file, optional + 112 + 8)?;
    let import_size = u32_at(file, optional + 112 + 12)?;
    let section_table = optional.checked_add(optional_size).ok_or(ImportParseError::Overflow)?;
    let mut sections = Vec::with_capacity(section_count);
    for i in 0..section_count {
        let o = section_table.checked_add(i.checked_mul(40).ok_or(ImportParseError::Overflow)?)
            .ok_or(ImportParseError::Overflow)?;
        let _ = file.get(o..o + 40).ok_or(ImportParseError::Truncated("section header"))?;
        sections.push(Section {
            virtual_size: u32_at(file, o + 8)?,
            virtual_address: u32_at(file, o + 12)?,
            raw_size: u32_at(file, o + 16)?,
            raw_pointer: u32_at(file, o + 20)?,
        });
    }
    if import_rva == 0 || import_size == 0 {
        return Ok(ImportManifest { modules: Vec::new(), function_count: 0 });
    }

    let import_end = import_rva.checked_add(import_size).ok_or(ImportParseError::Overflow)?;
    let mut descriptor_rva = import_rva;
    let mut modules = Vec::new();
    let mut total = 0usize;

    loop {
        if descriptor_rva.checked_add(20).ok_or(ImportParseError::Overflow)? > import_end {
            return Err(ImportParseError::Invalid("import descriptor table has no null terminator"));
        }
        let d = rva_to_offset(descriptor_rva, file, &sections, headers_size)?;
        let oft = u32_at(file, d)?;
        let name_rva = u32_at(file, d + 12)?;
        let ft = u32_at(file, d + 16)?;
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        if name_rva == 0 || ft == 0 {
            return Err(ImportParseError::Invalid("incomplete import descriptor"));
        }
        let name_offset = rva_to_offset(name_rva, file, &sections, headers_size)?;
        let dll_name = c_string(file, name_offset, "DLL name")?;
        let lookup_rva = if oft == 0 { ft } else { oft };
        let mut functions = Vec::new();
        let mut index = 0u32;

        loop {
            let thunk_rva = lookup_rva.checked_add(index.checked_mul(8).ok_or(ImportParseError::Overflow)?)
                .ok_or(ImportParseError::Overflow)?;
            let thunk_offset = rva_to_offset(thunk_rva, file, &sections, headers_size)?;
            let thunk = u64_at(file, thunk_offset)?;
            if thunk == 0 { break; }

            let symbol = if (thunk & 0x8000_0000_0000_0000) != 0 {
                ImportSymbol::Ordinal((thunk & 0xffff) as u16)
            } else {
                let name_rva = u32::try_from(thunk).map_err(|_| ImportParseError::Invalid("import name RVA exceeds 32 bits"))?;
                let name_offset = rva_to_offset(name_rva, file, &sections, headers_size)?;
                let hint = u16_at(file, name_offset)?;
                let name = c_string(file, name_offset + 2, "import symbol name")?;
                ImportSymbol::Name { hint, name }
            };
            let iat_rva = ft.checked_add(index.checked_mul(8).ok_or(ImportParseError::Overflow)?)
                .ok_or(ImportParseError::Overflow)?;
            // Validate the IAT slot is backed by bytes in the file.
            let _ = rva_to_offset(iat_rva, file, &sections, headers_size)?;
            functions.push(ImportedFunction { symbol, lookup_rva: thunk_rva, iat_rva });
            total = total.checked_add(1).ok_or(ImportParseError::Overflow)?;
            index = index.checked_add(1).ok_or(ImportParseError::Overflow)?;
        }

        modules.push(ImportedModule {
            name: dll_name,
            descriptor_rva,
            original_first_thunk_rva: oft,
            first_thunk_rva: ft,
            functions,
        });
        descriptor_rva = descriptor_rva.checked_add(20).ok_or(ImportParseError::Overflow)?;
    }

    Ok(ImportManifest { modules, function_count: total })
}

fn rva_to_offset(
    rva: u32,
    file: &[u8],
    sections: &[Section],
    headers_size: u32,
) -> Result<usize, ImportParseError> {
    if rva < headers_size {
        let offset = rva as usize;
        if offset < file.len() { return Ok(offset); }
        return Err(ImportParseError::Truncated("header RVA"));
    }
    for section in sections {
        let extent = section.virtual_size.max(section.raw_size);
        if let Some(delta) = rva.checked_sub(section.virtual_address) {
            if delta < extent {
                if delta >= section.raw_size {
                    return Err(ImportParseError::Invalid("RVA points into zero-filled section tail"));
                }
                let offset = section.raw_pointer.checked_add(delta).ok_or(ImportParseError::Overflow)? as usize;
                if offset >= file.len() {
                    return Err(ImportParseError::Truncated("section RVA"));
                }
                return Ok(offset);
            }
        }
    }
    Err(ImportParseError::Invalid("RVA is not backed by headers or section data"))
}

pub fn print_import_manifest(manifest: &ImportManifest) {
    println!("\n=== PHOENIX: PE IMPORT MANIFEST ===");
    println!("Imported modules: {}", manifest.modules.len());
    println!("Imported functions: {}", manifest.function_count);
    for module in &manifest.modules {
        println!("  {} — {} imports", module.name, module.functions.len());
    }
    println!("Inspection only: no DLLs loaded, no exports resolved, no IAT writes, no calls.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_with_imports() -> Vec<u8> {
        let mut f = vec![0u8; 0x800];
        f[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
        f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());
        let c = 0x84;
        f[c..c+2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[c+2..c+4].copy_from_slice(&1u16.to_le_bytes());
        f[c+16..c+18].copy_from_slice(&0xf0u16.to_le_bytes());
        let o = c + 20;
        f[o..o+2].copy_from_slice(&0x20bu16.to_le_bytes());
        f[o+60..o+64].copy_from_slice(&0x200u32.to_le_bytes());
        f[o+112+8..o+112+12].copy_from_slice(&0x1100u32.to_le_bytes());
        f[o+112+12..o+112+16].copy_from_slice(&40u32.to_le_bytes());
        let sh = o + 0xf0;
        f[sh+8..sh+12].copy_from_slice(&0x600u32.to_le_bytes());
        f[sh+12..sh+16].copy_from_slice(&0x1000u32.to_le_bytes());
        f[sh+16..sh+20].copy_from_slice(&0x600u32.to_le_bytes());
        f[sh+20..sh+24].copy_from_slice(&0x200u32.to_le_bytes());
        // import descriptor at RVA 0x1100 -> file 0x300
        f[0x300..0x304].copy_from_slice(&0x1140u32.to_le_bytes()); // OFT
        f[0x30c..0x310].copy_from_slice(&0x1180u32.to_le_bytes()); // DLL name
        f[0x310..0x314].copy_from_slice(&0x1160u32.to_le_bytes()); // FT
        f[0x380..0x38d].copy_from_slice(b"kernel32.dll\0");
        // Lookup and IAT thunks
        f[0x340..0x348].copy_from_slice(&0x11a0u64.to_le_bytes());
        f[0x348..0x350].copy_from_slice(&0u64.to_le_bytes());
        f[0x360..0x368].copy_from_slice(&0x11a0u64.to_le_bytes());
        f[0x368..0x370].copy_from_slice(&0u64.to_le_bytes());
        f[0x3a0..0x3a2].copy_from_slice(&7u16.to_le_bytes());
        f[0x3a2..0x3ad].copy_from_slice(b"ExitProcess");
        f
    }

    #[test]
    fn parses_named_import_and_iat_slot() {
        let manifest = parse_import_manifest(&pe_with_imports()).unwrap();
        assert_eq!(manifest.modules.len(), 1);
        assert_eq!(manifest.function_count, 1);
        assert_eq!(manifest.modules[0].name, "kernel32.dll");
        assert_eq!(manifest.modules[0].functions[0].iat_rva, 0x1160);
        assert_eq!(
            manifest.modules[0].functions[0].symbol,
            ImportSymbol::Name { hint: 7, name: "ExitProcess".into() }
        );
    }

    #[test]
    fn rejects_wrong_machine() {
        let mut f = pe_with_imports();
        f[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        assert_eq!(parse_import_manifest(&f), Err(ImportParseError::Invalid("not AMD64")));
    }

    #[test]
    fn rejects_unterminated_descriptor_table() {
        let mut f = pe_with_imports();
        // Make the second descriptor non-null so the directory ends without
        // the required null descriptor.
        f[0x314..0x318].copy_from_slice(&0x1140u32.to_le_bytes());
        f[0x320..0x324].copy_from_slice(&0x1180u32.to_le_bytes());
        f[0x324..0x328].copy_from_slice(&0x1160u32.to_le_bytes());
        assert!(parse_import_manifest(&f).is_err());
    }

    #[test]
    fn returns_empty_manifest_when_no_import_directory_exists() {
        let mut f = pe_with_imports();
        f[0x80 + 4 + 20 + 112 + 8..0x80 + 4 + 20 + 112 + 16].fill(0);
        let result = parse_import_manifest(&f).unwrap();
        assert!(result.modules.is_empty());
        assert_eq!(result.function_count, 0);
    }
}
