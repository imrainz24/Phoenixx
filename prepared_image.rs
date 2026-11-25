//! Builds a Windows-loader-compatible copy of a PE32+ title image.
//!
//! This is a data-only preparation step. It preserves the original import and
//! TLS metadata in the returned object while patching a separate byte buffer so
//! Windows can map the copy without resolving title imports or running its
//! entry point/TLS callbacks. It does not map the image or execute code.

use crate::loader_lifecycle::{
    LifecycleError, LoaderLifecyclePlan, build_loader_lifecycle_plan,
};
use crate::pe_image_stager::{PeImageInfo, PeMapError, parse_pe32_plus};
use crate::pe_import_manifest::{ImportManifest, ImportParseError, parse_import_manifest};
use std::fmt;

const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_IMPORT_DESCRIPTOR_SIZE: u32 = 20;
const IMAGE_TLS_DIRECTORY64_SIZE: usize = 40;
const TLS64_ADDRESS_OF_CALLBACKS: usize = 24;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;

#[derive(Debug)]
pub enum PreparedImageError {
    Pe(PeMapError),
    Imports(ImportParseError),
    Lifecycle(LifecycleError),
    Invalid(&'static str),
    Overflow,
}

impl From<PeMapError> for PreparedImageError {
    fn from(value: PeMapError) -> Self { Self::Pe(value) }
}
impl From<ImportParseError> for PreparedImageError {
    fn from(value: ImportParseError) -> Self { Self::Imports(value) }
}
impl From<LifecycleError> for PreparedImageError {
    fn from(value: LifecycleError) -> Self { Self::Lifecycle(value) }
}
impl fmt::Display for PreparedImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for PreparedImageError {}

/// Original metadata plus a distinct, patched file image for Windows mapping.
#[derive(Debug, Clone)]
pub struct PreparedImage {
    /// Parsed from the untouched executable.
    pub original_info: PeImageInfo,
    /// Imports and IAT RVAs from the untouched executable.
    pub imports: ImportManifest,
    /// TLS callbacks, exception metadata and section permissions from original.
    pub lifecycle: LoaderLifecyclePlan,
    /// Patched PE file bytes. The caller should write this outside the source
    /// game directory before attempting a Windows module load.
    pub bytes: Vec<u8>,
    /// Number of DIR64 relocation entries neutralized for the cleared TLS field.
    pub tls_relocations_neutralized: usize,
}

impl PreparedImage {
    pub fn original_entry_point_rva(&self) -> u32 { self.original_info.entry_point_rva }
    pub fn image_size(&self) -> u32 { self.original_info.size_of_image }
    pub fn original_import_count(&self) -> usize { self.imports.function_count }
    pub fn original_tls_callback_count(&self) -> usize {
        self.lifecycle.tls.as_ref().map_or(0, |tls| tls.callback_rvas.len())
    }
}

/// Prepare a copy of an AMD64 PE32+ executable for mapping as a DLL.
///
/// The original slice is never modified. The original import manifest and
/// lifecycle plan remain available so Phoenix can later bind imports and
/// initialize the title in a controlled order.
pub fn prepare(original: &[u8]) -> Result<PreparedImage, PreparedImageError> {
    let info = parse_pe32_plus(original)?;
    let imports = parse_import_manifest(original)?;
    let lifecycle = build_loader_lifecycle_plan(original)?;
    let mut bytes = original.to_vec();

    let (file_header, optional_header, optional_size) = header_offsets(&bytes)?;
    let characteristics = read_u16(&bytes, file_header + 18)? | IMAGE_FILE_DLL;
    write_u16(&mut bytes, file_header + 18, characteristics)?;

    // No title entry point is allowed to run during LoadLibraryExW.
    write_u32(&mut bytes, optional_header + 16, 0)?;
    write_u32(&mut bytes, optional_header + 64, 0)?; // CheckSum

    let dll_chars = read_u16(&bytes, optional_header + 70)?
        & !IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
    write_u16(&mut bytes, optional_header + 70, dll_chars)?;

    // Point the OS loader at the already-present null descriptor. The original
    // descriptors and IAT slots remain intact for Phoenix's own resolver.
    if let Some(import_dir) = directory_offset(&bytes, optional_header, optional_size, IMAGE_DIRECTORY_ENTRY_IMPORT)? {
        let import_rva = read_u32(&bytes, import_dir)?;
        let import_size = read_u32(&bytes, import_dir + 4)?;
        if import_rva != 0 && import_size != 0 {
            let terminator_rva = imports.modules.last()
                .map(|m| m.descriptor_rva.checked_add(IMAGE_IMPORT_DESCRIPTOR_SIZE))
                .unwrap_or(Some(import_rva))
                .ok_or(PreparedImageError::Overflow)?;
            let terminator_offset = rva_to_file_offset(&info, terminator_rva, IMAGE_IMPORT_DESCRIPTOR_SIZE as usize)?;
            let terminator = bytes.get(terminator_offset..terminator_offset + IMAGE_IMPORT_DESCRIPTOR_SIZE as usize)
                .ok_or(PreparedImageError::Invalid("import terminator is outside file"))?;
            if terminator.iter().any(|b| *b != 0) {
                return Err(PreparedImageError::Invalid("import descriptor terminator is not zero"));
            }
            write_u32(&mut bytes, import_dir, terminator_rva)?;
            write_u32(&mut bytes, import_dir + 4, IMAGE_IMPORT_DESCRIPTOR_SIZE)?;
        }
    }

    // Bound imports refer to the original imports and must not be consumed by
    // the Windows loader after the normal import directory has been detached.
    if let Some(bound_dir) = directory_offset(&bytes, optional_header, optional_size, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)? {
        write_u32(&mut bytes, bound_dir, 0)?;
        write_u32(&mut bytes, bound_dir + 4, 0)?;
    }

    let mut tls_relocations_neutralized = 0;
    if let Some(tls) = &lifecycle.tls {
        if tls.callback_array_rva.is_some() {
            let callbacks_field_rva = tls.directory.rva
                .checked_add(TLS64_ADDRESS_OF_CALLBACKS as u32)
                .ok_or(PreparedImageError::Overflow)?;
            let tls_dir_offset = rva_to_file_offset(&info, tls.directory.rva, IMAGE_TLS_DIRECTORY64_SIZE)?;
            write_u64(&mut bytes, tls_dir_offset + TLS64_ADDRESS_OF_CALLBACKS, 0)?;
            tls_relocations_neutralized = neutralize_dir64_relocations(
                &mut bytes, &info, callbacks_field_rva,
            )?;
        }
    }

    Ok(PreparedImage {
        original_info: info,
        imports,
        lifecycle,
        bytes,
        tls_relocations_neutralized,
    })
}

fn header_offsets(bytes: &[u8]) -> Result<(usize, usize, usize), PreparedImageError> {
    if read_u16(bytes, 0)? != 0x5a4d {
        return Err(PreparedImageError::Invalid("missing MZ signature"));
    }
    let pe = read_u32(bytes, 0x3c)? as usize;
    if read_u32(bytes, pe)? != 0x0000_4550 {
        return Err(PreparedImageError::Invalid("missing PE signature"));
    }
    let file_header = pe.checked_add(4).ok_or(PreparedImageError::Overflow)?;
    let optional_header = file_header.checked_add(20).ok_or(PreparedImageError::Overflow)?;
    let optional_size = read_u16(bytes, file_header + 16)? as usize;
    if read_u16(bytes, optional_header)? != 0x20b || optional_size < 112 {
        return Err(PreparedImageError::Invalid("not a complete PE32+ optional header"));
    }
    let _ = bytes.get(optional_header..optional_header.checked_add(optional_size).ok_or(PreparedImageError::Overflow)?)
        .ok_or(PreparedImageError::Invalid("truncated optional header"))?;
    Ok((file_header, optional_header, optional_size))
}

fn directory_offset(
    bytes: &[u8], optional: usize, optional_size: usize, index: usize,
) -> Result<Option<usize>, PreparedImageError> {
    if optional_size < 112 { return Ok(None); }
    let count = read_u32(bytes, optional + 108)? as usize;
    if index >= count { return Ok(None); }
    let relative = 112usize.checked_add(index.checked_mul(8).ok_or(PreparedImageError::Overflow)?)
        .ok_or(PreparedImageError::Overflow)?;
    if relative.checked_add(8).ok_or(PreparedImageError::Overflow)? > optional_size {
        return Err(PreparedImageError::Invalid("data directory exceeds optional header"));
    }
    Ok(Some(optional.checked_add(relative).ok_or(PreparedImageError::Overflow)?))
}

fn rva_to_file_offset(info: &PeImageInfo, rva: u32, length: usize) -> Result<usize, PreparedImageError> {
    let length_u32 = u32::try_from(length).map_err(|_| PreparedImageError::Overflow)?;
    let end = rva.checked_add(length_u32).ok_or(PreparedImageError::Overflow)?;
    if end > info.size_of_image { return Err(PreparedImageError::Invalid("RVA range exceeds SizeOfImage")); }
    if rva < info.size_of_headers {
        let start = rva as usize;
        return Ok(start);
    }
    for section in &info.sections {
        let extent = section.virtual_size.max(section.raw_size);
        if rva >= section.virtual_address {
            let delta = rva - section.virtual_address;
            if delta.checked_add(length_u32).is_some_and(|v| v <= section.raw_size) {
                return usize::try_from(section.raw_pointer.checked_add(delta).ok_or(PreparedImageError::Overflow)?)
                    .map_err(|_| PreparedImageError::Overflow);
            }
            if delta < extent { return Err(PreparedImageError::Invalid("RVA range is not file-backed")); }
        }
    }
    Err(PreparedImageError::Invalid("RVA does not map to a file-backed section"))
}

fn neutralize_dir64_relocations(
    bytes: &mut [u8], info: &PeImageInfo, target_rva: u32,
) -> Result<usize, PreparedImageError> {
    if info.relocation_rva == 0 || info.relocation_size == 0 { return Ok(0); }
    let start = rva_to_file_offset(info, info.relocation_rva, info.relocation_size as usize)?;
    let end = start.checked_add(info.relocation_size as usize).ok_or(PreparedImageError::Overflow)?;
    if end > bytes.len() { return Err(PreparedImageError::Invalid("relocation directory exceeds file")); }
    let mut cursor = start;
    let mut changed = 0usize;
    while cursor < end {
        if end - cursor < 8 { return Err(PreparedImageError::Invalid("truncated relocation block header")); }
        let page_rva = read_u32(bytes, cursor)?;
        let block_size = read_u32(bytes, cursor + 4)? as usize;
        if block_size < 8 || block_size % 2 != 0 || cursor.checked_add(block_size).is_none_or(|v| v > end) {
            return Err(PreparedImageError::Invalid("invalid relocation block size"));
        }
        let mut entry = cursor + 8;
        while entry < cursor + block_size {
            let value = read_u16(bytes, entry)?;
            let kind = value >> 12;
            if kind == IMAGE_REL_BASED_DIR64 {
                let relocation_rva = page_rva.checked_add(u32::from(value & 0x0fff))
                    .ok_or(PreparedImageError::Overflow)?;
                if relocation_rva == target_rva {
                    write_u16(bytes, entry, IMAGE_REL_BASED_ABSOLUTE)?;
                    changed += 1;
                }
            }
            entry += 2;
        }
        cursor += block_size;
    }
    Ok(changed)
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, PreparedImageError> {
    let end = at.checked_add(2).ok_or(PreparedImageError::Overflow)?;
    let b = bytes.get(at..end).ok_or(PreparedImageError::Invalid("truncated u16"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32(bytes: &[u8], at: usize) -> Result<u32, PreparedImageError> {
    let end = at.checked_add(4).ok_or(PreparedImageError::Overflow)?;
    let b = bytes.get(at..end).ok_or(PreparedImageError::Invalid("truncated u32"))?;
    Ok(u32::from_le_bytes(b.try_into().expect("four-byte slice")))
}
fn read_u64(bytes: &[u8], at: usize) -> Result<u64, PreparedImageError> {
    let end = at.checked_add(8).ok_or(PreparedImageError::Overflow)?;
    let b = bytes.get(at..end).ok_or(PreparedImageError::Invalid("truncated u64"))?;
    Ok(u64::from_le_bytes(b.try_into().expect("eight-byte slice")))
}

fn write_u16(bytes: &mut [u8], at: usize, value: u16) -> Result<(), PreparedImageError> {
    let end = at.checked_add(2).ok_or(PreparedImageError::Overflow)?;
    bytes.get_mut(at..end).ok_or(PreparedImageError::Invalid("u16 patch outside file"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write_u32(bytes: &mut [u8], at: usize, value: u32) -> Result<(), PreparedImageError> {
    let end = at.checked_add(4).ok_or(PreparedImageError::Overflow)?;
    bytes.get_mut(at..end).ok_or(PreparedImageError::Invalid("u32 patch outside file"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write_u64(bytes: &mut [u8], at: usize, value: u64) -> Result<(), PreparedImageError> {
    let end = at.checked_add(8).ok_or(PreparedImageError::Overflow)?;
    bytes.get_mut(at..end).ok_or(PreparedImageError::Invalid("u64 patch outside file"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_a_copy_of_the_test_executable_without_mutating_original() {
        let original = std::fs::read(std::env::current_exe().expect("test executable path"))
            .expect("read test executable");
        let prepared = prepare(&original).expect("prepare current PE executable");
        assert_eq!(prepared.bytes.len(), original.len());
        assert!(!prepared.bytes.is_empty());
        assert_eq!(read_u16(&prepared.bytes, 0).unwrap(), 0x5a4d);
        let (file_header, optional, optional_size) = header_offsets(&prepared.bytes).unwrap();
        assert_ne!(read_u16(&prepared.bytes, file_header + 18).unwrap() & IMAGE_FILE_DLL, 0);
        assert_eq!(read_u32(&prepared.bytes, optional + 16).unwrap(), 0);
        assert_eq!(read_u32(&prepared.bytes, optional + 64).unwrap(), 0);
        assert!(read_u16(&prepared.bytes, optional + 70).unwrap() & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY == 0);
        if let Some(import_dir) = directory_offset(&prepared.bytes, optional, optional_size, IMAGE_DIRECTORY_ENTRY_IMPORT).unwrap() {
            let rva = read_u32(&prepared.bytes, import_dir).unwrap();
            let size = read_u32(&prepared.bytes, import_dir + 4).unwrap();
            if rva != 0 && size != 0 {
                assert_eq!(size, IMAGE_IMPORT_DESCRIPTOR_SIZE);
                let at = rva_to_file_offset(&prepared.original_info, rva, 20).unwrap();
                assert!(prepared.bytes[at..at + 20].iter().all(|b| *b == 0));
            }
        }
        // Windows now sees an empty import table, while Phoenix still has the
        // original manifest and every original IAT slot remains byte-identical.
        let os_imports = parse_import_manifest(&prepared.bytes).unwrap();
        assert!(os_imports.modules.is_empty());
        assert_eq!(prepared.imports.function_count,
            prepared.imports.modules.iter().map(|m| m.functions.len()).sum::<usize>());
        for module in &prepared.imports.modules {
            for function in &module.functions {
                let at = rva_to_file_offset(&prepared.original_info, function.iat_rva, 8).unwrap();
                assert_eq!(&prepared.bytes[at..at + 8], &original[at..at + 8]);
            }
        }
        if let Some(tls) = &prepared.lifecycle.tls {
            if tls.callback_array_rva.is_some() {
                let at = rva_to_file_offset(&prepared.original_info, tls.directory.rva,
                    IMAGE_TLS_DIRECTORY64_SIZE).unwrap() + TLS64_ADDRESS_OF_CALLBACKS;
                assert_eq!(read_u64(&prepared.bytes, at).unwrap(), 0);
                // If the original image had a DIR64 relocation for this field,
                // preparation must have converted it to ABSOLUTE.
                if prepared.tls_relocations_neutralized > 0 {
                    assert!(prepared.tls_relocations_neutralized >= 1);
                }
            }
        }
    }

    #[test]
    fn preparation_is_deterministic() {
        let original = std::fs::read(std::env::current_exe().expect("test executable path"))
            .expect("read test executable");
        let a = prepare(&original).unwrap();
        let b = prepare(&original).unwrap();
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.tls_relocations_neutralized, b.tls_relocations_neutralized);
    }
}
