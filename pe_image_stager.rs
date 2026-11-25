//! Safe PE32+ image staging into Phoenix guest virtual memory.
//!
//! This maps headers and section bytes into guest-addressed host backing memory.
//! It supports PE32+ DIR64 base relocations. It does NOT resolve imports,
//! set final page protections,
//! run TLS callbacks, call DllMain, or execute the entry point.

use crate::guest_address_space::{AddressSpaceError, GuestAddressSpace, GuestRegion};
use crate::xmem_host_adapter::HostAllocationPolicy;
use crate::xmem_virtual_alloc::XMemVirtualAllocRequest;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeMapError {
    Truncated(&'static str),
    Invalid(&'static str),
    Overflow,
    UnsupportedMachine(u16),
    UnsupportedOptionalHeader(u16),
    AddressSpace(AddressSpaceError),
}

impl From<AddressSpaceError> for PeMapError {
    fn from(value: AddressSpaceError) -> Self {
        Self::AddressSpace(value)
    }
}

impl fmt::Display for PeMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PeMapError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImageInfo {
    pub preferred_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_point_rva: u32,
    pub relocation_rva: u32,
    pub relocation_size: u32,
    pub sections: Vec<PeSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeMappedImage {
    pub guest_base: usize,
    pub size: usize,
    pub entry_point: usize,
    pub section_count: usize,
    pub relocation_count: usize,
}

pub struct PeImageStager {
    address_space: GuestAddressSpace,
    mapped: Option<PeMappedImage>,
}

impl Default for PeImageStager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeImageStager {
    pub fn new() -> Self {
        Self { address_space: GuestAddressSpace::new(), mapped: None }
    }

    pub fn map_pe32_plus(&mut self, file: &[u8]) -> Result<PeMappedImage, PeMapError> {
        let info = parse_pe32_plus(file)?;
        let base = usize::try_from(info.preferred_base).map_err(|_| PeMapError::Overflow)?;
        self.map_pe32_plus_at(file, base)
    }

    /// Stage the image at a chosen guest base and apply supported DIR64 relocations.
    /// Unsupported relocation types fail closed; no code is executed.
    pub fn map_pe32_plus_at(&mut self, file: &[u8], guest_base: usize) -> Result<PeMappedImage, PeMapError> {
        if self.mapped.is_some() {
            return Err(PeMapError::Invalid("An image is already staged in this stager."));
        }
        let info = parse_pe32_plus(file)?;
        let image_size = info.size_of_image as usize;
        let image_end = guest_base.checked_add(image_size).ok_or(PeMapError::Overflow)?;
        let entry_point = guest_base.checked_add(info.entry_point_rva as usize)
            .ok_or(PeMapError::Overflow)?;
        if info.entry_point_rva as usize >= image_size {
            return Err(PeMapError::Invalid("Entry point RVA exceeds SizeOfImage"));
        }

        let request = XMemVirtualAllocRequest::new(
            0,
            image_size as u64,
            0,
            0,
            0,
        );
        let region = self.address_space.allocate_region(
            guest_base,
            image_size,
            request,
            HostAllocationPolicy::ReserveAndCommitReadWrite,
        )?;

        // Headers are copied first; committed memory is zero-initialized.
        if let Err(error) = self.address_space.write(
            guest_base, &file[..info.size_of_headers as usize],
        ) {
            let _ = self.address_space.free_region(region.guest_base);
            return Err(PeMapError::AddressSpace(error));
        }

        for section in &info.sections {
            if section.raw_size == 0 {
                continue;
            }
            let src_start = section.raw_pointer as usize;
            let src_end = src_start.checked_add(section.raw_size as usize)
                .ok_or(PeMapError::Overflow)?;
            let dst_start = guest_base.checked_add(section.virtual_address as usize)
                .ok_or(PeMapError::Overflow)?;
            let dst_end = dst_start.checked_add(section.raw_size as usize)
                .ok_or(PeMapError::Overflow)?;
            if src_end > file.len() {
                let _ = self.address_space.free_region(region.guest_base);
                return Err(PeMapError::Truncated("section raw data"));
            }
            if dst_end > image_end {
                let _ = self.address_space.free_region(region.guest_base);
                return Err(PeMapError::Invalid("section raw data exceeds SizeOfImage"));
            }
            if let Err(error) = self.address_space.write(dst_start, &file[src_start..src_end]) {
                let _ = self.address_space.free_region(region.guest_base);
                return Err(PeMapError::AddressSpace(error));
            }
        }

        let relocation_count = match apply_dir64_relocations(
            &mut self.address_space, guest_base, image_size, &info,
        ) {
            Ok(count) => count,
            Err(error) => {
                let _ = self.address_space.free_region(region.guest_base);
                return Err(error);
            }
        };

        let mapped = PeMappedImage {
            guest_base,
            size: image_size,
            entry_point,
            section_count: info.sections.len(),
            relocation_count,
        };
        self.mapped = Some(mapped);
        Ok(mapped)
    }

    pub fn read_guest(&self, address: usize, output: &mut [u8]) -> Result<(), PeMapError> {
        self.address_space.read(address, output)?;
        Ok(())
    }

    pub fn write_guest(&mut self, address: usize, bytes: &[u8]) -> Result<(), PeMapError> {
        self.address_space.write(address, bytes)?;
        Ok(())
    }

    pub fn mapped_image(&self) -> Option<PeMappedImage> {
        self.mapped
    }

    pub fn unload(&mut self) -> Result<(), PeMapError> {
        if let Some(mapped) = self.mapped.take() {
            self.address_space.free_region(mapped.guest_base)?;
        }
        Ok(())
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, PeMapError> {
    let bytes = data.get(offset..offset.checked_add(2).ok_or(PeMapError::Overflow)?)
        .ok_or(PeMapError::Truncated("u16 field"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, PeMapError> {
    let bytes = data.get(offset..offset.checked_add(4).ok_or(PeMapError::Overflow)?)
        .ok_or(PeMapError::Truncated("u32 field"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, PeMapError> {
    let bytes = data.get(offset..offset.checked_add(8).ok_or(PeMapError::Overflow)?)
        .ok_or(PeMapError::Truncated("u64 field"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

pub fn parse_pe32_plus(file: &[u8]) -> Result<PeImageInfo, PeMapError> {
    if read_u16(file, 0)? != 0x5a4d {
        return Err(PeMapError::Invalid("Missing MZ signature"));
    }
    let pe_offset = read_u32(file, 0x3c)? as usize;
    if read_u32(file, pe_offset)? != 0x00004550 {
        return Err(PeMapError::Invalid("Missing PE signature"));
    }

    let coff = pe_offset.checked_add(4).ok_or(PeMapError::Overflow)?;
    let machine = read_u16(file, coff)?;
    if machine != 0x8664 {
        return Err(PeMapError::UnsupportedMachine(machine));
    }
    let section_count = read_u16(file, coff + 2)? as usize;
    let optional_size = read_u16(file, coff + 16)? as usize;
    let optional = coff.checked_add(20).ok_or(PeMapError::Overflow)?;
    let magic = read_u16(file, optional)?;
    if magic != 0x20b {
        return Err(PeMapError::UnsupportedOptionalHeader(magic));
    }

    let entry_point_rva = read_u32(file, optional + 16)?;
    let preferred_base = read_u64(file, optional + 24)?;
    let size_of_image = read_u32(file, optional + 56)?;
    let size_of_headers = read_u32(file, optional + 60)?;
    if optional_size < 112 + 6 * 8 {
        return Err(PeMapError::Invalid("Optional header lacks base-relocation directory entry"));
    }
    let relocation_rva = read_u32(file, optional + 112 + 5 * 8)?;
    let relocation_size = read_u32(file, optional + 112 + 5 * 8 + 4)?;
    if size_of_image == 0 || size_of_headers == 0 || size_of_headers > size_of_image {
        return Err(PeMapError::Invalid("Invalid SizeOfImage/SizeOfHeaders"));
    }
    if entry_point_rva >= size_of_image {
        return Err(PeMapError::Invalid("Entry point RVA exceeds SizeOfImage"));
    }
    if size_of_headers as usize > file.len() {
        return Err(PeMapError::Truncated("headers"));
    }

    let section_table = optional.checked_add(optional_size).ok_or(PeMapError::Overflow)?;
    let table_size = section_count.checked_mul(40).ok_or(PeMapError::Overflow)?;
    let table_end = section_table.checked_add(table_size).ok_or(PeMapError::Overflow)?;
    if table_end > file.len() || table_end > size_of_headers as usize {
        return Err(PeMapError::Truncated("section table"));
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table + index * 40;
        let name_bytes = &file[offset..offset + 8];
        let name_end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        let virtual_size = read_u32(file, offset + 8)?;
        let virtual_address = read_u32(file, offset + 12)?;
        let raw_size = read_u32(file, offset + 16)?;
        let raw_pointer = read_u32(file, offset + 20)?;

        let virtual_extent = virtual_size.max(raw_size);
        let virtual_end = virtual_address.checked_add(virtual_extent)
            .ok_or(PeMapError::Overflow)?;
        if virtual_end > size_of_image {
            return Err(PeMapError::Invalid("section virtual range exceeds SizeOfImage"));
        }
        if raw_size != 0 {
            let raw_end = raw_pointer.checked_add(raw_size).ok_or(PeMapError::Overflow)?;
            if raw_end as usize > file.len() {
                return Err(PeMapError::Truncated("section raw data"));
            }
        }
        if virtual_extent != 0 && virtual_address < size_of_headers {
            return Err(PeMapError::Invalid("section virtual range overlaps image headers"));
        }
        sections.push(PeSection {
            name, virtual_address, virtual_size, raw_size, raw_pointer,
        });
    }

    // Section-table order is not assumed. Sort non-empty virtual ranges and
    // reject overlaps before the stager allocates or copies any image bytes.
    let mut virtual_ranges: Vec<(u32, u32)> = sections.iter()
        .filter_map(|section| {
            let extent = section.virtual_size.max(section.raw_size);
            (extent != 0).then(|| {
                (section.virtual_address, section.virtual_address + extent)
            })
        })
        .collect();
    virtual_ranges.sort_unstable_by_key(|range| range.0);
    for pair in virtual_ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(PeMapError::Invalid("section virtual ranges overlap"));
        }
    }

    Ok(PeImageInfo {
        preferred_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        relocation_rva,
        relocation_size,
        sections,
    })
}

 
fn apply_dir64_relocations(
    address_space: &mut GuestAddressSpace,
    guest_base: usize,
    image_size: usize,
    info: &PeImageInfo,
) -> Result<usize, PeMapError> {
    let delta = (guest_base as i128) - (info.preferred_base as i128);

    if info.relocation_size == 0 {
        if info.relocation_rva != 0 {
            return Err(PeMapError::Invalid("Relocation RVA is nonzero but directory size is zero"));
        }
        if delta != 0 {
            return Err(PeMapError::Invalid("Image needs relocation but has no relocation directory"));
        }
        return Ok(0);
    }
    if info.relocation_rva == 0 {
        return Err(PeMapError::Invalid("Relocation directory has a zero RVA"));
    }

    let directory_end = info.relocation_rva.checked_add(info.relocation_size)
        .ok_or(PeMapError::Overflow)? as usize;
    if directory_end > image_size {
        return Err(PeMapError::Invalid("Relocation directory exceeds SizeOfImage"));
    }

    let mut cursor = guest_base.checked_add(info.relocation_rva as usize)
        .ok_or(PeMapError::Overflow)?;
    let end = guest_base.checked_add(directory_end).ok_or(PeMapError::Overflow)?;
    let mut applied = 0usize;

    // Always walk and validate the relocation directory, even when the image is
    // loaded at its preferred base. A zero delta removes writes, not validation.
    while cursor < end {
        if end - cursor < 8 {
            return Err(PeMapError::Invalid("Truncated relocation block header"));
        }
        let mut header = [0u8; 8];
        address_space.read(cursor, &mut header)?;
        let page_rva = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let block_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if page_rva as usize >= image_size || page_rva & 0xfff != 0 {
            return Err(PeMapError::Invalid("Invalid relocation block page RVA"));
        }
        if block_size < 8 || block_size % 2 != 0 || block_size > end - cursor {
            return Err(PeMapError::Invalid("Invalid relocation block size"));
        }
        let entries = (block_size - 8) / 2;
        for index in 0..entries {
            let entry_address = cursor.checked_add(8 + index * 2).ok_or(PeMapError::Overflow)?;
            let mut raw = [0u8; 2];
            address_space.read(entry_address, &mut raw)?;
            let item = u16::from_le_bytes(raw);
            let kind = item >> 12;
            let offset = (item & 0x0fff) as u32;
            match kind {
                0 => {} // IMAGE_REL_BASED_ABSOLUTE padding
                10 => {
                    let target_rva = page_rva.checked_add(offset).ok_or(PeMapError::Overflow)?;
                    let target_end = target_rva.checked_add(8).ok_or(PeMapError::Overflow)?;
                    if target_end as usize > image_size {
                        return Err(PeMapError::Invalid("DIR64 target exceeds SizeOfImage"));
                    }
                    if delta != 0 {
                        let target = guest_base.checked_add(target_rva as usize).ok_or(PeMapError::Overflow)?;
                        let mut value_bytes = [0u8; 8];
                        address_space.read(target, &mut value_bytes)?;
                        let original = u64::from_le_bytes(value_bytes);
                        let relocated = (original as i128).checked_add(delta)
                            .ok_or(PeMapError::Overflow)?;
                        if relocated < 0 || relocated > u64::MAX as i128 {
                            return Err(PeMapError::Overflow);
                        }
                        address_space.write(target, &(relocated as u64).to_le_bytes())?;
                        applied += 1;
                    }
                }
                1 => return Err(PeMapError::Invalid("Unsupported HIGH relocation")),
                2 => return Err(PeMapError::Invalid("Unsupported LOW relocation")),
                3 => return Err(PeMapError::Invalid("Unsupported HIGHLOW relocation")),
                _ => return Err(PeMapError::Invalid("Unsupported relocation type")),
            }
        }
        cursor = cursor.checked_add(block_size).ok_or(PeMapError::Overflow)?;
    }
    if cursor != end {
        return Err(PeMapError::Invalid("Relocation directory size mismatch"));
    }
    Ok(applied)
}

pub fn print_stager_report() {
    println!("\n=== PHOENIX: PE32+ GUEST IMAGE STAGER ===");
    println!("Maps PE headers and section raw bytes into guest virtual memory.");
    println!("Applies PE32+ DIR64 base relocations; unsupported relocation types fail closed.");
    println!("No import resolution, final page protections, TLS, DllMain, or execution.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_pe() -> Vec<u8> {
        let mut file = vec![0u8; 0x400];
        file[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
        file[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        file[0x80..0x84].copy_from_slice(&0x00004550u32.to_le_bytes());

        let coff = 0x84;
        file[coff..coff+2].copy_from_slice(&0x8664u16.to_le_bytes());
        file[coff+2..coff+4].copy_from_slice(&1u16.to_le_bytes());
        file[coff+16..coff+18].copy_from_slice(&0xf0u16.to_le_bytes());

        let opt = coff + 20;
        file[opt..opt+2].copy_from_slice(&0x20bu16.to_le_bytes());
        file[opt+16..opt+20].copy_from_slice(&0x1000u32.to_le_bytes());
        file[opt+24..opt+32].copy_from_slice(&0x0000000140000000u64.to_le_bytes());
        file[opt+56..opt+60].copy_from_slice(&0x3000u32.to_le_bytes());
        file[opt+60..opt+64].copy_from_slice(&0x200u32.to_le_bytes());
        file[opt+112+5*8..opt+112+5*8+4].copy_from_slice(&0x1100u32.to_le_bytes());
        file[opt+112+5*8+4..opt+112+5*8+8].copy_from_slice(&12u32.to_le_bytes());

        let section = opt + 0xf0;
        file[section..section+5].copy_from_slice(b".text");
        file[section+8..section+12].copy_from_slice(&0x100u32.to_le_bytes());
        file[section+12..section+16].copy_from_slice(&0x1000u32.to_le_bytes());
        file[section+16..section+20].copy_from_slice(&0x200u32.to_le_bytes());
        file[section+20..section+24].copy_from_slice(&0x200u32.to_le_bytes());
        file[0x200..0x204].copy_from_slice(b"CODE");
        // DIR64 target at RVA 0x1020, plus ABSOLUTE padding.
        file[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes());
        file[0x304..0x308].copy_from_slice(&12u32.to_le_bytes());
        file[0x308..0x30a].copy_from_slice(&0xa020u16.to_le_bytes());
        file[0x30a..0x30c].copy_from_slice(&0u16.to_le_bytes());
        file[0x220..0x228].copy_from_slice(&0x0000000140001234u64.to_le_bytes());
        file
    }

    #[test]
    fn parses_amd64_pe32_plus_headers_and_sections() {
        let info = parse_pe32_plus(&tiny_pe()).unwrap();
        assert_eq!(info.preferred_base, 0x140000000);
        assert_eq!(info.size_of_image, 0x3000);
        assert_eq!(info.entry_point_rva, 0x1000);
        assert_eq!(info.sections.len(), 1);
        assert_eq!(info.sections[0].name, ".text");
    }

    #[test]
    fn stages_headers_and_section_bytes_at_guest_addresses() {
        let file = tiny_pe();
        let mut stager = PeImageStager::new();
        let mapped = stager.map_pe32_plus(&file).unwrap();

        assert_eq!(mapped.guest_base, 0x140000000usize);
        assert_eq!(mapped.entry_point, 0x140001000usize);
        assert_eq!(mapped.relocation_count, 0);
        let mut code = [0u8; 4];
        stager.read_guest(0x140001000, &mut code).unwrap();
        assert_eq!(&code, b"CODE");
    }

    #[test]
    fn applies_dir64_relocations_when_staged_at_alternate_guest_base() {
        let file = tiny_pe();
        let mut stager = PeImageStager::new();
        let mapped = stager.map_pe32_plus_at(&file, 0x150000000usize).unwrap();
        assert_eq!(mapped.relocation_count, 1);

        let mut pointer = [0u8; 8];
        stager.read_guest(0x150001020, &mut pointer).unwrap();
        assert_eq!(u64::from_le_bytes(pointer), 0x150001234);
    }

    #[test]
    fn rejects_non_amd64_and_non_pe32_plus_inputs() {
        let mut file = tiny_pe();
        file[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        assert!(matches!(parse_pe32_plus(&file), Err(PeMapError::UnsupportedMachine(0x14c))));

        let mut file = tiny_pe();
        file[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        assert!(matches!(parse_pe32_plus(&file), Err(PeMapError::UnsupportedOptionalHeader(0x10b))));
    }

    #[test]
    fn rejects_truncated_section_raw_data() {
        let mut file = tiny_pe();
        file.truncate(0x250);
        assert!(matches!(parse_pe32_plus(&file), Err(PeMapError::Truncated("section raw data"))));
    }

    #[test]
    fn unload_releases_the_staged_guest_region() {
        let mut stager = PeImageStager::new();
        stager.map_pe32_plus(&tiny_pe()).unwrap();
        stager.unload().unwrap();
        assert_eq!(stager.mapped_image(), None);
    }
    #[test]
    fn rejects_guest_image_range_overflow_before_allocating() {
        let mut stager = PeImageStager::new();
        let result = stager.map_pe32_plus_at(&tiny_pe(), usize::MAX - 0x1000);
        assert_eq!(result, Err(PeMapError::Overflow));
        assert_eq!(stager.mapped_image(), None);
        assert_eq!(stager.address_space.region_count(), 0);
    }

    #[test]
    fn rejects_entry_point_outside_image_without_allocating() {
        let mut file = tiny_pe();
        let optional_header = 0x98;
        file[optional_header + 16..optional_header + 20]
            .copy_from_slice(&0x3000u32.to_le_bytes());
        let mut stager = PeImageStager::new();
        assert_eq!(
            stager.map_pe32_plus_at(&file, 0x150000000),
            Err(PeMapError::Invalid("Entry point RVA exceeds SizeOfImage"))
        );
        assert_eq!(stager.address_space.region_count(), 0);
    }

    #[test]
    fn failed_stage_does_not_leave_an_active_region() {
        let mut file = tiny_pe();
        // Make the relocation directory structurally invalid after staging begins.
        file[0x304..0x308].copy_from_slice(&7u32.to_le_bytes());
        let mut stager = PeImageStager::new();
        assert!(stager.map_pe32_plus_at(&file, 0x150000000).is_err());
        assert_eq!(stager.mapped_image(), None);
        assert_eq!(stager.address_space.region_count(), 0);
    }

    #[test]
    fn validates_relocation_directory_even_at_preferred_base() {
        let mut file = tiny_pe();
        // Corrupt the relocation block size. Preferred-base staging must still
        // inspect the directory rather than silently skipping it for zero delta.
        file[0x304..0x308].copy_from_slice(&7u32.to_le_bytes());
        let mut stager = PeImageStager::new();
        assert!(stager.map_pe32_plus(&file).is_err());
        assert_eq!(stager.mapped_image(), None);
        assert_eq!(stager.address_space.region_count(), 0);
    }

    #[test]
    fn rejects_sections_that_overlap_in_guest_image_layout() {
        let mut file = tiny_pe();
        let coff = 0x84;
        let opt = coff + 20;
        let second = opt + 0xf0 + 40;
        file[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        file[second..second + 5].copy_from_slice(b".data");
        file[second + 8..second + 12].copy_from_slice(&0x100u32.to_le_bytes());
        file[second + 12..second + 16].copy_from_slice(&0x1080u32.to_le_bytes());
        file[second + 16..second + 20].copy_from_slice(&0x100u32.to_le_bytes());
        file[second + 20..second + 24].copy_from_slice(&0x300u32.to_le_bytes());

        assert_eq!(
            parse_pe32_plus(&file),
            Err(PeMapError::Invalid("section virtual ranges overlap"))
        );
    }

    #[test]
    fn rejects_sections_that_overlap_image_headers() {
        let mut file = tiny_pe();
        let section = 0x98 + 0xf0;
        file[section + 12..section + 16].copy_from_slice(&0x100u32.to_le_bytes());

        assert_eq!(
            parse_pe32_plus(&file),
            Err(PeMapError::Invalid("section virtual range overlaps image headers"))
        );
    }

}
