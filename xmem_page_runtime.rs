//! Page-size-aware XMem physical-page runtime for Project Phoenix.
//!
//! This composes the software page pool and virtual-region model. It supports
//! the 64 KiB and 2 MiB page modes demonstrated by the public GDK sample, but
//! does not claim Xbox physical-memory, cache, or GPU-coherency equivalence.

use crate::xmem_model_v3::{PageId, PageSize, PhysicalPagePool, VirtualRegion, XMemError};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    Model(XMemError),
    UnknownRegion,
    AddressOverflow,
}

impl From<XMemError> for RuntimeError {
    fn from(value: XMemError) -> Self { Self::Model(value) }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for RuntimeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegionId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionInfo {
    pub id: RegionId,
    pub base: usize,
    pub size: usize,
    pub page_size: PageSize,
    pub page_count: usize,
}

struct RegionEntry {
    info: RegionInfo,
    region: VirtualRegion,
    pages: Vec<PageId>,
}

pub struct XMemPageRuntime {
    pool: PhysicalPagePool,
    next_region_id: u64,
    regions: Vec<RegionEntry>,
}

impl Default for XMemPageRuntime {
    fn default() -> Self { Self::new() }
}

impl XMemPageRuntime {
    pub fn new() -> Self {
        Self { pool: PhysicalPagePool::new(), next_region_id: 1, regions: Vec::new() }
    }

    /// Allocate simulated physical pages and map them at a guest-relative base.
    /// The region size must be an exact multiple of the selected page size.
    pub fn allocate_and_map(
        &mut self,
        base: usize,
        size: usize,
        page_size: PageSize,
    ) -> Result<RegionInfo, RuntimeError> {
        let unit = page_size.bytes();
        if size == 0 || size % unit != 0 || base % unit != 0 {
            return Err(RuntimeError::Model(XMemError::UnalignedAddress { offset: base, page_size: unit }));
        }
        let end = base.checked_add(size).ok_or(RuntimeError::AddressOverflow)?;
        for existing in &self.regions {
            let existing_end = existing.info.base.checked_add(existing.info.size)
                .ok_or(RuntimeError::AddressOverflow)?;
            if base < existing_end && existing.info.base < end {
                return Err(RuntimeError::Model(XMemError::AddressOutOfRange(base)));
            }
        }
        let page_count = size / unit;
        let id_value = self.next_region_id;
        let next_id = id_value.checked_add(1).ok_or(RuntimeError::AddressOverflow)?;

        let pages = self.pool.allocate_with_size(page_count, page_size)?;
        let mut region: VirtualRegion = match VirtualRegion::reserve_with_page_size(size, page_size) {
            Ok(region) => region,
            Err(error) => { self.pool.free(&pages)?; return Err(error.into()); }
        };
        if let Err(error) = region.map(0, &pages, &mut self.pool) {
            self.pool.free(&pages)?;
            return Err(error.into());
        }

        let info = RegionInfo { id: RegionId(id_value), base, size, page_size, page_count };
        self.next_region_id = next_id;
        self.regions.push(RegionEntry { info, region, pages });
        Ok(info)
    }

    pub fn write(&mut self, id: RegionId, offset: usize, data: &[u8]) -> Result<(), RuntimeError> {
        let entry = self.regions.iter().find(|entry| entry.info.id == id).ok_or(RuntimeError::UnknownRegion)?;
        entry.region.write(&mut self.pool, offset, data)?;
        Ok(())
    }

    pub fn read(&self, id: RegionId, offset: usize, output: &mut [u8]) -> Result<(), RuntimeError> {
        let entry = self.regions.iter().find(|entry| entry.info.id == id).ok_or(RuntimeError::UnknownRegion)?;
        entry.region.read(&self.pool, offset, output)?;
        Ok(())
    }

    pub fn unmap_and_free(&mut self, id: RegionId) -> Result<(), RuntimeError> {
        let index = self.regions.iter().position(|entry| entry.info.id == id).ok_or(RuntimeError::UnknownRegion)?;
        // Copy the count before taking a mutable borrow of the region.
        let page_count = self.regions[index].info.page_count;
        let removed = self.regions[index].region.unmap(
            0,
            page_count,
            &mut self.pool,
        )?;
        self.pool.free(&removed)?;
        self.regions.remove(index);
        Ok(())
    }

    pub fn allocated_page_count(&self) -> usize { self.pool.allocated_count() }
    pub fn region_count(&self) -> usize { self.regions.len() }
}

pub fn print_runtime_report() {
    println!("\n=== PHOENIX: PAGE-SIZE-AWARE XMEM RUNTIME ===");
    println!("Software page modes: 64 KiB and 2 MiB");
    println!("Operations: allocate/map, read, write, unmap/free");
    println!("Xbox physical memory and GPU coherency are not emulated by this model.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_reads_writes_and_releases_64k_pages() {
        let mut runtime = XMemPageRuntime::new();
        let info = runtime.allocate_and_map(0, 2 * 0x10000, PageSize::KiB64).unwrap();
        assert_eq!(info.page_count, 2);
        runtime.write(info.id, 0x10000 - 4, b"Phoenix64K").unwrap();
        let mut out = [0; 10];
        runtime.read(info.id, 0x10000 - 4, &mut out).unwrap();
        assert_eq!(&out, b"Phoenix64K");
        assert_eq!(runtime.allocated_page_count(), 2);
        runtime.unmap_and_free(info.id).unwrap();
        assert_eq!(runtime.allocated_page_count(), 0);
        assert_eq!(runtime.region_count(), 0);
    }

    #[test]
    fn allocates_reads_writes_and_releases_2m_pages() {
        let mut runtime = XMemPageRuntime::new();
        let info = runtime.allocate_and_map(0, 2 * 0x200000, PageSize::MiB2).unwrap();
        assert_eq!(info.page_count, 2);
        runtime.write(info.id, 0x200000 - 3, b"Phoenix2M").unwrap();
        let mut out = [0; 9];
        runtime.read(info.id, 0x200000 - 3, &mut out).unwrap();
        assert_eq!(&out, b"Phoenix2M");
        runtime.unmap_and_free(info.id).unwrap();
        assert_eq!(runtime.allocated_page_count(), 0);
    }

    #[test]
    fn rejects_wrong_alignment_without_allocating_pages() {
        let mut runtime = XMemPageRuntime::new();
        assert!(runtime.allocate_and_map(0x1000, 0x10000, PageSize::KiB64).is_err());
        assert!(runtime.allocate_and_map(0, 0x1000, PageSize::KiB64).is_err());
        assert_eq!(runtime.allocated_page_count(), 0);
        assert_eq!(runtime.region_count(), 0);
    }

    #[test]
    fn overlapping_regions_fail_without_leaking_allocations() {
        let mut runtime = XMemPageRuntime::new();
        runtime.allocate_and_map(0, 0x10000, PageSize::KiB64).unwrap();
        let before = runtime.allocated_page_count();
        assert!(runtime.allocate_and_map(0, 0x10000, PageSize::KiB64).is_err());
        assert_eq!(runtime.allocated_page_count(), before);
        assert_eq!(runtime.region_count(), 1);
    }
}
