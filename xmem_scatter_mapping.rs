//! Phoenix software model for XMemMapPhysicalPagesScatter.
//!
//! `page_slots` are virtual page indices relative to `guest_base`. This is a
//! Phoenix abstraction, not a claim about the undocumented Xbox ABI layout.
//! Allocation flags remain opaque and page size is supplied explicitly.

use crate::xmem_model_v3::{PageId, PageSize, PhysicalPagePool, VirtualRegion, XMemError};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScatterError {
    Model(XMemError),
    ZeroPageCount,
    UnknownAllocation,
    UnknownMapping,
    AllocationAlreadyMapped,
    AllocationNotMapped,
    PageCountMismatch { expected: usize, actual: usize },
    DuplicateSlot(usize),
    AddressOverflow,
    MappingOverlap,
}
impl From<XMemError> for ScatterError { fn from(value: XMemError) -> Self { Self::Model(value) } }
impl fmt::Display for ScatterError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for ScatterError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScatterAllocationId(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScatterAllocationInfo { pub id: ScatterAllocationId, pub page_count: usize, pub page_size: PageSize, pub raw_flags: usize }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScatterMappingInfo { pub guest_base: usize, pub page_slots: Vec<usize>, pub page_size: PageSize, pub allocation_id: ScatterAllocationId }
struct Allocation { info: ScatterAllocationInfo, pages: Vec<PageId>, mapped: bool }
struct Mapping { info: ScatterMappingInfo, region: VirtualRegion }

/// Owns simulated pages and scatter mappings independently of host addresses.
pub struct XMemScatterPageManager {
    pool: PhysicalPagePool,
    next_id: u64,
    allocations: Vec<Allocation>,
    mappings: Vec<Mapping>,
}
impl Default for XMemScatterPageManager { fn default() -> Self { Self::new() } }
impl XMemScatterPageManager {
    pub fn new() -> Self { Self { pool: PhysicalPagePool::new(), next_id: 1, allocations: Vec::new(), mappings: Vec::new() } }

    pub fn allocate(&mut self, raw_flags: usize, page_count: usize, page_size: PageSize) -> Result<ScatterAllocationInfo, ScatterError> {
        if page_count == 0 { return Err(ScatterError::ZeroPageCount); }
        let next = self.next_id.checked_add(1).ok_or(ScatterError::AddressOverflow)?;
        let pages = self.pool.allocate_with_size(page_count, page_size)?;
        let info = ScatterAllocationInfo { id: ScatterAllocationId(self.next_id), page_count: pages.len(), page_size, raw_flags };
        self.next_id = next;
        self.allocations.push(Allocation { info, pages, mapped: false });
        Ok(info)
    }

    /// Map each physical page to the corresponding virtual page slot.
    /// Slot indices may be non-contiguous; duplicates are rejected.
    pub fn map_scatter(&mut self, guest_base: usize, page_slots: &[usize], id: ScatterAllocationId) -> Result<ScatterMappingInfo, ScatterError> {
        if page_slots.is_empty() { return Err(ScatterError::ZeroPageCount); }
        let allocation_index = self.allocations.iter().position(|a| a.info.id == id).ok_or(ScatterError::UnknownAllocation)?;
        if self.allocations[allocation_index].mapped { return Err(ScatterError::AllocationAlreadyMapped); }
        let allocation = &self.allocations[allocation_index];
        if page_slots.len() != allocation.info.page_count {
            return Err(ScatterError::PageCountMismatch { expected: allocation.info.page_count, actual: page_slots.len() });
        }
        let unit = allocation.info.page_size.bytes();
        if guest_base % unit != 0 { return Err(ScatterError::Model(XMemError::UnalignedAddress { offset: guest_base, page_size: unit })); }
        let mut sorted = page_slots.to_vec();
        sorted.sort_unstable();
        for pair in sorted.windows(2) { if pair[0] == pair[1] { return Err(ScatterError::DuplicateSlot(pair[0])); } }
        let max_slot = *sorted.last().ok_or(ScatterError::ZeroPageCount)?;
        let region_pages = max_slot.checked_add(1).ok_or(ScatterError::AddressOverflow)?;
        let region_size = region_pages.checked_mul(unit).ok_or(ScatterError::AddressOverflow)?;
        for slot in page_slots {
            let start = guest_base.checked_add(slot.checked_mul(unit).ok_or(ScatterError::AddressOverflow)?).ok_or(ScatterError::AddressOverflow)?;
            let end = start.checked_add(unit).ok_or(ScatterError::AddressOverflow)?;
            for existing in &self.mappings {
                let existing_unit = existing.info.page_size.bytes();
                for old_slot in &existing.info.page_slots {
                    let old_start = existing.info.guest_base.checked_add(old_slot.checked_mul(existing_unit).ok_or(ScatterError::AddressOverflow)?).ok_or(ScatterError::AddressOverflow)?;
                    let old_end = old_start.checked_add(existing_unit).ok_or(ScatterError::AddressOverflow)?;
                    if start < old_end && old_start < end { return Err(ScatterError::MappingOverlap); }
                }
            }
        }
        let offsets: Vec<usize> = page_slots.iter().map(|slot| slot.checked_mul(unit).ok_or(ScatterError::AddressOverflow)).collect::<Result<_, _>>()?;
        let mut region = VirtualRegion::reserve_with_page_size(region_size, allocation.info.page_size)?;
        region.map_scatter(&offsets, &allocation.pages, &mut self.pool)?;
        let info = ScatterMappingInfo { guest_base, page_slots: page_slots.to_vec(), page_size: allocation.info.page_size, allocation_id: id };
        self.allocations[allocation_index].mapped = true;
        self.mappings.push(Mapping { info: info.clone(), region });
        Ok(info)
    }

    pub fn unmap_scatter(&mut self, guest_base: usize, page_slots: &[usize]) -> Result<ScatterAllocationId, ScatterError> {
        let index = self.mappings.iter().position(|m| m.info.guest_base == guest_base && m.info.page_slots == page_slots).ok_or(ScatterError::UnknownMapping)?;
        let mapping = &mut self.mappings[index];
        let unit = mapping.info.page_size.bytes();
        for slot in &mapping.info.page_slots {
            let offset = slot.checked_mul(unit).ok_or(ScatterError::AddressOverflow)?;
            let removed = mapping.region.unmap(offset, 1, &mut self.pool)?;
            if removed.len() != 1 { return Err(ScatterError::Model(XMemError::PageCountMismatch { expected: 1, actual: removed.len() })); }
        }
        let id = mapping.info.allocation_id;
        self.mappings.remove(index);
        let allocation = self.allocations.iter_mut().find(|a| a.info.id == id).ok_or(ScatterError::UnknownAllocation)?;
        allocation.mapped = false;
        Ok(id)
    }

    pub fn free(&mut self, id: ScatterAllocationId) -> Result<(), ScatterError> {
        let index = self.allocations.iter().position(|a| a.info.id == id).ok_or(ScatterError::UnknownAllocation)?;
        if self.allocations[index].mapped { return Err(ScatterError::AllocationAlreadyMapped); }
        self.pool.free(&self.allocations[index].pages)?;
        self.allocations.remove(index);
        Ok(())
    }
    pub fn allocated_page_count(&self) -> usize { self.pool.allocated_count() }
    pub fn allocation_count(&self) -> usize { self.allocations.len() }
    pub fn mapping_count(&self) -> usize { self.mappings.len() }
    /// Read-only snapshot of active software scatter mappings for consistency audits.
    pub fn mapping_snapshot(&self) -> Vec<ScatterMappingInfo> {
        self.mappings.iter().map(|entry| entry.info.clone()).collect()
    }
}

pub fn print_scatter_report() {
    println!("\\n=== PHOENIX: XMEM SCATTER-MAPPING MODEL ===");
    println!("Supports explicit page-slot scatter mapping, unmapping, and page ownership.");
    println!("Slot indices and allocation handles are Phoenix abstractions; Xbox ABI flags remain opaque.");
    println!("No Xbox API, GPU mapping, or hardware page allocator is invoked.");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_noncontiguous_slots_and_releases_all_pages() {
        let mut m = XMemScatterPageManager::new();
        let a = m.allocate(0x1234, 3, PageSize::KiB64).unwrap();
        let map = m.map_scatter(0x10_0000, &[0, 3, 7], a.id).unwrap();
        assert_eq!(map.page_slots, vec![0, 3, 7]);
        assert_eq!(m.allocated_page_count(), 3);
        assert_eq!(m.unmap_scatter(0x10_0000, &[0, 3, 7]).unwrap(), a.id);
        m.free(a.id).unwrap();
        assert_eq!(m.allocated_page_count(), 0);
    }
    #[test]
    fn rejects_duplicate_slots_without_mapping_or_leak() {
        let mut m = XMemScatterPageManager::new();
        let a = m.allocate(0, 2, PageSize::KiB64).unwrap();
        assert_eq!(m.map_scatter(0x20_0000, &[2, 2], a.id), Err(ScatterError::DuplicateSlot(2)));
        assert_eq!(m.mapping_count(), 0);
        assert_eq!(m.allocated_page_count(), 2);
        m.free(a.id).unwrap();
    }
    #[test]
    fn rejects_page_count_mismatch_and_unaligned_base() {
        let mut m = XMemScatterPageManager::new();
        let a = m.allocate(0, 2, PageSize::KiB64).unwrap();
        assert!(matches!(m.map_scatter(0x30_0000, &[0], a.id), Err(ScatterError::PageCountMismatch { .. })));
        assert!(matches!(m.map_scatter(1, &[0, 1], a.id), Err(ScatterError::Model(XMemError::UnalignedAddress { .. }))));
        assert_eq!(m.mapping_count(), 0);
        m.free(a.id).unwrap();
    }
    #[test]
    fn rejects_overlap_with_existing_scatter_mapping() {
        let mut m = XMemScatterPageManager::new();
        let a = m.allocate(0, 2, PageSize::KiB64).unwrap();
        let b = m.allocate(0, 1, PageSize::KiB64).unwrap();
        m.map_scatter(0x40_0000, &[1, 4], a.id).unwrap();
        assert_eq!(m.map_scatter(0x40_0000, &[4], b.id), Err(ScatterError::MappingOverlap));
        assert_eq!(m.allocated_page_count(), 3);
        m.unmap_scatter(0x40_0000, &[1, 4]).unwrap();
        m.free(a.id).unwrap(); m.free(b.id).unwrap();
        assert_eq!(m.allocated_page_count(), 0);
    }
    #[test]
    fn supports_explicit_2m_scatter_pages() {
        let mut m = XMemScatterPageManager::new();
        let a = m.allocate(0x55, 2, PageSize::MiB2).unwrap();
        m.map_scatter(0x80_0000, &[0, 2], a.id).unwrap();
        assert_eq!(m.mapping_count(), 1);
        m.unmap_scatter(0x80_0000, &[0, 2]).unwrap();
        m.free(a.id).unwrap();
        assert_eq!(m.allocated_page_count(), 0);
    }
}
