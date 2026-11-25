//! Phoenix software model for the XMem physical-page allocation/mapping trio.
//!
//! This module models ownership and mapping state only. `flags` are retained
//! verbatim and are never decoded. Page size is supplied by the caller from
//! independent evidence. Handles are Phoenix IDs, not Xbox physical addresses.

use crate::xmem_model_v3::{PageId, PageSize, PhysicalPagePool, VirtualRegion, XMemError};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalPageError {
    Model(XMemError),
    ZeroPageCount,
    UnknownAllocation,
    AllocationAlreadyMapped,
    AllocationNotMapped,
    UnknownMapping,
    MappingOverlap,
    PageCountMismatch { expected: usize, actual: usize },
    SizeOverflow,
    AddressOverflow,
}

impl From<XMemError> for PhysicalPageError {
    fn from(value: XMemError) -> Self { Self::Model(value) }
}
impl fmt::Display for PhysicalPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for PhysicalPageError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhysicalAllocationId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalAllocationInfo {
    pub id: PhysicalAllocationId,
    pub page_count: usize,
    pub page_size: PageSize,
    /// Original ABI flags, preserved without interpretation.
    pub raw_flags: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingInfo {
    pub guest_base: usize,
    pub page_count: usize,
    pub page_size: PageSize,
    pub allocation_id: PhysicalAllocationId,
}

struct AllocationEntry {
    info: PhysicalAllocationInfo,
    pages: Vec<PageId>,
    mapped: bool,
}

struct MappingEntry {
    info: MappingInfo,
    region: VirtualRegion,
}

/// Owns simulated physical pages separately from guest virtual mappings.
pub struct XMemPhysicalPageManager {
    pool: PhysicalPagePool,
    next_allocation_id: u64,
    allocations: Vec<AllocationEntry>,
    mappings: Vec<MappingEntry>,
}

impl Default for XMemPhysicalPageManager {
    fn default() -> Self { Self::new() }
}

impl XMemPhysicalPageManager {
    pub fn new() -> Self {
        Self {
            pool: PhysicalPagePool::new(),
            next_allocation_id: 1,
            allocations: Vec::new(),
            mappings: Vec::new(),
        }
    }

    /// Simulates XMemAllocatePhysicalPages. The caller supplies page size
    /// explicitly; `raw_flags` are recorded but not decoded.
    pub fn allocate_physical_pages(
        &mut self,
        raw_flags: usize,
        requested_page_count: usize,
        page_size: PageSize,
    ) -> Result<PhysicalAllocationInfo, PhysicalPageError> {
        if requested_page_count == 0 { return Err(PhysicalPageError::ZeroPageCount); }
        let next_id = self.next_allocation_id.checked_add(1).ok_or(PhysicalPageError::AddressOverflow)?;
        let pages = self.pool.allocate_with_size(requested_page_count, page_size)?;
        let info = PhysicalAllocationInfo {
            id: PhysicalAllocationId(self.next_allocation_id),
            page_count: pages.len(),
            page_size,
            raw_flags,
        };
        self.next_allocation_id = next_id;
        self.allocations.push(AllocationEntry { info, pages, mapped: false });
        Ok(info)
    }

    /// Simulates XMemMapPhysicalPages with a non-null page array. The
    /// allocation handle stands in for the opaque array of page identifiers.
    pub fn map_physical_pages(
        &mut self,
        guest_base: usize,
        page_count: usize,
        allocation_id: PhysicalAllocationId,
    ) -> Result<MappingInfo, PhysicalPageError> {
        if page_count == 0 { return Err(PhysicalPageError::ZeroPageCount); }
        let index = self.allocations.iter().position(|entry| entry.info.id == allocation_id)
            .ok_or(PhysicalPageError::UnknownAllocation)?;
        if self.allocations[index].mapped { return Err(PhysicalPageError::AllocationAlreadyMapped); }
        let allocation = &self.allocations[index];
        if page_count != allocation.info.page_count {
            return Err(PhysicalPageError::PageCountMismatch { expected: allocation.info.page_count, actual: page_count });
        }
        let size = page_count.checked_mul(allocation.info.page_size.bytes()).ok_or(PhysicalPageError::SizeOverflow)?;
        let end = guest_base.checked_add(size).ok_or(PhysicalPageError::AddressOverflow)?;
        if guest_base % allocation.info.page_size.bytes() != 0 {
            return Err(PhysicalPageError::Model(XMemError::UnalignedAddress {
                offset: guest_base,
                page_size: allocation.info.page_size.bytes(),
            }));
        }
        for existing in &self.mappings {
            let existing_size = existing.info.page_count.checked_mul(existing.info.page_size.bytes()).ok_or(PhysicalPageError::SizeOverflow)?;
            let existing_end = existing.info.guest_base.checked_add(existing_size).ok_or(PhysicalPageError::AddressOverflow)?;
            if guest_base < existing_end && existing.info.guest_base < end {
                return Err(PhysicalPageError::MappingOverlap);
            }
        }

        let mut region = VirtualRegion::reserve_with_page_size(size, allocation.info.page_size)?;
        region.map(0, &allocation.pages, &mut self.pool)?;
        let info = MappingInfo { guest_base, page_count, page_size: allocation.info.page_size, allocation_id };
        self.allocations[index].mapped = true;
        self.mappings.push(MappingEntry { info, region });
        Ok(info)
    }

    /// Simulates XMemMapPhysicalPages with a null page array: unmap the range.
    /// The physical allocation remains owned and must subsequently be freed.
    pub fn unmap_physical_pages(
        &mut self,
        guest_base: usize,
        page_count: usize,
    ) -> Result<PhysicalAllocationId, PhysicalPageError> {
        if page_count == 0 { return Err(PhysicalPageError::ZeroPageCount); }
        let index = self.mappings.iter().position(|entry|
            entry.info.guest_base == guest_base && entry.info.page_count == page_count
        ).ok_or(PhysicalPageError::UnknownMapping)?;
        let mapping = &mut self.mappings[index];
        let removed = mapping.region.unmap(0, page_count, &mut self.pool)?;
        if removed.len() != page_count {
            return Err(PhysicalPageError::PageCountMismatch { expected: page_count, actual: removed.len() });
        }
        let allocation_id = mapping.info.allocation_id;
        self.mappings.remove(index);
        let allocation = self.allocations.iter_mut().find(|entry| entry.info.id == allocation_id)
            .ok_or(PhysicalPageError::UnknownAllocation)?;
        allocation.mapped = false;
        Ok(allocation_id)
    }

    /// Simulates XMemFreePhysicalPages. Mapped allocations cannot be freed.
    pub fn free_physical_pages(
        &mut self,
        allocation_id: PhysicalAllocationId,
    ) -> Result<(), PhysicalPageError> {
        let index = self.allocations.iter().position(|entry| entry.info.id == allocation_id)
            .ok_or(PhysicalPageError::UnknownAllocation)?;
        if self.allocations[index].mapped { return Err(PhysicalPageError::AllocationAlreadyMapped); }
        self.pool.free(&self.allocations[index].pages)?;
        self.allocations.remove(index);
        Ok(())
    }

    pub fn allocated_page_count(&self) -> usize { self.pool.allocated_count() }
    pub fn allocation_count(&self) -> usize { self.allocations.len() }
    pub fn mapping_count(&self) -> usize { self.mappings.len() }
    /// Read-only snapshot of active software mappings for consistency audits.
    pub fn mapping_snapshot(&self) -> Vec<MappingInfo> {
        self.mappings.iter().map(|entry| entry.info).collect()
    }
}

pub fn print_physical_page_report() {
    println!("\\n=== PHOENIX: XMEM PHYSICAL-PAGE MANAGER ===");
    println!("Software operations: allocate pages, map pages, null-array unmap, free pages");
    println!("Raw allocation flags are retained but not decoded.");
    println!("Page size is explicit; handles are Phoenix IDs, not Xbox physical addresses.");
    println!("No Xbox API, hardware page allocator, or GPU mapping is invoked.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_map_unmap_and_free_64k_pages() {
        let mut manager = XMemPhysicalPageManager::new();
        let allocation = manager.allocate_physical_pages(0xA5A5, 2, PageSize::KiB64).unwrap();
        assert_eq!(allocation.raw_flags, 0xA5A5);
        assert_eq!(manager.allocated_page_count(), 2);
        let mapping = manager.map_physical_pages(0x40000, 2, allocation.id).unwrap();
        assert_eq!(mapping.guest_base, 0x40000);
        assert!(manager.free_physical_pages(allocation.id).is_err());
        assert_eq!(manager.unmap_physical_pages(0x40000, 2).unwrap(), allocation.id);
        manager.free_physical_pages(allocation.id).unwrap();
        assert_eq!(manager.allocated_page_count(), 0);
        assert_eq!(manager.allocation_count(), 0);
        assert_eq!(manager.mapping_count(), 0);
    }

    #[test]
    fn supports_explicit_2m_pages() {
        let mut manager = XMemPhysicalPageManager::new();
        let allocation = manager.allocate_physical_pages(0, 3, PageSize::MiB2).unwrap();
        manager.map_physical_pages(0x20_0000, 3, allocation.id).unwrap();
        assert_eq!(manager.allocated_page_count(), 3);
        manager.unmap_physical_pages(0x20_0000, 3).unwrap();
        manager.free_physical_pages(allocation.id).unwrap();
        assert_eq!(manager.allocated_page_count(), 0);
    }

    #[test]
    fn rejects_free_while_mapped_and_double_mapping() {
        let mut manager = XMemPhysicalPageManager::new();
        let allocation = manager.allocate_physical_pages(0xDEAD, 1, PageSize::KiB64).unwrap();
        manager.map_physical_pages(0x10000, 1, allocation.id).unwrap();
        assert_eq!(manager.map_physical_pages(0x20000, 1, allocation.id), Err(PhysicalPageError::AllocationAlreadyMapped));
        assert_eq!(manager.free_physical_pages(allocation.id), Err(PhysicalPageError::AllocationAlreadyMapped));
        assert_eq!(manager.allocated_page_count(), 1);
    }

    #[test]
    fn rejects_overlap_and_wrong_page_count_without_leaks() {
        let mut manager = XMemPhysicalPageManager::new();
        let first = manager.allocate_physical_pages(0, 1, PageSize::KiB64).unwrap();
        let second = manager.allocate_physical_pages(0, 2, PageSize::KiB64).unwrap();
        manager.map_physical_pages(0x10000, 1, first.id).unwrap();
        assert!(matches!(manager.map_physical_pages(0x10000, 2, second.id), Err(PhysicalPageError::MappingOverlap)));
        assert!(matches!(manager.map_physical_pages(0x30000, 1, second.id), Err(PhysicalPageError::PageCountMismatch { .. })));
        assert_eq!(manager.allocated_page_count(), 3);
        manager.unmap_physical_pages(0x10000, 1).unwrap();
        manager.free_physical_pages(first.id).unwrap();
        manager.free_physical_pages(second.id).unwrap();
        assert_eq!(manager.allocated_page_count(), 0);
    }

    #[test]
    fn rejects_zero_count_and_unaligned_base() {
        let mut manager = XMemPhysicalPageManager::new();
        assert_eq!(manager.allocate_physical_pages(0, 0, PageSize::KiB64), Err(PhysicalPageError::ZeroPageCount));
        let allocation = manager.allocate_physical_pages(0, 1, PageSize::KiB64).unwrap();
        assert!(matches!(manager.map_physical_pages(1, 1, allocation.id), Err(PhysicalPageError::Model(XMemError::UnalignedAddress { .. }))));
        assert_eq!(manager.allocated_page_count(), 1);
        manager.free_physical_pages(allocation.id).unwrap();
    }
}
