//! Safe Rust adapter for the verified core XMem physical-page call shapes.
//!
//! Page identifiers are Phoenix synthetic tokens, never Xbox physical addresses.
//! The adapter models exact-count allocation only; partial allocation semantics
//! are intentionally not inferred. Scatter ABI remains separate/unverified.

use crate::xmem_memory_manager::{XMemAllocation, XMemManagerError, XMemMemoryManager};
use crate::xmem_model_v3::PageSize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalPageAbiError {
    Manager(XMemManagerError),
    ZeroPageCount,
    UnknownPageToken(usize),
    PageArrayMismatch,
    PageCountMismatch { expected: usize, actual: usize },
    AlreadyMapped,
    NotMapped,
    TokenOverflow,
}
impl From<XMemManagerError> for PhysicalPageAbiError {
    fn from(value: XMemManagerError) -> Self { Self::Manager(value) }
}
impl fmt::Display for PhysicalPageAbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for PhysicalPageAbiError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalPagesResult {
    pub page_count: usize,
    pub page_ids: Vec<usize>,
}

struct AllocationRecord {
    allocation: XMemAllocation,
    page_ids: Vec<usize>,
    mapped_base: Option<usize>,
}

/// Bridges verified XMem function shapes to Phoenix's software memory manager.
/// The page IDs returned here are opaque Phoenix tokens, not real physical pages.
pub struct XMemPhysicalPageAbiAdapter {
    manager: XMemMemoryManager,
    next_token: usize,
    allocations: Vec<AllocationRecord>,
}

impl Default for XMemPhysicalPageAbiAdapter {
    fn default() -> Self { Self::new() }
}

impl XMemPhysicalPageAbiAdapter {
    pub fn new() -> Self {
        Self { manager: XMemMemoryManager::new(), next_token: 1, allocations: Vec::new() }
    }

    /// Models XMemAllocatePhysicalPages(flags, inoutPageCount, outPages).
    /// `raw_flags` is retained by the lower layer without decoding.
    pub fn allocate_physical_pages(
        &mut self,
        raw_flags: usize,
        requested_page_count: usize,
        page_size: PageSize,
    ) -> Result<PhysicalPagesResult, PhysicalPageAbiError> {
        if requested_page_count == 0 {
            return Err(PhysicalPageAbiError::ZeroPageCount);
        }
        let next = self.next_token.checked_add(requested_page_count)
            .ok_or(PhysicalPageAbiError::TokenOverflow)?;
        let allocation = self.manager.allocate_contiguous(raw_flags, requested_page_count, page_size)?;
        let page_ids: Vec<usize> = (self.next_token..next).collect();
        self.next_token = next;
        self.allocations.push(AllocationRecord {
            allocation,
            page_ids: page_ids.clone(),
            mapped_base: None,
        });
        Ok(PhysicalPagesResult { page_count: page_ids.len(), page_ids })
    }

    /// Models XMemMapPhysicalPages with a non-null page array.
    /// The complete page-token array must identify one Phoenix allocation.
    pub fn map_physical_pages(
        &mut self,
        guest_base: usize,
        page_count: usize,
        page_ids: &[usize],
    ) -> Result<(), PhysicalPageAbiError> {
        if page_count == 0 { return Err(PhysicalPageAbiError::ZeroPageCount); }
        if page_count != page_ids.len() {
            return Err(PhysicalPageAbiError::PageCountMismatch {
                expected: page_count, actual: page_ids.len(),
            });
        }
        let index = self.allocations.iter().position(|record| record.page_ids == page_ids)
            .ok_or_else(|| {
                page_ids.first().copied().map(PhysicalPageAbiError::UnknownPageToken)
                    .unwrap_or(PhysicalPageAbiError::PageArrayMismatch)
            })?;
        if self.allocations[index].mapped_base.is_some() {
            return Err(PhysicalPageAbiError::AlreadyMapped);
        }
        let allocation = self.allocations[index].allocation;
        self.manager.map_contiguous(guest_base, page_count, allocation)?;
        self.allocations[index].mapped_base = Some(guest_base);
        Ok(())
    }

    /// Models XMemMapPhysicalPages(base, count, null): unmap the range.
    pub fn unmap_physical_pages(
        &mut self,
        guest_base: usize,
        page_count: usize,
    ) -> Result<(), PhysicalPageAbiError> {
        if page_count == 0 { return Err(PhysicalPageAbiError::ZeroPageCount); }
        let index = self.allocations.iter().position(|record| {
            record.mapped_base == Some(guest_base) && record.page_ids.len() == page_count
        }).ok_or(PhysicalPageAbiError::NotMapped)?;
        self.manager.unmap_contiguous(guest_base, page_count)?;
        self.allocations[index].mapped_base = None;
        Ok(())
    }

    /// Models XMemFreePhysicalPages(count, pages). A mapped allocation cannot
    /// be freed until its virtual mapping has been removed.
    pub fn free_physical_pages(
        &mut self,
        page_count: usize,
        page_ids: &[usize],
    ) -> Result<(), PhysicalPageAbiError> {
        if page_count == 0 { return Err(PhysicalPageAbiError::ZeroPageCount); }
        if page_count != page_ids.len() {
            return Err(PhysicalPageAbiError::PageCountMismatch {
                expected: page_count, actual: page_ids.len(),
            });
        }
        let index = self.allocations.iter().position(|record| record.page_ids == page_ids)
            .ok_or_else(|| page_ids.first().copied()
                .map(PhysicalPageAbiError::UnknownPageToken)
                .unwrap_or(PhysicalPageAbiError::PageArrayMismatch))?;
        if self.allocations[index].mapped_base.is_some() {
            return Err(PhysicalPageAbiError::AlreadyMapped);
        }
        let allocation = self.allocations[index].allocation;
        self.manager.free(allocation)?;
        self.allocations.remove(index);
        Ok(())
    }

    pub fn allocation_count(&self) -> usize { self.allocations.len() }
    pub fn allocated_page_count(&self) -> usize { self.manager.total_page_count() }
    pub fn mapping_count(&self) -> usize { self.manager.mapping_count() }
}

pub fn print_abi_adapter_report() {
    println!("\n=== PHOENIX XMEM PHYSICAL-PAGE ABI ADAPTER ===");
    println!("Models AllocatePhysicalPages, MapPhysicalPages, null-array unmap, and FreePhysicalPages call flow.");
    println!("Page identifiers are synthetic Phoenix tokens, not Xbox physical addresses.");
    println!("Exact-count allocation only; partial-allocation behavior is not inferred.");
    println!("Raw flags remain opaque; no Xbox function is invoked or exported.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_unique_synthetic_page_tokens() {
        let mut a = XMemPhysicalPageAbiAdapter::new();
        let first = a.allocate_physical_pages(0x55, 2, PageSize::KiB64).unwrap();
        let second = a.allocate_physical_pages(0xAA, 1, PageSize::KiB64).unwrap();
        assert_eq!(first.page_count, 2);
        assert_eq!(second.page_count, 1);
        assert_ne!(first.page_ids[0], second.page_ids[0]);
        assert_eq!(a.allocated_page_count(), 3);
    }

    #[test]
    fn complete_allocate_map_unmap_free_lifecycle() {
        let mut a = XMemPhysicalPageAbiAdapter::new();
        let pages = a.allocate_physical_pages(0x123, 2, PageSize::KiB64).unwrap();
        a.map_physical_pages(0x100_0000, pages.page_count, &pages.page_ids).unwrap();
        assert_eq!(a.mapping_count(), 1);
        a.unmap_physical_pages(0x100_0000, pages.page_count).unwrap();
        a.free_physical_pages(pages.page_count, &pages.page_ids).unwrap();
        assert_eq!(a.allocated_page_count(), 0);
        assert_eq!(a.allocation_count(), 0);
    }

    #[test]
    fn rejects_incomplete_or_forged_page_arrays() {
        let mut a = XMemPhysicalPageAbiAdapter::new();
        let pages = a.allocate_physical_pages(0, 2, PageSize::KiB64).unwrap();
        assert!(matches!(
            a.map_physical_pages(0x200_0000, 1, &pages.page_ids),
            Err(PhysicalPageAbiError::PageCountMismatch { .. })
        ));
        assert!(a.map_physical_pages(0x200_0000, 2, &[pages.page_ids[0], usize::MAX]).is_err());
        assert_eq!(a.mapping_count(), 0);
    }

    #[test]
    fn rejects_free_while_mapped_then_allows_after_unmap() {
        let mut a = XMemPhysicalPageAbiAdapter::new();
        let pages = a.allocate_physical_pages(0, 1, PageSize::MiB2).unwrap();
        a.map_physical_pages(0x400_0000, 1, &pages.page_ids).unwrap();
        assert!(a.free_physical_pages(1, &pages.page_ids).is_err());
        a.unmap_physical_pages(0x400_0000, 1).unwrap();
        a.free_physical_pages(1, &pages.page_ids).unwrap();
        assert_eq!(a.allocated_page_count(), 0);
    }

    #[test]
    fn rejects_zero_count_and_unknown_unmap() {
        let mut a = XMemPhysicalPageAbiAdapter::new();
        assert_eq!(
            a.allocate_physical_pages(0, 0, PageSize::KiB64),
            Err(PhysicalPageAbiError::ZeroPageCount)
        );
        assert_eq!(
            a.unmap_physical_pages(0x500_0000, 1),
            Err(PhysicalPageAbiError::NotMapped)
        );
    }
}
