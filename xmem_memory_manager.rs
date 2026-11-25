//! Unified Phoenix-facing facade over the current XMem page models.
//!
//! This is an orchestration layer, not a shared physical-memory implementation:
//! contiguous and scatter allocations remain owned by their respective
//! software managers. Xbox ABI flags remain opaque.

use crate::xmem_model_v3::PageSize;
use crate::xmem_physical_pages::{
    MappingInfo, PhysicalAllocationInfo, PhysicalPageError, XMemPhysicalPageManager,
};
use crate::xmem_scatter_mapping::{
    ScatterAllocationInfo, ScatterError, ScatterMappingInfo, XMemScatterPageManager,
};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemManagerError {
    WrongAllocationKind,
    Contiguous(PhysicalPageError),
    Scatter(ScatterError),
    MappingOverlap,
    AddressOverflow,
    RegistryMappingCountMismatch { registry: usize, backends: usize },
    RegistryOverlap,
    InvalidRegistryRange,
    BackendMappingMismatch,
}
impl From<PhysicalPageError> for XMemManagerError {
    fn from(value: PhysicalPageError) -> Self { Self::Contiguous(value) }
}
impl From<ScatterError> for XMemManagerError {
    fn from(value: ScatterError) -> Self { Self::Scatter(value) }
}
impl fmt::Display for XMemManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for XMemManagerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XMemAllocation {
    Contiguous(PhysicalAllocationInfo),
    Scatter(ScatterAllocationInfo),
}
impl XMemAllocation {
    pub fn page_count(&self) -> usize {
        match self {
            Self::Contiguous(v) => v.page_count,
            Self::Scatter(v) => v.page_count,
        }
    }
    pub fn page_size(&self) -> PageSize {
        match self {
            Self::Contiguous(v) => v.page_size,
            Self::Scatter(v) => v.page_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MappingKind {
    Contiguous { page_count: usize },
    Scatter { page_slots: Vec<usize> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobalMappingRecord {
    guest_base: usize,
    occupied_ranges: Vec<(usize, usize)>,
    page_size: usize,
    kind: MappingKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XMemMemoryAudit {
    pub allocation_count: usize,
    pub mapping_count: usize,
    pub contiguous_pages: usize,
    pub scatter_pages: usize,
    pub total_pages: usize,
    pub registered_ranges: usize,
}

/// One API surface for Phoenix's two currently modeled page-mapping paths.
/// The underlying pools remain separate, but all virtual ranges are checked
/// against one shared registry before either backend is asked to map them.
pub struct XMemMemoryManager {
    contiguous: XMemPhysicalPageManager,
    scatter: XMemScatterPageManager,
    global_mappings: Vec<GlobalMappingRecord>,
}
impl Default for XMemMemoryManager {
    fn default() -> Self { Self::new() }
}
impl XMemMemoryManager {
    pub fn new() -> Self {
        Self {
            contiguous: XMemPhysicalPageManager::new(),
            scatter: XMemScatterPageManager::new(),
            global_mappings: Vec::new(),
        }
    }

    fn ensure_global_ranges_free(&self, requested: &[(usize, usize)]) -> Result<(), XMemManagerError> {
        for &(start, end) in requested {
            if start >= end { return Err(XMemManagerError::AddressOverflow); }
            for existing in &self.global_mappings {
                for &(old_start, old_end) in &existing.occupied_ranges {
                    if start < old_end && old_start < end {
                        return Err(XMemManagerError::MappingOverlap);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn allocate_contiguous(
        &mut self, raw_flags: usize, page_count: usize, page_size: PageSize,
    ) -> Result<XMemAllocation, XMemManagerError> {
        Ok(XMemAllocation::Contiguous(
            self.contiguous.allocate_physical_pages(raw_flags, page_count, page_size)?
        ))
    }

    pub fn map_contiguous(
        &mut self, guest_base: usize, page_count: usize, allocation: XMemAllocation,
    ) -> Result<MappingInfo, XMemManagerError> {
        let info = match allocation {
            XMemAllocation::Contiguous(info) => info,
            XMemAllocation::Scatter(_) => return Err(XMemManagerError::WrongAllocationKind),
        };
        let bytes = info.page_size.bytes();
        let size = page_count.checked_mul(bytes).ok_or(XMemManagerError::AddressOverflow)?;
        let end = guest_base.checked_add(size).ok_or(XMemManagerError::AddressOverflow)?;
        let ranges = vec![(guest_base, end)];
        self.ensure_global_ranges_free(&ranges)?;
        let mapped = self.contiguous.map_physical_pages(guest_base, page_count, info.id)?;
        self.global_mappings.push(GlobalMappingRecord {
            guest_base,
            occupied_ranges: ranges,
            page_size: bytes,
            kind: MappingKind::Contiguous { page_count },
        });
        Ok(mapped)
    }

    pub fn unmap_contiguous(
        &mut self, guest_base: usize, page_count: usize,
    ) -> Result<(), XMemManagerError> {
        self.contiguous.unmap_physical_pages(guest_base, page_count)?;
        let index = self.global_mappings.iter().position(|record|
            record.guest_base == guest_base
                && record.kind == (MappingKind::Contiguous { page_count })
        ).ok_or(XMemManagerError::AddressOverflow)?;
        self.global_mappings.remove(index);
        Ok(())
    }

    pub fn allocate_scatter(
        &mut self, raw_flags: usize, page_count: usize, page_size: PageSize,
    ) -> Result<XMemAllocation, XMemManagerError> {
        Ok(XMemAllocation::Scatter(self.scatter.allocate(raw_flags, page_count, page_size)?))
    }

    pub fn map_scatter(
        &mut self, guest_base: usize, page_slots: &[usize], allocation: XMemAllocation,
    ) -> Result<ScatterMappingInfo, XMemManagerError> {
        let info = match allocation {
            XMemAllocation::Scatter(info) => info,
            XMemAllocation::Contiguous(_) => return Err(XMemManagerError::WrongAllocationKind),
        };
        let unit = info.page_size.bytes();
        let mut ranges = Vec::with_capacity(page_slots.len());
        for slot in page_slots {
            let offset = slot.checked_mul(unit).ok_or(XMemManagerError::AddressOverflow)?;
            let start = guest_base.checked_add(offset).ok_or(XMemManagerError::AddressOverflow)?;
            let end = start.checked_add(unit).ok_or(XMemManagerError::AddressOverflow)?;
            ranges.push((start, end));
        }
        self.ensure_global_ranges_free(&ranges)?;
        let mapped = self.scatter.map_scatter(guest_base, page_slots, info.id)?;
        self.global_mappings.push(GlobalMappingRecord {
            guest_base,
            occupied_ranges: ranges,
            page_size: unit,
            kind: MappingKind::Scatter { page_slots: page_slots.to_vec() },
        });
        Ok(mapped)
    }

    pub fn unmap_scatter(
        &mut self, guest_base: usize, page_slots: &[usize],
    ) -> Result<(), XMemManagerError> {
        self.scatter.unmap_scatter(guest_base, page_slots)?;
        let index = self.global_mappings.iter().position(|record|
            record.guest_base == guest_base
                && record.kind == (MappingKind::Scatter { page_slots: page_slots.to_vec() })
        ).ok_or(XMemManagerError::AddressOverflow)?;
        self.global_mappings.remove(index);
        Ok(())
    }

    pub fn free(&mut self, allocation: XMemAllocation) -> Result<(), XMemManagerError> {
        match allocation {
            XMemAllocation::Contiguous(info) => self.contiguous.free_physical_pages(info.id)?,
            XMemAllocation::Scatter(info) => self.scatter.free(info.id)?,
        }
        Ok(())
    }

    /// Validate the facade's bookkeeping against both underlying software managers.
    /// This checks metadata consistency; it does not inspect host or Xbox hardware mappings.
    pub fn audit(&self) -> Result<XMemMemoryAudit, XMemManagerError> {
        let backend_mappings = self.contiguous.mapping_count() + self.scatter.mapping_count();
        if self.global_mappings.len() != backend_mappings {
            return Err(XMemManagerError::RegistryMappingCountMismatch {
                registry: self.global_mappings.len(),
                backends: backend_mappings,
            });
        }

        for record in &self.global_mappings {
            if record.page_size == 0 || record.occupied_ranges.is_empty() {
                return Err(XMemManagerError::InvalidRegistryRange);
            }
            if let MappingKind::Scatter { page_slots } = &record.kind {
                if page_slots.is_empty() {
                    return Err(XMemManagerError::InvalidRegistryRange);
                }
                let mut sorted = page_slots.clone();
                sorted.sort_unstable();
                if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(XMemManagerError::InvalidRegistryRange);
                }
            }
            match &record.kind {
                MappingKind::Contiguous { page_count } => {
                    if *page_count == 0 || record.occupied_ranges.len() != 1 {
                        return Err(XMemManagerError::InvalidRegistryRange);
                    }
                    let expected_len = page_count
                        .checked_mul(record.page_size)
                        .ok_or(XMemManagerError::InvalidRegistryRange)?;
                    let (start, end) = record.occupied_ranges[0];
                    if start >= end || start % record.page_size != 0
                        || end.checked_sub(start) != Some(expected_len)
                    {
                        return Err(XMemManagerError::InvalidRegistryRange);
                    }
                }
                MappingKind::Scatter { page_slots } => {
                    if page_slots.len() != record.occupied_ranges.len() {
                        return Err(XMemManagerError::InvalidRegistryRange);
                    }
                    for &(start, end) in &record.occupied_ranges {
                        if start >= end || start % record.page_size != 0
                            || end.checked_sub(start) != Some(record.page_size)
                        {
                            return Err(XMemManagerError::InvalidRegistryRange);
                        }
                    }
                }
            }
        }

        let contiguous_snapshot = self.contiguous.mapping_snapshot();
        let scatter_snapshot = self.scatter.mapping_snapshot();

        for record in &self.global_mappings {
            let matches_backend = match &record.kind {
                MappingKind::Contiguous { page_count } => contiguous_snapshot.iter().any(|mapping| {
                    mapping.guest_base == record.guest_base
                        && mapping.page_count == *page_count
                        && mapping.page_size.bytes() == record.page_size
                }),
                MappingKind::Scatter { page_slots } => scatter_snapshot.iter().any(|mapping| {
                    mapping.guest_base == record.guest_base
                        && mapping.page_slots == *page_slots
                        && mapping.page_size.bytes() == record.page_size
                }),
            };
            if !matches_backend {
                return Err(XMemManagerError::BackendMappingMismatch);
            }
        }

        for mapping in &contiguous_snapshot {
            let present = self.global_mappings.iter().any(|record| {
                record.guest_base == mapping.guest_base
                    && record.page_size == mapping.page_size.bytes()
                    && record.kind == (MappingKind::Contiguous { page_count: mapping.page_count })
            });
            if !present { return Err(XMemManagerError::BackendMappingMismatch); }
        }
        for mapping in &scatter_snapshot {
            let present = self.global_mappings.iter().any(|record| {
                record.guest_base == mapping.guest_base
                    && record.page_size == mapping.page_size.bytes()
                    && record.kind == (MappingKind::Scatter { page_slots: mapping.page_slots.clone() })
            });
            if !present { return Err(XMemManagerError::BackendMappingMismatch); }
        }

        for left in 0..self.global_mappings.len() {
            for right in (left + 1)..self.global_mappings.len() {
                for &(a_start, a_end) in &self.global_mappings[left].occupied_ranges {
                    for &(b_start, b_end) in &self.global_mappings[right].occupied_ranges {
                        if a_start < b_end && b_start < a_end {
                            return Err(XMemManagerError::RegistryOverlap);
                        }
                    }
                }
            }
        }

        Ok(XMemMemoryAudit {
            allocation_count: self.allocation_count(),
            mapping_count: backend_mappings,
            contiguous_pages: self.contiguous_page_count(),
            scatter_pages: self.scatter_page_count(),
            total_pages: self.total_page_count(),
            registered_ranges: self.global_mappings.iter().map(|m| m.occupied_ranges.len()).sum(),
        })
    }

    pub fn contiguous_page_count(&self) -> usize { self.contiguous.allocated_page_count() }
    pub fn scatter_page_count(&self) -> usize { self.scatter.allocated_page_count() }
    pub fn total_page_count(&self) -> usize {
        self.contiguous_page_count().saturating_add(self.scatter_page_count())
    }
    pub fn allocation_count(&self) -> usize {
        self.contiguous.allocation_count() + self.scatter.allocation_count()
    }
    pub fn mapping_count(&self) -> usize {
        self.contiguous.mapping_count() + self.scatter.mapping_count()
    }
}

pub fn print_manager_report() {
    println!("\n=== PHOENIX: UNIFIED XMEM MEMORY-MANAGER FACADE ===");
    println!("One Phoenix API coordinates contiguous and scatter page operations.");
    println!("The underlying software page pools remain separate.");
    println!("Contiguous and scatter mappings share one global virtual-overlap registry.");
    println!("A metadata audit checks registry/backend counts, mapping identity, range validity, and overlap.");
    println!("Allocation handles are typed to prevent mixing contiguous and scatter operations.");
    println!("Xbox flags remain opaque; no Xbox APIs or hardware mappings are invoked.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_facade_runs_contiguous_lifecycle() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_contiguous(0x1234, 2, PageSize::KiB64).unwrap();
        assert_eq!(m.total_page_count(), 2);
        m.map_contiguous(0x10_0000, 2, a).unwrap();
        assert_eq!(m.mapping_count(), 1);
        assert!(m.free(a).is_err());
        m.unmap_contiguous(0x10_0000, 2).unwrap();
        m.free(a).unwrap();
        assert_eq!(m.total_page_count(), 0);
        assert_eq!(m.allocation_count(), 0);
    }

    #[test]
    fn unified_facade_runs_scatter_lifecycle() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_scatter(0x5678, 3, PageSize::KiB64).unwrap();
        m.map_scatter(0x20_0000, &[0, 2, 5], a).unwrap();
        assert_eq!(m.total_page_count(), 3);
        assert_eq!(m.mapping_count(), 1);
        m.unmap_scatter(0x20_0000, &[0, 2, 5]).unwrap();
        m.free(a).unwrap();
        assert_eq!(m.total_page_count(), 0);
    }

    #[test]
    fn facade_rejects_cross_kind_operations() {
        let mut m = XMemMemoryManager::new();
        let contiguous = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();
        assert_eq!(
            m.map_scatter(0x30_0000, &[0], contiguous),
            Err(XMemManagerError::WrongAllocationKind)
        );
        m.free(contiguous).unwrap();

        let scatter = m.allocate_scatter(0, 1, PageSize::KiB64).unwrap();
        assert_eq!(
            m.map_contiguous(0x40_0000, 1, scatter),
            Err(XMemManagerError::WrongAllocationKind)
        );
        m.free(scatter).unwrap();
        assert_eq!(m.total_page_count(), 0);
    }

    #[test]
    fn facade_tracks_both_pools_without_handle_collision() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();
        let b = m.allocate_scatter(0, 2, PageSize::MiB2).unwrap();
        assert_eq!(a.page_count(), 1);
        assert_eq!(b.page_count(), 2);
        assert_eq!(m.contiguous_page_count(), 1);
        assert_eq!(m.scatter_page_count(), 2);
        assert_eq!(m.total_page_count(), 3);
        m.free(a).unwrap();
        m.free(b).unwrap();
        assert_eq!(m.total_page_count(), 0);
    }
    #[test]
    fn global_registry_rejects_contiguous_scatter_cross_overlap() {
        let mut m = XMemMemoryManager::new();
        let contiguous = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();
        let scatter = m.allocate_scatter(0, 1, PageSize::KiB64).unwrap();

        m.map_contiguous(0x50_0000, 1, contiguous).unwrap();
        assert_eq!(
            m.map_scatter(0x50_0000, &[0], scatter),
            Err(XMemManagerError::MappingOverlap)
        );
        assert_eq!(m.mapping_count(), 1);

        m.unmap_contiguous(0x50_0000, 1).unwrap();
        m.map_scatter(0x50_0000, &[0], scatter).unwrap();
        assert_eq!(m.mapping_count(), 1);
        m.unmap_scatter(0x50_0000, &[0]).unwrap();
        m.free(contiguous).unwrap();
        m.free(scatter).unwrap();
        assert_eq!(m.total_page_count(), 0);
        assert!(m.global_mappings.is_empty());
    }

    #[test]
    fn global_registry_rejects_scatter_slot_overlapping_contiguous_range() {
        let mut m = XMemMemoryManager::new();
        let scatter = m.allocate_scatter(0, 1, PageSize::KiB64).unwrap();
        let contiguous = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();

        m.map_scatter(0x60_0000, &[3], scatter).unwrap();
        // Slot 3 begins at base + 3 * 64 KiB.
        assert_eq!(
            m.map_contiguous(0x63_0000, 1, contiguous),
            Err(XMemManagerError::MappingOverlap)
        );
        assert_eq!(m.mapping_count(), 1);

        m.unmap_scatter(0x60_0000, &[3]).unwrap();
        m.free(scatter).unwrap();
        m.free(contiguous).unwrap();
    }

    #[test]
    fn global_registry_allows_disjoint_scatter_slots() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_scatter(0, 1, PageSize::KiB64).unwrap();
        let b = m.allocate_scatter(0, 1, PageSize::KiB64).unwrap();
        m.map_scatter(0x70_0000, &[0], a).unwrap();
        m.map_scatter(0x70_0000, &[2], b).unwrap();
        assert_eq!(m.mapping_count(), 2);
        m.unmap_scatter(0x70_0000, &[0]).unwrap();
        m.unmap_scatter(0x70_0000, &[2]).unwrap();
        m.free(a).unwrap();
        m.free(b).unwrap();
        assert!(m.global_mappings.is_empty());
    }

    #[test]
    fn audit_reports_consistent_mixed_memory_state() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_contiguous(0, 2, PageSize::KiB64).unwrap();
        let b = m.allocate_scatter(0, 2, PageSize::MiB2).unwrap();
        m.map_contiguous(0x90_0000, 2, a).unwrap();
        m.map_scatter(0x20_0000_0000, &[0, 2], b).unwrap();

        let audit = m.audit().unwrap();
        assert_eq!(audit.allocation_count, 2);
        assert_eq!(audit.mapping_count, 2);
        assert_eq!(audit.contiguous_pages, 2);
        assert_eq!(audit.scatter_pages, 2);
        assert_eq!(audit.total_pages, 4);
        assert_eq!(audit.registered_ranges, 3);

        m.unmap_contiguous(0x90_0000, 2).unwrap();
        m.unmap_scatter(0x20_0000_0000, &[0, 2]).unwrap();
        m.free(a).unwrap();
        m.free(b).unwrap();
        assert_eq!(m.audit().unwrap().total_pages, 0);
    }

    #[test]
    fn audit_detects_registry_backend_count_mismatch() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();
        m.map_contiguous(0xA0_0000, 1, a).unwrap();
        m.global_mappings.clear();
        assert_eq!(
            m.audit(),
            Err(XMemManagerError::RegistryMappingCountMismatch { registry: 0, backends: 1 })
        );
    }

    #[test]
    fn audit_detects_corrupt_or_overlapping_registry_ranges() {
        let mut m = XMemMemoryManager::new();
        let a = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();
        let b = m.allocate_scatter(0, 1, PageSize::KiB64).unwrap();
        m.map_contiguous(0xB0_0000, 1, a).unwrap();
        m.map_scatter(0xC0_0000, &[0], b).unwrap();
        m.global_mappings[1].occupied_ranges[0] = (0xB0_0000, 0xB1_0000);
        assert_eq!(m.audit(), Err(XMemManagerError::RegistryOverlap));
    }

    #[test]
    fn audit_accepts_multi_page_contiguous_range() {
        let mut m = XMemMemoryManager::new();
        let allocation = m.allocate_contiguous(0, 2, PageSize::KiB64).unwrap();
        m.map_contiguous(0xD0_0000, 2, allocation).unwrap();

        let audit = m.audit().unwrap();
        assert_eq!(audit.mapping_count, 1);
        assert_eq!(audit.contiguous_pages, 2);
        assert_eq!(audit.registered_ranges, 1);

        m.unmap_contiguous(0xD0_0000, 2).unwrap();
        m.free(allocation).unwrap();
        assert_eq!(m.audit().unwrap().total_pages, 0);
    }

    #[test]
    fn audit_detects_backend_registry_identity_mismatch() {
        let mut m = XMemMemoryManager::new();
        let allocation = m.allocate_contiguous(0, 1, PageSize::KiB64).unwrap();
        m.map_contiguous(0xE0_0000, 1, allocation).unwrap();
        m.global_mappings[0].guest_base = 0xF0_0000;
        m.global_mappings[0].occupied_ranges = vec![(0xF0_0000, 0xF1_0000)];
        assert_eq!(m.audit(), Err(XMemManagerError::BackendMappingMismatch));
    }

}
