//! Phoenix host-side model of Xbox-style physical-page allocation and mapping.
//!
//! Supports the two page sizes demonstrated by Microsoft's Xbox GDK sample:
//! 64 KiB and 2 MiB. This remains a simulation, not a real Xbox memory API.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

pub const XMEM_PAGE_SIZE_64K: usize = 64 * 1024;
pub const XMEM_PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
/// Backwards-compatible default used by the original Phoenix model.
pub const XMEM_PAGE_SIZE: usize = XMEM_PAGE_SIZE_64K;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PageSize {
    KiB64,
    MiB2,
}

impl PageSize {
    pub const fn bytes(self) -> usize {
        match self {
            Self::KiB64 => XMEM_PAGE_SIZE_64K,
            Self::MiB2 => XMEM_PAGE_SIZE_2M,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageId(usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemError {
    ZeroPageCount,
    OutOfMemory,
    InvalidPage(PageId),
    PageAlreadyMapped(PageId),
    PageNotAllocated(PageId),
    PageStillMapped(PageId),
    PageSizeMismatch { expected: PageSize, actual: PageSize },
    AddressOutOfRange(usize),
    UnalignedAddress { offset: usize, page_size: usize },
    LengthOutOfRange { offset: usize, length: usize },
    PageCountMismatch { expected: usize, actual: usize },
}

impl fmt::Display for XMemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPageCount => write!(f, "page count must be greater than zero"),
            Self::OutOfMemory => write!(f, "physical page pool is exhausted"),
            Self::InvalidPage(id) => write!(f, "invalid physical page id {}", id.0),
            Self::PageAlreadyMapped(id) => write!(f, "physical page {} is already mapped", id.0),
            Self::PageNotAllocated(id) => write!(f, "physical page {} is not allocated", id.0),
            Self::PageStillMapped(id) => write!(f, "physical page {} cannot be freed while mapped", id.0),
            Self::PageSizeMismatch { expected, actual } => write!(f, "page size mismatch: region uses {expected:?}, page uses {actual:?}"),
            Self::AddressOutOfRange(offset) => write!(f, "virtual offset {offset:#x} is outside the reserved region"),
            Self::UnalignedAddress { offset, page_size } => write!(f, "virtual offset {offset:#x} is not aligned to {page_size:#x}"),
            Self::LengthOutOfRange { offset, length } => write!(f, "range {offset:#x}..{:#x} exceeds the reserved region", offset.saturating_add(*length)),
            Self::PageCountMismatch { expected, actual } => write!(f, "expected {expected} pages, received {actual}"),
        }
    }
}
impl Error for XMemError {}

#[derive(Debug)]
struct PhysicalPage {
    size: PageSize,
    bytes: Box<[u8]>,
    mapping_count: usize,
}

/// Owns host-backed storage for simulated physical pages.
#[derive(Debug, Default)]
pub struct PhysicalPagePool {
    pages: Vec<Option<PhysicalPage>>,
}

impl PhysicalPagePool {
    pub fn new() -> Self { Self::default() }

    /// Original 64 KiB allocator retained for existing Phoenix callers.
    pub fn allocate(&mut self, count: usize) -> Result<Vec<PageId>, XMemError> {
        self.allocate_with_size(count, PageSize::KiB64)
    }

    pub fn allocate_with_size(&mut self, count: usize, size: PageSize) -> Result<Vec<PageId>, XMemError> {
        if count == 0 { return Err(XMemError::ZeroPageCount); }
        let mut ids = Vec::with_capacity(count);
        for index in 0..self.pages.len() {
            if self.pages[index].is_none() {
                self.pages[index] = Some(Self::make_page(size));
                ids.push(PageId(index));
                if ids.len() == count { return Ok(ids); }
            }
        }
        while ids.len() < count {
            let index = self.pages.len();
            self.pages.push(Some(Self::make_page(size)));
            ids.push(PageId(index));
        }
        Ok(ids)
    }

    fn make_page(size: PageSize) -> PhysicalPage {
        PhysicalPage { size, bytes: vec![0; size.bytes()].into_boxed_slice(), mapping_count: 0 }
    }

    pub fn free(&mut self, ids: &[PageId]) -> Result<(), XMemError> {
        let mut unique = HashSet::with_capacity(ids.len());
        for &id in ids {
            if !unique.insert(id) { return Err(XMemError::InvalidPage(id)); }
            let page = self.page(id)?;
            if page.mapping_count != 0 { return Err(XMemError::PageStillMapped(id)); }
        }
        for &id in ids { self.pages[id.0] = None; }
        Ok(())
    }

    pub fn allocated_count(&self) -> usize { self.pages.iter().filter(|p| p.is_some()).count() }

    fn page(&self, id: PageId) -> Result<&PhysicalPage, XMemError> {
        self.pages.get(id.0).ok_or(XMemError::InvalidPage(id))?.as_ref().ok_or(XMemError::PageNotAllocated(id))
    }
    fn page_mut(&mut self, id: PageId) -> Result<&mut PhysicalPage, XMemError> {
        self.pages.get_mut(id.0).ok_or(XMemError::InvalidPage(id))?.as_mut().ok_or(XMemError::PageNotAllocated(id))
    }
}

/// A reserved host-side virtual range. Unmapped pages read as unavailable.
#[derive(Debug)]
pub struct VirtualRegion {
    size: usize,
    page_size: PageSize,
    mappings: Vec<Option<PageId>>,
}

impl VirtualRegion {
    /// Original constructor retained for existing 64 KiB callers.
    pub fn reserve(size: usize) -> Result<Self, XMemError> {
        Self::reserve_with_page_size(size, PageSize::KiB64)
    }

    pub fn reserve_with_page_size(size: usize, page_size: PageSize) -> Result<Self, XMemError> {
        if size == 0 { return Err(XMemError::ZeroPageCount); }
        let unit = page_size.bytes();
        let rounded = size.checked_add(unit - 1)
            .ok_or(XMemError::LengthOutOfRange { offset: 0, length: size })?
            / unit * unit;
        Ok(Self { size: rounded, page_size, mappings: vec![None; rounded / unit] })
    }

    pub fn size(&self) -> usize { self.size }
    pub fn page_size(&self) -> PageSize { self.page_size }
    pub fn mapped_page_count(&self) -> usize { self.mappings.iter().filter(|p| p.is_some()).count() }

    pub fn map(&mut self, offset: usize, ids: &[PageId], pool: &mut PhysicalPagePool) -> Result<(), XMemError> {
        let unit = self.page_size.bytes();
        if offset % unit != 0 { return Err(XMemError::UnalignedAddress { offset, page_size: unit }); }
        if ids.is_empty() { return Err(XMemError::ZeroPageCount); }
        let start = offset / unit;
        let end = start.checked_add(ids.len()).ok_or(XMemError::AddressOutOfRange(offset))?;
        if end > self.mappings.len() { return Err(XMemError::PageCountMismatch { expected: self.mappings.len().saturating_sub(start), actual: ids.len() }); }
        let mut unique_ids = HashSet::with_capacity(ids.len());
        for &id in ids {
            let page = pool.page(id)?;
            if page.size != self.page_size { return Err(XMemError::PageSizeMismatch { expected: self.page_size, actual: page.size }); }
            if !unique_ids.insert(id) || self.mappings.iter().any(|mapped| *mapped == Some(id)) { return Err(XMemError::PageAlreadyMapped(id)); }
        }
        if self.mappings[start..end].iter().any(Option::is_some) { return Err(XMemError::AddressOutOfRange(offset)); }
        for &id in ids { pool.page_mut(id)?.mapping_count += 1; }
        self.mappings[start..end].copy_from_slice(&ids.iter().copied().map(Some).collect::<Vec<_>>());
        Ok(())
    }

    pub fn map_scatter(&mut self, offsets: &[usize], ids: &[PageId], pool: &mut PhysicalPagePool) -> Result<(), XMemError> {
        if offsets.len() != ids.len() { return Err(XMemError::PageCountMismatch { expected: offsets.len(), actual: ids.len() }); }
        if offsets.is_empty() { return Err(XMemError::ZeroPageCount); }
        let unit = self.page_size.bytes();
        let mut unique_ids = HashSet::with_capacity(ids.len());
        let mut unique_slots = HashSet::with_capacity(offsets.len());
        for (&offset, &id) in offsets.iter().zip(ids) {
            if offset % unit != 0 { return Err(XMemError::UnalignedAddress { offset, page_size: unit }); }
            let slot = offset / unit;
            if slot >= self.mappings.len() || self.mappings[slot].is_some() || !unique_slots.insert(slot) { return Err(XMemError::AddressOutOfRange(offset)); }
            let page = pool.page(id)?;
            if page.size != self.page_size { return Err(XMemError::PageSizeMismatch { expected: self.page_size, actual: page.size }); }
            if !unique_ids.insert(id) || self.mappings.iter().any(|mapped| *mapped == Some(id)) { return Err(XMemError::PageAlreadyMapped(id)); }
        }
        for &id in ids { pool.page_mut(id)?.mapping_count += 1; }
        for (&offset, &id) in offsets.iter().zip(ids) { self.mappings[offset / unit] = Some(id); }
        Ok(())
    }

    pub fn unmap(&mut self, offset: usize, count: usize, pool: &mut PhysicalPagePool) -> Result<Vec<PageId>, XMemError> {
        let unit = self.page_size.bytes();
        if offset % unit != 0 { return Err(XMemError::UnalignedAddress { offset, page_size: unit }); }
        if count == 0 { return Err(XMemError::ZeroPageCount); }
        let start = offset / unit;
        let end = start.checked_add(count).ok_or(XMemError::AddressOutOfRange(offset))?;
        if end > self.mappings.len() { return Err(XMemError::AddressOutOfRange(offset)); }
        let mut removed = Vec::with_capacity(count);
        for slot in &mut self.mappings[start..end] { if let Some(id) = slot.take() { removed.push(id); } }
        for &id in &removed { pool.page_mut(id)?.mapping_count -= 1; }
        Ok(removed)
    }

    pub fn write(&self, pool: &mut PhysicalPagePool, offset: usize, data: &[u8]) -> Result<(), XMemError> {
        self.check_range(offset, data.len())?;
        let unit = self.page_size.bytes();
        let mut consumed = 0;
        while consumed < data.len() {
            let absolute = offset + consumed;
            let page_index = absolute / unit;
            let page_offset = absolute % unit;
            let amount = (unit - page_offset).min(data.len() - consumed);
            let id = self.mappings[page_index].ok_or(XMemError::AddressOutOfRange(absolute))?;
            let page = pool.page_mut(id)?;
            if page.size != self.page_size { return Err(XMemError::PageSizeMismatch { expected: self.page_size, actual: page.size }); }
            page.bytes[page_offset..page_offset + amount].copy_from_slice(&data[consumed..consumed + amount]);
            consumed += amount;
        }
        Ok(())
    }

    pub fn read(&self, pool: &PhysicalPagePool, offset: usize, output: &mut [u8]) -> Result<(), XMemError> {
        self.check_range(offset, output.len())?;
        let unit = self.page_size.bytes();
        let mut consumed = 0;
        while consumed < output.len() {
            let absolute = offset + consumed;
            let page_index = absolute / unit;
            let page_offset = absolute % unit;
            let amount = (unit - page_offset).min(output.len() - consumed);
            let id = self.mappings[page_index].ok_or(XMemError::AddressOutOfRange(absolute))?;
            let page = pool.page(id)?;
            if page.size != self.page_size { return Err(XMemError::PageSizeMismatch { expected: self.page_size, actual: page.size }); }
            output[consumed..consumed + amount].copy_from_slice(&page.bytes[page_offset..page_offset + amount]);
            consumed += amount;
        }
        Ok(())
    }

    fn check_range(&self, offset: usize, length: usize) -> Result<(), XMemError> {
        let end = offset.checked_add(length).ok_or(XMemError::LengthOutOfRange { offset, length })?;
        if end > self.size { return Err(XMemError::LengthOutOfRange { offset, length }); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_map_write_read_unmap_and_free_64k() {
        let mut pool = PhysicalPagePool::new();
        let pages = pool.allocate(2).unwrap();
        let mut region = VirtualRegion::reserve(2 * XMEM_PAGE_SIZE_64K).unwrap();
        region.map(0, &pages, &mut pool).unwrap();
        let payload = b"Phoenix memory mapping test";
        region.write(&mut pool, XMEM_PAGE_SIZE_64K - 5, payload).unwrap();
        let mut actual = vec![0; payload.len()];
        region.read(&pool, XMEM_PAGE_SIZE_64K - 5, &mut actual).unwrap();
        assert_eq!(&actual, payload);
        assert_eq!(region.unmap(0, 2, &mut pool).unwrap(), pages);
        pool.free(&pages).unwrap();
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn supports_2m_page_allocation_mapping_and_cross_page_io() {
        let mut pool = PhysicalPagePool::new();
        let pages = pool.allocate_with_size(2, PageSize::MiB2).unwrap();
        let mut region = VirtualRegion::reserve_with_page_size(2 * XMEM_PAGE_SIZE_2M, PageSize::MiB2).unwrap();
        region.map(0, &pages, &mut pool).unwrap();
        let payload = b"Phoenix 2 MiB page test";
        region.write(&mut pool, XMEM_PAGE_SIZE_2M - 4, payload).unwrap();
        let mut actual = vec![0; payload.len()];
        region.read(&pool, XMEM_PAGE_SIZE_2M - 4, &mut actual).unwrap();
        assert_eq!(&actual, payload);
        assert_eq!(region.unmap(0, 2, &mut pool).unwrap(), pages);
        pool.free(&pages).unwrap();
    }

    #[test]
    fn scatter_mapping_uses_requested_virtual_slots() {
        let mut pool = PhysicalPagePool::new();
        let pages = pool.allocate(2).unwrap();
        let mut region = VirtualRegion::reserve(3 * XMEM_PAGE_SIZE).unwrap();
        region.map_scatter(&[0, 2 * XMEM_PAGE_SIZE], &pages, &mut pool).unwrap();
        assert_eq!(region.mapped_page_count(), 2);
        region.write(&mut pool, 2 * XMEM_PAGE_SIZE, b"scatter").unwrap();
        let mut out = [0; 7];
        region.read(&pool, 2 * XMEM_PAGE_SIZE, &mut out).unwrap();
        assert_eq!(&out, b"scatter");
    }

    #[test]
    fn rejects_mixed_page_sizes() {
        let mut pool = PhysicalPagePool::new();
        let pages = pool.allocate_with_size(1, PageSize::MiB2).unwrap();
        let mut region = VirtualRegion::reserve(XMEM_PAGE_SIZE_64K).unwrap();
        assert!(matches!(region.map(0, &pages, &mut pool), Err(XMemError::PageSizeMismatch { .. })));
    }

    #[test]
    fn rejects_unaligned_and_out_of_range_mapping() {
        let mut pool = PhysicalPagePool::new();
        let pages = pool.allocate(1).unwrap();
        let mut region = VirtualRegion::reserve(XMEM_PAGE_SIZE).unwrap();
        assert!(matches!(region.map(1, &pages, &mut pool), Err(XMemError::UnalignedAddress { .. })));
        assert!(region.map(XMEM_PAGE_SIZE, &pages, &mut pool).is_err());
    }
}
