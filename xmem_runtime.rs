//! Project Phoenix XMem runtime model.
//!
//! Integrates virtual slots and physical-page ownership into one stateful API.
//! This remains a deterministic software compatibility model: it does not
//! call Xbox XMem exports or claim Xbox physical-memory equivalence.

use crate::physical_page_model::{
    PhysicalPageError, PhysicalPageId, PhysicalPageModel, PAGE_SIZE,
};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XMemRuntimeError {
    InvalidAddress,
    InvalidSize,
    AddressOverflow,
    Physical(PhysicalPageError),
}

impl From<PhysicalPageError> for XMemRuntimeError {
    fn from(value: PhysicalPageError) -> Self {
        Self::Physical(value)
    }
}

impl fmt::Display for XMemRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for XMemRuntimeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XMemRegion {
    pub base: usize,
    pub size: usize,
    pub page_count: usize,
}

pub struct XMemRuntime {
    model: PhysicalPageModel,
    regions: Vec<XMemRegion>,
}

impl XMemRuntime {
    pub fn new(virtual_size: usize) -> Result<Self, XMemRuntimeError> {
        Ok(Self {
            model: PhysicalPageModel::new(virtual_size)?,
            regions: Vec::new(),
        })
    }

    pub fn allocate_and_map(
        &mut self,
        base: usize,
        size: usize,
    ) -> Result<XMemRegion, XMemRuntimeError> {
        if size == 0 {
            return Err(XMemRuntimeError::InvalidSize);
        }
        if base % PAGE_SIZE != 0 {
            return Err(XMemRuntimeError::InvalidAddress);
        }
        if size % PAGE_SIZE != 0 {
            return Err(XMemRuntimeError::InvalidSize);
        }
        let end = base.checked_add(size).ok_or(XMemRuntimeError::AddressOverflow)?;
        if end > self.model.virtual_size() {
            return Err(XMemRuntimeError::InvalidAddress);
        }

        let page_count = size / PAGE_SIZE;
        let pages = self.model.allocate_pages(page_count)?;
        if let Err(error) = self.model.map_scatter(base, &pages) {
            for page in pages {
                let _ = self.model.free_page(page);
            }
            return Err(error.into());
        }

        let region = XMemRegion { base, size, page_count };
        self.regions.push(region);
        Ok(region)
    }

    pub fn map_existing_pages(
        &mut self,
        mappings: &[(usize, PhysicalPageId)],
    ) -> Result<(), XMemRuntimeError> {
        self.model.map_scatter_slots(mappings)?;
        Ok(())
    }

    pub fn write(&mut self, address: usize, bytes: &[u8]) -> Result<(), XMemRuntimeError> {
        self.model.write(address, bytes)?;
        Ok(())
    }

    pub fn read(&self, address: usize, output: &mut [u8]) -> Result<(), XMemRuntimeError> {
        self.model.read(address, output)?;
        Ok(())
    }

    pub fn unmap_region(&mut self, base: usize, size: usize) -> Result<(), XMemRuntimeError> {
        let region_index = self.regions.iter()
            .position(|region| region.base == base && region.size == size)
            .ok_or(XMemRuntimeError::InvalidAddress)?;

        let pages = self.model.unmap_range(base, size)?;
        for page in pages {
            self.model.free_page(page)?;
        }
        self.regions.remove(region_index);
        Ok(())
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn allocated_page_count(&self) -> usize {
        self.model.allocated_page_count()
    }

    pub fn virtual_size(&self) -> usize {
        self.model.virtual_size()
    }
}

pub fn print_runtime_report() {
    println!("\n=== PHOENIX: XMEM RUNTIME MODEL ===");
    println!("Integrated operations: allocate+map, read, write, unmap+free");
    println!("Page size: {:#x}", PAGE_SIZE);
    println!("This runtime currently uses the software physical-page model.");
    println!("Xbox allocation flags and hardware physical-page semantics remain unimplemented.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_write_read_unmap_releases_all_pages() {
        let mut runtime = XMemRuntime::new(0x10000).unwrap();
        let region = runtime.allocate_and_map(0x2000, 0x3000).unwrap();
        assert_eq!(region.page_count, 3);
        assert_eq!(runtime.region_count(), 1);
        assert_eq!(runtime.allocated_page_count(), 3);

        runtime.write(0x2ffb, b"phoenix-memory").unwrap();
        let mut output = [0u8; 14];
        runtime.read(0x2ffb, &mut output).unwrap();
        assert_eq!(&output, b"phoenix-memory");

        runtime.unmap_region(region.base, region.size).unwrap();
        assert_eq!(runtime.region_count(), 0);
        assert_eq!(runtime.allocated_page_count(), 0);
    }

    #[test]
    fn failed_overlapping_allocation_does_not_leak_pages() {
        let mut runtime = XMemRuntime::new(0x4000).unwrap();
        runtime.allocate_and_map(0x1000, 0x1000).unwrap();

        let before = runtime.allocated_page_count();
        assert!(runtime.allocate_and_map(0x1000, 0x2000).is_err());
        assert_eq!(runtime.allocated_page_count(), before);
        assert_eq!(runtime.region_count(), 1);
    }

    #[test]
    fn rejects_unaligned_and_out_of_range_regions() {
        let mut runtime = XMemRuntime::new(0x4000).unwrap();
        assert_eq!(
            runtime.allocate_and_map(1, 0x1000),
            Err(XMemRuntimeError::InvalidAddress)
        );
        assert_eq!(
            runtime.allocate_and_map(0x3000, 0x2000),
            Err(XMemRuntimeError::InvalidAddress)
        );
        assert_eq!(
            runtime.allocate_and_map(0, 0x1001),
            Err(XMemRuntimeError::InvalidSize)
        );
    }

    #[test]
    fn rejects_unmapping_an_unknown_region() {
        let mut runtime = XMemRuntime::new(0x4000).unwrap();
        assert_eq!(
            runtime.unmap_region(0, 0x1000),
            Err(XMemRuntimeError::InvalidAddress)
        );
    }
}
