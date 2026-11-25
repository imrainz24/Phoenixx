//! Top-level Phoenix XMem compatibility runtime.
//!
//! This module coordinates the two XMem software models currently implemented:
//! XMemVirtualAlloc and physical-page allocation/mapping. It deliberately does
//! not decode undocumented Xbox flags, export Xbox ABI functions, or claim that
//! Phoenix synthetic page IDs are Xbox physical addresses.

use crate::xmem_model_v3::PageSize;
use crate::xmem_physical_page_abi::{
    PhysicalPageAbiError, PhysicalPagesResult, XMemPhysicalPageAbiAdapter,
};
use crate::xmem_virtual_alloc::{XMemVirtualAllocRequest};
use crate::xmem_virtual_alloc_abi::{
    VirtualAllocAbiError, VirtualAllocationInfo, VirtualAllocationHandle,
    XMemVirtualAllocAbiAdapter,
};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemRuntimeError {
    VirtualAlloc(VirtualAllocAbiError),
    PhysicalPages(PhysicalPageAbiError),
}

impl From<VirtualAllocAbiError> for XMemRuntimeError {
    fn from(value: VirtualAllocAbiError) -> Self { Self::VirtualAlloc(value) }
}
impl From<PhysicalPageAbiError> for XMemRuntimeError {
    fn from(value: PhysicalPageAbiError) -> Self { Self::PhysicalPages(value) }
}
impl fmt::Display for XMemRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for XMemRuntimeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XMemRuntimeStats {
    pub virtual_allocation_count: usize,
    pub virtual_page_count: usize,
    pub physical_allocation_count: usize,
    pub physical_page_count: usize,
    pub physical_mapping_count: usize,
}

/// Owns Phoenix's software implementations of the currently modelled XMem
/// operations. The virtual-allocation and physical-page backends remain
/// separate internally; this type gives the compatibility layer one entry
/// point and one lifecycle owner.
pub struct XMemCompatibilityRuntime {
    virtual_alloc: XMemVirtualAllocAbiAdapter,
    physical_pages: XMemPhysicalPageAbiAdapter,
}

impl Default for XMemCompatibilityRuntime {
    fn default() -> Self { Self::new() }
}

impl XMemCompatibilityRuntime {
    pub fn new() -> Self {
        Self {
            virtual_alloc: XMemVirtualAllocAbiAdapter::new(),
            physical_pages: XMemPhysicalPageAbiAdapter::new(),
        }
    }

    /// Model a five-argument XMemVirtualAlloc request at an explicit Phoenix
    /// guest address. `page_size` is supplied by Phoenix policy, not decoded
    /// from the request's undocumented Xbox flag fields.
    pub fn virtual_allocate(
        &mut self,
        request: XMemVirtualAllocRequest,
        guest_base: u64,
        page_size: PageSize,
    ) -> Result<VirtualAllocationInfo, XMemRuntimeError> {
        Ok(self.virtual_alloc.allocate(request, guest_base, page_size)?)
    }

    pub fn virtual_write(
        &mut self,
        handle: VirtualAllocationHandle,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), XMemRuntimeError> {
        self.virtual_alloc.write(handle, offset, bytes)?;
        Ok(())
    }

    pub fn virtual_read(
        &self,
        handle: VirtualAllocationHandle,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), XMemRuntimeError> {
        self.virtual_alloc.read(handle, offset, output)?;
        Ok(())
    }

    pub fn virtual_free(
        &mut self,
        handle: VirtualAllocationHandle,
    ) -> Result<(), XMemRuntimeError> {
        self.virtual_alloc.free(handle)?;
        Ok(())
    }

    /// Allocate Phoenix synthetic page tokens. Raw Xbox flags are preserved
    /// by the underlying model and are not interpreted.
    pub fn allocate_physical_pages(
        &mut self,
        raw_flags: usize,
        page_count: usize,
        page_size: PageSize,
    ) -> Result<PhysicalPagesResult, XMemRuntimeError> {
        Ok(self.physical_pages.allocate_physical_pages(raw_flags, page_count, page_size)?)
    }

    pub fn map_physical_pages(
        &mut self,
        guest_base: usize,
        page_count: usize,
        page_ids: &[usize],
    ) -> Result<(), XMemRuntimeError> {
        self.physical_pages.map_physical_pages(guest_base, page_count, page_ids)?;
        Ok(())
    }

    pub fn unmap_physical_pages(
        &mut self,
        guest_base: usize,
        page_count: usize,
    ) -> Result<(), XMemRuntimeError> {
        self.physical_pages.unmap_physical_pages(guest_base, page_count)?;
        Ok(())
    }

    pub fn free_physical_pages(
        &mut self,
        page_count: usize,
        page_ids: &[usize],
    ) -> Result<(), XMemRuntimeError> {
        self.physical_pages.free_physical_pages(page_count, page_ids)?;
        Ok(())
    }

    pub fn stats(&self) -> XMemRuntimeStats {
        XMemRuntimeStats {
            virtual_allocation_count: self.virtual_alloc.allocation_count(),
            virtual_page_count: self.virtual_alloc.allocated_page_count(),
            physical_allocation_count: self.physical_pages.allocation_count(),
            physical_page_count: self.physical_pages.allocated_page_count(),
            physical_mapping_count: self.physical_pages.mapping_count(),
        }
    }
}

pub fn print_runtime_report() {
    println!("\n=== PHOENIX: XMEM COMPATIBILITY RUNTIME ===");
    println!("Coordinates the XMemVirtualAlloc and physical-page software adapters.");
    println!("Supports virtual allocation/read/write/free and physical allocate/map/unmap/free.");
    println!("Page size and guest placement are explicit Phoenix policy inputs.");
    println!("Xbox allocation flags remain opaque; synthetic page IDs are not Xbox physical addresses.");
    println!("No Xbox ABI functions are exported or called; this is not yet executable compatibility.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmem_virtual_alloc::GRAPHICS_INIT_REQUEST;

    #[test]
    fn virtual_allocation_runs_complete_lifecycle_through_runtime() {
        let mut runtime = XMemCompatibilityRuntime::new();
        let allocation = runtime.virtual_allocate(
            GRAPHICS_INIT_REQUEST,
            0x1_0000_0000,
            PageSize::KiB64,
        ).unwrap();
        runtime.virtual_write(allocation.handle, 0x100, b"Phoenix").unwrap();
        let mut bytes = [0u8; 7];
        runtime.virtual_read(allocation.handle, 0x100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"Phoenix");
        assert_eq!(runtime.stats().virtual_allocation_count, 1);
        runtime.virtual_free(allocation.handle).unwrap();
        assert_eq!(runtime.stats().virtual_allocation_count, 0);
        assert_eq!(runtime.stats().virtual_page_count, 0);
    }

    #[test]
    fn physical_pages_run_complete_lifecycle_through_runtime() {
        let mut runtime = XMemCompatibilityRuntime::new();
        let pages = runtime.allocate_physical_pages(0x280, 2, PageSize::KiB64).unwrap();
        runtime.map_physical_pages(0x300_0000, pages.page_count, &pages.page_ids).unwrap();
        assert_eq!(runtime.stats().physical_mapping_count, 1);
        runtime.unmap_physical_pages(0x300_0000, pages.page_count).unwrap();
        runtime.free_physical_pages(pages.page_count, &pages.page_ids).unwrap();
        let stats = runtime.stats();
        assert_eq!(stats.physical_allocation_count, 0);
        assert_eq!(stats.physical_page_count, 0);
        assert_eq!(stats.physical_mapping_count, 0);
    }

    #[test]
    fn runtime_keeps_virtual_and_physical_accounting_separate() {
        let mut runtime = XMemCompatibilityRuntime::new();
        let allocation = runtime.virtual_allocate(
            GRAPHICS_INIT_REQUEST,
            0x1_0000_0000,
            PageSize::KiB64,
        ).unwrap();
        let pages = runtime.allocate_physical_pages(0x180, 1, PageSize::MiB2).unwrap();
        let stats = runtime.stats();
        assert_eq!(stats.virtual_allocation_count, 1);
        assert_eq!(stats.virtual_page_count, 1);
        assert_eq!(stats.physical_allocation_count, 1);
        assert_eq!(stats.physical_page_count, 1);
        runtime.virtual_free(allocation.handle).unwrap();
        runtime.free_physical_pages(pages.page_count, &pages.page_ids).unwrap();
    }
}
