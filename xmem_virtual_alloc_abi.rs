//! Lifecycle-owning adapter for observed XMemVirtualAlloc requests.
//!
//! This routes requests into Phoenix's software page runtime using explicit
//! placement and page-size policy. It never decodes Xbox flags or invokes
//! Xbox APIs. Handles and guest addresses are Phoenix-side abstractions.

use crate::xmem_model_v3::PageSize;
use crate::xmem_page_runtime::{RegionInfo, RuntimeError, XMemPageRuntime};
use crate::xmem_virtual_alloc::{RequestError, XMemVirtualAllocRequest};
use std::fmt;

/// Phoenix-only guest address window used for automatic placement.
/// These are emulator-model addresses, not asserted Xbox process addresses.
pub const PHOENIX_GUEST_WINDOW_START: usize = 0x1_0000_0000;
pub const PHOENIX_GUEST_WINDOW_END: usize = 0x2_0000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtualAllocAbiError {
    InvalidRequest(RequestError),
    FixedAddressMismatch { requested: u64, selected: u64 },
    AddressDoesNotFitHost(u64),
    Runtime(RuntimeError),
    UnknownHandle,
    HandleExhausted,
    GuestAddressSpaceExhausted,
    InvalidPlacementWindow,
    RegistryOverlap,
    AccountingMismatch,
}
impl From<RuntimeError> for VirtualAllocAbiError {
    fn from(value: RuntimeError) -> Self { Self::Runtime(value) }
}
impl fmt::Display for VirtualAllocAbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for VirtualAllocAbiError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualAllocationHandle(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualAllocationInfo {
    pub handle: VirtualAllocationHandle,
    pub guest_base: usize,
    pub size: usize,
    pub page_size: PageSize,
    pub page_count: usize,
}

struct AllocationEntry {
    info: VirtualAllocationInfo,
    region: RegionInfo,
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    if alignment == 0 || !alignment.is_power_of_two() { return None; }
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualAllocationAudit {
    pub allocation_count: usize,
    pub region_count: usize,
    pub total_pages: usize,
    pub total_bytes: usize,
}

pub struct XMemVirtualAllocAbiAdapter {
    runtime: XMemPageRuntime,
    next_handle: u64,
    allocations: Vec<AllocationEntry>,
}
impl Default for XMemVirtualAllocAbiAdapter {
    fn default() -> Self { Self::new() }
}
impl XMemVirtualAllocAbiAdapter {
    pub fn new() -> Self {
        Self { runtime: XMemPageRuntime::new(), next_handle: 1, allocations: Vec::new() }
    }

    /// Automatically chooses the first aligned free guest range in Phoenix's
    /// configured guest window. This is Phoenix placement policy only.
    pub fn allocate_auto(
        &mut self,
        request: XMemVirtualAllocRequest,
        page_size: PageSize,
    ) -> Result<VirtualAllocationInfo, VirtualAllocAbiError> {
        request.validate().map_err(VirtualAllocAbiError::InvalidRequest)?;
        if request.requested_address != 0 {
            let requested = usize::try_from(request.requested_address)
                .map_err(|_| VirtualAllocAbiError::AddressDoesNotFitHost(request.requested_address))?;
            return self.allocate(request, requested as u64, page_size);
        }

        let size = usize::try_from(request.size)
            .map_err(|_| VirtualAllocAbiError::AddressDoesNotFitHost(request.size))?;
        let alignment = page_size.bytes();
        let mut candidate = align_up(PHOENIX_GUEST_WINDOW_START, alignment)
            .ok_or(VirtualAllocAbiError::InvalidPlacementWindow)?;
        if PHOENIX_GUEST_WINDOW_START >= PHOENIX_GUEST_WINDOW_END {
            return Err(VirtualAllocAbiError::InvalidPlacementWindow);
        }

        let mut occupied: Vec<(usize, usize)> = self.allocations.iter().map(|entry| {
            let start = entry.info.guest_base;
            let end = start.checked_add(entry.info.size).unwrap_or(usize::MAX);
            (start, end)
        }).collect();
        occupied.sort_unstable_by_key(|range| range.0);

        for (start, end) in occupied {
            let candidate_end = candidate.checked_add(size)
                .ok_or(VirtualAllocAbiError::GuestAddressSpaceExhausted)?;
            if candidate_end <= start {
                break;
            }
            if candidate < end && start < candidate_end {
                candidate = align_up(end, alignment)
                    .ok_or(VirtualAllocAbiError::GuestAddressSpaceExhausted)?;
            }
        }

        let end = candidate.checked_add(size)
            .ok_or(VirtualAllocAbiError::GuestAddressSpaceExhausted)?;
        if end > PHOENIX_GUEST_WINDOW_END {
            return Err(VirtualAllocAbiError::GuestAddressSpaceExhausted);
        }
        self.allocate(request, candidate as u64, page_size)
    }

    /// The caller must provide a page size and guest placement established
    /// independently. A nonzero request address must match that placement.
    pub fn allocate(
        &mut self,
        request: XMemVirtualAllocRequest,
        selected_guest_base: u64,
        page_size: PageSize,
    ) -> Result<VirtualAllocationInfo, VirtualAllocAbiError> {
        request.validate().map_err(VirtualAllocAbiError::InvalidRequest)?;
        if request.requested_address != 0 && request.requested_address != selected_guest_base {
            return Err(VirtualAllocAbiError::FixedAddressMismatch {
                requested: request.requested_address,
                selected: selected_guest_base,
            });
        }
        let base = usize::try_from(selected_guest_base)
            .map_err(|_| VirtualAllocAbiError::AddressDoesNotFitHost(selected_guest_base))?;
        let size = usize::try_from(request.size)
            .map_err(|_| VirtualAllocAbiError::AddressDoesNotFitHost(request.size))?;
        let next = self.next_handle.checked_add(1).ok_or(VirtualAllocAbiError::HandleExhausted)?;

        let region = self.runtime.allocate_and_map(base, size, page_size)?;
        let info = VirtualAllocationInfo {
            handle: VirtualAllocationHandle(self.next_handle),
            guest_base: base,
            size,
            page_size,
            page_count: region.page_count,
        };
        self.next_handle = next;
        self.allocations.push(AllocationEntry { info, region });
        Ok(info)
    }

    pub fn write(
        &mut self, handle: VirtualAllocationHandle, offset: usize, bytes: &[u8],
    ) -> Result<(), VirtualAllocAbiError> {
        let entry = self.allocations.iter().find(|e| e.info.handle == handle)
            .ok_or(VirtualAllocAbiError::UnknownHandle)?;
        self.runtime.write(entry.region.id, offset, bytes)?;
        Ok(())
    }

    pub fn read(
        &self, handle: VirtualAllocationHandle, offset: usize, output: &mut [u8],
    ) -> Result<(), VirtualAllocAbiError> {
        let entry = self.allocations.iter().find(|e| e.info.handle == handle)
            .ok_or(VirtualAllocAbiError::UnknownHandle)?;
        self.runtime.read(entry.region.id, offset, output)?;
        Ok(())
    }

    pub fn free(&mut self, handle: VirtualAllocationHandle) -> Result<(), VirtualAllocAbiError> {
        let index = self.allocations.iter().position(|e| e.info.handle == handle)
            .ok_or(VirtualAllocAbiError::UnknownHandle)?;
        self.runtime.unmap_and_free(self.allocations[index].region.id)?;
        self.allocations.remove(index);
        Ok(())
    }

    /// Return metadata for a live Phoenix allocation handle.
    pub fn allocation_info(
        &self, handle: VirtualAllocationHandle,
    ) -> Result<VirtualAllocationInfo, VirtualAllocAbiError> {
        self.allocations.iter()
            .find(|entry| entry.info.handle == handle)
            .map(|entry| entry.info)
            .ok_or(VirtualAllocAbiError::UnknownHandle)
    }

    /// Find the live allocation containing a guest address.
    pub fn allocation_containing(
        &self, guest_address: usize,
    ) -> Option<VirtualAllocationInfo> {
        self.allocations.iter().find_map(|entry| {
            let start = entry.info.guest_base;
            let end = start.checked_add(entry.info.size)?;
            (guest_address >= start && guest_address < end).then_some(entry.info)
        })
    }

    /// Snapshot live allocation metadata without exposing mutable internals.
    pub fn allocation_snapshot(&self) -> Vec<VirtualAllocationInfo> {
        self.allocations.iter().map(|entry| entry.info).collect()
    }

    /// Check adapter bookkeeping against the underlying page runtime.
    pub fn audit(&self) -> Result<VirtualAllocationAudit, VirtualAllocAbiError> {
        if self.runtime.region_count() != self.allocations.len() {
            return Err(VirtualAllocAbiError::AccountingMismatch);
        }
        // Check the allocation table for overlapping address claims first,
        // so overlap corruption is reported distinctly from backend mismatch.
        for left in 0..self.allocations.len() {
            let a = self.allocations[left].info;
            let a_end = a.guest_base.checked_add(a.size)
                .ok_or(VirtualAllocAbiError::AccountingMismatch)?;
            for right in (left + 1)..self.allocations.len() {
                let b = self.allocations[right].info;
                let b_end = b.guest_base.checked_add(b.size)
                    .ok_or(VirtualAllocAbiError::AccountingMismatch)?;
                if a.guest_base < b_end && b.guest_base < a_end {
                    return Err(VirtualAllocAbiError::RegistryOverlap);
                }
            }
        }

        let mut total_pages = 0usize;
        for entry in &self.allocations {
            let expected_size = entry.info.page_count.checked_mul(entry.info.page_size.bytes())
                .ok_or(VirtualAllocAbiError::AccountingMismatch)?;
            if expected_size != entry.info.size || entry.region.base != entry.info.guest_base {
                return Err(VirtualAllocAbiError::AccountingMismatch);
            }
            total_pages = total_pages.checked_add(entry.info.page_count)
                .ok_or(VirtualAllocAbiError::AccountingMismatch)?;
        }
        if total_pages != self.runtime.allocated_page_count() {
            return Err(VirtualAllocAbiError::AccountingMismatch);
        }
        Ok(VirtualAllocationAudit {
            allocation_count: self.allocations.len(),
            region_count: self.runtime.region_count(),
            total_pages,
            total_bytes: self.allocations.iter().map(|e| e.info.size).sum(),
        })
    }

    pub fn allocation_count(&self) -> usize { self.allocations.len() }
    pub fn allocated_page_count(&self) -> usize { self.runtime.allocated_page_count() }
}

pub fn print_virtual_alloc_abi_report() {
    println!("\n=== PHOENIX XMEM VIRTUAL-ALLOC ABI ADAPTER ===");
    println!("Owns request-to-region lifecycle using explicit Phoenix placement and page-size policy.");
    println!("Supports allocate, read, write, free, metadata queries, snapshots, and integrity audits.");
    println!("Zero-address requests use first-fit placement in a Phoenix-configured guest window.");
    println!("Raw Xbox allocation, attribute, and protection fields are not decoded.");
    println!("This is not an Xbox ABI export and does not execute Xbox code.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmem_virtual_alloc::{FIXED_20_MIB_REQUEST, GRAPHICS_INIT_REQUEST};

    #[test]
    fn graphics_request_allocates_reads_writes_and_frees() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let info = adapter.allocate(GRAPHICS_INIT_REQUEST, 0x10000, PageSize::KiB64).unwrap();
        assert_eq!(info.size, 0x10000);
        assert_eq!(info.page_count, 1);
        adapter.write(info.handle, 0x120, b"Phoenix").unwrap();
        let mut out = [0u8; 7];
        adapter.read(info.handle, 0x120, &mut out).unwrap();
        assert_eq!(&out, b"Phoenix");
        adapter.free(info.handle).unwrap();
        assert_eq!(adapter.allocation_count(), 0);
        assert_eq!(adapter.allocated_page_count(), 0);
    }

    #[test]
    fn fixed_address_must_match_selected_guest_address() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let request = XMemVirtualAllocRequest::new(0x40000, 0x10000, 0, 0, 0);
        assert!(matches!(
            adapter.allocate(request, 0x50000, PageSize::KiB64),
            Err(VirtualAllocAbiError::FixedAddressMismatch { .. })
        ));
        assert_eq!(adapter.allocated_page_count(), 0);
    }

    #[test]
    fn fixed_twenty_mib_request_uses_explicit_two_mib_page_mode() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let info = adapter.allocate(FIXED_20_MIB_REQUEST, 0x20_0000, PageSize::MiB2).unwrap();
        assert_eq!(info.page_count, 10);
        assert_eq!(info.size, 0x1400000);
        adapter.free(info.handle).unwrap();
        assert_eq!(adapter.allocated_page_count(), 0);
    }

    #[test]
    fn rejects_invalid_size_and_duplicate_guest_region_without_leaks() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let zero = XMemVirtualAllocRequest::new(0, 0, 0, 0, 0);
        assert!(matches!(
            adapter.allocate(zero, 0x10000, PageSize::KiB64),
            Err(VirtualAllocAbiError::InvalidRequest(RequestError::ZeroSize))
        ));
        let info = adapter.allocate(GRAPHICS_INIT_REQUEST, 0x10000, PageSize::KiB64).unwrap();
        assert!(adapter.allocate(GRAPHICS_INIT_REQUEST, 0x10000, PageSize::KiB64).is_err());
        assert_eq!(adapter.allocation_count(), 1);
        assert_eq!(adapter.allocated_page_count(), 1);
        adapter.free(info.handle).unwrap();
    }

    #[test]
    fn rejects_unknown_handles_for_memory_access_and_free() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let unknown = VirtualAllocationHandle(999);
        assert_eq!(adapter.write(unknown, 0, b"x"), Err(VirtualAllocAbiError::UnknownHandle));
        assert_eq!(adapter.read(unknown, 0, &mut [0]), Err(VirtualAllocAbiError::UnknownHandle));
        assert_eq!(adapter.free(unknown), Err(VirtualAllocAbiError::UnknownHandle));
    }
    #[test]
    fn zero_address_request_uses_first_aligned_free_guest_range() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let first = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        let second = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        assert_eq!(first.guest_base, PHOENIX_GUEST_WINDOW_START);
        assert_eq!(second.guest_base, PHOENIX_GUEST_WINDOW_START + 0x10000);
        adapter.free(first.handle).unwrap();
        adapter.free(second.handle).unwrap();
    }

    #[test]
    fn automatic_placement_reuses_a_freed_gap() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let first = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        let second = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        adapter.free(first.handle).unwrap();
        let replacement = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        assert_eq!(replacement.guest_base, first.guest_base);
        assert_ne!(replacement.guest_base, second.guest_base);
        adapter.free(second.handle).unwrap();
        adapter.free(replacement.handle).unwrap();
    }

    #[test]
    fn automatic_placement_aligns_two_mib_allocations() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let info = adapter.allocate_auto(FIXED_20_MIB_REQUEST, PageSize::MiB2).unwrap();
        assert_eq!(info.guest_base % 0x20_0000, 0);
        assert_eq!(info.guest_base, PHOENIX_GUEST_WINDOW_START);
        adapter.free(info.handle).unwrap();
    }

    #[test]
    fn fixed_request_address_is_honored_by_automatic_entrypoint() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let fixed = XMemVirtualAllocRequest::new(0x3000_0000, 0x10000, 0, 0, 0);
        let info = adapter.allocate_auto(fixed, PageSize::KiB64).unwrap();
        assert_eq!(info.guest_base, 0x3000_0000);
        adapter.free(info.handle).unwrap();
    }

    #[test]
    fn automatic_placement_does_not_leak_on_invalid_page_size_request() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let invalid = XMemVirtualAllocRequest::new(0, 0x1000, 0, 0, 0);
        assert!(adapter.allocate_auto(invalid, PageSize::KiB64).is_err());
        assert_eq!(adapter.allocation_count(), 0);
        assert_eq!(adapter.allocated_page_count(), 0);
    }

    #[test]
    fn queries_allocation_metadata_by_handle_and_address() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let info = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        assert_eq!(adapter.allocation_info(info.handle).unwrap(), info);
        assert_eq!(adapter.allocation_containing(info.guest_base), Some(info));
        assert_eq!(adapter.allocation_containing(info.guest_base + info.size - 1), Some(info));
        assert_eq!(adapter.allocation_containing(info.guest_base + info.size), None);
        adapter.free(info.handle).unwrap();
        assert_eq!(adapter.allocation_info(info.handle), Err(VirtualAllocAbiError::UnknownHandle));
    }

    #[test]
    fn allocation_snapshot_and_audit_track_mixed_page_modes() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let a = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        let b = adapter.allocate_auto(FIXED_20_MIB_REQUEST, PageSize::MiB2).unwrap();
        let snapshot = adapter.allocation_snapshot();
        assert_eq!(snapshot.len(), 2);
        let audit = adapter.audit().unwrap();
        assert_eq!(audit.allocation_count, 2);
        assert_eq!(audit.region_count, 2);
        assert_eq!(audit.total_pages, 11);
        assert_eq!(audit.total_bytes, 0x10000 + 0x1400000);
        adapter.free(a.handle).unwrap();
        adapter.free(b.handle).unwrap();
        assert_eq!(adapter.audit().unwrap().total_pages, 0);
    }

    #[test]
    fn audit_detects_overlapping_allocation_metadata() {
        let mut adapter = XMemVirtualAllocAbiAdapter::new();
        let first = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();
        let second = adapter.allocate_auto(GRAPHICS_INIT_REQUEST, PageSize::KiB64).unwrap();

        // Corrupt the second metadata record so it claims the first allocation's range.
        adapter.allocations[1].info.guest_base = first.guest_base;
        assert_eq!(adapter.audit(), Err(VirtualAllocAbiError::RegistryOverlap));

        // Restore the record so both runtime regions can be released normally.
        adapter.allocations[1].info.guest_base = second.guest_base;
        assert!(adapter.audit().is_ok());
        adapter.free(first.handle).unwrap();
        adapter.free(second.handle).unwrap();
    }

}
