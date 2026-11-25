//! Guest virtual-address space layered over Phoenix host allocations.
//!
//! Guest addresses are logical Xbox image addresses. Host pointers are never
//! exposed as guest addresses. Each guest region resolves to an allocation
//! handle managed by AllocationRegistry.

use crate::xmem_allocation_registry::{
    AllocationHandle, AllocationRegistry, RegistryError,
};
use crate::xmem_host_adapter::HostAllocationPolicy;
use crate::xmem_virtual_alloc::XMemVirtualAllocRequest;
use std::collections::BTreeMap;
use std::fmt;

pub const GUEST_PAGE_SIZE: usize = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    ZeroSize,
    UnalignedBase,
    UnalignedSize,
    AddressOverflow,
    Overlap,
    RegionNotFound,
    AccessCrossesRegion,
    Registry(RegistryError),
}

impl From<RegistryError> for AddressSpaceError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

impl fmt::Display for AddressSpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for AddressSpaceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestRegion {
    pub guest_base: usize,
    pub size: usize,
    pub allocation: AllocationHandle,
}

pub struct GuestAddressSpace {
    registry: AllocationRegistry,
    regions: BTreeMap<usize, GuestRegion>,
}

impl Default for GuestAddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestAddressSpace {
    pub fn new() -> Self {
        Self {
            registry: AllocationRegistry::new(),
            regions: BTreeMap::new(),
        }
    }

    /// Reserve a logical guest range and create its host backing allocation.
    /// `request.requested_address` must be zero; guest_base is tracked separately.
    pub fn allocate_region(
        &mut self,
        guest_base: usize,
        size: usize,
        request: XMemVirtualAllocRequest,
        policy: HostAllocationPolicy,
    ) -> Result<GuestRegion, AddressSpaceError> {
        if size == 0 {
            return Err(AddressSpaceError::ZeroSize);
        }
        if guest_base % GUEST_PAGE_SIZE != 0 {
            return Err(AddressSpaceError::UnalignedBase);
        }
        if size % GUEST_PAGE_SIZE != 0 {
            return Err(AddressSpaceError::UnalignedSize);
        }
        let end = guest_base.checked_add(size)
            .ok_or(AddressSpaceError::AddressOverflow)?;

        if let Some((&previous_base, previous)) = self.regions.range(..=guest_base).next_back() {
            let previous_end = previous_base.checked_add(previous.size)
                .ok_or(AddressSpaceError::AddressOverflow)?;
            if previous_end > guest_base {
                return Err(AddressSpaceError::Overlap);
            }
        }
        if let Some((&next_base, _)) = self.regions.range(guest_base..).next() {
            if next_base < end {
                return Err(AddressSpaceError::Overlap);
            }
        }

        if request.size != size as u64 {
            return Err(AddressSpaceError::UnalignedSize);
        }

        let handle = self.registry.allocate(request, policy)?;
        let region = GuestRegion {
            guest_base,
            size,
            allocation: handle,
        };
        self.regions.insert(guest_base, region);
        Ok(region)
    }

    pub fn commit(
        &mut self,
        guest_address: usize,
        size: usize,
    ) -> Result<(), AddressSpaceError> {
        let (region, offset) = self.resolve(guest_address, size)?;
        self.registry.commit(region.allocation, offset, size)?;
        Ok(())
    }

    pub fn decommit(
        &mut self,
        guest_address: usize,
        size: usize,
    ) -> Result<(), AddressSpaceError> {
        let (region, offset) = self.resolve(guest_address, size)?;
        self.registry.decommit(region.allocation, offset, size)?;
        Ok(())
    }

    pub fn write(
        &mut self,
        guest_address: usize,
        bytes: &[u8],
    ) -> Result<(), AddressSpaceError> {
        let (region, offset) = self.resolve(guest_address, bytes.len())?;
        self.registry.write(region.allocation, offset, bytes)?;
        Ok(())
    }

    pub fn read(
        &self,
        guest_address: usize,
        output: &mut [u8],
    ) -> Result<(), AddressSpaceError> {
        let (region, offset) = self.resolve(guest_address, output.len())?;
        self.registry.read(region.allocation, offset, output)?;
        Ok(())
    }

    pub fn free_region(
        &mut self,
        guest_base: usize,
    ) -> Result<(), AddressSpaceError> {
        let region = self.regions.remove(&guest_base)
            .ok_or(AddressSpaceError::RegionNotFound)?;
        self.registry.free(region.allocation)?;
        Ok(())
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn regions(&self) -> impl Iterator<Item = GuestRegion> + '_ {
        self.regions.values().copied()
    }

    fn resolve(
        &self,
        guest_address: usize,
        length: usize,
    ) -> Result<(GuestRegion, usize), AddressSpaceError> {
        let (&base, region) = self.regions.range(..=guest_address)
            .next_back()
            .ok_or(AddressSpaceError::RegionNotFound)?;

        let end = guest_address.checked_add(length)
            .ok_or(AddressSpaceError::AddressOverflow)?;
        let region_end = base.checked_add(region.size)
            .ok_or(AddressSpaceError::AddressOverflow)?;

        if guest_address < base || guest_address >= region_end {
            return Err(AddressSpaceError::RegionNotFound);
        }
        if end > region_end {
            return Err(AddressSpaceError::AccessCrossesRegion);
        }

        Ok((*region, guest_address - base))
    }
}

pub fn print_address_space_report() {
    println!("\n=== PHOENIX: GUEST VIRTUAL ADDRESS SPACE ===");
    println!("Tracks logical guest ranges separately from host pointers.");
    println!("Operations: reserve guest region, commit/decommit, read/write, free.");
    println!("Overlapping ranges and cross-region accesses are rejected.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmem_virtual_alloc::GRAPHICS_INIT_REQUEST;

    fn request(size: usize) -> XMemVirtualAllocRequest {
        XMemVirtualAllocRequest::new(0, size as u64, 0x20401000, 0x283, 0x42404)
    }

    #[test]
    fn guest_address_resolves_to_host_backing_and_supports_access() {
        let mut space = GuestAddressSpace::new();
        let region = space.allocate_region(
            0x10000000,
            0x10000,
            GRAPHICS_INIT_REQUEST,
            HostAllocationPolicy::ReserveAndCommitReadWrite,
        ).unwrap();

        assert_eq!(region.guest_base, 0x10000000);
        space.write(0x10000100, b"Phoenix").unwrap();
        let mut output = [0u8; 7];
        space.read(0x10000100, &mut output).unwrap();
        assert_eq!(&output, b"Phoenix");
    }

    #[test]
    fn rejects_overlapping_guest_regions_without_leaking_registry_entries() {
        let mut space = GuestAddressSpace::new();
        space.allocate_region(
            0x10000000, 0x2000,
            request(0x2000), HostAllocationPolicy::ReserveAndCommitReadWrite,
        ).unwrap();

        assert_eq!(
            space.allocate_region(
                0x10001000, 0x2000,
                request(0x2000), HostAllocationPolicy::ReserveAndCommitReadWrite,
            ),
            Err(AddressSpaceError::Overlap)
        );
        assert_eq!(space.region_count(), 1);
    }

    #[test]
    fn rejects_access_that_crosses_guest_region_boundary() {
        let mut space = GuestAddressSpace::new();
        space.allocate_region(
            0x20000000, 0x1000,
            request(0x1000), HostAllocationPolicy::ReserveAndCommitReadWrite,
        ).unwrap();

        assert_eq!(
            space.write(0x20000fff, b"two"),
            Err(AddressSpaceError::AccessCrossesRegion)
        );
    }

    #[test]
    fn commit_and_decommit_use_guest_addresses() {
        let mut space = GuestAddressSpace::new();
        space.allocate_region(
            0x30000000, 0x2000,
            request(0x2000), HostAllocationPolicy::ReserveOnly,
        ).unwrap();

        space.commit(0x30000000, 0x1000).unwrap();
        space.write(0x30000000, b"X").unwrap();
        space.decommit(0x30000000, 0x1000).unwrap();

        let mut output = [0u8; 1];
        assert!(matches!(
            space.read(0x30000000, &mut output),
            Err(AddressSpaceError::Registry(_))
        ));
    }

    #[test]
    fn freeing_guest_region_removes_it_from_address_space() {
        let mut space = GuestAddressSpace::new();
        space.allocate_region(
            0x40000000, 0x1000,
            request(0x1000), HostAllocationPolicy::ReserveAndCommitReadWrite,
        ).unwrap();

        space.free_region(0x40000000).unwrap();
        assert_eq!(space.region_count(), 0);
        assert_eq!(
            space.read(0x40000000, &mut [0u8; 1]),
            Err(AddressSpaceError::RegionNotFound)
        );
    }
}
