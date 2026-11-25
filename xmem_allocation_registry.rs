//! Project Phoenix host allocation registry.
//!
//! Owns XMem-to-host allocations by stable handles and centralizes lifecycle
//! operations. It is a host-side development layer, not an Xbox XMem ABI
//! implementation. Xbox flag interpretation remains deliberately separate.

use crate::xmem_host_adapter::{
    create_host_allocation, AdapterError, HostAllocationPolicy, XMemHostAllocation,
};
use crate::xmem_virtual_alloc::XMemVirtualAllocRequest;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllocationHandle(u64);

impl AllocationHandle {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    HandleExhausted,
    UnknownHandle,
    Adapter(AdapterError),
}

impl From<AdapterError> for RegistryError {
    fn from(value: AdapterError) -> Self {
        Self::Adapter(value)
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for RegistryError {}

pub struct AllocationRegistry {
    next_handle: u64,
    allocations: BTreeMap<AllocationHandle, XMemHostAllocation>,
}

impl Default for AllocationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AllocationRegistry {
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            allocations: BTreeMap::new(),
        }
    }

    pub fn allocate(
        &mut self,
        request: XMemVirtualAllocRequest,
        policy: HostAllocationPolicy,
    ) -> Result<AllocationHandle, RegistryError> {
        let handle_value = self.next_handle;
        let next = handle_value
            .checked_add(1)
            .ok_or(RegistryError::HandleExhausted)?;

        // Create first; only consume a handle after host allocation succeeds.
        let allocation = create_host_allocation(request, policy)?;
        let handle = AllocationHandle(handle_value);
        self.allocations.insert(handle, allocation);
        self.next_handle = next;
        Ok(handle)
    }

    pub fn commit(
        &mut self,
        handle: AllocationHandle,
        offset: usize,
        size: usize,
    ) -> Result<(), RegistryError> {
        self.allocations
            .get_mut(&handle)
            .ok_or(RegistryError::UnknownHandle)?
            .commit(offset, size)
            .map_err(RegistryError::from)
    }

    pub fn decommit(
        &mut self,
        handle: AllocationHandle,
        offset: usize,
        size: usize,
    ) -> Result<(), RegistryError> {
        self.allocations
            .get_mut(&handle)
            .ok_or(RegistryError::UnknownHandle)?
            .decommit(offset, size)
            .map_err(RegistryError::from)
    }

    pub fn write(
        &mut self,
        handle: AllocationHandle,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), RegistryError> {
        self.allocations
            .get_mut(&handle)
            .ok_or(RegistryError::UnknownHandle)?
            .write(offset, bytes)
            .map_err(RegistryError::from)
    }

    pub fn read(
        &self,
        handle: AllocationHandle,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), RegistryError> {
        self.allocations
            .get(&handle)
            .ok_or(RegistryError::UnknownHandle)?
            .read(offset, output)
            .map_err(RegistryError::from)
    }

    pub fn allocation_size(
        &self,
        handle: AllocationHandle,
    ) -> Result<usize, RegistryError> {
        self.allocations
            .get(&handle)
            .map(XMemHostAllocation::reserved_size)
            .ok_or(RegistryError::UnknownHandle)
    }

    pub fn free(
        &mut self,
        handle: AllocationHandle,
    ) -> Result<(), RegistryError> {
        let allocation = self.allocations
            .remove(&handle)
            .ok_or(RegistryError::UnknownHandle)?;
        allocation.release().map_err(RegistryError::from)
    }

    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }
}

pub fn print_registry_report() {
    println!("\n=== PHOENIX: HOST ALLOCATION REGISTRY ===");
    println!("Tracks host allocations using stable handles.");
    println!("Operations: allocate, commit, decommit, read, write, query size, free.");
    println!("Registry owns allocation lifetimes; dropping it releases remaining host regions.");
    println!("This does not implement Xbox handles or Xbox allocation flag semantics.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmem_virtual_alloc::GRAPHICS_INIT_REQUEST;

    #[test]
    fn allocates_accesses_and_frees_by_handle() {
        let mut registry = AllocationRegistry::new();
        let handle = registry.allocate(
            GRAPHICS_INIT_REQUEST,
            HostAllocationPolicy::ReserveAndCommitReadWrite,
        ).unwrap();

        assert_eq!(registry.allocation_count(), 1);
        assert_eq!(registry.allocation_size(handle).unwrap(), 0x10000);

        registry.write(handle, 0x80, b"Phoenix").unwrap();
        let mut output = [0u8; 7];
        registry.read(handle, 0x80, &mut output).unwrap();
        assert_eq!(&output, b"Phoenix");

        registry.free(handle).unwrap();
        assert_eq!(registry.allocation_count(), 0);
        assert_eq!(
            registry.allocation_size(handle),
            Err(RegistryError::UnknownHandle)
        );
    }

    #[test]
    fn reserve_only_allocation_can_be_committed_and_decommitted_by_handle() {
        let mut registry = AllocationRegistry::new();
        let handle = registry.allocate(
            GRAPHICS_INIT_REQUEST,
            HostAllocationPolicy::ReserveOnly,
        ).unwrap();

        let mut output = [0u8; 1];
        assert!(matches!(
            registry.read(handle, 0, &mut output),
            Err(RegistryError::Adapter(AdapterError::Host(
                crate::host_virtual_memory::VmError::NotCommitted
            )))
        ));

        registry.commit(handle, 0, 0x1000).unwrap();
        registry.write(handle, 0, b"R").unwrap();
        registry.read(handle, 0, &mut output).unwrap();
        assert_eq!(output[0], b'R');

        registry.decommit(handle, 0, 0x1000).unwrap();
        registry.free(handle).unwrap();
    }

    #[test]
    fn failed_allocation_does_not_consume_a_handle_or_registry_slot() {
        let mut registry = AllocationRegistry::new();
        let invalid = XMemVirtualAllocRequest::new(0x1234, 0x1000, 0, 0, 0);

        assert!(registry.allocate(invalid, HostAllocationPolicy::ReserveOnly).is_err());
        assert_eq!(registry.allocation_count(), 0);

        let valid = registry.allocate(
            GRAPHICS_INIT_REQUEST,
            HostAllocationPolicy::ReserveOnly,
        ).unwrap();
        assert_eq!(valid.value(), 1);
    }

    #[test]
    fn rejects_unknown_handles_for_every_operation() {
        let mut registry = AllocationRegistry::new();
        let unknown = AllocationHandle(999);

        assert_eq!(
            registry.allocation_size(unknown),
            Err(RegistryError::UnknownHandle)
        );
        assert_eq!(registry.free(unknown), Err(RegistryError::UnknownHandle));
        assert_eq!(registry.write(unknown, 0, b"x"), Err(RegistryError::UnknownHandle));
        assert_eq!(registry.read(unknown, 0, &mut [0u8; 1]), Err(RegistryError::UnknownHandle));
        assert_eq!(registry.commit(unknown, 0, 0x1000), Err(RegistryError::UnknownHandle));
        assert_eq!(registry.decommit(unknown, 0, 0x1000), Err(RegistryError::UnknownHandle));
    }
}
