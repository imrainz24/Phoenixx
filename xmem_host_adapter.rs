//! Explicit host adapter for observed XMemVirtualAlloc requests.
//!
//! IMPORTANT: XMem allocation_type, XALLOC_ATTRIBUTES, and protection values
//! are not interpreted here. The caller must select a host policy explicitly.
//! The adapter only accepts a null requested address because the current host
//! backend does not implement fixed-address reservation.

use crate::host_virtual_memory::{HostVirtualMemory, VmError, HOST_PAGE_SIZE};
use crate::xmem_virtual_alloc::{RequestError, XMemVirtualAllocRequest};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAllocationPolicy {
    ReserveOnly,
    ReserveAndCommitReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    InvalidRequest(RequestError),
    RequestedAddressNotSupported,
    SizeDoesNotFitHost,
    Host(VmError),
}

impl From<VmError> for AdapterError {
    fn from(value: VmError) -> Self {
        Self::Host(value)
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for AdapterError {}

pub struct XMemHostAllocation {
    request: XMemVirtualAllocRequest,
    policy: HostAllocationPolicy,
    memory: HostVirtualMemory,
}

impl XMemHostAllocation {
    pub fn request(&self) -> XMemVirtualAllocRequest {
        self.request
    }

    pub fn policy(&self) -> HostAllocationPolicy {
        self.policy
    }

    pub fn reserved_size(&self) -> usize {
        self.memory.size()
    }

    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), AdapterError> {
        self.memory.write(offset, bytes)?;
        Ok(())
    }

    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), AdapterError> {
        self.memory.read(offset, output)?;
        Ok(())
    }

    pub fn commit(&mut self, offset: usize, size: usize) -> Result<(), AdapterError> {
        self.memory.map(offset, size)?;
        Ok(())
    }

    pub fn decommit(&mut self, offset: usize, size: usize) -> Result<(), AdapterError> {
        self.memory.unmap(offset, size)?;
        Ok(())
    }

    pub fn release(self) -> Result<(), AdapterError> {
        self.memory.release()?;
        Ok(())
    }
}

/// Create a host allocation for an XMem request using an explicit policy.
/// This deliberately does not infer reserve/commit behavior from Xbox flags.
pub fn create_host_allocation(
    request: XMemVirtualAllocRequest,
    policy: HostAllocationPolicy,
) -> Result<XMemHostAllocation, AdapterError> {
    request.validate().map_err(AdapterError::InvalidRequest)?;

    if request.requested_address != 0 {
        return Err(AdapterError::RequestedAddressNotSupported);
    }

    let requested_size =
        usize::try_from(request.size).map_err(|_| AdapterError::SizeDoesNotFitHost)?;

    let mut memory = HostVirtualMemory::reserve(requested_size)?;

    if policy == HostAllocationPolicy::ReserveAndCommitReadWrite {
        let committed_size = memory.size();
        // Host backend requires page-aligned ranges. Reservation is rounded
        // to the host page size, so commit the complete rounded reservation.
        debug_assert_eq!(committed_size % HOST_PAGE_SIZE, 0);
        memory.map(0, committed_size)?;
    }

    Ok(XMemHostAllocation {
        request,
        policy,
        memory,
    })
}

pub fn print_adapter_report() {
    println!("\n=== PHOENIX: XMEM -> HOST ALLOCATION ADAPTER ===");
    println!("Accepts observed XMem request records with an explicit host policy.");
    println!("Policies: reserve-only or reserve-and-commit read/write.");
    println!("Rejects non-null requested addresses; fixed-address support is not implemented.");
    println!("Xbox flags are preserved but not interpreted or translated.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmem_virtual_alloc::{
        FIXED_20_MIB_REQUEST, GRAPHICS_INIT_REQUEST,
    };

    #[test]
    fn creates_and_uses_explicitly_committed_graphics_request() {
        let mut allocation = create_host_allocation(
            GRAPHICS_INIT_REQUEST,
            HostAllocationPolicy::ReserveAndCommitReadWrite,
        ).unwrap();

        assert_eq!(allocation.reserved_size(), 0x10000);
        assert_eq!(allocation.request(), GRAPHICS_INIT_REQUEST);

        allocation.write(0x100, b"Phoenix").unwrap();
        let mut output = [0u8; 7];
        allocation.read(0x100, &mut output).unwrap();
        assert_eq!(&output, b"Phoenix");

        allocation.release().unwrap();
    }

    #[test]
    fn reserve_only_policy_requires_explicit_commit_before_access() {
        let mut allocation = create_host_allocation(
            FIXED_20_MIB_REQUEST,
            HostAllocationPolicy::ReserveOnly,
        ).unwrap();

        let mut byte = [0u8; 1];
        assert!(matches!(allocation.read(0, &mut byte), Err(AdapterError::Host(VmError::NotCommitted))));

        allocation.commit(0, HOST_PAGE_SIZE).unwrap();
        allocation.write(0, b"X").unwrap();
        allocation.read(0, &mut byte).unwrap();
        assert_eq!(byte[0], b'X');

        allocation.decommit(0, HOST_PAGE_SIZE).unwrap();
        allocation.release().unwrap();
    }

    #[test]
    fn rejects_non_null_requested_address_instead_of_ignoring_it() {
        let request = XMemVirtualAllocRequest::new(
            0x100000,
            0x1000,
            0x2000,
            0,
            4,
        );
        assert_eq!(
            create_host_allocation(request, HostAllocationPolicy::ReserveOnly)
                .err(),
            Some(AdapterError::RequestedAddressNotSupported)
        );
    }

    #[test]
    fn rejects_zero_sized_request_before_host_allocation() {
        let request = XMemVirtualAllocRequest::new(0, 0, 0, 0, 0);
        assert_eq!(
            create_host_allocation(request, HostAllocationPolicy::ReserveOnly).err(),
            Some(AdapterError::InvalidRequest(RequestError::ZeroSize))
        );
    }
}
