//! Explicit bridge from the observed XMemVirtualAlloc request shape to the
//! Phoenix software page runtime.
//!
//! Important: this module does NOT decode allocation_type, XALLOC_ATTRIBUTES,
//! or protection bits. The caller must supply a page size established by
//! independent evidence and a guest placement chosen by Phoenix's address
//! space manager. A zero requested address means the caller may choose the
//! placement; a nonzero requested address must match it exactly.

use crate::xmem_model_v3::PageSize;
use crate::xmem_page_runtime::{RegionInfo, RuntimeError, XMemPageRuntime};
use crate::xmem_virtual_alloc::{RequestError, XMemVirtualAllocRequest};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    InvalidRequest(RequestError),
    SizeDoesNotFitHost(u64),
    FixedAddressMismatch { requested: u64, selected: u64 },
    Runtime(RuntimeError),
}

impl From<RuntimeError> for BridgeError {
    fn from(value: RuntimeError) -> Self { Self::Runtime(value) }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BridgeError {}

/// Apply a validated request to the simulated page runtime.
///
/// `selected_guest_base` is a Phoenix-selected guest-relative address, not a
/// host pointer. `page_size` is explicit and is never inferred from raw flags.
pub fn allocate_request(
    runtime: &mut XMemPageRuntime,
    request: &XMemVirtualAllocRequest,
    selected_guest_base: u64,
    page_size: PageSize,
) -> Result<RegionInfo, BridgeError> {
    request.validate().map_err(BridgeError::InvalidRequest)?;

    if request.requested_address != 0 && request.requested_address != selected_guest_base {
        return Err(BridgeError::FixedAddressMismatch {
            requested: request.requested_address,
            selected: selected_guest_base,
        });
    }

    let base = usize::try_from(selected_guest_base)
        .map_err(|_| BridgeError::SizeDoesNotFitHost(selected_guest_base))?;
    let size = usize::try_from(request.size)
        .map_err(|_| BridgeError::SizeDoesNotFitHost(request.size))?;

    runtime.allocate_and_map(base, size, page_size).map_err(BridgeError::from)
}

pub fn print_bridge_report() {
    println!("\n=== PHOENIX: XMEM REQUEST BRIDGE ===");
    println!("Connects the five-field XMemVirtualAlloc request to the software page runtime.");
    println!("Page size and guest placement must be supplied explicitly by Phoenix.");
    println!("Raw allocation, attribute, and protection flags are preserved, never decoded here.");
    println!("A fixed requested address must match the selected guest address.");
    println!("This is a software model; it does not call Xbox APIs or allocate Xbox memory.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmem_virtual_alloc::{FIXED_20_MIB_REQUEST, GRAPHICS_INIT_REQUEST};

    #[test]
    fn bridges_graphics_request_when_page_mode_is_explicit() {
        let mut runtime = XMemPageRuntime::new();
        let info = allocate_request(
            &mut runtime,
            &GRAPHICS_INIT_REQUEST,
            0x10000,
            PageSize::KiB64,
        ).unwrap();
        assert_eq!(info.base, 0x10000);
        assert_eq!(info.size, 0x10000);
        assert_eq!(info.page_count, 1);
        runtime.unmap_and_free(info.id).unwrap();
        assert_eq!(runtime.allocated_page_count(), 0);
    }

    #[test]
    fn preserves_fixed_address_requirement() {
        let mut runtime = XMemPageRuntime::new();
        let request = XMemVirtualAllocRequest::new(0x40000, 0x10000, 0, 0, 0);
        let result = allocate_request(&mut runtime, &request, 0x50000, PageSize::KiB64);
        assert!(matches!(result, Err(BridgeError::FixedAddressMismatch { .. })));
        assert_eq!(runtime.allocated_page_count(), 0);
    }

    #[test]
    fn zero_address_uses_explicit_phoenix_placement_without_decoding_flags() {
        let mut runtime = XMemPageRuntime::new();
        let info = allocate_request(
            &mut runtime,
            &FIXED_20_MIB_REQUEST,
            0x20_0000,
            PageSize::MiB2,
        ).unwrap();
        assert_eq!(info.base, 0x20_0000);
        assert_eq!(info.page_count, 10);
        runtime.unmap_and_free(info.id).unwrap();
    }

    #[test]
    fn rejects_zero_size_before_allocating() {
        let mut runtime = XMemPageRuntime::new();
        let request = XMemVirtualAllocRequest::new(0, 0, 0, 0, 0);
        assert!(matches!(
            allocate_request(&mut runtime, &request, 0x10000, PageSize::KiB64),
            Err(BridgeError::InvalidRequest(RequestError::ZeroSize))
        ));
        assert_eq!(runtime.allocated_page_count(), 0);
    }
}
