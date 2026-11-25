//! Typed ABI boundary for XMemVirtualAlloc.
//!
//! Microsoft documents the Xbox XMem reference as NDA-gated. This module
//! therefore preserves the observed ABI fields without inventing meanings
//! for allocation flags, XALLOC_ATTRIBUTES bits, or protection values.
//! It is a request/validation layer only; it does not allocate host memory.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XMemVirtualAllocRequest {
    pub requested_address: u64,
    pub size: u64,
    pub allocation_type: u32,
    pub xalloc_attributes: u32,
    pub protection: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    ZeroSize,
}

impl XMemVirtualAllocRequest {
    /// Construct a request using the observed five-argument ABI order:
    /// address, size, allocation type, XALLOC_ATTRIBUTES, protection.
    pub const fn new(
        requested_address: u64,
        size: u64,
        allocation_type: u32,
        xalloc_attributes: u32,
        protection: u32,
    ) -> Self {
        Self {
            requested_address,
            size,
            allocation_type,
            xalloc_attributes,
            protection,
        }
    }

    /// Validate only facts we can safely assert without the NDA ABI details.
    pub const fn validate(&self) -> Result<(), RequestError> {
        if self.size == 0 {
            return Err(RequestError::ZeroSize);
        }
        Ok(())
    }
}

/// The exact request observed in the game's D3D12 Xbox device initialization.
pub const GRAPHICS_INIT_REQUEST: XMemVirtualAllocRequest =
    XMemVirtualAllocRequest::new(
        0,
        0x10000,
        0x20401000,
        0x283,
        0x42404,
    );

/// Fixed-size 20 MiB request observed in FUN_145ba6c10.
pub const FIXED_20_MIB_REQUEST: XMemVirtualAllocRequest =
    XMemVirtualAllocRequest::new(
        0,
        0x1400000,
        0x20403000,
        0x181,
        4,
    );

pub fn print_abi_report() {
    println!("\n=== PHOENIX: TYPED XMemVirtualAlloc ABI REQUESTS ===");
    println!("Argument order: address, size, allocation_type, XALLOC_ATTRIBUTES, protection.");
    for (label, request) in [
        ("Graphics initialization", GRAPHICS_INIT_REQUEST),
        ("Fixed 20 MiB allocation", FIXED_20_MIB_REQUEST),
    ] {
        println!(
            "  {}: address={:#x}, size={:#x}, alloc_type={:#x}, attrs={:#x}, protect={:#x}",
            label,
            request.requested_address,
            request.size,
            request.allocation_type,
            request.xalloc_attributes,
            request.protection
        );
        println!("    validation={:?}", request.validate());
    }
    println!("No host allocation performed; undocumented flag meanings remain opaque.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphics_request_preserves_all_five_arguments_in_abi_order() {
        assert_eq!(GRAPHICS_INIT_REQUEST.requested_address, 0);
        assert_eq!(GRAPHICS_INIT_REQUEST.size, 0x10000);
        assert_eq!(GRAPHICS_INIT_REQUEST.allocation_type, 0x20401000);
        assert_eq!(GRAPHICS_INIT_REQUEST.xalloc_attributes, 0x283);
        assert_eq!(GRAPHICS_INIT_REQUEST.protection, 0x42404);
        assert_eq!(GRAPHICS_INIT_REQUEST.validate(), Ok(()));
    }

    #[test]
    fn fixed_twenty_mib_request_preserves_all_five_arguments() {
        assert_eq!(FIXED_20_MIB_REQUEST.size, 0x1400000);
        assert_eq!(FIXED_20_MIB_REQUEST.allocation_type, 0x20403000);
        assert_eq!(FIXED_20_MIB_REQUEST.xalloc_attributes, 0x181);
        assert_eq!(FIXED_20_MIB_REQUEST.protection, 4);
    }

    #[test]
    fn rejects_zero_sized_requests_without_guessing_flag_semantics() {
        let request = XMemVirtualAllocRequest::new(0, 0, 0, 0, 0);
        assert_eq!(request.validate(), Err(RequestError::ZeroSize));
    }
}
