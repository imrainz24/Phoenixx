//! Safe guest-call marshalling for the verified XMem x64 call shapes.
//!
//! This decodes a captured x64 call frame into typed Phoenix requests. Guest
//! pointers are accessed only through GuestMemory; they are never cast to host
//! pointers. Page-size and zero-address placement are explicit Phoenix policy.
//! This is a marshaller, not a machine-code thunk or an exported Xbox DLL ABI.

use crate::import_dispatch_registry::ImportDispatchRegistry;
use crate::xmem_dispatch_bridge::{XMemCall, XMemCallResult, XMemDispatchBridge, XMemDispatchError};
use crate::xmem_model_v3::PageSize;
use crate::xmem_virtual_alloc::XMemVirtualAllocRequest;
use std::fmt;

pub trait GuestMemory {
    fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), GuestMemoryError>;
    fn write_guest(&mut self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestMemoryError {
    NullPointer,
    AddressOverflow,
    UnmappedOrOutOfRange { address: u64, length: usize },
}

impl fmt::Display for GuestMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for GuestMemoryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X64CallFrame {
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    /// Stack arguments beginning at the fifth argument (the caller has
    /// already accounted for the x64 return address and shadow space).
    pub stack_args: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XMemAbiPolicy {
    pub virtual_page_size: PageSize,
    pub physical_page_size: PageSize,
    /// Phoenix-selected base for null-address XMemVirtualAlloc calls.
    pub null_virtual_alloc_base: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemAbiError {
    MissingFifthArgument,
    NullPointer,
    GuestMemory(GuestMemoryError),
    Dispatch(XMemDispatchError),
    InvalidPageCount,
    PageArrayTooLarge,
    UnexpectedDispatchResult,
}
impl From<GuestMemoryError> for XMemAbiError {
    fn from(value: GuestMemoryError) -> Self { Self::GuestMemory(value) }
}
impl From<XMemDispatchError> for XMemAbiError {
    fn from(value: XMemDispatchError) -> Self { Self::Dispatch(value) }
}
impl fmt::Display for XMemAbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for XMemAbiError {}

pub struct XMemGuestAbi<M: GuestMemory> {
    memory: M,
    policy: XMemAbiPolicy,
}

impl<M: GuestMemory> XMemGuestAbi<M> {
    pub fn new(memory: M, policy: XMemAbiPolicy) -> Self { Self { memory, policy } }
    pub fn memory(&self) -> &M { &self.memory }
    pub fn memory_mut(&mut self) -> &mut M { &mut self.memory }
    pub fn into_memory(self) -> M { self.memory }

    /// Decode XMemVirtualAlloc(address,size,allocationFlags,memoryType,protectionFlags).
    /// Returns the selected guest address on success; errors represent ABI failure.
    pub fn virtual_alloc(
        &mut self,
        bridge: &mut XMemDispatchBridge,
        registry: &ImportDispatchRegistry,
        frame: X64CallFrame,
    ) -> Result<u64, XMemAbiError> {
        let protection = *frame.stack_args.first().ok_or(XMemAbiError::MissingFifthArgument)?;
        let selected_base = if frame.rcx == 0 {
            self.policy.null_virtual_alloc_base
        } else {
            frame.rcx
        };
        let request = XMemVirtualAllocRequest::new(
            frame.rcx,
            frame.rdx,
            frame.r8 as u32,
            frame.r9 as u32,
            protection as u32,
        );
        match bridge.invoke(registry, "xmem.dll", "XMemVirtualAlloc",
            XMemCall::VirtualAlloc {
                request,
                guest_base: selected_base,
                page_size: self.policy.virtual_page_size,
            })? {
            XMemCallResult::VirtualAllocation(info) => Ok(info.guest_base as u64),
            _ => Err(XMemAbiError::UnexpectedDispatchResult),
        }
    }

    /// Decode XMemAllocatePhysicalPages(flags, inoutPageCount, outPages).
    /// The public sample's in/out count and page array are 64-bit ULONG_PTRs.
    pub fn allocate_physical_pages(
        &mut self,
        bridge: &mut XMemDispatchBridge,
        registry: &ImportDispatchRegistry,
        frame: X64CallFrame,
    ) -> Result<bool, XMemAbiError> {
        if frame.rdx == 0 || frame.r8 == 0 { return Err(XMemAbiError::NullPointer); }
        let requested = self.read_u64(frame.rdx)?;
        let requested = usize::try_from(requested).map_err(|_| XMemAbiError::InvalidPageCount)?;
        if requested == 0 { return Err(XMemAbiError::InvalidPageCount); }

        let result = bridge.invoke(registry, "xmem.dll", "XMemAllocatePhysicalPages",
            XMemCall::AllocatePhysicalPages {
                raw_flags: usize::try_from(frame.rcx).map_err(|_| XMemAbiError::InvalidPageCount)?,
                page_count: requested,
                page_size: self.policy.physical_page_size,
            })?;
        let pages = match result {
            XMemCallResult::PhysicalPages(pages) => pages,
            _ => return Err(XMemAbiError::UnexpectedDispatchResult),
        };
        // Write the page array first. If either guest write fails, release the
        // just-created allocation so a bad guest pointer cannot leak pages.
        if let Err(error) = self.write_page_ids(frame.r8, &pages.page_ids) {
            let _ = bridge.invoke(registry, "xmem.dll", "XMemFreePhysicalPages",
                XMemCall::FreePhysicalPages {
                    page_count: pages.page_count,
                    page_ids: pages.page_ids,
                });
            return Err(error);
        }
        if let Err(error) = self.write_u64(frame.rdx, pages.page_count as u64) {
            let _ = self.write_page_ids(frame.r8, &vec![0; pages.page_count]);
            let _ = bridge.invoke(registry, "xmem.dll", "XMemFreePhysicalPages",
                XMemCall::FreePhysicalPages {
                    page_count: pages.page_count,
                    page_ids: pages.page_ids,
                });
            return Err(error);
        }
        Ok(true)
    }

    /// Decode XMemFreePhysicalPages(pageCount, pages).
    pub fn free_physical_pages(
        &mut self,
        bridge: &mut XMemDispatchBridge,
        registry: &ImportDispatchRegistry,
        frame: X64CallFrame,
    ) -> Result<bool, XMemAbiError> {
        let count = usize::try_from(frame.rcx).map_err(|_| XMemAbiError::InvalidPageCount)?;
        if count == 0 { return Err(XMemAbiError::InvalidPageCount); }
        let page_ids = self.read_page_ids(frame.rdx, count)?;
        bridge.invoke(registry, "xmem.dll", "XMemFreePhysicalPages",
            XMemCall::FreePhysicalPages { page_count: count, page_ids })?;
        Ok(true)
    }

    /// Decode XMemMapPhysicalPages(baseAddress,pageCount,pageArray).
    /// A null pageArray requests unmapping, matching the sampled call pattern.
    pub fn map_physical_pages(
        &mut self,
        bridge: &mut XMemDispatchBridge,
        registry: &ImportDispatchRegistry,
        frame: X64CallFrame,
    ) -> Result<u64, XMemAbiError> {
        let count = usize::try_from(frame.rdx).map_err(|_| XMemAbiError::InvalidPageCount)?;
        if count == 0 { return Err(XMemAbiError::InvalidPageCount); }
        let page_ids = if frame.r8 == 0 {
            None
        } else {
            Some(self.read_page_ids(frame.r8, count)?)
        };
        bridge.invoke(registry, "xmem.dll", "XMemMapPhysicalPages",
            XMemCall::MapPhysicalPages {
                guest_base: usize::try_from(frame.rcx).map_err(|_| XMemAbiError::InvalidPageCount)?,
                page_count: count,
                page_ids,
            })?;
        Ok(frame.rcx)
    }

    fn read_u64(&self, address: u64) -> Result<u64, XMemAbiError> {
        if address == 0 { return Err(XMemAbiError::NullPointer); }
        let mut bytes = [0u8; 8];
        self.memory.read_guest(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), XMemAbiError> {
        if address == 0 { return Err(XMemAbiError::NullPointer); }
        self.memory.write_guest(address, &value.to_le_bytes())?;
        Ok(())
    }

    fn read_page_ids(&self, address: u64, count: usize) -> Result<Vec<usize>, XMemAbiError> {
        if address == 0 { return Err(XMemAbiError::NullPointer); }
        let byte_count = count.checked_mul(8).ok_or(XMemAbiError::PageArrayTooLarge)?;
        if byte_count > 16 * 1024 * 1024 { return Err(XMemAbiError::PageArrayTooLarge); }
        let mut bytes = vec![0u8; byte_count];
        self.memory.read_guest(address, &mut bytes)?;
        bytes.chunks_exact(8).map(|chunk| {
            let value = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
            usize::try_from(value).map_err(|_| XMemAbiError::PageArrayTooLarge)
        }).collect()
    }

    fn write_page_ids(&mut self, address: u64, ids: &[usize]) -> Result<(), XMemAbiError> {
        if address == 0 { return Err(XMemAbiError::NullPointer); }
        let byte_count = ids.len().checked_mul(8).ok_or(XMemAbiError::PageArrayTooLarge)?;
        if byte_count > 16 * 1024 * 1024 { return Err(XMemAbiError::PageArrayTooLarge); }
        let mut bytes = Vec::with_capacity(byte_count);
        for id in ids {
            bytes.extend_from_slice(&u64::try_from(*id)
                .map_err(|_| XMemAbiError::PageArrayTooLarge)?.to_le_bytes());
        }
        self.memory.write_guest(address, &bytes)?;
        Ok(())
    }
}

pub fn print_guest_abi_report() {
    println!("\n=== PHOENIX XMEM GUEST ABI MARSHALLER ===");
    println!("Decodes captured x64 argument registers and fifth stack argument.");
    println!("Reads/writes guest pointers only through a checked GuestMemory interface.");
    println!("Page size and null-address placement remain explicit Phoenix policy.");
    println!("Not yet a machine-code thunk, DLL export, or executable IAT patch.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iat_binding_plan::{BindingStatus, IatBinding, IatBindingPlan, BindingSymbol};
    use crate::import_dispatch_registry::ImportDispatchRegistry;
    use std::collections::BTreeMap;

    struct TestMemory { bytes: BTreeMap<u64, u8>, deny_write_at: Option<u64> }
    impl Default for TestMemory { fn default() -> Self { Self { bytes: BTreeMap::new(), deny_write_at: None } } }
    impl GuestMemory for TestMemory {
        fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), GuestMemoryError> {
            let end = address.checked_add(output.len() as u64)
                .ok_or(GuestMemoryError::AddressOverflow)?;
            let output_len = output.len();
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = *self.bytes.get(&(address + i as u64))
                    .ok_or(GuestMemoryError::UnmappedOrOutOfRange {
                        address,
                        length: output_len,
                    })?;
            }
            let _ = end;
            Ok(())
        }
        fn write_guest(&mut self, address: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
            address.checked_add(bytes.len() as u64).ok_or(GuestMemoryError::AddressOverflow)?;
            for (i, byte) in bytes.iter().enumerate() {
                if self.deny_write_at == Some(address) { return Err(GuestMemoryError::UnmappedOrOutOfRange { address, length: bytes.len() }); }
                self.bytes.insert(address + i as u64, *byte);
            }
            Ok(())
        }
    }

    fn registry() -> ImportDispatchRegistry {
        let names = [
            "XMemVirtualAlloc", "XMemAllocatePhysicalPages",
            "XMemFreePhysicalPages", "XMemMapPhysicalPages",
        ];
        let bindings = names.iter().enumerate().map(|(i, name)| IatBinding {
            module: "xmem.dll".into(),
            symbol: BindingSymbol::Name((*name).into()),
            iat_rva: 0x1200 + (i as u32) * 8,
            status: BindingStatus::Unresolved,
        }).collect::<Vec<_>>();
        let plan = IatBindingPlan {
            guest_base: 0x1_4000_0000,
            image_size: 0x4000,
            resolved_count: 0,
            unresolved_count: bindings.len(),
            bindings,
        };
        let mut registry = ImportDispatchRegistry::from_binding_plan(&plan).unwrap();
        registry.bind_xmem_compatibility();
        registry
    }

    fn frame(rcx: u64, rdx: u64, r8: u64, r9: u64, fifth: u64) -> X64CallFrame {
        X64CallFrame { rcx, rdx, r8, r9, stack_args: vec![fifth] }
    }

    #[test]
    fn marshals_five_argument_virtual_alloc_and_returns_guest_address() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let memory = TestMemory::default();
        let policy = XMemAbiPolicy {
            virtual_page_size: PageSize::KiB64,
            physical_page_size: PageSize::KiB64,
            null_virtual_alloc_base: 0x1_0000_0000,
        };
        let mut abi = XMemGuestAbi::new(memory, policy);
        let result = abi.virtual_alloc(&mut bridge, &registry,
            frame(0, 0x10000, 0x20401000, 0x283, 0x42404)).unwrap();
        assert_eq!(result, 0x1_0000_0000);
    }

    #[test]
    fn marshals_physical_page_allocate_map_unmap_and_free_with_guest_arrays() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, &2u64.to_le_bytes()).unwrap();
        let policy = XMemAbiPolicy {
            virtual_page_size: PageSize::KiB64,
            physical_page_size: PageSize::KiB64,
            null_virtual_alloc_base: 0x1_0000_0000,
        };
        let mut abi = XMemGuestAbi::new(memory, policy);
        assert!(abi.allocate_physical_pages(&mut bridge, &registry,
            frame(0x280, 0x1000, 0x2000, 0, 0)).unwrap());
        let mut page_bytes = [0u8; 16];
        abi.memory().read_guest(0x2000, &mut page_bytes).unwrap();
        let first = u64::from_le_bytes(page_bytes[0..8].try_into().unwrap());
        let second = u64::from_le_bytes(page_bytes[8..16].try_into().unwrap());
        assert_ne!(first, second);

        abi.map_physical_pages(&mut bridge, &registry,
            frame(0x300_0000, 2, 0x2000, 0, 0)).unwrap();
        abi.map_physical_pages(&mut bridge, &registry,
            frame(0x300_0000, 2, 0, 0, 0)).unwrap();
        abi.free_physical_pages(&mut bridge, &registry,
            frame(2, 0x2000, 0, 0, 0)).unwrap();
    }

    #[test]
    fn rejects_unmapped_guest_pointer_without_host_pointer_dereference() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let policy = XMemAbiPolicy {
            virtual_page_size: PageSize::KiB64,
            physical_page_size: PageSize::KiB64,
            null_virtual_alloc_base: 0x1_0000_0000,
        };
        let mut abi = XMemGuestAbi::new(TestMemory::default(), policy);
        assert!(matches!(
            abi.allocate_physical_pages(&mut bridge, &registry,
                frame(0x280, 0xDEAD, 0x2000, 0, 0)),
            Err(XMemAbiError::GuestMemory(GuestMemoryError::UnmappedOrOutOfRange { .. }))
        ));
    }

    #[test]
    fn rejects_missing_fifth_argument_and_null_required_pointers() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let policy = XMemAbiPolicy {
            virtual_page_size: PageSize::KiB64,
            physical_page_size: PageSize::KiB64,
            null_virtual_alloc_base: 0x1_0000_0000,
        };
        let mut abi = XMemGuestAbi::new(TestMemory::default(), policy);
        let mut no_fifth = frame(0, 0x10000, 0x20401000, 0x283, 0);
        no_fifth.stack_args = Vec::new();
        assert_eq!(abi.virtual_alloc(&mut bridge, &registry, no_fifth),
            Err(XMemAbiError::MissingFifthArgument));
        assert_eq!(abi.allocate_physical_pages(&mut bridge, &registry,
            frame(0x280, 0, 0x2000, 0, 0)), Err(XMemAbiError::NullPointer));
    }

    #[test]
    fn rejects_oversized_page_arrays_before_allocation_or_copy() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let policy = XMemAbiPolicy {
            virtual_page_size: PageSize::KiB64,
            physical_page_size: PageSize::KiB64,
            null_virtual_alloc_base: 0x1_0000_0000,
        };
        let mut abi = XMemGuestAbi::new(TestMemory::default(), policy);
        assert_eq!(abi.free_physical_pages(&mut bridge, &registry,
            frame((16 * 1024 * 1024 / 8 + 1) as u64, 0x1000, 0, 0, 0)),
            Err(XMemAbiError::PageArrayTooLarge));
    }
    #[test]
    fn failed_page_array_output_rolls_back_physical_allocation() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let mut memory = TestMemory::default();
        memory.write_guest(0x1000, &2u64.to_le_bytes()).unwrap();
        memory.deny_write_at = Some(0x2000);
        let policy = XMemAbiPolicy {
            virtual_page_size: PageSize::KiB64,
            physical_page_size: PageSize::KiB64,
            null_virtual_alloc_base: 0x1_0000_0000,
        };
        let mut abi = XMemGuestAbi::new(memory, policy);
        assert!(abi.allocate_physical_pages(&mut bridge, &registry,
            frame(0x280, 0x1000, 0x2000, 0, 0)).is_err());
        // A subsequent allocation receives a fresh synthetic token and succeeds,
        // proving the failed output path released the first allocation.
        abi.memory_mut().deny_write_at = None;
        let result = abi.allocate_physical_pages(&mut bridge, &registry,
            frame(0x280, 0x1000, 0x2000, 0, 0)).unwrap();
        assert!(result);
    }

}
