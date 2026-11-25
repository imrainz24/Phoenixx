//! Typed XMem dispatch-call bridge.
//!
//! This is an internal Phoenix call boundary: it accepts typed Rust requests,
//! checks that the selected registry route matches the requested operation,
//! and forwards to XMemCompatibilityRuntime. It is NOT an Xbox ABI thunk,
//! does not dereference guest pointers, and does not patch the executable IAT.

use crate::import_dispatch_registry::{DispatchTarget, ImportDispatchRegistry, XMemHandler};
use crate::xmem_compat_runtime::{XMemCompatibilityRuntime, XMemRuntimeError};
use crate::xmem_model_v3::PageSize;
use crate::xmem_physical_page_abi::PhysicalPagesResult;
use crate::xmem_virtual_alloc::{XMemVirtualAllocRequest};
use crate::xmem_virtual_alloc_abi::{VirtualAllocationInfo, VirtualAllocationHandle};
use crate::iat_binding_plan::BindingSymbol;
use crate::import_dispatch_registry::GuestImportId;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemCall {
    VirtualAlloc {
        request: XMemVirtualAllocRequest,
        guest_base: u64,
        page_size: PageSize,
    },
    AllocatePhysicalPages {
        raw_flags: usize,
        page_count: usize,
        page_size: PageSize,
    },
    FreePhysicalPages {
        page_count: usize,
        page_ids: Vec<usize>,
    },
    MapPhysicalPages {
        guest_base: usize,
        page_count: usize,
        page_ids: Option<Vec<usize>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemCallResult {
    VirtualAllocation(VirtualAllocationInfo),
    PhysicalPages(PhysicalPagesResult),
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XMemDispatchError {
    ImportNotFound,
    NotXMemCompatibilityRoute,
    HandlerCallMismatch { expected: XMemHandler },
    Runtime(XMemRuntimeError),
}

impl From<XMemRuntimeError> for XMemDispatchError {
    fn from(value: XMemRuntimeError) -> Self { Self::Runtime(value) }
}
impl fmt::Display for XMemDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}
impl std::error::Error for XMemDispatchError {}

pub struct XMemDispatchBridge {
    runtime: XMemCompatibilityRuntime,
}

impl Default for XMemDispatchBridge {
    fn default() -> Self { Self::new() }
}

impl XMemDispatchBridge {
    pub fn new() -> Self { Self { runtime: XMemCompatibilityRuntime::new() } }

    pub fn invoke(
        &mut self,
        registry: &ImportDispatchRegistry,
        module: &str,
        symbol: &str,
        call: XMemCall,
    ) -> Result<XMemCallResult, XMemDispatchError> {
        let id = GuestImportId {
            module: module.to_ascii_lowercase(),
            symbol: BindingSymbol::Name(symbol.to_owned()),
        };
        let entry = registry.get(&id).ok_or(XMemDispatchError::ImportNotFound)?;
        let handler = match &entry.target {
            DispatchTarget::XMemCompatibility(handler) => *handler,
            _ => return Err(XMemDispatchError::NotXMemCompatibilityRoute),
        };

        match (handler, call) {
            (XMemHandler::VirtualAlloc, XMemCall::VirtualAlloc {
                request, guest_base, page_size,
            }) => {
                let info = self.runtime.virtual_allocate(request, guest_base, page_size)?;
                Ok(XMemCallResult::VirtualAllocation(info))
            }
            (XMemHandler::AllocatePhysicalPages, XMemCall::AllocatePhysicalPages {
                raw_flags, page_count, page_size,
            }) => {
                let result = self.runtime.allocate_physical_pages(raw_flags, page_count, page_size)?;
                Ok(XMemCallResult::PhysicalPages(result))
            }
            (XMemHandler::FreePhysicalPages, XMemCall::FreePhysicalPages {
                page_count, page_ids,
            }) => {
                self.runtime.free_physical_pages(page_count, &page_ids)?;
                Ok(XMemCallResult::Completed)
            }
            (XMemHandler::MapPhysicalPages, XMemCall::MapPhysicalPages {
                guest_base, page_count, page_ids: Some(page_ids),
            }) => {
                self.runtime.map_physical_pages(guest_base, page_count, &page_ids)?;
                Ok(XMemCallResult::Completed)
            }
            (XMemHandler::MapPhysicalPages, XMemCall::MapPhysicalPages {
                guest_base, page_count, page_ids: None,
            }) => {
                self.runtime.unmap_physical_pages(guest_base, page_count)?;
                Ok(XMemCallResult::Completed)
            }
            (expected, _) => Err(XMemDispatchError::HandlerCallMismatch { expected }),
        }
    }

    pub fn virtual_write(
        &mut self, handle: VirtualAllocationHandle, offset: usize, bytes: &[u8],
    ) -> Result<(), XMemDispatchError> {
        self.runtime.virtual_write(handle, offset, bytes)?;
        Ok(())
    }

    pub fn virtual_read(
        &self, handle: VirtualAllocationHandle, offset: usize, output: &mut [u8],
    ) -> Result<(), XMemDispatchError> {
        self.runtime.virtual_read(handle, offset, output)?;
        Ok(())
    }

    pub fn virtual_free(
        &mut self, handle: VirtualAllocationHandle,
    ) -> Result<(), XMemDispatchError> {
        self.runtime.virtual_free(handle)?;
        Ok(())
    }
}

pub fn print_dispatch_bridge_report() {
    println!("\n=== PHOENIX XMEM TYPED DISPATCH BRIDGE ===");
    println!("Routes typed internal calls from XMem import metadata into the software runtime.");
    println!("Checks import identity and handler/call agreement before dispatch.");
    println!("Does not implement raw Xbox ABI thunks, dereference guest pointers, or patch the IAT.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iat_binding_plan::{BindingSymbol, IatBinding, IatBindingPlan, BindingStatus};
    use crate::import_dispatch_registry::ImportDispatchRegistry;
    use crate::xmem_virtual_alloc::GRAPHICS_INIT_REQUEST;

    fn registry() -> ImportDispatchRegistry {
        let bindings = vec![
            ("xmem.dll", "XMemVirtualAlloc", 0x1200),
            ("xmem.dll", "XMemAllocatePhysicalPages", 0x1208),
            ("xmem.dll", "XMemFreePhysicalPages", 0x1210),
            ("xmem.dll", "XMemMapPhysicalPages", 0x1218),
            ("kernel32.dll", "ExitProcess", 0x1220),
        ].into_iter().map(|(module, name, iat_rva)| IatBinding {
            module: module.into(),
            symbol: BindingSymbol::Name(name.into()),
            iat_rva,
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

    #[test]
    fn invokes_virtual_alloc_route_and_supports_memory_access() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let result = bridge.invoke(&registry, "XMEM.DLL", "XMemVirtualAlloc",
            XMemCall::VirtualAlloc {
                request: GRAPHICS_INIT_REQUEST,
                guest_base: 0x1_0000_0000,
                page_size: PageSize::KiB64,
            }).unwrap();
        let info = match result {
            XMemCallResult::VirtualAllocation(info) => info,
            other => panic!("unexpected result: {other:?}"),
        };
        bridge.virtual_write(info.handle, 0x80, b"Phoenix").unwrap();
        let mut bytes = [0u8; 7];
        bridge.virtual_read(info.handle, 0x80, &mut bytes).unwrap();
        assert_eq!(&bytes, b"Phoenix");
        bridge.virtual_free(info.handle).unwrap();
    }

    #[test]
    fn invokes_physical_page_allocate_map_unmap_and_free_routes() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let allocated = bridge.invoke(&registry, "xmem.dll", "XMemAllocatePhysicalPages",
            XMemCall::AllocatePhysicalPages {
                raw_flags: 0x280, page_count: 2, page_size: PageSize::KiB64,
            }).unwrap();
        let pages = match allocated {
            XMemCallResult::PhysicalPages(pages) => pages,
            other => panic!("unexpected result: {other:?}"),
        };
        bridge.invoke(&registry, "xmem.dll", "XMemMapPhysicalPages",
            XMemCall::MapPhysicalPages {
                guest_base: 0x300_0000, page_count: 2, page_ids: Some(pages.page_ids.clone()),
            }).unwrap();
        bridge.invoke(&registry, "xmem.dll", "XMemMapPhysicalPages",
            XMemCall::MapPhysicalPages {
                guest_base: 0x300_0000, page_count: 2, page_ids: None,
            }).unwrap();
        bridge.invoke(&registry, "xmem.dll", "XMemFreePhysicalPages",
            XMemCall::FreePhysicalPages {
                page_count: 2, page_ids: pages.page_ids,
            }).unwrap();
    }

    #[test]
    fn rejects_call_that_does_not_match_registered_handler() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let result = bridge.invoke(&registry, "xmem.dll", "XMemVirtualAlloc",
            XMemCall::AllocatePhysicalPages {
                raw_flags: 0, page_count: 1, page_size: PageSize::KiB64,
            });
        assert_eq!(result, Err(XMemDispatchError::HandlerCallMismatch {
            expected: XMemHandler::VirtualAlloc,
        }));
    }

    #[test]
    fn refuses_unresolved_non_xmem_import() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        let result = bridge.invoke(&registry, "kernel32.dll", "ExitProcess",
            XMemCall::AllocatePhysicalPages {
                raw_flags: 0, page_count: 1, page_size: PageSize::KiB64,
            });
        assert_eq!(result, Err(XMemDispatchError::NotXMemCompatibilityRoute));
    }

    #[test]
    fn rejects_unknown_import_identity() {
        let registry = registry();
        let mut bridge = XMemDispatchBridge::new();
        assert_eq!(
            bridge.invoke(&registry, "xmem.dll", "XMemUnknown",
                XMemCall::AllocatePhysicalPages {
                    raw_flags: 0, page_count: 1, page_size: PageSize::KiB64,
                }),
            Err(XMemDispatchError::ImportNotFound)
        );
    }
}
