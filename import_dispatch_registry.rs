//! Import dispatch registry model for Project Phoenix.
//!
//! Keeps guest import identities separate from host function addresses. This is
//! metadata only: it does not call host APIs or patch the guest IAT.

use std::collections::HashMap;

use crate::iat_binding_plan::{BindingSymbol, IatBindingPlan, BindingStatus};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuestImportId {
    pub module: String,
    pub symbol: BindingSymbol,
}

/// Typed route identifiers for XMem operations implemented by Phoenix's
/// software runtime. These are metadata routes, not callable Xbox ABI exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XMemHandler {
    VirtualAlloc,
    AllocatePhysicalPages,
    FreePhysicalPages,
    MapPhysicalPages,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTarget {
    HostAddress(u64),
    XMemCompatibility(XMemHandler),
    CompatibilityStubRequired,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XMemBindingSummary {
    pub bound: usize,
    pub unsupported_xmem: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchEntry {
    pub id: GuestImportId,
    pub iat_rva: u32,
    pub target: DispatchTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDispatchRegistry {
    entries: Vec<DispatchEntry>,
    by_id: HashMap<GuestImportId, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    DuplicateImport(GuestImportId),
    MissingBindingForImport(GuestImportId),
}

impl ImportDispatchRegistry {
    pub fn from_binding_plan(plan: &IatBindingPlan) -> Result<Self, RegistryError> {
        let mut entries = Vec::with_capacity(plan.bindings.len());
        let mut by_id = HashMap::with_capacity(plan.bindings.len());

        for binding in &plan.bindings {
            let id = GuestImportId {
                module: binding.module.to_ascii_lowercase(),
                symbol: binding.symbol.clone(),
            };
            if by_id.contains_key(&id) {
                return Err(RegistryError::DuplicateImport(id));
            }
            let target = match binding.status {
                BindingStatus::Resolved { host_address, .. } => {
                    DispatchTarget::HostAddress(host_address)
                }
                BindingStatus::Unresolved => DispatchTarget::Unresolved,
            };
            let index = entries.len();
            by_id.insert(id.clone(), index);
            entries.push(DispatchEntry { id, iat_rva: binding.iat_rva, target });
        }

        Ok(Self { entries, by_id })
    }

    pub fn entries(&self) -> &[DispatchEntry] {
        &self.entries
    }

    pub fn get(&self, id: &GuestImportId) -> Option<&DispatchEntry> {
        self.by_id.get(id).and_then(|index| self.entries.get(*index))
    }

    /// Bind only the XMem imports for which Phoenix currently has a matching
    /// software-runtime operation. Unknown XMem exports remain unresolved.
    /// This changes dispatch metadata only; it does not invoke or patch anything.
    pub fn bind_xmem_compatibility(&mut self) -> XMemBindingSummary {
        let mut summary = XMemBindingSummary::default();
        for entry in &mut self.entries {
            if entry.id.module != "xmem.dll" {
                continue;
            }
            let handler = match &entry.id.symbol {
                BindingSymbol::Name(name) if name.eq_ignore_ascii_case("XMemVirtualAlloc") =>
                    Some(XMemHandler::VirtualAlloc),
                BindingSymbol::Name(name) if name.eq_ignore_ascii_case("XMemAllocatePhysicalPages") =>
                    Some(XMemHandler::AllocatePhysicalPages),
                BindingSymbol::Name(name) if name.eq_ignore_ascii_case("XMemFreePhysicalPages") =>
                    Some(XMemHandler::FreePhysicalPages),
                BindingSymbol::Name(name) if name.eq_ignore_ascii_case("XMemMapPhysicalPages") =>
                    Some(XMemHandler::MapPhysicalPages),
                _ => None,
            };
            match handler {
                Some(handler) => {
                    entry.target = DispatchTarget::XMemCompatibility(handler);
                    summary.bound += 1;
                }
                None => summary.unsupported_xmem += 1,
            }
        }
        summary
    }

    pub fn mark_compatibility_stub_required(
        &mut self,
        id: &GuestImportId,
    ) -> Result<(), RegistryError> {
        let index = self.by_id.get(id).copied()
            .ok_or_else(|| RegistryError::MissingBindingForImport(id.clone()))?;
        self.entries[index].target = DispatchTarget::CompatibilityStubRequired;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iat_binding_plan::{IatBinding, IatBindingPlan};

    fn plan() -> IatBindingPlan {
        IatBindingPlan {
            guest_base: 0x1_4000_0000,
            image_size: 0x4000,
            bindings: vec![
                IatBinding {
                    module: "KERNEL32.DLL".into(),
                    symbol: BindingSymbol::Name("ExitProcess".into()),
                    iat_rva: 0x1200,
                    status: BindingStatus::Resolved {
                        host_address: 0x7fff_1234_5678,
                        guest_iat_address: 0x1_4000_1200,
                    },
                },
                IatBinding {
                    module: "d3d12_xs.dll".into(),
                    symbol: BindingSymbol::Name("D3D12XboxCreateDevice".into()),
                    iat_rva: 0x1208,
                    status: BindingStatus::Unresolved,
                },
            ],
            resolved_count: 1,
            unresolved_count: 1,
        }
    }

    #[test]
    fn creates_registry_with_separate_host_and_guest_imports() {
        let registry = ImportDispatchRegistry::from_binding_plan(&plan()).unwrap();
        assert_eq!(registry.entries().len(), 2);
        assert_eq!(
            registry.entries()[0].target,
            DispatchTarget::HostAddress(0x7fff_1234_5678)
        );
        assert_eq!(registry.entries()[1].target, DispatchTarget::Unresolved);
    }

    #[test]
    fn looks_up_import_case_insensitively_by_normalized_module() {
        let registry = ImportDispatchRegistry::from_binding_plan(&plan()).unwrap();
        let id = GuestImportId {
            module: "kernel32.dll".into(),
            symbol: BindingSymbol::Name("ExitProcess".into()),
        };
        assert!(registry.get(&id).is_some());
    }

    #[test]
    fn can_mark_xbox_import_as_compatibility_stub_required() {
        let mut registry = ImportDispatchRegistry::from_binding_plan(&plan()).unwrap();
        let id = GuestImportId {
            module: "d3d12_xs.dll".into(),
            symbol: BindingSymbol::Name("D3D12XboxCreateDevice".into()),
        };
        registry.mark_compatibility_stub_required(&id).unwrap();
        assert_eq!(
            registry.get(&id).unwrap().target,
            DispatchTarget::CompatibilityStubRequired
        );
    }

    #[test]
    fn rejects_duplicate_import_identity() {
        let mut p = plan();
        p.bindings.push(p.bindings[0].clone());
        assert!(matches!(
            ImportDispatchRegistry::from_binding_plan(&p),
            Err(RegistryError::DuplicateImport(_))
        ));
    }

    #[test]
    fn rejects_marking_unknown_import() {
        let mut registry = ImportDispatchRegistry::from_binding_plan(&plan()).unwrap();
        let id = GuestImportId {
            module: "missing.dll".into(),
            symbol: BindingSymbol::Ordinal(1),
        };
        assert_eq!(
            registry.mark_compatibility_stub_required(&id),
            Err(RegistryError::MissingBindingForImport(id))
        );
    }
    #[test]
    fn binds_only_supported_xmem_imports_to_typed_runtime_routes() {
        let mut p = plan();
        p.bindings = vec![
            IatBinding {
                module: "XMEM.DLL".into(),
                symbol: BindingSymbol::Name("XMemVirtualAlloc".into()),
                iat_rva: 0x1300,
                status: BindingStatus::Unresolved,
            },
            IatBinding {
                module: "xmem.dll".into(),
                symbol: BindingSymbol::Name("XMemAllocatePhysicalPages".into()),
                iat_rva: 0x1308,
                status: BindingStatus::Unresolved,
            },
            IatBinding {
                module: "xmem.dll".into(),
                symbol: BindingSymbol::Name("XMemFreePhysicalPages".into()),
                iat_rva: 0x1310,
                status: BindingStatus::Unresolved,
            },
            IatBinding {
                module: "xmem.dll".into(),
                symbol: BindingSymbol::Name("XMemMapPhysicalPages".into()),
                iat_rva: 0x1318,
                status: BindingStatus::Unresolved,
            },
            IatBinding {
                module: "xmem.dll".into(),
                symbol: BindingSymbol::Name("XMemTransferMemory".into()),
                iat_rva: 0x1320,
                status: BindingStatus::Unresolved,
            },
            IatBinding {
                module: "d3d12_xs.dll".into(),
                symbol: BindingSymbol::Name("D3D12XboxCreateDevice".into()),
                iat_rva: 0x1328,
                status: BindingStatus::Unresolved,
            },
        ];
        p.resolved_count = 0;
        p.unresolved_count = p.bindings.len();
        let mut registry = ImportDispatchRegistry::from_binding_plan(&p).unwrap();
        let summary = registry.bind_xmem_compatibility();
        assert_eq!(summary.bound, 4);
        assert_eq!(summary.unsupported_xmem, 1);
        assert_eq!(registry.entries()[0].target,
            DispatchTarget::XMemCompatibility(XMemHandler::VirtualAlloc));
        assert_eq!(registry.entries()[1].target,
            DispatchTarget::XMemCompatibility(XMemHandler::AllocatePhysicalPages));
        assert_eq!(registry.entries()[2].target,
            DispatchTarget::XMemCompatibility(XMemHandler::FreePhysicalPages));
        assert_eq!(registry.entries()[3].target,
            DispatchTarget::XMemCompatibility(XMemHandler::MapPhysicalPages));
        assert_eq!(registry.entries()[4].target, DispatchTarget::Unresolved);
        assert_eq!(registry.entries()[5].target, DispatchTarget::Unresolved);
    }

    #[test]
    fn xmem_binding_does_not_override_resolved_windows_imports() {
        let mut registry = ImportDispatchRegistry::from_binding_plan(&plan()).unwrap();
        let summary = registry.bind_xmem_compatibility();
        assert_eq!(summary.bound, 0);
        assert_eq!(registry.entries()[0].target,
            DispatchTarget::HostAddress(0x7fff_1234_5678));
    }

}
