//! Structured IAT binding plan for Project Phoenix.
//!
//! This module joins parsed PE imports with externally supplied export-resolution
//! results and validates every destination slot. It deliberately does NOT write
//! addresses into the staged image or call imported functions.

use crate::pe_import_manifest::{ImportManifest, ImportSymbol};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BindingSymbol {
    Name(String),
    Ordinal(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExportKey {
    pub module: String,
    pub symbol: BindingSymbol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportResolution {
    pub key: ExportKey,
    /// Host address reported by a resolver. This is data only; never called here.
    pub host_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingStatus {
    Resolved { host_address: u64, guest_iat_address: u64 },
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatBinding {
    pub module: String,
    pub symbol: BindingSymbol,
    pub iat_rva: u32,
    pub status: BindingStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatBindingPlan {
    pub guest_base: u64,
    pub image_size: u32,
    pub bindings: Vec<IatBinding>,
    pub resolved_count: usize,
    pub unresolved_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingPlanError {
    ZeroImageSize,
    ImageEndOverflow,
    IatSlotOutsideImage { rva: u32 },
    GuestAddressOverflow { rva: u32 },
    DuplicateIatSlot { rva: u32 },
}

fn normalize_module(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn import_symbol(symbol: &ImportSymbol) -> BindingSymbol {
    match symbol {
        ImportSymbol::Name { name, .. } => BindingSymbol::Name(name.clone()),
        ImportSymbol::Ordinal(value) => BindingSymbol::Ordinal(*value),
    }
}

pub fn build_iat_binding_plan(
    manifest: &ImportManifest,
    resolutions: &[ExportResolution],
    guest_base: u64,
    image_size: u32,
) -> Result<IatBindingPlan, BindingPlanError> {
    if image_size == 0 {
        return Err(BindingPlanError::ZeroImageSize);
    }
    let image_end = guest_base.checked_add(image_size as u64)
        .ok_or(BindingPlanError::ImageEndOverflow)?;

    let mut lookup = std::collections::HashMap::new();
    for resolution in resolutions {
        lookup.insert(
            (normalize_module(&resolution.key.module), resolution.key.symbol.clone()),
            resolution.host_address,
        );
    }

    let mut seen_slots = std::collections::HashSet::new();
    let mut bindings = Vec::with_capacity(manifest.function_count);
    let mut resolved_count = 0usize;
    let mut unresolved_count = 0usize;

    for module in &manifest.modules {
        for function in &module.functions {
            let rva = function.iat_rva;
            let slot_end = rva.checked_add(8)
                .ok_or(BindingPlanError::IatSlotOutsideImage { rva })?;
            if slot_end > image_size {
                return Err(BindingPlanError::IatSlotOutsideImage { rva });
            }
            if !seen_slots.insert(rva) {
                return Err(BindingPlanError::DuplicateIatSlot { rva });
            }
            let guest_iat_address = guest_base.checked_add(rva as u64)
                .ok_or(BindingPlanError::GuestAddressOverflow { rva })?;
            let guest_slot_end = guest_iat_address.checked_add(8)
                .ok_or(BindingPlanError::GuestAddressOverflow { rva })?;
            if guest_slot_end > image_end {
                return Err(BindingPlanError::GuestAddressOverflow { rva });
            }

            let symbol = import_symbol(&function.symbol);
            let key = (normalize_module(&module.name), symbol.clone());
            let host_address = lookup.get(&key).copied().flatten();
            let status = match host_address {
                Some(address) if address != 0 => {
                    resolved_count += 1;
                    BindingStatus::Resolved {
                        host_address: address,
                        guest_iat_address,
                    }
                }
                _ => {
                    unresolved_count += 1;
                    BindingStatus::Unresolved
                }
            };
            bindings.push(IatBinding {
                module: module.name.clone(),
                symbol,
                iat_rva: rva,
                status,
            });
        }
    }

    Ok(IatBindingPlan {
        guest_base,
        image_size,
        bindings,
        resolved_count,
        unresolved_count,
    })
}

pub fn print_iat_binding_plan(plan: &IatBindingPlan) {
    println!("\n=== PHOENIX: IAT BINDING PLAN ===");
    println!("Import slots: {}", plan.bindings.len());
    println!("Resolved candidates: {}", plan.resolved_count);
    println!("Unresolved imports: {}", plan.unresolved_count);
    for binding in &plan.bindings {
        let symbol = match &binding.symbol {
            BindingSymbol::Name(name) => name.clone(),
            BindingSymbol::Ordinal(value) => format!("ordinal #{value}"),
        };
        match binding.status {
            BindingStatus::Resolved { host_address, guest_iat_address } => {
                println!(
                    "  {}!{} -> host {:#018x}; guest IAT {:#018x}",
                    binding.module, symbol, host_address, guest_iat_address
                );
            }
            BindingStatus::Unresolved => {
                println!("  {}!{} -> UNRESOLVED", binding.module, symbol);
            }
        }
    }
    println!("Safety: plan only; no IAT memory written; no imported function called.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_import_manifest::{
        ImportedFunction, ImportedModule, ImportManifest,
    };

    fn manifest() -> ImportManifest {
        ImportManifest {
            modules: vec![ImportedModule {
                name: "KERNEL32.DLL".into(),
                descriptor_rva: 0x1000,
                original_first_thunk_rva: 0x1100,
                first_thunk_rva: 0x1200,
                functions: vec![
                    ImportedFunction {
                        symbol: ImportSymbol::Name { hint: 0, name: "ExitProcess".into() },
                        lookup_rva: 0x1100,
                        iat_rva: 0x1200,
                    },
                    ImportedFunction {
                        symbol: ImportSymbol::Ordinal(17),
                        lookup_rva: 0x1108,
                        iat_rva: 0x1208,
                    },
                ],
            }],
            function_count: 2,
        }
    }

    #[test]
    fn builds_resolved_and_unresolved_bindings_without_writing_iat() {
        let resolutions = vec![ExportResolution {
            key: ExportKey {
                module: "kernel32.dll".into(),
                symbol: BindingSymbol::Name("ExitProcess".into()),
            },
            host_address: Some(0x7fff_1234_5678),
        }];
        let plan = build_iat_binding_plan(&manifest(), &resolutions, 0x1_4000_0000, 0x4000).unwrap();
        assert_eq!(plan.resolved_count, 1);
        assert_eq!(plan.unresolved_count, 1);
        assert_eq!(
            plan.bindings[0].status,
            BindingStatus::Resolved {
                host_address: 0x7fff_1234_5678,
                guest_iat_address: 0x1_4000_1200,
            }
        );
        assert_eq!(plan.bindings[1].status, BindingStatus::Unresolved);
    }

    #[test]
    fn rejects_iat_slot_outside_image() {
        let mut m = manifest();
        m.modules[0].functions[0].iat_rva = 0x4000;
        assert_eq!(
            build_iat_binding_plan(&m, &[], 0x1000, 0x4000),
            Err(BindingPlanError::IatSlotOutsideImage { rva: 0x4000 })
        );
    }

    #[test]
    fn rejects_duplicate_iat_slots() {
        let mut m = manifest();
        m.modules[0].functions[1].iat_rva = 0x1200;
        assert_eq!(
            build_iat_binding_plan(&m, &[], 0x1000, 0x4000),
            Err(BindingPlanError::DuplicateIatSlot { rva: 0x1200 })
        );
    }

    #[test]
    fn rejects_guest_address_overflow() {
        assert_eq!(
            build_iat_binding_plan(&manifest(), &[], u64::MAX - 0x1000, 0x4000),
            Err(BindingPlanError::ImageEndOverflow)
        );
    }

    #[test]
    fn rejects_zero_sized_image() {
        assert_eq!(
            build_iat_binding_plan(&manifest(), &[], 0x1000, 0),
            Err(BindingPlanError::ZeroImageSize)
        );
    }
}
