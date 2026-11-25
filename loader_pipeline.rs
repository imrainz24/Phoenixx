//! Integrated PE loading preparation pipeline for Project Phoenix.
//!
//! Connects PE staging, import parsing, IAT binding planning, and dispatch
//! registry construction and a transactional, allowlisted patch of resolved
//! Windows IAT entries in staged guest memory. It never calls imports, runs TLS
//! callbacks, invokes DllMain, or executes the game's entry point.

use crate::iat_binding_plan::{
    build_iat_binding_plan, ExportResolution, IatBindingPlan, BindingPlanError,
};
use crate::import_dispatch_registry::{
    ImportDispatchRegistry, RegistryError,
};
use crate::pe_image_stager::{
    PeImageStager, PeMapError, PeMappedImage,
};
use crate::pe_import_manifest::{
    parse_import_manifest, ImportManifest, ImportParseError,
};

#[derive(Debug)]
pub enum LoaderPipelineError {
    Stage(PeMapError),
    Imports(ImportParseError),
    BindingPlan(BindingPlanError),
    Registry(RegistryError),
    GuestBaseNotRepresentable,
}

impl From<PeMapError> for LoaderPipelineError {
    fn from(value: PeMapError) -> Self { Self::Stage(value) }
}
impl From<ImportParseError> for LoaderPipelineError {
    fn from(value: ImportParseError) -> Self { Self::Imports(value) }
}
impl From<BindingPlanError> for LoaderPipelineError {
    fn from(value: BindingPlanError) -> Self { Self::BindingPlan(value) }
}
impl From<RegistryError> for LoaderPipelineError {
    fn from(value: RegistryError) -> Self { Self::Registry(value) }
}

/// Failure while writing resolved Windows exports into the staged guest IAT.
/// The patcher is data-only: it never calls these addresses or executes the image.
#[derive(Debug)]
pub enum IatPatchError {
    ResolvedNonWindowsModule { module: String },
    ZeroHostAddress { rva: u32 },
    AddressOverflow { rva: u32 },
    Read { rva: u32, source: PeMapError },
    Write { rva: u32, source: PeMapError },
    Rollback { rva: u32, source: PeMapError },
}

fn is_supported_windows_module(module: &str) -> bool {
    let name = module.to_ascii_lowercase();
    if name.starts_with("api-ms-win-") || name.starts_with("ext-ms-win-") {
        return true;
    }
    matches!(name.as_str(),
        "kernel32.dll" | "kernelbase.dll" | "ntdll.dll" | "user32.dll" |
        "gdi32.dll" | "advapi32.dll" | "ws2_32.dll" | "winhttp.dll" |
        "bcrypt.dll" | "mfplat.dll" | "mfreadwrite.dll" | "ole32.dll" |
        "oleaut32.dll" | "msvcp140.dll" | "vcruntime140.dll" |
        "vcruntime140_1.dll" | "ucrtbase.dll" | "sechost.dll" |
        "combase.dll" | "rpcrt4.dll" | "shlwapi.dll" | "version.dll" |
        "setupapi.dll" | "cfgmgr32.dll" | "imm32.dll" | "winmm.dll"
    )
}

pub struct PreparedPeImage {
    pub mapped: PeMappedImage,
    pub imports: ImportManifest,
    pub bindings: IatBindingPlan,
    pub dispatch: ImportDispatchRegistry,
    stager: PeImageStager,
}

impl PreparedPeImage {
    /// Read bytes from the staged guest image. This is inspection access only.
    pub fn read_guest(&self, address: usize, output: &mut [u8]) -> Result<(), PeMapError> {
        self.stager.read_guest(address, output)
    }


    /// Patch only resolved imports from an explicit Windows-module allowlist.
    /// All original slots are snapshotted first; on a write failure, prior
    /// writes are rolled back. Xbox and middleware imports remain untouched.
    /// This writes only Phoenix's staged guest-memory backing, never the EXE file.
    pub fn patch_windows_iat(&mut self) -> Result<usize, IatPatchError> {
        let mut patches: Vec<(u32, usize, [u8; 8], [u8; 8])> = Vec::new();
        for binding in &self.bindings.bindings {
            let host_address = match &binding.status {
                crate::iat_binding_plan::BindingStatus::Resolved { host_address, .. } => *host_address,
                crate::iat_binding_plan::BindingStatus::Unresolved => continue,
            };
            if !is_supported_windows_module(&binding.module) {
                return Err(IatPatchError::ResolvedNonWindowsModule { module: binding.module.clone() });
            }
            if host_address == 0 {
                return Err(IatPatchError::ZeroHostAddress { rva: binding.iat_rva });
            }
            let address = self.mapped.guest_base.checked_add(binding.iat_rva as usize)
                .ok_or(IatPatchError::AddressOverflow { rva: binding.iat_rva })?;
            let mut original = [0u8; 8];
            self.stager.read_guest(address, &mut original)
                .map_err(|source| IatPatchError::Read { rva: binding.iat_rva, source })?;
            patches.push((binding.iat_rva, address, original, host_address.to_le_bytes()));
        }

        let mut applied = 0usize;
        for (rva, address, original, replacement) in &patches {
            if let Err(source) = self.stager.write_guest(*address, replacement) {
                // Restore the failed slot too, in case a backend ever reports
                // an error after a partial write, then restore earlier slots.
                if let Err(rollback_source) = self.stager.write_guest(*address, original) {
                    return Err(IatPatchError::Rollback { rva: *rva, source: rollback_source });
                }
                for (rollback_rva, rollback_address, rollback_original, _) in patches[..applied].iter().rev() {
                    if let Err(rollback_source) = self.stager.write_guest(*rollback_address, rollback_original) {
                        return Err(IatPatchError::Rollback { rva: *rollback_rva, source: rollback_source });
                    }
                }
                return Err(IatPatchError::Write { rva: *rva, source });
            }
            applied += 1;
        }
        Ok(applied)
    }

    /// Explicitly release the staged image.
    pub fn unload(mut self) -> Result<(), PeMapError> {
        self.stager.unload()
    }
}

/// Stage a PE32+ image and connect its imports to supplied host-export results.
///
/// `resolutions` must contain only export addresses independently validated by
/// the caller. Missing entries remain unresolved. This function never writes
/// those addresses into the image's IAT.
pub fn prepare_pe_image(
    file: &[u8],
    guest_base: usize,
    resolutions: &[ExportResolution],
) -> Result<PreparedPeImage, LoaderPipelineError> {
    let mut stager = PeImageStager::new();
    let mapped = stager.map_pe32_plus_at(file, guest_base)?;

    let prepared: Result<PreparedPeImage, LoaderPipelineError> = (|| {
        let imports = parse_import_manifest(file)?;
        let (bindings, dispatch) = build_import_state(&imports, mapped, resolutions)?;

        Ok(PreparedPeImage {
            mapped,
            imports,
            bindings,
            dispatch,
            stager: PeImageStager::new(),
        })
    })();

    match prepared {
        Ok(mut result) => {
            // Transfer the actual staged image owner into the returned object.
            result.stager = stager;
            Ok(result)
        }
        Err(error) => {
            let _ = stager.unload();
            Err(error)
        }
    }
}


/// Build the import-binding and dispatch layers for an already staged image.
/// Kept separate so the integration boundary can be tested without allocating
/// host virtual memory.
pub fn build_import_state(
    imports: &ImportManifest,
    mapped: PeMappedImage,
    resolutions: &[ExportResolution],
) -> Result<(IatBindingPlan, ImportDispatchRegistry), LoaderPipelineError> {
    let guest_base = u64::try_from(mapped.guest_base)
        .map_err(|_| LoaderPipelineError::GuestBaseNotRepresentable)?;
    // PE32+ SizeOfImage is a u32; the stager preserves that value.
    let image_size = mapped.size as u32;
    let bindings = build_iat_binding_plan(imports, resolutions, guest_base, image_size)?;
    let mut dispatch = ImportDispatchRegistry::from_binding_plan(&bindings)?;
    // Register known XMem compatibility routes in the dispatch metadata.
    // This does not call handlers or write guest IAT slots.
    dispatch.bind_xmem_compatibility();
    Ok((bindings, dispatch))
}

pub fn print_pipeline_summary(prepared: &PreparedPeImage) {
    println!("\n=== PHOENIX: INTEGRATED PE PREPARATION ===");
    println!("Guest image base: {:#x}", prepared.mapped.guest_base);
    println!("Image size: {:#x}", prepared.mapped.size);
    println!("Entry point address (not executed): {:#x}", prepared.mapped.entry_point);
    println!("Sections staged: {}", prepared.mapped.section_count);
    println!("DIR64 relocations applied: {}", prepared.mapped.relocation_count);
    println!("Imported DLLs: {}", prepared.imports.modules.len());
    println!("Imported functions: {}", prepared.imports.function_count);
    println!("Resolved export candidates: {}", prepared.bindings.resolved_count);
    println!("Unresolved imports: {}", prepared.bindings.unresolved_count);
    println!("Dispatch entries: {}", prepared.dispatch.entries().len());
    let xmem_routes = prepared.dispatch.entries().iter()
        .filter(|entry| matches!(
            entry.target,
            crate::import_dispatch_registry::DispatchTarget::XMemCompatibility(_)
        )).count();
    println!("XMem compatibility routes registered: {}", xmem_routes);
    println!("Safety: resolved Windows IAT slots may be patched in staged guest memory only; no imports are called; entry point not executed.");
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::iat_binding_plan::{BindingSymbol, ExportKey};
    use crate::pe_import_manifest::{ImportedFunction, ImportedModule, ImportSymbol};

    fn sample_imports() -> ImportManifest {
        ImportManifest {
            modules: vec![ImportedModule {
                name: "kernel32.dll".into(),
                descriptor_rva: 0x1000,
                original_first_thunk_rva: 0x1100,
                first_thunk_rva: 0x1200,
                functions: vec![ImportedFunction {
                    symbol: ImportSymbol::Name { hint: 0, name: "ExitProcess".into() },
                    lookup_rva: 0x1100,
                    iat_rva: 0x1200,
                }],
            }],
            function_count: 1,
        }
    }

    fn sample_mapped() -> PeMappedImage {
        PeMappedImage {
            guest_base: 0x1_4000_0000usize,
            size: 0x4000,
            entry_point: 0x1_4000_1000usize,
            section_count: 5,
            relocation_count: 12,
        }
    }

    #[test]
    fn connects_import_manifest_to_binding_plan_and_dispatch_registry() {
        let exports = vec![ExportResolution {
            key: ExportKey {
                module: "KERNEL32.DLL".into(),
                symbol: BindingSymbol::Name("ExitProcess".into()),
            },
            host_address: Some(0x7fff_1234_5678),
        }];
        let (plan, dispatch) = build_import_state(&sample_imports(), sample_mapped(), &exports).unwrap();
        assert_eq!(plan.resolved_count, 1);
        assert_eq!(plan.unresolved_count, 0);
        assert_eq!(dispatch.entries().len(), 1);
        assert_eq!(
            dispatch.entries()[0].target,
            crate::import_dispatch_registry::DispatchTarget::HostAddress(0x7fff_1234_5678)
        );
    }

    #[test]
    fn leaves_missing_platform_exports_unresolved_in_dispatch_registry() {
        let (plan, dispatch) = build_import_state(&sample_imports(), sample_mapped(), &[]).unwrap();
        assert_eq!(plan.resolved_count, 0);
        assert_eq!(plan.unresolved_count, 1);
        assert_eq!(
            dispatch.entries()[0].target,
            crate::import_dispatch_registry::DispatchTarget::Unresolved
        );
    }

    #[test]
    fn rejects_iat_slots_outside_the_staged_image() {
        let mut imports = sample_imports();
        imports.modules[0].functions[0].iat_rva = 0x4000;
        assert!(matches!(
            build_import_state(&imports, sample_mapped(), &[]),
            Err(LoaderPipelineError::BindingPlan(BindingPlanError::IatSlotOutsideImage { rva: 0x4000 }))
        ));
    }
    #[test]
    fn build_import_state_registers_known_xmem_handlers() {
        let imports = ImportManifest {
            modules: vec![ImportedModule {
                name: "xmem.dll".into(),
                descriptor_rva: 0x1000,
                original_first_thunk_rva: 0x1100,
                first_thunk_rva: 0x1200,
                functions: vec![
                    ImportedFunction {
                        symbol: ImportSymbol::Name { hint: 0, name: "XMemVirtualAlloc".into() },
                        lookup_rva: 0x1100,
                        iat_rva: 0x1200,
                    },
                    ImportedFunction {
                        symbol: ImportSymbol::Name { hint: 0, name: "XMemAllocatePhysicalPages".into() },
                        lookup_rva: 0x1108,
                        iat_rva: 0x1208,
                    },
                    ImportedFunction {
                        symbol: ImportSymbol::Name { hint: 0, name: "XMemTransferMemory".into() },
                        lookup_rva: 0x1110,
                        iat_rva: 0x1210,
                    },
                ],
            }],
            function_count: 3,
        };
        let (_, dispatch) = build_import_state(&imports, sample_mapped(), &[]).unwrap();
        use crate::import_dispatch_registry::{DispatchTarget, XMemHandler};
        assert_eq!(dispatch.entries()[0].target,
            DispatchTarget::XMemCompatibility(XMemHandler::VirtualAlloc));
        assert_eq!(dispatch.entries()[1].target,
            DispatchTarget::XMemCompatibility(XMemHandler::AllocatePhysicalPages));
        assert_eq!(dispatch.entries()[2].target, DispatchTarget::Unresolved);
    }


    #[test]
    fn windows_module_allowlist_excludes_xbox_and_middleware() {
        assert!(is_supported_windows_module("KERNEL32.DLL"));
        assert!(is_supported_windows_module("api-ms-win-core-file-l1-1-0.dll"));
        assert!(!is_supported_windows_module("xmem.dll"));
        assert!(!is_supported_windows_module("d3d12_xs.dll"));
        assert!(!is_supported_windows_module("Bink2Scarlett.dll"));
    }

}
