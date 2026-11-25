//! XMem ABI contract notes for Project Phoenix.
//!
//! Function-pointer shapes and flag usage below are transcribed from
//! Microsoft's Xbox GDK FSR3 frame-interpolation sample. These are contracts
//! only: this module does not export Xbox DLL symbols or invoke Xbox code.

use std::ffi::c_void;

pub type WinBool = i32;
pub type UlongPtr = usize;
pub type Dword = u32;
pub type SizeT = usize;
pub type Pvoid = *mut c_void;
pub type PULONG_PTR = *mut UlongPtr;

/// XMemAllocatePhysicalPages(flags, inoutPageCount, outPages) -> BOOL.
pub type XMemAllocatePhysicalPagesFn = unsafe extern "system" fn(
    flags: UlongPtr,
    inout_page_count: PULONG_PTR,
    out_pages: PULONG_PTR,
) -> WinBool;

/// XMemFreePhysicalPages(pageCount, pages) -> BOOL.
pub type XMemFreePhysicalPagesFn = unsafe extern "system" fn(
    page_count: u64,
    pages: PULONG_PTR,
) -> WinBool;

/// XMemMapPhysicalPages(baseAddress, pageCount, pageArray) -> mapped address.
/// Passing a null pageArray unmaps the range.
pub type XMemMapPhysicalPagesFn = unsafe extern "system" fn(
    base_address: Pvoid,
    page_count: u64,
    page_array: PULONG_PTR,
) -> Pvoid;

/// XMemVirtualAlloc(address, size, allocationFlags, memoryType, protectionFlags).
pub type XMemVirtualAllocFn = unsafe extern "system" fn(
    address: Pvoid,
    size: SizeT,
    allocation_flags: Dword,
    memory_type: Dword,
    protection_flags: Dword,
) -> Pvoid;

pub const PAGE_SIZE_64K: usize = 64 * 1024;
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct AbiEntry {
    pub name: &'static str,
    pub signature_status: &'static str,
    pub implementation_status: &'static str,
}

pub const VERIFIED_ENTRIES: [AbiEntry; 4] = [
    AbiEntry { name: "XMemAllocatePhysicalPages", signature_status: "signature and argument order shown in Microsoft GDK sample", implementation_status: "not implemented" },
    AbiEntry { name: "XMemFreePhysicalPages", signature_status: "signature and argument order shown in Microsoft GDK sample", implementation_status: "not implemented" },
    AbiEntry { name: "XMemMapPhysicalPages", signature_status: "signature and null-array unmap behavior shown in Microsoft GDK sample", implementation_status: "not implemented" },
    AbiEntry { name: "XMemVirtualAlloc", signature_status: "five-argument call and demonstrated flag combinations shown in Microsoft GDK sample", implementation_status: "not implemented" },
];

pub fn print_contract_report() {
    println!("\n=== PHOENIX XMEM ABI CONTRACT ===");
    println!("Verified public call shapes: {}", VERIFIED_ENTRIES.len());
    for entry in VERIFIED_ENTRIES {
        println!("{} — {}; {}", entry.name, entry.signature_status, entry.implementation_status);
    }
    println!("64 KiB page size: {PAGE_SIZE_64K:#x}");
    println!("2 MiB page size: {PAGE_SIZE_2M:#x}");
    println!("Sample allocation modes: MEM_64K_PAGES or XMEM_2MB_CLUSTERS");
    println!("Sample virtual allocation uses MEM_RESERVE | page-size flag and XMEM_GRAPHICS | XMEM_MAPPABLE");
    println!("XMemMapPhysicalPagesScatter and XMemAlloc/XMemFree remain unverified here.");
    println!("No Xbox ABI function is called or exported by this report.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_sizes_match_sampled_xbox_page_modes() {
        assert_eq!(PAGE_SIZE_64K, 0x1_0000);
        assert_eq!(PAGE_SIZE_2M, 0x20_0000);
    }

    #[test]
    fn verified_contract_covers_core_physical_mapping_calls() {
        let names: Vec<_> = VERIFIED_ENTRIES.iter().map(|entry| entry.name).collect();
        assert!(names.contains(&"XMemAllocatePhysicalPages"));
        assert!(names.contains(&"XMemFreePhysicalPages"));
        assert!(names.contains(&"XMemMapPhysicalPages"));
        assert!(names.contains(&"XMemVirtualAlloc"));
    }
}
