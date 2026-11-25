//! XMemVirtualAlloc call profiles recovered from Ghidra.
//!
//! Argument order is corroborated against Microsoft's Xbox GDK sample:
//!   (address, size, allocation_type, XALLOC_ATTRIBUTES, protection)
//! The raw values below are preserved exactly. Attribute/protection bit
//! meanings are not expanded unless independently documented.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XMemCallProfile {
    pub caller: &'static str,
    pub size_expression: &'static str,
    pub allocation_type: u32,
    pub xalloc_attributes: u32,
    pub protection: u32,
    pub purpose_hint: &'static str,
}

pub const CALL_PROFILES: [XMemCallProfile; 9] = [
    XMemCallProfile {
        caller: "FUN_141d6e620",
        size_expression: "param_1 (runtime)",
        allocation_type: 0x20403000, xalloc_attributes: 0x181, protection: 4,
        purpose_hint: "required region; optionally allocates a second region with the same settings",
    },
    XMemCallProfile {
        caller: "FUN_141e1cf60",
        size_expression: "lVar8 (runtime, derived after D3D12ConfigureVirtualMemoryX)",
        allocation_type: 0x20402000, xalloc_attributes: 0x21, protection: 4,
        purpose_hint: "first of two virtual-memory regions configured during initialization",
    },
    XMemCallProfile {
        caller: "FUN_141e1cf60",
        size_expression: "DAT_1471bf980 (same size as first region)",
        allocation_type: 0x20402000, xalloc_attributes: 3, protection: 0x801,
        purpose_hint: "second region paired with the first initialization allocation",
    },
    XMemCallProfile {
        caller: "FUN_141e1cf60",
        size_expression: "lVar1 (runtime)",
        allocation_type: 0x20003000, xalloc_attributes: 0x183, protection: 0x22004,
        purpose_hint: "repeated resource allocation in initialization switch cases 0, 4, and 5",
    },
    XMemCallProfile {
        caller: "FUN_141e1cf60",
        size_expression: "lVar1 (runtime)",
        allocation_type: 0x20003000, xalloc_attributes: 0x283, protection: 0x2404,
        purpose_hint: "resource allocation in initialization switch case 2",
    },
    XMemCallProfile {
        caller: "FUN_145eb1fa0",
        size_expression: "param_1 (runtime)",
        allocation_type: 0x20402000, xalloc_attributes: 0x23, protection: 0x2404,
        purpose_hint: "single required allocation",
    },
    XMemCallProfile {
        caller: "FUN_145ba6c10",
        size_expression: "0x1400000 (20 MiB)",
        allocation_type: 0x20403000, xalloc_attributes: 0x181, protection: 4,
        purpose_hint: "fixed-size allocation followed by initialization",
    },
    XMemCallProfile {
        caller: "FUN_142478440",
        size_expression: "0x10000 (64 KiB)",
        allocation_type: 0x20401000, xalloc_attributes: 0x283, protection: 0x42404,
        purpose_hint: "allocation during D3D12 Xbox device initialization",
    },
    XMemCallProfile {
        caller: "FUN_141e6c110",
        size_expression: "RDI (runtime)",
        allocation_type: 0x20402000, xalloc_attributes: 0x21, protection: 4,
        purpose_hint: "runtime allocation; companion call uses attributes 0x23 and protection 0x801",
    },
];

pub fn print_usage_report() {
    println!("\n=== PHOENIX: XMEM USAGE PROFILES FROM DECOMPILED CALLERS ===");
    println!("Argument order: address, size, allocation_type, XALLOC_ATTRIBUTES, protection.");
    println!("Raw values are preserved; no undocumented bit meanings are assumed.");
    for p in CALL_PROFILES {
        println!(
            "  {} | size={} | alloc_type={:#010x} | attrs={:#x} | protect={:#x}",
            p.caller, p.size_expression, p.allocation_type, p.xalloc_attributes, p.protection
        );
        println!("    observed use: {}", p.purpose_hint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_the_graphics_initialization_arguments_in_abi_order() {
        assert!(CALL_PROFILES.iter().any(|p|
            p.caller == "FUN_142478440"
            && p.size_expression == "0x10000 (64 KiB)"
            && p.allocation_type == 0x20401000
            && p.xalloc_attributes == 0x283
            && p.protection == 0x42404
        ));
    }

    #[test]
    fn records_fixed_twenty_mib_allocation_in_abi_order() {
        assert!(CALL_PROFILES.iter().any(|p|
            p.caller == "FUN_145ba6c10"
            && p.allocation_type == 0x20403000
            && p.xalloc_attributes == 0x181
            && p.protection == 4
        ));
    }
}
