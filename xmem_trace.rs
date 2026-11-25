//! Reverse-engineering observations extracted from Ghidra for Project Phoenix.
//!
//! These are raw call-site facts, not guessed Xbox API semantics. In particular,
//! register values are recorded as observed immediately before a call; dynamic
//! register values are intentionally left as descriptions rather than invented.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualAllocObservation {
    pub call_site: u64,
    pub caller: &'static str,
    pub rcx: &'static str,
    pub rdx: &'static str,
    pub r8: &'static str,
    pub r9: &'static str,
    pub stack_arg5: &'static str,
}

pub const XMEM_VIRTUAL_ALLOC_OBSERVATIONS: [VirtualAllocObservation; 5] = [
    VirtualAllocObservation {
        call_site: 0x1424786b9,
        caller: "FUN_142478440",
        rcx: "0x0",
        rdx: "0x10000",
        r8: "0x20401000",
        r9: "0x283",
        stack_arg5: "0x42404",
    },
    VirtualAllocObservation {
        call_site: 0x141e6c1a6,
        caller: "FUN_141e6c110",
        rcx: "0x0",
        rdx: "RDI (runtime value)",
        r8: "0x20402000",
        r9: "0x21",
        stack_arg5: "0x4",
    },
    VirtualAllocObservation {
        call_site: 0x141e6c273,
        caller: "FUN_141e6c110",
        rcx: "0x0",
        rdx: "RDI (runtime value)",
        r8: "0x20402000",
        r9: "0x23",
        stack_arg5: "0x801",
    },
    VirtualAllocObservation {
        call_site: 0x141e8659e,
        caller: "FUN_141e86440",
        rcx: "0x0",
        rdx: "RSI (runtime value)",
        r8: "0x42000",
        r9: "0x7",
        stack_arg5: "0x1",
    },
    VirtualAllocObservation {
        call_site: 0x141e865d0,
        caller: "FUN_141e86440",
        rcx: "RBP-0x8 (runtime value)",
        rdx: "R14 (runtime value)",
        r8: "0x20406000",
        r9: "0x27",
        stack_arg5: "0x1004",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalPageObservation {
    pub call_site: u64,
    pub caller: &'static str,
    pub flags_register: &'static str,
    pub flags_value: u32,
}

pub const XMEM_PHYSICAL_PAGE_OBSERVATIONS: [PhysicalPageObservation; 4] = [
    PhysicalPageObservation {
        call_site: 0x142216493,
        caller: "FUN_1422163d0",
        flags_register: "ECX",
        flags_value: 0x180,
    },
    PhysicalPageObservation {
        call_site: 0x141e6c22d,
        caller: "FUN_141e6c110",
        flags_register: "ECX",
        flags_value: 0x380,
    },
    PhysicalPageObservation {
        call_site: 0x141e866e4,
        caller: "FUN_141e86440",
        flags_register: "ECX",
        flags_value: 0x280,
    },
    PhysicalPageObservation {
        call_site: 0x145eb27a7,
        caller: "FUN_145eb2780",
        flags_register: "ECX",
        flags_value: 0x280,
    },
];

pub fn print_observation_report() {
    println!("\n=== PHOENIX: EXECUTABLE-DERIVED XMEM CALL OBSERVATIONS ===");
    println!("Source: Ghidra cross-references from game_scarlett_master.exe");
    println!("These are raw observations; flag meanings and complete prototypes are not inferred here.");

    println!("\nXMemVirtualAlloc call sites:");
    for item in XMEM_VIRTUAL_ALLOC_OBSERVATIONS {
        println!(
            "  {:#x} in {} | RCX={} RDX={} R8={} R9={} stack[+0x20]={}",
            item.call_site, item.caller, item.rcx, item.rdx, item.r8, item.r9, item.stack_arg5
        );
    }

    println!("\nXMemAllocatePhysicalPages call sites:");
    for item in XMEM_PHYSICAL_PAGE_OBSERVATIONS {
        println!(
            "  {:#x} in {} | {}={:#x}",
            item.call_site, item.caller, item.flags_register, item.flags_value
        );
    }

    println!("\nImportant: this report records call-site evidence only.");
    println!("It does not yet implement XMemVirtualAlloc or XMemAllocatePhysicalPages.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_the_confirmed_graphics_initialization_virtual_alloc_call() {
        let call = XMEM_VIRTUAL_ALLOC_OBSERVATIONS
            .iter()
            .find(|item| item.call_site == 0x1424786b9)
            .unwrap();

        assert_eq!(call.caller, "FUN_142478440");
        assert_eq!(call.rcx, "0x0");
        assert_eq!(call.rdx, "0x10000");
        assert_eq!(call.r8, "0x20401000");
        assert_eq!(call.r9, "0x283");
        assert_eq!(call.stack_arg5, "0x42404");
    }

    #[test]
    fn records_physical_page_allocation_flag_values_without_guessing_meanings() {
        let values: Vec<u32> = XMEM_PHYSICAL_PAGE_OBSERVATIONS
            .iter()
            .map(|item| item.flags_value)
            .collect();

        assert_eq!(values, vec![0x180, 0x380, 0x280, 0x280]);
    }
}
