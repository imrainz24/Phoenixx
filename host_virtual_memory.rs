//! Host-side virtual-memory arena for Project Phoenix.
//!
//! On Windows this uses VirtualAlloc/VirtualFree to reserve, commit, and
//! decommit real host virtual memory. On other platforms it uses a Vec-backed
//! test implementation with identical range/commit validation.
//!
//! This is NOT yet an Xbox XMem implementation: Xbox allocation flags,
//! physical-page semantics, and XALLOC_ATTRIBUTES are deliberately not mapped
//! onto Windows flags here.

use std::fmt;

pub const HOST_PAGE_SIZE: usize = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    ZeroSize,
    SizeOverflow,
    OffsetOutOfRange,
    SizeOutOfRange,
    UnalignedRange,
    NotCommitted,
    AlreadyMapped,
    AlreadyReleased,
    HostReserveFailed,
    HostCommitFailed,
    HostDecommitFailed,
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VmError {}

fn round_up_to_page(size: usize) -> Result<usize, VmError> {
    if size == 0 {
        return Err(VmError::ZeroSize);
    }
    size.checked_add(HOST_PAGE_SIZE - 1)
        .map(|n| n & !(HOST_PAGE_SIZE - 1))
        .ok_or(VmError::SizeOverflow)
}

#[cfg(windows)]
mod host {
    use std::ffi::c_void;

    pub const MEM_COMMIT: u32 = 0x1000;
    pub const MEM_RESERVE: u32 = 0x2000;
    pub const MEM_DECOMMIT: u32 = 0x4000;
    pub const MEM_RELEASE: u32 = 0x8000;
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READWRITE: u32 = 0x04;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn VirtualAlloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protect: u32,
        ) -> *mut c_void;

        pub fn VirtualFree(address: *mut c_void, size: usize, free_type: u32) -> i32;
    }
}

pub struct HostVirtualMemory {
    size: usize,
    committed_pages: Vec<bool>,
    released: bool,
    #[cfg(windows)]
    base: std::ptr::NonNull<u8>,
    #[cfg(not(windows))]
    storage: Vec<u8>,
}

impl HostVirtualMemory {
    /// Reserve a host virtual-address range. The size is rounded up to 4 KiB.
    pub fn reserve(requested_size: usize) -> Result<Self, VmError> {
        let size = round_up_to_page(requested_size)?;
        let page_count = size / HOST_PAGE_SIZE;

        #[cfg(windows)]
        {
            use std::ffi::c_void;
            let raw = unsafe {
                host::VirtualAlloc(
                    std::ptr::null_mut(),
                    size,
                    host::MEM_RESERVE,
                    host::PAGE_NOACCESS,
                )
            };
            let base = std::ptr::NonNull::new(raw.cast::<u8>())
                .ok_or(VmError::HostReserveFailed)?;
            Ok(Self {
                size,
                committed_pages: vec![false; page_count],
                released: false,
                base,
            })
        }

        #[cfg(not(windows))]
        {
            Ok(Self {
                size,
                committed_pages: vec![false; page_count],
                released: false,
                storage: vec![0u8; size],
            })
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn validate_page_range(&self, offset: usize, size: usize) -> Result<(usize, usize), VmError> {
        if self.released {
            return Err(VmError::AlreadyReleased);
        }
        if size == 0 {
            return Err(VmError::ZeroSize);
        }
        if offset % HOST_PAGE_SIZE != 0 || size % HOST_PAGE_SIZE != 0 {
            return Err(VmError::UnalignedRange);
        }
        let end = offset.checked_add(size).ok_or(VmError::SizeOverflow)?;
        if end > self.size {
            return Err(VmError::SizeOutOfRange);
        }
        Ok((offset / HOST_PAGE_SIZE, end / HOST_PAGE_SIZE))
    }

    /// Commit a page-aligned subrange as read/write host memory.
    pub fn map(&mut self, offset: usize, size: usize) -> Result<(), VmError> {
        let (first, end) = self.validate_page_range(offset, size)?;
        if self.committed_pages[first..end].iter().any(|v| *v) {
            return Err(VmError::AlreadyMapped);
        }

        #[cfg(windows)]
        {
            let address = unsafe { self.base.as_ptr().add(offset) };
            let result = unsafe {
                host::VirtualAlloc(
                    address.cast(),
                    size,
                    host::MEM_COMMIT,
                    host::PAGE_READWRITE,
                )
            };
            if result.is_null() {
                return Err(VmError::HostCommitFailed);
            }
        }

        #[cfg(not(windows))]
        {
            self.storage[offset..offset + size].fill(0);
        }

        self.committed_pages[first..end].fill(true);
        Ok(())
    }

    /// Decommit a previously committed page-aligned subrange.
    pub fn unmap(&mut self, offset: usize, size: usize) -> Result<(), VmError> {
        let (first, end) = self.validate_page_range(offset, size)?;
        if self.committed_pages[first..end].iter().any(|v| !*v) {
            return Err(VmError::NotCommitted);
        }

        #[cfg(windows)]
        {
            let address = unsafe { self.base.as_ptr().add(offset) };
            let result = unsafe {
                host::VirtualFree(address.cast(), size, host::MEM_DECOMMIT)
            };
            if result == 0 {
                return Err(VmError::HostDecommitFailed);
            }
        }

        #[cfg(not(windows))]
        {
            self.storage[offset..offset + size].fill(0);
        }

        self.committed_pages[first..end].fill(false);
        Ok(())
    }

    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), VmError> {
        self.validate_access(offset, data.len())?;
        #[cfg(windows)]
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.base.as_ptr().add(offset),
                data.len(),
            );
        }
        #[cfg(not(windows))]
        {
            self.storage[offset..offset + data.len()].copy_from_slice(data);
        }
        Ok(())
    }

    pub fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), VmError> {
        self.validate_access(offset, output.len())?;
        #[cfg(windows)]
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.base.as_ptr().add(offset),
                output.as_mut_ptr(),
                output.len(),
            );
        }
        #[cfg(not(windows))]
        {
            output.copy_from_slice(&self.storage[offset..offset + output.len()]);
        }
        Ok(())
    }

    fn validate_access(&self, offset: usize, length: usize) -> Result<(), VmError> {
        if self.released {
            return Err(VmError::AlreadyReleased);
        }
        if length == 0 {
            return if offset <= self.size { Ok(()) } else { Err(VmError::SizeOutOfRange) };
        }
        let end = offset.checked_add(length).ok_or(VmError::SizeOverflow)?;
        if end > self.size {
            return Err(VmError::SizeOutOfRange);
        }
        let first_page = offset / HOST_PAGE_SIZE;
        let last_page = (end - 1) / HOST_PAGE_SIZE;
        if self.committed_pages[first_page..=last_page].iter().any(|v| !*v) {
            return Err(VmError::NotCommitted);
        }
        Ok(())
    }

    /// Explicitly release the complete reserved range.
    pub fn release(mut self) -> Result<(), VmError> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<(), VmError> {
        if self.released {
            return Err(VmError::AlreadyReleased);
        }
        #[cfg(windows)]
        {
            let result = unsafe {
                host::VirtualFree(self.base.as_ptr().cast(), 0, host::MEM_RELEASE)
            };
            if result == 0 {
                return Err(VmError::HostDecommitFailed);
            }
        }
        #[cfg(not(windows))]
        {
            self.storage.clear();
        }
        self.committed_pages.clear();
        self.released = true;
        Ok(())
    }
}

impl Drop for HostVirtualMemory {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.release_inner();
        }
    }
}

pub fn print_backend_report() {
    println!("\n=== PHOENIX: HOST VIRTUAL-MEMORY BACKEND ===");
    println!("Host page size: {:#x}", HOST_PAGE_SIZE);
    #[cfg(windows)]
    println!("Backend: Windows VirtualAlloc / VirtualFree");
    #[cfg(not(windows))]
    println!("Backend: Vec-backed portable test implementation");
    println!("Operations: reserve, map/commit, read, write, unmap/decommit, release");
    println!("Xbox XMem flags are not translated by this host backend.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_commit_write_read_decommit_and_release() {
        let mut memory = HostVirtualMemory::reserve(0x10000).unwrap();
        assert_eq!(memory.size(), 0x10000);

        memory.map(0, 0x1000).unwrap();
        memory.write(0x20, b"PHOENIX").unwrap();

        let mut bytes = [0u8; 7];
        memory.read(0x20, &mut bytes).unwrap();
        assert_eq!(&bytes, b"PHOENIX");

        memory.unmap(0, 0x1000).unwrap();
        assert_eq!(
            memory.read(0x20, &mut bytes),
            Err(VmError::NotCommitted)
        );

        memory.map(0, 0x1000).unwrap();
        memory.read(0x20, &mut bytes).unwrap();
        assert_eq!(&bytes, &[0u8; 7]);

        memory.release().unwrap();
    }

    #[test]
    fn rejects_unaligned_and_out_of_range_mapping() {
        let mut memory = HostVirtualMemory::reserve(0x2000).unwrap();
        assert_eq!(memory.map(1, 0x1000), Err(VmError::UnalignedRange));
        assert_eq!(memory.map(0x2000, 0x1000), Err(VmError::SizeOutOfRange));
    }

    #[test]
    fn rejects_access_to_uncommitted_pages() {
        let memory = HostVirtualMemory::reserve(0x1000).unwrap();
        let mut bytes = [0u8; 1];
        assert_eq!(memory.read(0, &mut bytes), Err(VmError::NotCommitted));
    }

    #[test]
    fn rounds_reservation_up_to_page_size() {
        let memory = HostVirtualMemory::reserve(0x1001).unwrap();
        assert_eq!(memory.size(), 0x2000);
    }
}
