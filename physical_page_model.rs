//! Project Phoenix physical-page compatibility model.
//!
//! This is a deterministic host-side model for tracking page ownership and
//! virtual-slot mappings. It does NOT allocate Xbox physical RAM, call
//! XMemAllocatePhysicalPages, or reproduce Xbox cache/coherency attributes.
//! The model is intentionally explicit about those limitations.

use std::collections::BTreeMap;
use std::fmt;

pub const PAGE_SIZE: usize = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalPageId(u64);

impl PhysicalPageId {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalPageError {
    ZeroPages,
    ZeroLength,
    UnalignedAddress,
    AddressOutOfRange,
    PageNotAllocated,
    PageAlreadyMapped,
    VirtualSlotAlreadyMapped,
    VirtualSlotNotMapped,
    PageStillMapped,
    SizeOverflow,
}

impl fmt::Display for PhysicalPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for PhysicalPageError {}

#[derive(Debug)]
struct PhysicalPage {
    bytes: Box<[u8; PAGE_SIZE]>,
}

pub struct PhysicalPageModel {
    virtual_size: usize,
    next_id: u64,
    pages: BTreeMap<PhysicalPageId, PhysicalPage>,
    virtual_slots: Vec<Option<PhysicalPageId>>,
}

impl PhysicalPageModel {
    /// Create a virtual mapping window. Size is rounded up to a 4 KiB page.
    pub fn new(virtual_size: usize) -> Result<Self, PhysicalPageError> {
        if virtual_size == 0 {
            return Err(PhysicalPageError::ZeroLength);
        }
        let rounded = virtual_size
            .checked_add(PAGE_SIZE - 1)
            .ok_or(PhysicalPageError::SizeOverflow)?
            & !(PAGE_SIZE - 1);
        Ok(Self {
            virtual_size: rounded,
            next_id: 1,
            pages: BTreeMap::new(),
            virtual_slots: vec![None; rounded / PAGE_SIZE],
        })
    }

    pub fn virtual_size(&self) -> usize {
        self.virtual_size
    }

    pub fn allocated_page_count(&self) -> usize {
        self.pages.len()
    }

    /// Allocate zero-filled model pages and return stable page identifiers.
    pub fn allocate_pages(
        &mut self,
        count: usize,
    ) -> Result<Vec<PhysicalPageId>, PhysicalPageError> {
        if count == 0 {
            return Err(PhysicalPageError::ZeroPages);
        }

        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            let id = PhysicalPageId(self.next_id);
            self.next_id = self.next_id
                .checked_add(1)
                .ok_or(PhysicalPageError::SizeOverflow)?;
            self.pages.insert(
                id,
                PhysicalPage {
                    bytes: Box::new([0; PAGE_SIZE]),
                },
            );
            ids.push(id);
        }
        Ok(ids)
    }

    /// Map one allocated page into a virtual page slot.
    pub fn map_page(
        &mut self,
        virtual_address: usize,
        page_id: PhysicalPageId,
    ) -> Result<(), PhysicalPageError> {
        self.validate_virtual_page(virtual_address)?;
        if !self.pages.contains_key(&page_id) {
            return Err(PhysicalPageError::PageNotAllocated);
        }
        if self.virtual_slots[virtual_address / PAGE_SIZE].is_some() {
            return Err(PhysicalPageError::VirtualSlotAlreadyMapped);
        }
        if self.virtual_slots.iter().any(|slot| *slot == Some(page_id)) {
            return Err(PhysicalPageError::PageAlreadyMapped);
        }
        self.virtual_slots[virtual_address / PAGE_SIZE] = Some(page_id);
        Ok(())
    }

    /// Scatter-map a list of pages into consecutive virtual slots.
    pub fn map_scatter(
        &mut self,
        virtual_address: usize,
        pages: &[PhysicalPageId],
    ) -> Result<(), PhysicalPageError> {
        if pages.is_empty() {
            return Err(PhysicalPageError::ZeroPages);
        }
        self.validate_virtual_page(virtual_address)?;
        let start = virtual_address / PAGE_SIZE;
        let end = start.checked_add(pages.len())
            .ok_or(PhysicalPageError::SizeOverflow)?;
        if end > self.virtual_slots.len() {
            return Err(PhysicalPageError::AddressOutOfRange);
        }

        for (index, page_id) in pages.iter().enumerate() {
            if !self.pages.contains_key(page_id) {
                return Err(PhysicalPageError::PageNotAllocated);
            }
            if self.virtual_slots[start + index].is_some() {
                return Err(PhysicalPageError::VirtualSlotAlreadyMapped);
            }
            if self.virtual_slots.iter().any(|slot| slot == &Some(*page_id)) {
                return Err(PhysicalPageError::PageAlreadyMapped);
            }
            if pages[..index].contains(page_id) {
                return Err(PhysicalPageError::PageAlreadyMapped);
            }
        }

        for (index, page_id) in pages.iter().enumerate() {
            self.virtual_slots[start + index] = Some(*page_id);
        }
        Ok(())
    }

    /// Map pages to explicitly selected, potentially non-contiguous virtual slots.
    /// Validation is completed for the entire request before any slot is changed.
    pub fn map_scatter_slots(
        &mut self,
        mappings: &[(usize, PhysicalPageId)],
    ) -> Result<(), PhysicalPageError> {
        if mappings.is_empty() {
            return Err(PhysicalPageError::ZeroPages);
        }

        for (index, (virtual_address, page_id)) in mappings.iter().enumerate() {
            self.validate_virtual_page(*virtual_address)?;
            if !self.pages.contains_key(page_id) {
                return Err(PhysicalPageError::PageNotAllocated);
            }
            let slot = virtual_address / PAGE_SIZE;
            if self.virtual_slots[slot].is_some() {
                return Err(PhysicalPageError::VirtualSlotAlreadyMapped);
            }
            if self.virtual_slots.iter().any(|existing| existing == &Some(*page_id)) {
                return Err(PhysicalPageError::PageAlreadyMapped);
            }
            for (other_address, other_page) in &mappings[..index] {
                if other_address == virtual_address {
                    return Err(PhysicalPageError::VirtualSlotAlreadyMapped);
                }
                if other_page == page_id {
                    return Err(PhysicalPageError::PageAlreadyMapped);
                }
            }
        }

        for (virtual_address, page_id) in mappings {
            self.virtual_slots[virtual_address / PAGE_SIZE] = Some(*page_id);
        }
        Ok(())
    }

    /// Remove one mapping while keeping its physical page allocated.
    pub fn unmap_page(
        &mut self,
        virtual_address: usize,
    ) -> Result<PhysicalPageId, PhysicalPageError> {
        self.validate_virtual_page(virtual_address)?;
        self.virtual_slots[virtual_address / PAGE_SIZE]
            .take()
            .ok_or(PhysicalPageError::VirtualSlotNotMapped)
    }

    /// Return the page identifier currently mapped at an aligned virtual address.
    pub fn mapped_page(
        &self,
        virtual_address: usize,
    ) -> Result<Option<PhysicalPageId>, PhysicalPageError> {
        self.validate_virtual_page(virtual_address)?;
        Ok(self.virtual_slots[virtual_address / PAGE_SIZE])
    }

    /// Remove mappings from a page-aligned virtual range; pages remain allocated.
    pub fn unmap_range(
        &mut self,
        virtual_address: usize,
        size: usize,
    ) -> Result<Vec<PhysicalPageId>, PhysicalPageError> {
        let (start, end) = self.validate_range(virtual_address, size)?;
        if self.virtual_slots[start..end].iter().any(Option::is_none) {
            return Err(PhysicalPageError::VirtualSlotNotMapped);
        }
        let mut unmapped = Vec::with_capacity(end - start);
        for slot in &mut self.virtual_slots[start..end] {
            unmapped.push(slot.take().expect("validated mapped slot"));
        }
        Ok(unmapped)
    }

    /// Free an allocated page. A page must be unmapped first.
    pub fn free_page(
        &mut self,
        page_id: PhysicalPageId,
    ) -> Result<(), PhysicalPageError> {
        if !self.pages.contains_key(&page_id) {
            return Err(PhysicalPageError::PageNotAllocated);
        }
        if self.virtual_slots.iter().any(|slot| *slot == Some(page_id)) {
            return Err(PhysicalPageError::PageStillMapped);
        }
        self.pages.remove(&page_id);
        Ok(())
    }

    pub fn write(
        &mut self,
        virtual_address: usize,
        data: &[u8],
    ) -> Result<(), PhysicalPageError> {
        self.access_chunks(virtual_address, data.len(), |page, page_offset, data_offset, count| {
            page[page_offset..page_offset + count]
                .copy_from_slice(&data[data_offset..data_offset + count]);
        })
    }

    pub fn read(
        &self,
        virtual_address: usize,
        output: &mut [u8],
    ) -> Result<(), PhysicalPageError> {
        self.validate_access(virtual_address, output.len())?;
        let mut done = 0;
        while done < output.len() {
            let address = virtual_address + done;
            let slot_index = address / PAGE_SIZE;
            let page_offset = address % PAGE_SIZE;
            let count = (PAGE_SIZE - page_offset).min(output.len() - done);
            let page_id = self.virtual_slots[slot_index]
                .ok_or(PhysicalPageError::VirtualSlotNotMapped)?;
            let page = self.pages.get(&page_id)
                .ok_or(PhysicalPageError::PageNotAllocated)?;
            output[done..done + count]
                .copy_from_slice(&page.bytes[page_offset..page_offset + count]);
            done += count;
        }
        Ok(())
    }

    fn access_chunks<F>(
        &mut self,
        virtual_address: usize,
        length: usize,
        mut operation: F,
    ) -> Result<(), PhysicalPageError>
    where
        F: FnMut(&mut [u8; PAGE_SIZE], usize, usize, usize),
    {
        self.validate_access(virtual_address, length)?;
        let mut done = 0;
        while done < length {
            let address = virtual_address + done;
            let slot_index = address / PAGE_SIZE;
            let page_offset = address % PAGE_SIZE;
            let count = (PAGE_SIZE - page_offset).min(length - done);
            let page_id = self.virtual_slots[slot_index]
                .ok_or(PhysicalPageError::VirtualSlotNotMapped)?;
            let page = self.pages.get_mut(&page_id)
                .ok_or(PhysicalPageError::PageNotAllocated)?;
            operation(&mut page.bytes, page_offset, done, count);
            done += count;
        }
        Ok(())
    }

    fn validate_access(
        &self,
        virtual_address: usize,
        length: usize,
    ) -> Result<(), PhysicalPageError> {
        if length == 0 {
            return Ok(());
        }
        let end = virtual_address.checked_add(length)
            .ok_or(PhysicalPageError::SizeOverflow)?;
        if end > self.virtual_size {
            return Err(PhysicalPageError::AddressOutOfRange);
        }
        let first = virtual_address / PAGE_SIZE;
        let last = (end - 1) / PAGE_SIZE;
        if self.virtual_slots[first..=last].iter().any(Option::is_none) {
            return Err(PhysicalPageError::VirtualSlotNotMapped);
        }
        Ok(())
    }

    fn validate_virtual_page(
        &self,
        address: usize,
    ) -> Result<(), PhysicalPageError> {
        if address % PAGE_SIZE != 0 {
            return Err(PhysicalPageError::UnalignedAddress);
        }
        if address >= self.virtual_size {
            return Err(PhysicalPageError::AddressOutOfRange);
        }
        Ok(())
    }

    fn validate_range(
        &self,
        address: usize,
        size: usize,
    ) -> Result<(usize, usize), PhysicalPageError> {
        if size == 0 {
            return Err(PhysicalPageError::ZeroLength);
        }
        if address % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return Err(PhysicalPageError::UnalignedAddress);
        }
        let end_address = address.checked_add(size)
            .ok_or(PhysicalPageError::SizeOverflow)?;
        if end_address > self.virtual_size {
            return Err(PhysicalPageError::AddressOutOfRange);
        }
        Ok((address / PAGE_SIZE, end_address / PAGE_SIZE))
    }
}

pub fn print_model_report() {
    println!("\n=== PHOENIX: PHYSICAL-PAGE OWNERSHIP / MAPPING MODEL ===");
    println!("Page size: {:#x}", PAGE_SIZE);
    println!("Operations: allocate IDs, map/scatter-map, read/write, unmap, free");
    println!("This is a software model; no Xbox physical pages are allocated.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_maps_writes_reads_unmaps_and_frees() {
        let mut model = PhysicalPageModel::new(0x4000).unwrap();
        let pages = model.allocate_pages(2).unwrap();
        model.map_scatter(0, &pages).unwrap();

        model.write(0x0ffb, b"across-page-boundary").unwrap();
        let mut output = [0u8; 20];
        model.read(0x0ffb, &mut output).unwrap();
        assert_eq!(&output, b"across-page-boundary");

        let unmapped = model.unmap_range(0, 0x2000).unwrap();
        assert_eq!(unmapped, pages);
        for page in pages {
            model.free_page(page).unwrap();
        }
        assert_eq!(model.allocated_page_count(), 0);
    }

    #[test]
    fn prevents_freeing_a_mapped_page() {
        let mut model = PhysicalPageModel::new(0x2000).unwrap();
        let page = model.allocate_pages(1).unwrap()[0];
        model.map_page(0, page).unwrap();
        assert_eq!(model.free_page(page), Err(PhysicalPageError::PageStillMapped));
    }

    #[test]
    fn rejects_mapping_the_same_page_twice() {
        let mut model = PhysicalPageModel::new(0x3000).unwrap();
        let page = model.allocate_pages(1).unwrap()[0];
        assert_eq!(
            model.map_scatter(0, &[page, page]),
            Err(PhysicalPageError::PageAlreadyMapped)
        );
    }

    #[test]
    fn rejects_unaligned_and_out_of_range_scatter_mapping() {
        let mut model = PhysicalPageModel::new(0x2000).unwrap();
        let pages = model.allocate_pages(2).unwrap();
        assert_eq!(
            model.map_scatter(1, &pages),
            Err(PhysicalPageError::UnalignedAddress)
        );
        assert_eq!(
            model.map_scatter(0x1000, &pages),
            Err(PhysicalPageError::AddressOutOfRange)
        );
    }

    #[test]
    fn rejects_reads_from_unmapped_slots() {
        let model = PhysicalPageModel::new(0x1000).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            model.read(0, &mut byte),
            Err(PhysicalPageError::VirtualSlotNotMapped)
        );
    }

    #[test]
    fn maps_pages_to_non_contiguous_virtual_slots() {
        let mut model = PhysicalPageModel::new(0x6000).unwrap();
        let pages = model.allocate_pages(3).unwrap();

        model.map_scatter_slots(&[
            (0x0000, pages[0]),
            (0x2000, pages[1]),
            (0x5000, pages[2]),
        ]).unwrap();

        model.write(0x0000, b"first").unwrap();
        model.write(0x2000, b"second").unwrap();
        model.write(0x5000, b"third").unwrap();

        let mut a = [0u8; 5];
        let mut b = [0u8; 6];
        let mut c = [0u8; 5];
        model.read(0x0000, &mut a).unwrap();
        model.read(0x2000, &mut b).unwrap();
        model.read(0x5000, &mut c).unwrap();

        assert_eq!(&a, b"first");
        assert_eq!(&b, b"second");
        assert_eq!(&c, b"third");
    }

    #[test]
    fn unmapping_and_remapping_preserves_physical_page_contents() {
        let mut model = PhysicalPageModel::new(0x4000).unwrap();
        let page = model.allocate_pages(1).unwrap()[0];
        model.map_page(0x0000, page).unwrap();
        model.write(0x0010, b"persistent").unwrap();

        assert_eq!(model.unmap_page(0x0000).unwrap(), page);
        assert_eq!(model.mapped_page(0x0000).unwrap(), None);

        model.map_page(0x3000, page).unwrap();
        let mut bytes = [0u8; 10];
        model.read(0x3010, &mut bytes).unwrap();
        assert_eq!(&bytes, b"persistent");
    }

    #[test]
    fn scatter_slot_mapping_is_atomic_on_validation_failure() {
        let mut model = PhysicalPageModel::new(0x4000).unwrap();
        let pages = model.allocate_pages(2).unwrap();
        model.map_page(0x1000, pages[1]).unwrap();

        let result = model.map_scatter_slots(&[
            (0x0000, pages[0]),
            (0x1000, pages[1]),
        ]);

        assert_eq!(result, Err(PhysicalPageError::VirtualSlotAlreadyMapped));
        assert_eq!(model.mapped_page(0x0000).unwrap(), None);
        assert_eq!(model.mapped_page(0x1000).unwrap(), Some(pages[1]));
    }

}
