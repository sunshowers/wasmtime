//! A "dummy" implementation of mmaps for miri where "we do the best we can"
//!
//! Namely this uses `alloc` to allocate memory for the "mmap" specifically to
//! create page-aligned allocations. This allocation doesn't handle operations
//! like becoming executable or becoming readonly or being created from files,
//! but it's enough to get various tests running relying on memories and such.

use crate::prelude::*;
use crate::runtime::vm::{HostAlignedByteCount, SendSyncPtr};
use std::alloc::{self, Layout};
use std::fs::File;
use std::ops::Range;
use std::path::Path;
use std::ptr::NonNull;

pub fn open_file_for_mmap(_path: &Path) -> Result<File> {
    bail!("not supported on miri");
}

#[derive(Debug)]
pub struct Mmap {
    memory: SendSyncPtr<[u8]>,
}

impl Mmap {
    pub fn new_empty() -> Mmap {
        Mmap {
            memory: crate::vm::sys::empty_mmap(),
        }
    }

    pub fn new(size: HostAlignedByteCount) -> Result<Self> {
        let mut ret = Mmap::reserve(size)?;
        ret.make_accessible(HostAlignedByteCount::ZERO, size)?;
        Ok(ret)
    }

    pub fn reserve(size: HostAlignedByteCount) -> Result<Self> {
        if size.byte_count() > 1 << 32 {
            bail!("failed to allocate memory");
        }
        let layout = make_layout(size);
        let ptr = unsafe { alloc::alloc(layout) };
        if ptr.is_null() {
            bail!("failed to allocate memory");
        }

        let memory = std::ptr::slice_from_raw_parts_mut(ptr.cast(), size.byte_count());
        let memory = SendSyncPtr::new(NonNull::new(memory).unwrap());
        Ok(Mmap { memory })
    }

    pub fn from_file(_file: &File) -> Result<Self> {
        bail!("not supported on miri");
    }

    pub fn make_accessible(
        &mut self,
        start: HostAlignedByteCount,
        len: HostAlignedByteCount,
    ) -> Result<()> {
        // The memory is technically always accessible but this marks it as
        // initialized for miri-level checking.
        unsafe {
            std::ptr::write_bytes(
                self.as_mut_ptr().add(start.byte_count()),
                0u8,
                len.byte_count(),
            );
        }
        Ok(())
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.memory.as_ptr() as *const u8
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.memory.as_ptr().cast()
    }

    pub fn len(&self) -> usize {
        self.memory.as_ptr().len()
    }

    pub unsafe fn make_executable(
        &self,
        _range: Range<usize>,
        _enable_branch_protection: bool,
    ) -> Result<()> {
        Ok(())
    }

    pub unsafe fn make_readonly(&self, _range: Range<usize>) -> Result<()> {
        Ok(())
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len().is_zero() {
            return;
        }
        unsafe {
            let layout = make_layout(self.len());
            alloc::dealloc(self.as_mut_ptr(), layout);
        }
    }
}

fn make_layout(size: HostAlignedByteCount) -> Layout {
    Layout::from_size_align(size.byte_count(), crate::runtime::vm::host_page_size()).unwrap()
}
