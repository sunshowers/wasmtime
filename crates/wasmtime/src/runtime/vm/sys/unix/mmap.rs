use crate::prelude::*;
use crate::runtime::vm::SendSyncPtr;
use core::mem::ManuallyDrop;
use nodit::interval::ie;
use nodit::{Interval, NoditSet};
use rustix::mm::{mprotect, MprotectFlags};
use std::ops::Range;
use std::os::fd::{AsFd, BorrowedFd};
use std::ptr::{self, NonNull};
use std::sync::Mutex;
#[cfg(feature = "std")]
use std::{fs::File, path::Path};

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "illumos", target_os = "linux"))] {
        // On illumos, by default, mmap reserves what it calls "swap space" ahead of time, so that
        // memory accesses are guaranteed not to fail once mmap succeeds. NORESERVE is for cases
        // where that memory is never meant to be accessed -- e.g. memory that's used as guard
        // pages.
        //
        // This is less crucial on Linux because Linux tends to overcommit memory by default, but is
        // still a good idea to pass in for large allocations that don't need to be backed by
        // physical memory.
        pub(super) const MMAP_NORESERVE_FLAG: rustix::mm::MapFlags =
            rustix::mm::MapFlags::NORESERVE;
    } else {
        pub(super) const MMAP_NORESERVE_FLAG: rustix::mm::MapFlags = rustix::mm::MapFlags::empty();
    }
}

#[derive(Debug)]
pub struct Mmap {
    imp: MmapImpl,
}

impl Mmap {
    #[inline]
    pub fn new_empty() -> Mmap {
        Self {
            imp: MmapImpl::new_empty(),
        }
    }

    #[inline]
    pub fn new(size: usize) -> Result<Mmap> {
        Ok(Self {
            imp: MmapImpl::new(size)?,
        })
    }

    #[inline]
    pub fn reserve(size: usize) -> Result<Mmap> {
        Ok(Self {
            imp: MmapImpl::reserve(size)?,
        })
    }

    #[cfg(feature = "std")]
    pub fn from_file(path: &Path) -> Result<(Self, File)> {
        let (imp, file) = MmapImpl::from_file(path)?;
        Ok((Self { imp }, file))
    }

    #[inline]
    pub fn make_accessible(&self, start: usize, len: usize) -> Result<()> {
        self.imp.make_accessible(start, len)
    }

    #[inline]
    pub unsafe fn make_executable(
        &self,
        range: Range<usize>,
        enable_branch_protection: bool,
    ) -> Result<()> {
        self.imp.make_executable(range, enable_branch_protection)
    }

    #[inline]
    pub unsafe fn make_readonly(&self, range: Range<usize>) -> Result<()> {
        self.imp.make_readonly(range)
    }

    #[inline]
    pub unsafe fn make_inaccessible(&self, range: Range<usize>) -> Result<()> {
        self.imp.make_inaccessible(range)
    }

    #[inline]
    pub unsafe fn decommit(&self, range: Range<usize>) -> Result<()> {
        self.imp.decommit(range)
    }

    #[inline]
    pub unsafe fn map_fd<Fd: AsFd>(
        &self,
        start: usize,
        fd: Fd,
        len: usize,
        offset: u64,
    ) -> Result<()> {
        self.imp.map_fd(start, fd.as_fd(), len, offset)
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.imp.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.imp.as_mut_ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.imp.len()
    }
}

#[derive(Debug)]
enum MmapImpl {
    Regular(MmapRegular),
    DevNull(MmapDevNull),
}

impl MmapImpl {
    #[inline]
    fn new_empty() -> Self {
        Self::Regular(MmapRegular::new_empty())
    }

    #[inline]
    fn new(size: usize) -> Result<Self> {
        Ok(Self::Regular(MmapRegular::new_read_write(size)?))
    }

    #[inline]
    fn reserve(size: usize) -> Result<Self> {
        Ok(Self::DevNull(MmapDevNull::reserve(size)?))
    }

    #[cfg(feature = "std")]
    fn from_file(path: &Path) -> Result<(Self, File)> {
        let (imp, file) = MmapRegular::from_file(path)?;
        Ok((Self::Regular(imp), file))
    }

    #[inline]
    fn make_accessible(&self, start: usize, len: usize) -> Result<()> {
        match self {
            Self::Regular(imp) => imp.make_accessible(start, len),
            Self::DevNull(imp) => imp.make_accessible(start, len),
        }
    }

    #[inline]
    unsafe fn make_executable(
        &self,
        range: Range<usize>,
        enable_branch_protection: bool,
    ) -> Result<()> {
        match self {
            Self::Regular(imp) => imp.make_executable(range, enable_branch_protection),
            Self::DevNull(imp) => imp.make_executable(range, enable_branch_protection),
        }
    }

    #[inline]
    unsafe fn make_readonly(&self, range: Range<usize>) -> Result<()> {
        match self {
            Self::Regular(imp) => imp.make_readonly(range),
            Self::DevNull(imp) => imp.make_readonly(range),
        }
    }

    #[inline]
    unsafe fn make_inaccessible(&self, range: Range<usize>) -> Result<()> {
        match self {
            Self::Regular(imp) => imp.make_inaccessible(range),
            Self::DevNull(imp) => imp.make_inaccessible(range),
        }
    }

    #[inline]
    unsafe fn decommit(&self, range: Range<usize>) -> Result<()> {
        match self {
            Self::Regular(imp) => imp.decommit(range),
            Self::DevNull(imp) => imp.decommit(range),
        }
    }

    #[inline]
    unsafe fn map_fd(
        &self,
        start: usize,
        fd: BorrowedFd<'_>,
        len: usize,
        offset: u64,
    ) -> Result<()> {
        match self {
            Self::Regular(imp) => imp.map_fd(start, fd, len, offset),
            Self::DevNull(imp) => imp.map_fd(start, fd, len, offset),
        }
    }

    #[inline]
    fn as_ptr(&self) -> *const u8 {
        match self {
            Self::Regular(imp) => imp.memory.as_ptr() as *const u8,
            Self::DevNull(imp) => imp.memory.as_ptr() as *const u8,
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Self::Regular(imp) => imp.memory.as_ptr().cast(),
            Self::DevNull(imp) => imp.memory.as_ptr().cast(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Regular(imp) => imp.memory.as_ptr().len(),
            Self::DevNull(imp) => imp.memory.as_ptr().len(),
        }
    }
}

/// An mmap impl that's backed by a single `mmap` call, whether anonymous or file-backed.
#[derive(Debug)]
struct MmapRegular {
    memory: SendSyncPtr<[u8]>,
}

impl MmapRegular {
    fn new_empty() -> Self {
        let memory = crate::vm::sys::empty_mmap();
        Self { memory }
    }

    fn new_read_write(size: usize) -> Result<Self> {
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                size,
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::PRIVATE | MMAP_NORESERVE_FLAG,
            )
            .err2anyhow()?
        };
        let memory = std::ptr::slice_from_raw_parts_mut(ptr.cast(), size);
        let memory = SendSyncPtr::new(NonNull::new(memory).unwrap());
        Ok(Self { memory })
    }

    fn reserve(size: usize) -> Result<Self> {
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                size,
                rustix::mm::ProtFlags::empty(),
                // Astute readers might be wondering why a function called "reserve" passes in a
                // NORESERVE flag. That's because "reserve" in this context means one of two
                // different things.
                //
                // * This method is used to allocate virtual memory that starts off in a state where
                //   it cannot be accessed (i.e. causes a segfault if accessed).
                // * NORESERVE is meant for virtual memory space for which backing physical/swap
                //   pages are reserved on first access.
                //
                // Virtual memory that cannot be accessed should not have a backing store reserved
                // for it. Hence, passing in NORESERVE is correct here.
                rustix::mm::MapFlags::PRIVATE | MMAP_NORESERVE_FLAG,
            )
            .err2anyhow()?
        };

        let memory = std::ptr::slice_from_raw_parts_mut(ptr.cast(), size);
        let memory = SendSyncPtr::new(NonNull::new(memory).unwrap());
        Ok(Self { memory })
    }

    #[cfg(feature = "std")]
    fn from_file(path: &Path) -> Result<(Self, File)> {
        let file = File::open(path)
            .err2anyhow()
            .context("failed to open file")?;
        let len = file
            .metadata()
            .err2anyhow()
            .context("failed to get file metadata")?
            .len();
        let len = usize::try_from(len).map_err(|_| anyhow::anyhow!("file too large to map"))?;
        let ptr = unsafe {
            rustix::mm::mmap(
                ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::PRIVATE,
                &file,
                0,
            )
            .err2anyhow()
            .context(format!("mmap failed to allocate {len:#x} bytes"))?
        };
        let memory = std::ptr::slice_from_raw_parts_mut(ptr.cast(), len);
        let memory = SendSyncPtr::new(NonNull::new(memory).unwrap());

        Ok((Self { memory }, file))
    }

    fn make_accessible(&self, start: usize, len: usize) -> Result<()> {
        let ptr = self.memory.as_ptr();
        unsafe {
            mprotect(
                ptr.byte_add(start).cast(),
                len,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .err2anyhow()?;
        }

        Ok(())
    }

    unsafe fn make_executable(
        &self,
        range: Range<usize>,
        enable_branch_protection: bool,
    ) -> Result<()> {
        let base = self.memory.as_ptr().byte_add(range.start).cast();
        let len = range.end - range.start;

        let flags = MprotectFlags::READ | MprotectFlags::EXEC;
        let flags = if enable_branch_protection {
            #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
            if std::arch::is_aarch64_feature_detected!("bti") {
                MprotectFlags::from_bits_retain(flags.bits() | /* PROT_BTI */ 0x10)
            } else {
                flags
            }

            #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
            flags
        } else {
            flags
        };

        mprotect(base, len, flags).err2anyhow()?;

        Ok(())
    }

    unsafe fn make_readonly(&self, range: Range<usize>) -> Result<()> {
        let len = range.end - range.start;
        if len == 0 {
            return Ok(());
        }

        let base = self.memory.as_ptr().byte_add(range.start).cast();

        mprotect(base, len, MprotectFlags::READ).err2anyhow()?;

        Ok(())
    }

    unsafe fn make_inaccessible(&self, range: Range<usize>) -> Result<()> {
        let len = range.end - range.start;
        if len == 0 {
            return Ok(());
        }

        let base = self.memory.as_ptr().byte_add(range.start).cast();

        mprotect(base, len, MprotectFlags::empty()).err2anyhow()?;

        Ok(())
    }

    unsafe fn decommit(&self, range: Range<usize>) -> Result<()> {
        let len = range.end - range.start;
        if len == 0 {
            return Ok(());
        }

        let base = self.memory.as_ptr().byte_add(range.start).cast();

        unsafe {
            cfg_if::cfg_if! {
                if #[cfg(target_os = "linux")] {
                    use rustix::mm::{madvise, Advice};

                    // On Linux, this is enough to cause the kernel to initialize
                    // the pages to 0 on next access
                    madvise(base, len, Advice::LinuxDontNeed)?;
                } else {
                    // By creating a new mapping at the same location, this will
                    // discard the mapping for the pages in the given range.
                    // The new mapping will be to the CoW zero page, so this
                    // effectively zeroes the pages.
                    rustix::mm::mmap_anonymous(
                        base,
                        len,
                        rustix::mm::ProtFlags::READ
                            | rustix::mm::ProtFlags::WRITE,
                        rustix::mm::MapFlags::PRIVATE
                            | super::mmap::MMAP_NORESERVE_FLAG
                            | rustix::mm::MapFlags::FIXED,
                    )?;
                }
            }
        }

        Ok(())
    }

    unsafe fn map_fd(
        &self,
        start: usize,
        fd: BorrowedFd<'_>,
        len: usize,
        offset: u64,
    ) -> Result<()> {
        let base = self.memory.as_ptr().byte_add(start).cast();
        rustix::mm::mmap(
            base,
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::PRIVATE | rustix::mm::MapFlags::FIXED,
            fd,
            offset,
        )
        .err2anyhow()?;

        Ok(())
    }
}

impl Drop for MmapRegular {
    fn drop(&mut self) {
        unsafe {
            let ptr = self.memory.as_ptr().cast();
            let len = self.memory.as_ptr().len();
            if len == 0 {
                return;
            }
            rustix::mm::munmap(ptr, len).expect("munmap failed");
        }
    }
}

/// An mmap impl based on `/dev/null` for PROT_NONE regions.
#[derive(Debug)]
struct MmapDevNull {
    memory: SendSyncPtr<[u8]>,
    // The mutex is required because some of the anon_ranges APIs take &self.
    anon_ranges: Mutex<NoditSet<usize, Interval<usize>>>,
}

impl MmapDevNull {
    fn reserve(size: usize) -> Result<Self> {
        // With mmap, the fd doesn't need to be kept open after the mmap call, so we can drop it at
        // the end of the function.
        let fd = File::open("/dev/null")
            .err2anyhow()
            .context("error opening /dev/null")?;
        let ptr = unsafe {
            rustix::mm::mmap(
                ptr::null_mut(),
                size,
                rustix::mm::ProtFlags::empty(),
                rustix::mm::MapFlags::PRIVATE | MMAP_NORESERVE_FLAG,
                &fd,
                0,
            )
            .err2anyhow()
            .context("mmap call failed")?
        };
        let memory = std::ptr::slice_from_raw_parts_mut(ptr.cast(), size);
        let memory = SendSyncPtr::new(NonNull::new(memory).unwrap());
        Ok(MmapDevNull {
            memory,
            anon_ranges: Mutex::new(NoditSet::new()),
        })
    }

    fn make_accessible(&self, start: usize, len: usize) -> Result<()> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("overflow in {start} + {len}"))?;
        self.operate_on(start, end, Op::MakeAccessible)
    }

    unsafe fn make_executable(
        &self,
        range: Range<usize>,
        enable_branch_protection: bool,
    ) -> Result<()> {
        self.operate_on(
            range.start,
            range.end,
            Op::MakeExecutable {
                enable_branch_protection,
            },
        )
    }

    unsafe fn make_readonly(&self, range: Range<usize>) -> Result<()> {
        self.operate_on(range.start, range.end, Op::MakeReadonly)
    }

    unsafe fn make_inaccessible(&self, range: Range<usize>) -> Result<()> {
        self.operate_on(range.start, range.end, Op::MakeProtected)
    }

    // Operate on [start, end) with the given operation.
    fn operate_on(&self, start: usize, end: usize, op: Op) -> Result<()> {
        // nodit panics on zero-length intervals so we need an explicit check here.
        if start == end {
            return Ok(());
        }

        let mut anon_ranges = self.anon_ranges.lock().expect("lock not poisoned");

        // mprotect all the overlapping regions.
        let mprotect_flags = op.mprotect_flags();
        for range in anon_ranges.overlapping(ie(start, end)) {
            let start = range.start();
            // range.end() is inclusive, so we need to add 1 to get the length.
            let len = (range.end() - start) + 1;
            // SAFETY: this region was already mapped anonymously, so it's safe to call mprotect
            // on it.
            unsafe {
                let ptr = self.memory.as_ptr().byte_add(start).cast();
                mprotect(ptr, len, mprotect_flags)
                    .err2anyhow()
                    .with_context(|| format!("mprotect with {op:?} failed"))?;
            }
        }

        if let Some(prot_flags) = op.mmap_prot_flags() {
            // mmap all the gaps. We collect the gaps first because of the borrow checker: we can't
            // insert into the set while iterating over it.
            let gaps: Vec<_> = anon_ranges.gaps_trimmed(ie(start, end)).collect();

            for range in gaps {
                let start = range.start();
                // range.end() is inclusive, so we need to add 1 to get the length.
                let len = (range.end() - start) + 1;
                unsafe {
                    let ptr = self.memory.as_ptr().byte_add(start).cast();
                    rustix::mm::mmap_anonymous(
                        ptr,
                        len,
                        prot_flags,
                        rustix::mm::MapFlags::PRIVATE
                            | MMAP_NORESERVE_FLAG
                            | rustix::mm::MapFlags::FIXED,
                    )
                    .err2anyhow()
                    .with_context(|| format!("mmap_anonymous with {op:?} failed"))?;

                    // TODO: call mprotect if required
                }

                // We might be tempted to insert the new region into the interval set in one big go at
                // the end, but that is quite risky -- if the mmap fails, we would have to remove
                // whatever parts failed from the interval set. It's much easier to insert each
                // successful mmap into the set incrementally.
                anon_ranges.insert_merge_touching_or_overlapping(ie(start, start + len));
            }
        }

        Ok(())
    }

    unsafe fn map_fd(
        &self,
        start: usize,
        fd: BorrowedFd<'_>,
        len: usize,
        offset: u64,
    ) -> Result<()> {
        let mut anon_ranges = self.anon_ranges.lock().expect("lock not poisoned");

        let base = self.memory.as_ptr().byte_add(start).cast();
        let ptr = rustix::mm::mmap(
            base,
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::PRIVATE | rustix::mm::MapFlags::FIXED,
            fd,
            offset,
        )
        .err2anyhow()?;
        assert_eq!(base, ptr);

        // TODO: should probably check that the new region doesn't overlap with existing regions.
        anon_ranges.insert_merge_touching_or_overlapping(ie(start, start + len));

        Ok(())
    }

    unsafe fn decommit(&self, range: Range<usize>) -> Result<()> {
        if range.start == range.end {
            return Ok(());
        }

        let mut anon_ranges = self.anon_ranges.lock().expect("lock not poisoned");

        let start = range.start;
        let end = range.end;

        let base = self.memory.as_ptr().byte_add(start).cast();

        // Remap the range as /dev/null.
        let fd = File::open("/dev/null")
            .err2anyhow()
            .context("error opening /dev/null")?;
        let ptr = unsafe {
            rustix::mm::mmap(
                base,
                end - start,
                rustix::mm::ProtFlags::empty(),
                rustix::mm::MapFlags::PRIVATE | MMAP_NORESERVE_FLAG | rustix::mm::MapFlags::FIXED,
                &fd,
                0,
            )
            .err2anyhow()
            .context("mmap call failed")?
        };
        assert_eq!(base, ptr);

        // Clean out the range from the interval set.
        let cut = NoditSet::from_iter_strict(anon_ranges.cut(ie(start, end)))
            .expect("NoditSet::cut cannot return overlapping ranges");
        *anon_ranges = cut;

        Ok(())
    }
}

#[derive(Debug)]
enum Op {
    MakeAccessible,
    MakeExecutable { enable_branch_protection: bool },
    MakeReadonly,
    MakeProtected,
}

impl Op {
    fn mprotect_flags(&self) -> MprotectFlags {
        match self {
            Op::MakeAccessible => MprotectFlags::READ | MprotectFlags::WRITE,
            Op::MakeExecutable {
                enable_branch_protection,
            } => {
                let flags = MprotectFlags::READ | MprotectFlags::EXEC;
                if *enable_branch_protection {
                    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
                    if std::arch::is_aarch64_feature_detected!("bti") {
                        MprotectFlags::from_bits_retain(flags.bits() | /* PROT_BTI */ 0x10)
                    } else {
                        flags
                    }

                    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
                    flags
                } else {
                    flags
                }
            }
            Op::MakeReadonly => MprotectFlags::READ,
            Op::MakeProtected => MprotectFlags::empty(),
        }
    }

    // None if new mmaps don't need to be created.
    fn mmap_prot_flags(&self) -> Option<rustix::mm::ProtFlags> {
        match self {
            Op::MakeAccessible => Some(rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE),
            Op::MakeExecutable { .. } => {
                Some(rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::EXEC)
            }
            Op::MakeReadonly => Some(rustix::mm::ProtFlags::READ),
            Op::MakeProtected => None,
        }
    }
}

impl Drop for MmapDevNull {
    fn drop(&mut self) {
        // munmap can work across multiple different mmap calls, so we can just munmap the entire
        // memory in one go.
        unsafe {
            let ptr = self.memory.as_ptr().cast();
            let len = self.memory.as_ptr().len();
            if len == 0 {
                return;
            }
            rustix::mm::munmap(ptr, len).expect("munmap failed");
        }
    }
}
