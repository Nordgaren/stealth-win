// This is the std library default GlobalAlloc for windows, but with in-lined calls to GetProcessHeap,
// and removed the Atomic that stores the cached heap address. GetProcessHeap in this crate uses the internal
// GetProcAddress, which works in both mapped and unmapped memory.

use crate::windows::kernel32::{GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc};
use core::alloc::{GlobalAlloc, Layout};
use core::{cmp, mem, ptr};

// Heap memory management on Windows is done by using the system Heap API (heapapi.h)
// See https://docs.microsoft.com/windows/win32/api/heapapi/

// An allocator that doesn't use any imports to get the ProcessHeap. This allows usage of things that
// allocate memory at runtime, in an unmapped process.
pub struct NoImportAllocator;
// Header containing a pointer to the start of an allocated block.
// SAFETY: Size and alignment must be <= `MIN_ALIGN`.
#[repr(C)]
struct Header(*mut u8);

// The minimum alignment guaranteed by the architecture. This value is used to
// add fast paths for low alignment values.
pub const MIN_ALIGN: usize = 16;
// Flag to indicate that the memory returned by `HeapAlloc` should be zeroed.
pub const HEAP_ZERO_MEMORY: u32 = 0x00000008;

// Allocate a block of optionally zeroed memory for a given `layout`.
// SAFETY: Returns a pointer satisfying the guarantees of `System` about allocated pointers,
// or null if the operation fails. If this returns non-null `HEAP` will have been successfully
// initialized.
#[inline]
unsafe fn allocate(layout: Layout, zeroed: bool) -> *mut u8 {
    let heap = GetProcessHeap();
    if heap == 0 {
        // Allocation has failed, could not get the current process heap.
        return ptr::null_mut();
    }

    // Allocated memory will be either zeroed or uninitialized.
    let flags = if zeroed { HEAP_ZERO_MEMORY } else { 0 };

    if layout.align() <= MIN_ALIGN {
        // SAFETY: `heap` is a non-null handle returned by `GetProcessHeap`.
        // The returned pointer points to the start of an allocated block.
        unsafe { HeapAlloc(heap, flags, layout.size()) as *mut u8 }
    } else {
        // Allocate extra padding in order to be able to satisfy the alignment.
        let total = layout.align() + layout.size();

        // SAFETY: `heap` is a non-null handle returned by `GetProcessHeap`.
        let ptr = unsafe { HeapAlloc(heap, flags, total) as *mut u8 };
        if ptr.is_null() {
            // Allocation has failed.
            return ptr::null_mut();
        }

        // Create a correctly aligned pointer offset from the start of the allocated block,
        // and write a header before it.

        let offset = layout.align() - (ptr as usize & (layout.align() - 1));
        // SAFETY: `MIN_ALIGN` <= `offset` <= `layout.align()` and the size of the allocated
        // block is `layout.align() + layout.size()`. `aligned` will thus be a correctly aligned
        // pointer inside the allocated block with at least `layout.size()` bytes after it and at
        // least `MIN_ALIGN` bytes of padding before it.
        let aligned = unsafe { ptr.add(offset) };
        // SAFETY: Because the size and alignment of a header is <= `MIN_ALIGN` and `aligned`
        // is aligned to at least `MIN_ALIGN` and has at least `MIN_ALIGN` bytes of padding before
        // it, it is safe to write a header directly before it.
        unsafe { ptr::write((aligned as *mut Header).sub(1), Header(ptr)) };

        // SAFETY: The returned pointer does not point to the to the start of an allocated block,
        // but there is a header readable directly before it containing the location of the start
        // of the block.
        aligned
    }
}

pub unsafe fn realloc_fallback(
    alloc: &NoImportAllocator,
    ptr: *mut u8,
    old_layout: Layout,
    new_size: usize,
) -> *mut u8 {
    // Docs for GlobalAlloc::realloc require this to be valid:
    let new_layout = Layout::from_size_align_unchecked(new_size, old_layout.align());

    let new_ptr = GlobalAlloc::alloc(alloc, new_layout);
    if !new_ptr.is_null() {
        let size = cmp::min(old_layout.size(), new_size);
        ptr::copy_nonoverlapping(ptr, new_ptr, size);
        GlobalAlloc::dealloc(alloc, ptr, old_layout);
    }
    new_ptr
}

unsafe impl GlobalAlloc for NoImportAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Pointers returned by `allocate` satisfy the guarantees of `System`
        let zeroed = false;
        unsafe { allocate(layout, zeroed) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Pointers returned by `allocate` satisfy the guarantees of `System`
        let zeroed = true;
        unsafe { allocate(layout, zeroed) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let block = {
            if layout.align() <= MIN_ALIGN {
                ptr
            } else {
                // The location of the start of the block is stored in the padding before `ptr`.

                // SAFETY: Because of the contract of `System`, `ptr` is guaranteed to be non-null
                // and have a header readable directly before it.
                unsafe { ptr::read((ptr as *mut Header).sub(1)).0 }
            }
        };

        // SAFETY: because `ptr` has been successfully allocated with this allocator,
        // `HEAP` must have been successfully initialized.
        let heap = unsafe { GetProcessHeap() };

        // SAFETY: `heap` is a non-null handle returned by `GetProcessHeap`,
        // `block` is a pointer to the start of an allocated block.
        unsafe { HeapFree(heap, 0, block as usize) };
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= MIN_ALIGN {
            // SAFETY: because `ptr` has been successfully allocated with this allocator,
            // `HEAP` must have been successfully initialized.
            let heap = unsafe { GetProcessHeap() };

            // SAFETY: `heap` is a non-null handle returned by `GetProcessHeap`,
            // `ptr` is a pointer to the start of an allocated block.
            // The returned pointer points to the start of an allocated block.
            unsafe { HeapReAlloc(heap, 0, ptr as usize, new_size) as *mut u8 }
        } else {
            // SAFETY: `realloc_fallback` is implemented using `dealloc` and `alloc`, which will
            // correctly handle `ptr` and return a pointer satisfying the guarantees of `System`
            unsafe { realloc_fallback(self, ptr, layout, new_size) }
        }
    }
}
