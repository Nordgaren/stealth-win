use crate::util::copy_buffer;
use crate::windows::kernel32::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use crate::windows::user32::MessageBoxA;
use std::alloc::Layout;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use std::mem::size_of;
use std::ops::{Index, IndexMut, RangeFrom};
use std::ptr::NonNull;
use std::slice::SliceIndex;
use std::{cmp, fmt, mem, ptr};

pub struct SVec<T> {
    ptr: NonNull<T>,
    cap: usize,
    len: usize,
}

const BACKSPACE: u8 = 8;

impl<T> Display for SVec<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_slice());
        Ok(())
    }
}

impl<T> UpperHex for SVec<T>
where
    T: UpperHex,
    T: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X?}", self.as_slice());
        Ok(())
    }
}

impl<T> LowerHex for SVec<T>
where
    T: LowerHex,
    T: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x?}", self.as_slice());
        Ok(())
    }
}

impl<T, Idx: SliceIndex<[T]>> Index<Idx> for SVec<T> {
    type Output = Idx::Output;
    #[inline]
    fn index(&self, index: Idx) -> &Self::Output {
        &self.as_slice().index(index)
    }
}

impl<T, Idx: SliceIndex<[T]>> IndexMut<Idx> for SVec<T> {
    #[inline]
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}

pub trait ToSVec<T> {
    fn to_svec(&self) -> SVec<T>;
}

impl<T> ToSVec<T> for [T]
where
    T: Sized,
{
    fn to_svec(&self) -> SVec<T> {
        let mut svec = SVec::with_capacity(self.len());

        unsafe {
            copy_buffer(self.as_ptr(), svec.as_mut_ptr(), self.len());
            svec.set_len(self.len());
        }

        svec
    }
}

impl<T> Drop for SVec<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(self.as_mut_ptr(), self.len));
            VirtualFree(self.ptr.as_ptr() as usize, 0, MEM_RELEASE);
        }
    }
}

impl<T> SVec<T> {
    // Yes, I took the comment, too, because its hilarious!
    // Tiny Vecs are dumb. Skip to:
    // - 8 if the element size is 1, because any heap allocators is likely
    //   to round up a request of less than 8 bytes to at least 8 bytes.
    // - 4 if elements are moderate-sized (<= 1 KiB).
    // - 1 otherwise, to avoid wasting too much space for very short Vecs.
    pub(crate) const MIN_NON_ZERO_CAP: usize = if mem::size_of::<T>() == 1 {
        8
    } else if mem::size_of::<T>() <= 1024 {
        4
    } else {
        1
    };
    pub fn new() -> Self {
        SVec {
            ptr: NonNull::dangling(),
            cap: 0,
            len: 0,
        }
    }
    pub fn with_capacity(size: usize) -> Self {
        let mut svec = SVec::new();
        svec.grow(size);
        svec
    }
    pub fn push(&mut self, value: T) {
        if self.cap == self.len {
            self.grow(1);
        }
        unsafe {
            let end = self.as_mut_ptr().add(self.len);
            ptr::write(end, value);
            self.len += 1;
        }
    }
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            unsafe {
                self.len -= 1;
                Some(ptr::read(self.as_ptr().add(self.len())))
            }
        }
    }
    fn grow(&mut self, additional: usize) {
        debug_assert!(additional > 0);

        if size_of::<T>() == 0 {
            panic!("Cannot grow zero sized types")
        }

        // For some reason, self.len.checked_add(additional) causes a crash if you are working in an unmapped PE.
        // Handle everything here, instead of bubbling up one function, like in Vec.
        let required_cap = self.len + additional;

        let new_cap = cmp::max(self.cap * 2, required_cap);
        let new_cap = cmp::max(Self::MIN_NON_ZERO_CAP, new_cap);
        let new_layout = Layout::array::<T>(new_cap).expect("Could not get layout.");
        let tmp = self.as_ptr();

        unsafe {
            let ptr = VirtualAlloc(
                0,
                new_layout.size(),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            );
            self.ptr = NonNull::new(ptr as *mut T).expect("Could not allocate memory!");
            copy_buffer(tmp, self.as_mut_ptr(), self.len());
            if !tmp.is_null() {
                VirtualFree(tmp as usize, 0, MEM_RELEASE);
            }
        }
        self.cap = new_cap;
    }
    pub fn truncate(&mut self, len: usize) {
        unsafe {
            if len > self.len {
                return;
            }
            let remaining_len = self.len - len;
            let s = ptr::slice_from_raw_parts_mut(self.as_mut_ptr().add(len), remaining_len);
            self.len = len;
            ptr::drop_in_place(s);
        }
    }
    pub unsafe fn set_len(&mut self, new_len: usize) {
        assert!(
            new_len <= self.capacity(),
            "Cannot set length({:X}) above capacity ({:X})",
            new_len,
            self.capacity()
        );

        self.len = new_len;
    }
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }
    pub fn as_mut_slice(&self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn capacity(&self) -> usize {
        self.cap
    }
}

struct DropTest(&'static mut i32);

impl Drop for DropTest {
    fn drop(&mut self) {
        println!("Dropping {:X}", self.0);
        *self.0 -= 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::svec::{DropTest, SVec, ToSVec};

    #[test]
    fn test_svec() {
        unsafe {
            let mut svec = SVec::new();
            svec.push(0);
            assert_eq!(svec.len(), 1);
        }
    }

    #[test]
    fn test_svec_capacity() {
        unsafe {
            let mut svec = SVec::new();
            assert_eq!(svec.capacity(), 0);
            svec.push(1);
            assert_eq!(svec.capacity(), 4);
            svec.push(2);
            svec.push(3);
            svec.push(4);
            assert_eq!(svec.capacity(), 4);
            svec.push(5);
            assert_eq!(svec.capacity(), 8);
        }
    }

    #[test]
    fn index() {
        let mut svec = SVec::new();
        svec.push(0x1000);
        assert_eq!(svec[0], 0x1000);
    }

    #[test]
    fn index_mut() {
        let mut svec = SVec::new();
        svec.push(0x1000);
        svec[0] = 0x2000;
        assert_eq!(svec[0], 0x2000);
    }

    #[test]
    fn slices() {
        let mut svec = SVec::new();
        svec.push(1);
        svec.push(2);
        svec.push(3);
        svec.push(4);
        svec.push(5);
        let indexed_slice = &svec[1..];
        assert_eq!(indexed_slice, [2, 3, 4, 5]);
    }

    static mut COUNT: i32 = 0;

    fn drop_test_function_call() {
        let mut svec = SVec::new();
        unsafe {
            COUNT = 16;
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
        }
    }

    #[test]
    fn drop_test() {
        drop_test_function_call();
        unsafe {
            assert_eq!(COUNT, 0);
        }
    }

    #[test]
    fn truncate_test() {
        let mut svec = SVec::new();
        unsafe {
            COUNT = 6;
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            svec.push(DropTest(&mut COUNT));
            println!("Truncating");
            svec.truncate(3);
            assert_eq!(svec.len(), 3);
            assert_eq!(COUNT, 3);
        }
    }

    #[test]
    fn formatting_test() {
        let mut svec = SVec::new();
        svec.push(0);
        svec.push(1);
        svec.push(2);
        svec.push(3);
        svec.push(4);
        svec.push(5);
        svec.push(6);
        svec.push(7);
        svec.push(8);
        svec.push(9);
        svec.push(10);
        svec.push(11);
        svec.push(12);
        svec.push(13);
        svec.push(14);
        svec.push(15);
        assert_eq!(
            format!("{:X}", svec),
            format!(
                "{:X?}",
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
        );
        assert_eq!(
            format!("{:x}", svec),
            format!(
                "{:x?}",
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
        );
        assert_eq!(
            format!("{}", svec),
            format!(
                "{:?}",
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            )
        );
    }
}
