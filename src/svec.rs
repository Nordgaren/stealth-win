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
use std::slice::{Iter, SliceIndex};
use std::{cmp, fmt, mem, ptr};

pub struct SVec<T> {
    ptr: NonNull<T>,
    cap: usize,
    len: usize,
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
    #[inline]
    pub fn new() -> Self {
        SVec {
            ptr: NonNull::dangling(),
            cap: 0,
            len: 0,
        }
    }
    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        let mut svec = SVec::new();
        svec.grow(size);
        svec
    }
    #[inline]
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
    #[inline]
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
        if size_of::<T>() == 0 {
            panic!()
        }

        // For some reason, self.len.checked_add(additional) causes a crash if you are working in an unmapped PE.
        // Handle everything here, instead of bubbling up one function, like in Vec.
        let required_cap = self.len + additional;

        let new_cap = cmp::max(self.cap * 2, required_cap);
        let new_cap = cmp::max(Self::MIN_NON_ZERO_CAP, new_cap);
        let new_layout = Layout::array::<T>(new_cap).unwrap();

        unsafe {
            let tmp = self.as_ptr();
            let ptr = VirtualAlloc(
                0,
                new_layout.size(),
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            );
            self.ptr = NonNull::new(ptr as *mut T).unwrap();
            copy_buffer(tmp, self.as_mut_ptr(), self.len());
            VirtualFree(tmp as usize, 0, MEM_RELEASE);
        }
        self.cap = new_cap;
    }
    pub fn resize(&mut self, new_len: usize, value: T)
    where
        T: Clone,
    {
        let len = self.len();

        if new_len > len {
            self.extend_with(new_len - len, value)
        } else {
            self.truncate(new_len);
        }
    }
    pub fn extend_with(&mut self, n: usize, value: T)
    where
        T: Clone,
    {
        self.grow(self.len + n);
        let old_size = self.len;
        self.len += n;

        for i in old_size..self.len {
            self[i] = value.clone();
        }
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
    #[inline]
    pub unsafe fn set_len(&mut self, new_len: usize) {
        assert!(new_len <= self.capacity());

        self.len = new_len;
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }
    #[inline]
    pub fn as_mut_slice(&self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }
    #[inline]
    pub fn iter(&self) -> Iter<'_, T> {
        self.as_slice().iter()
    }
}

impl<T> FromIterator<T> for SVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut iterator = iter.into_iter();
        let mut svec = SVec::new();

        while let Some(item) = iterator.next() {
            svec.push(item);
        }

        svec
    }
}

impl<'a, T> IntoIterator for &'a SVec<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

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
            VirtualFree(self.as_ptr() as usize, 0, MEM_RELEASE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DUMMY_SLICE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

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
        let mut svec: SVec<u8> = (0..=15).collect();

        assert_eq!(&svec[1..], &DUMMY_SLICE[1..]);
    }

    static mut DROP_COUNT: i32 = 0;

    struct DropTest(i32);
    impl Drop for DropTest {
        fn drop(&mut self) {
            unsafe {
                DROP_COUNT -= self.0;
            }
        }
    }

    fn drop_test_function_call() {
        let mut svec = SVec::new();
        unsafe {
            svec.push(DropTest(1));
        }
    }

    #[test]
    fn drop_test() {
        unsafe {
            DROP_COUNT = 1;
            drop_test_function_call();
            assert_eq!(DROP_COUNT, 0);
        }
    }

    #[test]
    fn truncate_test() {
        let mut svec = SVec::new();
        unsafe {
            DROP_COUNT = 2;
            svec.push(DropTest(1));
            svec.push(DropTest(1));
            svec.truncate(1);
            assert_eq!(svec.len(), 1);
            assert_eq!(DROP_COUNT, 1);
        }
    }

    #[test]
    fn formatting_test() {
        let mut svec: SVec<u32> = (0..=15).collect();

        assert_eq!(format!("{:X}", svec), format!("{:X?}", DUMMY_SLICE));
        assert_eq!(format!("{:x}", svec), format!("{:x?}", DUMMY_SLICE));
        assert_eq!(format!("{}", svec), format!("{:?}", DUMMY_SLICE));
    }

    #[test]
    fn collect_test() {
        let svec: SVec<u8> = (0..=15).collect();

        assert_eq!(svec.as_slice(), &DUMMY_SLICE);
    }

    #[test]
    fn iter_test() {
        let svec: SVec<u8> = (0..=15).collect();

        for (i, b) in svec.iter().enumerate() {
            assert_eq!(*b, DUMMY_SLICE[i])
        }
    }

    const GROW_LEN: usize = 10;
    #[test]
    fn resize_grow() {
        let mut svec = SVec::new();
        svec.resize(GROW_LEN, 0);
        assert_eq!(&svec[..], [0; GROW_LEN])
    }

    #[test]
    fn resize_shrink() {
        let mut svec: SVec<u8> = (0..=15).collect();
        svec.resize(10, 0);
        assert_eq!(&svec[..], &DUMMY_SLICE[..=9])
    }
}
