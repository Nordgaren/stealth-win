use std::{cmp, mem, ptr};
use std::alloc::Layout;
use std::fmt::{Display, Formatter, LowerHex, UpperHex};
use std::mem::size_of;
use std::ops::{Index, IndexMut};
use std::ptr::NonNull;
use std::slice::SliceIndex;
use crate::windows::kernel32::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree};

pub struct SVec<T> {
    ptr: NonNull<T>,
    cap: usize,
    len: usize,
}

impl<T> Display for SVec<T> where T: Display,  T: UpperHex, T: LowerHex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ ");
        for i in 0..self.len() {
            write!(f, "{}, ", self[i]);
        }
        write!(f, "{}{} ]\n", 8u8 as char, 8u8 as char);
        Ok(())
    }
}

impl<T, Idx> Index<Idx> for SVec<T> where Idx: SliceIndex<[T], Output = T> {
    type Output = T;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl<T, Idx> IndexMut<Idx> for SVec<T> where Idx: SliceIndex<[T], Output = T>  {
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

pub trait ToSVec<T> {
    fn to_svec(&self) -> SVec<T>;
}

impl<T> ToSVec<T> for &[T] where T: Sized {
    fn to_svec(&self) -> SVec<T> {
        let mut svec = SVec::new();
        svec.grow(self.len());
        let slice = svec.as_mut_slice();

        for i in 0..self.len() {
            unsafe {
                slice[i] = ptr::read(self.as_ptr().add(i));
            }
        }
        svec.len = self.len();
        svec
    }
}

impl<T> Drop for SVec<T> {
    fn drop(&mut self) {
        let ptr = self.ptr.as_ptr();
        unsafe {
            VirtualFree(ptr as usize, 0, MEM_RELEASE);
            #[cfg(test)]
            println!("Dropping SVec: {:X}", ptr as usize);
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

        let required_cap = self.len.checked_add(additional).expect(&format!("Could not grow len: {:X} additional: {:X}", self.len, additional));

        let cap = cmp::max(self.cap * 2, required_cap);
        let cap = cmp::max(Self::MIN_NON_ZERO_CAP, cap);
        let new_layout = Layout::array::<T>(cap).expect("Could not get layout.");
        let tmp = self.ptr.as_ptr();

        unsafe {
            let ptr = VirtualAlloc(0, new_layout.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            self.ptr = NonNull::new(ptr as *mut T).expect("Could not allocate memory!");
            copy_buffer(tmp, ptr as *mut T, self.len);
            if !tmp.is_null() {
                VirtualFree(tmp as usize, 0, MEM_RELEASE);
            }
        }
        self.cap = cap;
    }
    fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
    fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
    pub fn as_slice(&self) -> &[T] {
        unsafe {
            std::slice::from_raw_parts(self.as_ptr(), self.capacity())
        }
    }
    pub fn as_mut_slice(&self) -> &mut [T] {
        unsafe {
            std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.capacity())
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn capacity(&self) -> usize {
        self.cap
    }
}

unsafe fn copy_buffer<T>(src: *const T, dst: *mut T, len: usize) {
    let total_size = size_of::<T>() * len;
    let src_slice = std::slice::from_raw_parts(src as *const u8, total_size);
    let dst_slice = std::slice::from_raw_parts_mut(dst as *mut u8, total_size);

    for i in 0..total_size {
        dst_slice[i] = src_slice[i];
    }
}


#[cfg(test)]
mod tests {
    use crate::svec::SVec;

    #[test]
    fn test_svec() {
        unsafe {
            let mut svec = SVec::new();
            svec.push(0);
        }
    }

    #[test]
    fn test_svec_capacity() {
        unsafe {
            let mut svec = SVec::new();
            assert_eq!(svec.capacity(), 0);
            svec.push(1);
            assert_eq!(svec.capacity(), 4);
            svec.push(69);
            svec.push(420);
            svec.push(2);
            assert_eq!(svec.capacity(), 4);
            svec.push(3);
            assert_eq!(svec.capacity(), 8);
            println!("{}", svec)
        }
    }

    fn drop_vec() {
        let svec: SVec<u32> = SVec::new();
    }

    #[test]
    fn test_drop() {
        drop_vec();
    }

    #[test]
    fn index() {
        let mut svec = SVec::new();
        svec.push(420);
        println!("420 in hex: {:X}", svec[0]);
    }

    #[test]
    fn index_mut() {
        let mut svec = SVec::new();
        svec.push(420);
        svec[0] = 69;
        println!("69 in hex: {:X}", svec[0]);
    }
}