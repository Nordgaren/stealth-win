use core::ops::{Deref, DerefMut};

pub struct Ptr<T> {
    address: *const T,
}

impl<T> Ptr<T> {
    pub fn from_ptr(address: *const T) -> Ptr<T> {
        Ptr { address }
    }
    pub fn from_usize(address: usize) -> Ptr<T> {
        Ptr {
            address: address as *const T,
        }
    }
    pub fn as_ptr(&self) -> *const T {
        self.address
    }
    pub fn set_address(&mut self, address: *const T) {
        self.address = address;
    }
}
impl<T> Deref for Ptr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.address }
    }
}

impl<T> Default for Ptr<T> {
    fn default() -> Self {
        Ptr {
            address: 0 as *mut T,
        }
    }
}

impl<T> From<*const T> for Ptr<T> {
    fn from(address: *const T) -> Self {
        Ptr { address }
    }
}

impl<T> From<*mut T> for Ptr<T> {
    fn from(address: *mut T) -> Self {
        Ptr { address }
    }
}
impl<T> From<MutPtr<T>> for Ptr<T> {
    fn from(address: MutPtr<T>) -> Self {
        Ptr {
            address: address.as_mut_ptr(),
        }
    }
}

pub struct MutPtr<T> {
    address: *mut T,
}
impl<T> MutPtr<T> {
    pub fn from_mut_ptr(address: *mut T) -> MutPtr<T> {
        MutPtr { address }
    }
    pub fn from_usize(address: usize) -> MutPtr<T> {
        MutPtr {
            address: address as *mut T,
        }
    }
    pub fn as_mut_ptr(&self) -> *mut T {
        self.address
    }
    pub fn set_address(&mut self, address: *mut T) {
        self.address = address;
    }
}

impl<T> Deref for MutPtr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.address }
    }
}

impl<T> DerefMut for MutPtr<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.address }
    }
}

impl<T> Default for MutPtr<T> {
    fn default() -> Self {
        MutPtr {
            address: 0 as *mut T,
        }
    }
}

impl<T> From<Ptr<T>> for MutPtr<T> {
    fn from(address: Ptr<T>) -> Self {
        MutPtr {
            address: address.as_ptr() as *mut T,
        }
    }
}

impl<T> From<*const T> for MutPtr<T> {
    fn from(address: *const T) -> Self {
        MutPtr {
            address: address as *mut T,
        }
    }
}

impl<T> From<*mut T> for MutPtr<T> {
    fn from(address: *mut T) -> Self {
        MutPtr { address }
    }
}
