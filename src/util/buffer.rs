
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

use super::kind::*;

#[repr(transparent)]
pub struct OwnedBuffer<T, const N: usize, K = NoKindTag<T>>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    data: [T; N],
    _phantom: std::marker::PhantomData<K>,
}

impl<T, const N: usize, K> Clone for OwnedBuffer<T, N, K>
where 
    T: Clone,
    K: Kind<Item = T>,
{
    fn clone(&self) -> Self {
        let mut new = MaybeUninit::<Self>::uninit();
        unsafe {
            new.as_mut_ptr().copy_from_nonoverlapping(self as *const _, 1);
            new.assume_init()
        }
    }
}

impl<T, const N: usize, K> Copy for OwnedBuffer<T, N, K>
where 
    T: Copy,
    K: Kind<Item = T>,
{}

impl<T, const N: usize, K> Default for OwnedBuffer<T, N, K>
where 
    T: Default + Sized + Copy,
    K: Kind<Item = T>,
{
    fn default() -> Self {
        Self {
            data: [T::default(); N],
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T, const N: usize, K> Deref for OwnedBuffer<T, N, K>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    type Target = [T; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, const N: usize, K> DerefMut for OwnedBuffer<T, N, K>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T, const N: usize, K> Debug for OwnedBuffer<T, N, K>
where 
    T: Debug,
    K: Kind<Item = T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.data[..].fmt(f)
    }
}

impl<T, const N: usize, K> PartialEq for OwnedBuffer<T, N, K>
where 
    T: PartialEq,
    K: Kind<Item = T>,
{
    fn eq(&self, other: &Self) -> bool {
        self.data[..] == other.data[..]
    }
}

impl<T, const N: usize, K> Eq for OwnedBuffer<T, N, K>
where 
    T: Eq,
    K: Kind<Item = T>,
{}

impl<T, const N: usize, K> Hash for OwnedBuffer<T, N, K>
where 
    T: Hash,
    K: Kind<Item = T>,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data[..].hash(state)
    }
}

impl<T, const N: usize, K> OwnedBuffer<T, N, K>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    pub unsafe fn new_zeroed() -> Self {
        std::mem::zeroed()
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub fn as_ptr(&self) -> *const T {
        self.data.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.data.as_mut_ptr()
    }

    pub fn as_slice(&self) -> &[T; N] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [T; N] {
        &mut self.data
    }

    pub fn into_inner(self) -> [T; N] {
        self.data
    }
}

#[repr(transparent)]
pub struct BorrowedConstBuffer<'a, T, const N: usize, K = NoKindTag<T>>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    ptr: *const T,
    _phantom: std::marker::PhantomData<(&'a [T; N], K)>,
}

impl<'a, T, const N: usize, K> Clone for BorrowedConstBuffer<'a, T, N, K>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    fn clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, T, const N: usize, K> Deref for BorrowedConstBuffer<'a, T, N, K>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    type Target = [T; N];

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.ptr as *const [T; N]) }
    }
}

impl<'a, T, const N: usize, K> Debug for BorrowedConstBuffer<'a, T, N, K>
where 
    T: Debug,
    K: Kind<Item = T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.deref().fmt(f)
    }
}

impl<'a, T, const N: usize, K> BorrowedConstBuffer<'a, T, N, K>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    pub unsafe fn new(ptr: *const T) -> Self {
        Self {
            ptr,
            _phantom: std::marker::PhantomData,
        }
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    pub fn as_slice(&self) -> &[T; N] {
        self.deref()
    }
}

#[derive(Debug, Clone)]
pub enum Buffer<'a, T, const N: usize, K = NoKindTag<T>>
where 
    T: Sized,
    K: Kind<Item = T>,
{
    Owned(OwnedBuffer<T, N, K>),
    Borrowed(BorrowedConstBuffer<'a, T, N, K>),
}
