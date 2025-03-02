pub mod box_pool;
pub mod chunk_pool;

use box_pool::BoxPool;
use chunk_pool::ChunkPool;
use std::fmt;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr;
use std::rc::Rc;
use std::task::{Context, Poll};

#[derive(Clone, Copy, Debug)]
pub enum PoolType {
    Box,
    Chunk,
}

#[derive(Clone)]
pub(crate) enum PoolImpl {
    Box(Rc<BoxPool>),
    Chunk(Rc<ChunkPool>),
}

#[derive(Clone)]
pub(crate) struct Pool {
    pub(crate) inner: PoolImpl,
}

impl Pool {
    pub(crate) fn new(total_size: usize, obj_sizes: Vec<usize>) -> Self {
        Self::new_with_type(PoolType::Box, total_size, obj_sizes)
    }

    pub(crate) fn new_with_type(
        pool_type: PoolType,
        total_size: usize,
        obj_sizes: Vec<usize>,
    ) -> Self {
        let inner = match pool_type {
            PoolType::Box => PoolImpl::Box(Rc::new(BoxPool::new(total_size, obj_sizes))),
            PoolType::Chunk => PoolImpl::Chunk(Rc::new(ChunkPool::new(total_size, obj_sizes))),
        };
        Pool { inner }
    }

    pub(crate) fn init(&self) -> bool {
        if let PoolImpl::Chunk(pool) = &self.inner {
            pool.init()
        } else {
            true
        }
    }

    pub(crate) fn alloc<T, F>(&self, init: F) -> PoolBox<T>
    where
        F: FnOnce() -> T,
    {
        match &self.inner {
            PoolImpl::Box(pool) => pool.alloc(init, self.inner.clone()),
            PoolImpl::Chunk(pool) => pool.alloc(init, self.inner.clone()),
        }
    }

    pub(crate) fn alloc_future<F>(&self, future: F) -> Pin<PoolBox<dyn Future<Output = F::Output>>>
    where
        F: Future + 'static,
    {
        match &self.inner {
            PoolImpl::Box(pool) => pool.alloc_future(future, self.inner.clone()),
            PoolImpl::Chunk(pool) => pool.alloc_future(future, self.inner.clone()),
        }
    }
}

pub(crate) struct PoolBox<T: ?Sized> {
    pub(crate) ptr: *mut T,
    pub(crate) pool: PoolImpl,
}

impl<T> PoolBox<T> {
    pub fn into_raw(self) -> *mut T {
        let this = ManuallyDrop::new(self);
        unsafe {
            let _ = ptr::read(&this.pool);
        }
        this.ptr
    }

    pub(crate) unsafe fn from_raw(ptr: *mut T, pool: &Pool) -> Self {
        PoolBox {
            ptr,
            pool: pool.inner.clone(),
        }
    }
}

impl<T: ?Sized> Deref for PoolBox<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T: ?Sized> DerefMut for PoolBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr }
    }
}

impl<T: ?Sized> Drop for PoolBox<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                let _ = Box::from_raw(self.ptr);
            }
        }
    }
}

impl<F: Future> Future for PoolBox<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            let future = &mut *self.get_unchecked_mut().ptr;
            Pin::new_unchecked(future).poll(cx)
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for PoolBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
