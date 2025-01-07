use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct Pool {
    _marker: PhantomData<()>,
}

impl Pool {
    pub(crate) fn new(_capacity: usize) -> Self {
        Pool {
            _marker: PhantomData,
        }
    }
}

impl Pool {
    pub(crate) fn get<T, F>(&self, init: F) -> PoolBox<T>
    where
        F: FnOnce() -> T,
    {
        let ptr = Box::into_raw(Box::new(init()));
        PoolBox {
            ptr,
            pool: Rc::new(self.clone()),
        }
    }

    pub(crate) fn new_future<F>(&self, future: F) -> Pin<PoolBox<dyn Future<Output = F::Output>>>
    where
        F: Future + 'static,
    {
        let future = Box::new(future);
        let ptr = Box::into_raw(future) as *mut dyn Future<Output = F::Output>;
        unsafe {
            Pin::new_unchecked(PoolBox {
                ptr,
                pool: Rc::new(self.clone()),
            })
        }
    }
}

pub struct PoolBox<T: ?Sized> {
    ptr: *mut T,
    pool: Rc<Pool>,
}

impl<T> PoolBox<T> {
    pub fn pool(&self) -> &Rc<Pool> {
        &self.pool
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
        unsafe {
            let _ = Box::from_raw(self.ptr);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct TestObj {
        value: i32,
    }

    #[test]
    fn test_pool_basic() {
        let pool = Pool::new(10);
        let obj = pool.get(|| TestObj { value: 42 });

        assert_eq!(obj.value, 42);
    }

    #[test]
    fn test_pooled_object_deref() {
        let pool = Pool::new(10);
        let mut obj = pool.get(|| TestObj { value: 42 });

        // 测试解引用
        assert_eq!(obj.value, 42);

        // 测试可变解引用
        obj.value = 100;
        assert_eq!(obj.value, 100);
    }

    #[test]
    fn test_multiple_objects() {
        let pool = Pool::new(10);

        let obj1 = pool.get(|| TestObj { value: 1 });
        let obj2 = pool.get(|| TestObj { value: 2 });

        assert_eq!(obj1.value, 1);
        assert_eq!(obj2.value, 2);
    }
}
