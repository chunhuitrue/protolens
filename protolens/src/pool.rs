use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr;
use std::rc::Rc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct Pool {
    _marker: PhantomData<()>,
}

impl Pool {
    pub fn new(_total_size: usize, _obj_sizes: Vec<usize>) -> Self {
        Pool {
            _marker: PhantomData,
        }
    }

    pub(crate) fn alloc<T, F>(&self, init: F) -> PoolBox<T>
    where
        F: FnOnce() -> T,
    {
        let ptr = Box::into_raw(Box::new(init()));
        PoolBox {
            ptr,
            pool: Rc::new(self.clone()),
        }
    }

    pub(crate) fn alloc_future<F>(&self, future: F) -> Pin<PoolBox<dyn Future<Output = F::Output>>>
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

pub(crate) struct PoolBox<T: ?Sized> {
    ptr: *mut T,
    #[allow(dead_code)]
    pool: Rc<Pool>,
}

impl<T> PoolBox<T> {
    pub fn into_raw(self) -> *mut T {
        let this = ManuallyDrop::new(self);
        unsafe {
            let _ = ptr::read(&this.pool);
        }
        this.ptr
    }

    pub unsafe fn from_raw(ptr: *mut T, pool: Rc<Pool>) -> Self {
        PoolBox { ptr, pool }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct TestObj {
        value: i32,
    }

    #[test]
    fn test_pool_basic() {
        let pool = Pool::new(4096, vec![10]);
        let obj = pool.alloc(|| TestObj { value: 42 });

        assert_eq!(obj.value, 42);
    }

    #[test]
    fn test_pooled_object_deref() {
        let pool = Pool::new(4096, vec![10]);
        let mut obj = pool.alloc(|| TestObj { value: 42 });

        // 测试解引用
        assert_eq!(obj.value, 42);

        // 测试可变解引用
        obj.value = 100;
        assert_eq!(obj.value, 100);
    }

    #[test]
    fn test_multiple_objects() {
        let pool = Pool::new(4096, vec![10]);

        let obj1 = pool.alloc(|| TestObj { value: 1 });
        let obj2 = pool.alloc(|| TestObj { value: 2 });

        assert_eq!(obj1.value, 1);
        assert_eq!(obj2.value, 2);
    }

    #[test]
    fn test_into_raw_from_raw() {
        let pool = Pool::new(4096, vec![10]);
        let obj = pool.alloc(|| TestObj { value: 42 });

        // 转换为原始指针
        let raw_ptr = obj.into_raw();

        // 使用 from_raw 重新构造 PoolBox
        let pool_ref = Rc::new(pool);
        let reconstructed_obj = unsafe { PoolBox::from_raw(raw_ptr, pool_ref) };

        // 验证重构后的对象值正确
        assert_eq!(reconstructed_obj.value, 42);

        // 修改重构后的对象并验证
        let mut obj2 = reconstructed_obj;
        obj2.value = 100;
        assert_eq!(obj2.value, 100);
    }

    #[test]
    fn test_multiple_into_raw_from_raw() {
        let pool = Pool::new(4096, vec![10]);
        let pool_ref = Rc::new(pool);

        // 创建多个对象并测试转换
        let obj1 = pool_ref.alloc(|| TestObj { value: 1 });
        let obj2 = pool_ref.alloc(|| TestObj { value: 2 });

        let raw_ptr1 = obj1.into_raw();
        let raw_ptr2 = obj2.into_raw();

        // 重新构造并验证
        let reconstructed1 = unsafe { PoolBox::from_raw(raw_ptr1, pool_ref.clone()) };
        let reconstructed2 = unsafe { PoolBox::from_raw(raw_ptr2, pool_ref.clone()) };

        assert_eq!(reconstructed1.value, 1);
        assert_eq!(reconstructed2.value, 2);
    }

    #[test]
    fn test_into_raw_rc_count() {
        use std::rc::Rc;

        let pool = Pool::new(4096, vec![10]);
        let pool_rc = Rc::new(pool);
        let pool_weak = Rc::downgrade(&pool_rc);

        let obj = PoolBox {
            ptr: Box::into_raw(Box::new(42)),
            pool: pool_rc.clone(),
        };
        assert_eq!(Rc::strong_count(&pool_rc), 2); // 一个在 pool_rc，一个在 obj.pool

        let raw_ptr = obj.into_raw();
        assert_eq!(Rc::strong_count(&pool_rc), 1); // 现在只剩下 pool_rc

        // 验证指针仍然有效
        unsafe {
            assert_eq!(*raw_ptr, 42);
            // 清理测试资源
            let _ = Box::from_raw(raw_ptr);
        }

        // 验证 weak 引用仍然有效
        assert!(pool_weak.upgrade().is_some());
    }
}
