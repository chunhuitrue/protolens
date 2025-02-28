use crate::box_pool::*;
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
    // 将来可以添加其他类型
    // Custom,
}

#[derive(Clone)]
pub(crate) enum PoolImpl {
    Box(Rc<BoxPool>),
    // 将来可以添加其他实现
    // Custom(Rc<CustomPool>),
}

#[derive(Clone)]
pub(crate) struct Pool {
    inner: PoolImpl,
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
            // 将来添加其他实现
            // PoolType::Custom => PoolImpl::Custom(Rc::new(CustomPool::new(total_size, obj_sizes))),
        };
        Pool { inner }
    }

    pub(crate) fn alloc<T, F>(&self, init: F) -> PoolBox<T>
    where
        F: FnOnce() -> T,
    {
        match &self.inner {
            PoolImpl::Box(boxpool) => boxpool.alloc(init, self.inner.clone()),
            // 将来添加其他实现
            // PoolImpl::Custom(custompool) => custompool.alloc(init, self.inner.clone()),
        }
    }

    pub(crate) fn alloc_future<F>(&self, future: F) -> Pin<PoolBox<dyn Future<Output = F::Output>>>
    where
        F: Future + 'static,
    {
        match &self.inner {
            PoolImpl::Box(boxpool) => boxpool.alloc_future(future, self.inner.clone()),
            // 将来添加其他实现
            // PoolImpl::Custom(custompool) => custompool.alloc_future(future, self.inner.clone()),
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
        // let pool_ref = pool.inner.clone();
        let reconstructed_obj = unsafe { PoolBox::from_raw(raw_ptr, &pool) };

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
        // let pool_ref = pool.inner.clone();

        // 创建多个对象并测试转换
        let obj1 = pool.alloc(|| TestObj { value: 1 });
        let obj2 = pool.alloc(|| TestObj { value: 2 });

        let raw_ptr1 = obj1.into_raw();
        let raw_ptr2 = obj2.into_raw();

        // 重新构造并验证
        let reconstructed1 = unsafe { PoolBox::from_raw(raw_ptr1, &pool) };
        let reconstructed2 = unsafe { PoolBox::from_raw(raw_ptr2, &pool) };

        assert_eq!(reconstructed1.value, 1);
        assert_eq!(reconstructed2.value, 2);
    }

    #[test]
    fn test_into_raw_rc_count() {
        use std::rc::Rc;

        let pool = Pool::new(4096, vec![10]);

        // 获取 BoxPool 的引用，用于检查引用计数
        let boxpool = match &pool.inner {
            PoolImpl::Box(bp) => bp.clone(),
        };

        // 记录初始引用计数（此时应该是 2：一个在 pool.inner，一个在 boxpool）
        let initial_count = Rc::strong_count(&boxpool);
        assert_eq!(initial_count, 2);

        let obj = pool.alloc(|| 42);

        let count_after_alloc = Rc::strong_count(&boxpool);
        assert_eq!(count_after_alloc, 3);

        let pool_weak = Rc::downgrade(&boxpool);
        let raw_ptr = obj.into_raw();
        unsafe {
            assert_eq!(*raw_ptr, 42);
            // 使用 from_raw 重新构造 PoolBox
            let reconstructed = PoolBox::from_raw(raw_ptr, &pool);
            assert_eq!(*reconstructed, 42);
        }

        assert!(pool_weak.upgrade().is_some());
        // 验证最终引用计数与初始引用计数相同
        assert_eq!(Rc::strong_count(&boxpool), initial_count);
    }
}
