use crate::pool::*;
use std::marker::PhantomData;
use std::pin::Pin;

#[derive(Clone)]
pub(crate) struct BoxPool {
    _marker: PhantomData<()>,
}

impl BoxPool {
    pub(crate) fn new(_total_size: usize, _obj_sizes: Vec<usize>) -> Self {
        BoxPool {
            _marker: PhantomData,
        }
    }

    pub(crate) fn alloc<T, F>(&self, init: F, pool_impl: PoolImpl) -> PoolBox<T>
    where
        F: FnOnce() -> T,
    {
        let ptr = Box::into_raw(Box::new(init()));
        PoolBox {
            ptr,
            pool: pool_impl,
        }
    }

    pub(crate) fn alloc_future<F>(
        &self,
        future: F,
        pool_impl: PoolImpl,
    ) -> Pin<PoolBox<dyn Future<Output = F::Output>>>
    where
        F: Future + 'static,
    {
        let future = Box::new(future);
        let ptr = Box::into_raw(future) as *mut dyn Future<Output = F::Output>;
        unsafe {
            Pin::new_unchecked(PoolBox {
                ptr,
                pool: pool_impl,
            })
        }
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
            _ => panic!("Expected BoxPool implementation"),
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
