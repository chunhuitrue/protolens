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
