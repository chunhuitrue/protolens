use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

pub struct Pool<T> {
    _phantom: PhantomData<T>,
}

pub struct PooledObject<T> {
    inner: Option<Box<T>>,
    pool: *const Pool<T>,
}

impl<T> Pool<T> {
    pub fn new(_capacity: usize) -> Self {
        Pool {
            _phantom: PhantomData,
        }
    }

    pub fn acquire<F>(&self, init: F) -> PooledObject<T>
    where
        F: FnOnce() -> T,
    {
        PooledObject {
            inner: Some(Box::new(init())),
            pool: self,
        }
    }

    fn release(&self, obj: Box<T>) {
        // 暂时直接丢弃对象，后续实现真正的回收逻辑
        drop(obj);
    }
}

impl<T> Deref for PooledObject<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap().as_ref()
    }
}

impl<T> DerefMut for PooledObject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap().as_mut()
    }
}

impl<T> Drop for PooledObject<T> {
    fn drop(&mut self) {
        // 取出内部的对象并归还给池
        if let Some(inner) = self.inner.take() {
            unsafe {
                (*self.pool).release(inner);
            }
        }
    }
}

impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self::new(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_basic_usage() {
        struct TestObj {
            value: i32,
        }

        let pool = Pool::<TestObj>::new(5);
        
        let obj = pool.acquire(|| TestObj { value: 42 });
        assert_eq!(obj.value, 42);
        
        // obj 会在这里自动 drop 并回收到池中
    }
}
