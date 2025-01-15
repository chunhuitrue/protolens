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

    // /// 计算一组数字的最小公倍数
    // fn calculate_lcm(sizes: Vec<usize>) -> usize {
    //     if sizes.is_empty() {
    //         return 0;
    //     }

    //     // 从第一个数开始，依次计算与下一个数的最小公倍数
    //     sizes.into_iter().fold(1, |acc, num| {
    //         // 避免计算时出现 0
    //         if num == 0 {
    //             acc
    //         } else {
    //             // lcm(a,b) = (a*b)/gcd(a,b)
    //             acc * num / Self::gcd(acc, num)
    //         }
    //     })
    // }

    // /// 计算两个数的最大公约数（使用辗转相除法）
    // fn gcd(mut a: usize, mut b: usize) -> usize {
    //     while b != 0 {
    //         let temp = b;
    //         b = a % b;
    //         a = temp;
    //     }
    //     a
    // }
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

    // #[test]
    // fn test_calculate_lcm() {
    //     assert_eq!(Pool::calculate_lcm(vec![2, 3]), 6);
    //     assert_eq!(Pool::calculate_lcm(vec![2, 4, 6]), 12);
    //     assert_eq!(Pool::calculate_lcm(vec![3, 5, 7]), 105);
    //     assert_eq!(Pool::calculate_lcm(vec![3, 5, 8]), 120);
    //     assert_eq!(Pool::calculate_lcm(vec![3, 5, 9]), 45);
    //     assert_eq!(Pool::calculate_lcm(vec![]), 0);
    //     assert_eq!(Pool::calculate_lcm(vec![0, 5]), 5);
    //     assert_eq!(Pool::calculate_lcm(vec![1]), 1);
    //     assert_eq!(Pool::calculate_lcm(vec![16, 20, 24]), 240);
    //     assert_eq!(Pool::calculate_lcm(vec![25, 35, 45]), 1575);
    //     assert_eq!(Pool::calculate_lcm(vec![48, 64, 96]), 192);
    //     assert_eq!(Pool::calculate_lcm(vec![17, 23, 29]), 11339);
    //     assert_eq!(Pool::calculate_lcm(vec![100, 200, 300]), 600);
    //     assert_eq!(Pool::calculate_lcm(vec![111, 222, 333]), 666);
    //     assert_eq!(Pool::calculate_lcm(vec![128, 125, 225]), 144000);
    //     assert_eq!(Pool::calculate_lcm(vec![144, 168, 192]), 4032);
    //     assert_eq!(Pool::calculate_lcm(vec![75, 80, 85]), 20400);
    //     assert_eq!(Pool::calculate_lcm(vec![150, 175, 200]), 4200);
    //     assert_eq!(Pool::calculate_lcm(vec![256, 384, 512]), 1536);
    //     assert_eq!(Pool::calculate_lcm(vec![365, 455, 545]), 3620435);
    //     assert_eq!(Pool::calculate_lcm(vec![625, 725, 825]), 598125);
    //     assert_eq!(Pool::calculate_lcm(vec![777, 888, 999]), 55944);
    //     assert_eq!(Pool::calculate_lcm(vec![512, 768, 896]), 10752);
    //     assert_eq!(Pool::calculate_lcm(vec![1024, 1536, 1792]), 21504);
    //     assert_eq!(Pool::calculate_lcm(vec![1111, 1234, 2222]), 1370974);
    //     assert_eq!(Pool::calculate_lcm(vec![1728, 1944, 2160]), 77760);
    //     assert_eq!(Pool::calculate_lcm(vec![256, 1024, 2048]), 2048);
    //     assert_eq!(Pool::calculate_lcm(vec![375, 1125, 1875]), 5625);
    //     assert_eq!(Pool::calculate_lcm(vec![196, 1568, 2352]), 4704);
    //     assert_eq!(Pool::calculate_lcm(vec![1237, 1733, 2341]), 5018450861);
    //     assert_eq!(Pool::calculate_lcm(vec![961, 1369, 1681]), 2211538729);
    // }
}
