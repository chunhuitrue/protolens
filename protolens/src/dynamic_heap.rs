#![allow(unused)]

use crate::heap::Heap;
use crate::pool::{Pool, PoolBox};
use std::rc::Rc;

pub type Heap32<T> = Heap<T, 32>;
pub type Heap64<T> = Heap<T, 64>;
pub type Heap128<T> = Heap<T, 128>;
pub type Heap256<T> = Heap<T, 256>;
pub type Heap512<T> = Heap<T, 512>;
pub type Heap1024<T> = Heap<T, 1024>;

#[derive(Debug)]
pub enum DynamicHeap<T> {
    Size32(Heap32<T>),
    Size64(Heap64<T>),
    Size128(Heap128<T>),
    Size256(Heap256<T>),
    Size512(Heap512<T>),
    Size1024(Heap1024<T>),
}

impl<T: Ord> DynamicHeap<T> {
    pub fn new_in_pool(pool: &Rc<Pool>, capacity: usize) -> Self {
        match capacity {
            0..=32 => DynamicHeap::Size32(Heap32::new_uninit_in_pool(pool)),
            33..=64 => DynamicHeap::Size64(Heap64::new_uninit_in_pool(pool)),
            65..=128 => DynamicHeap::Size128(Heap128::new_uninit_in_pool(pool)),
            129..=256 => DynamicHeap::Size256(Heap256::new_uninit_in_pool(pool)),
            257..=512 => DynamicHeap::Size512(Heap512::new_uninit_in_pool(pool)),
            _ => DynamicHeap::Size1024(Heap1024::new_uninit_in_pool(pool)),
        }
    }

    pub fn memory_size(capacity: usize) -> usize {
        match capacity {
            0..=32 => Heap32::<T>::array_size(),
            33..=64 => Heap64::<T>::array_size(),
            65..=128 => Heap128::<T>::array_size(),
            129..=256 => Heap256::<T>::array_size(),
            257..=512 => Heap512::<T>::array_size(),
            _ => Heap1024::<T>::array_size(),
        }
    }

    pub fn capacity(&self) -> usize {
        match self {
            DynamicHeap::Size32(_) => 32,
            DynamicHeap::Size64(_) => 64,
            DynamicHeap::Size128(_) => 128,
            DynamicHeap::Size256(_) => 256,
            DynamicHeap::Size512(_) => 512,
            DynamicHeap::Size1024(_) => 1024,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            DynamicHeap::Size32(h) => h.len(),
            DynamicHeap::Size64(h) => h.len(),
            DynamicHeap::Size128(h) => h.len(),
            DynamicHeap::Size256(h) => h.len(),
            DynamicHeap::Size512(h) => h.len(),
            DynamicHeap::Size1024(h) => h.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            DynamicHeap::Size32(h) => h.is_empty(),
            DynamicHeap::Size64(h) => h.is_empty(),
            DynamicHeap::Size128(h) => h.is_empty(),
            DynamicHeap::Size256(h) => h.is_empty(),
            DynamicHeap::Size512(h) => h.is_empty(),
            DynamicHeap::Size1024(h) => h.is_empty(),
        }
    }

    pub fn clear(&mut self) {
        match self {
            DynamicHeap::Size32(h) => h.clear(),
            DynamicHeap::Size64(h) => h.clear(),
            DynamicHeap::Size128(h) => h.clear(),
            DynamicHeap::Size256(h) => h.clear(),
            DynamicHeap::Size512(h) => h.clear(),
            DynamicHeap::Size1024(h) => h.clear(),
        }
    }

    pub fn push(&mut self, item: T) -> bool {
        match self {
            DynamicHeap::Size32(h) => h.push(item),
            DynamicHeap::Size64(h) => h.push(item),
            DynamicHeap::Size128(h) => h.push(item),
            DynamicHeap::Size256(h) => h.push(item),
            DynamicHeap::Size512(h) => h.push(item),
            DynamicHeap::Size1024(h) => h.push(item),
        }
    }

    pub fn peek(&self) -> Option<&T> {
        match self {
            DynamicHeap::Size32(h) => h.peek(),
            DynamicHeap::Size64(h) => h.peek(),
            DynamicHeap::Size128(h) => h.peek(),
            DynamicHeap::Size256(h) => h.peek(),
            DynamicHeap::Size512(h) => h.peek(),
            DynamicHeap::Size1024(h) => h.peek(),
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        match self {
            DynamicHeap::Size32(h) => h.pop(),
            DynamicHeap::Size64(h) => h.pop(),
            DynamicHeap::Size128(h) => h.pop(),
            DynamicHeap::Size256(h) => h.pop(),
            DynamicHeap::Size512(h) => h.pop(),
            DynamicHeap::Size1024(h) => h.pop(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_heap_basic() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut heap = DynamicHeap::new_in_pool(&pool, 50);

        assert!(heap.push(3));
        assert!(heap.push(1));
        assert!(heap.push(4));
        assert!(heap.push(2));

        assert_eq!(heap.pop(), Some(1));
        assert_eq!(heap.pop(), Some(2));
        assert_eq!(heap.pop(), Some(3));
        assert_eq!(heap.pop(), Some(4));
        assert_eq!(heap.pop(), None);
    }

    #[test]
    fn test_dynamic_heap_capacity() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut heap = DynamicHeap::new_in_pool(&pool, 32);

        for i in 0..32 {
            assert!(heap.push(i));
        }
        assert_eq!(heap.len(), 32);

        // 第33个元素应该插入失败
        assert!(!heap.push(33));
    }
}
