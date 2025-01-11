#![allow(unused)]

use std::cmp::Ordering;
use crate::pool::{Pool, PoolBox};
use std::mem::MaybeUninit;
use std::rc::Rc;

/// 基于定长数组的二叉堆实现
#[derive(Debug)]
pub struct Heap<T, const N: usize> {
    data: PoolBox<[MaybeUninit<T>; N]>,
    len: usize,
}

impl<T: Ord, const N: usize> Heap<T, N> {
    pub fn memory_size() -> usize {
        std::mem::size_of::<[MaybeUninit<T>; N]>()
    }

    // 为 PacketWrapper 提供专门的初始化方法
    pub fn new_uninit_in_pool(pool: &Rc<Pool>) -> Self {
        let data = pool.alloc(|| unsafe { 
            std::mem::MaybeUninit::<[MaybeUninit<T>; N]>::uninit().assume_init()
        });
        Heap {
            data,
            len: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn push(&mut self, item: T) -> bool {
        if self.len >= N {
            return false;
        }
        self.data[self.len].write(item);
        self.len += 1;
        self.sift_up(self.len - 1);
        true
    }

    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            Some(unsafe { self.data[0].assume_init_ref() })
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }

        let item = unsafe { self.data[0].assume_init_read() };
        self.len -= 1;
        if !self.is_empty() {
            let last = unsafe { self.data[self.len].assume_init_read() };
            self.data[0].write(last);
            self.sift_down(0);
        }
        Some(item)
    }

    fn sift_up(&mut self, mut pos: usize) {
        while pos > 0 {
            let parent = (pos - 1) / 2;
            unsafe {
                if self.data[pos].assume_init_ref().cmp(self.data[parent].assume_init_ref()) == Ordering::Greater {
                    break;
                }
            }
            self.data.swap(pos, parent);
            pos = parent;
        }
    }

    fn sift_down(&mut self, mut pos: usize) {
        let len = self.len;
        loop {
            let mut smallest = pos;
            let left = 2 * pos + 1;
            let right = 2 * pos + 2;

            unsafe {
                if left < len && self.data[left].assume_init_ref().cmp(self.data[smallest].assume_init_ref()) == Ordering::Less {
                    smallest = left;
                }
                if right < len && self.data[right].assume_init_ref().cmp(self.data[smallest].assume_init_ref()) == Ordering::Less {
                    smallest = right;
                }
            }

            if smallest == pos {
                break;
            }

            self.data.swap(pos, smallest);
            pos = smallest;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MyPacket;
    use crate::PacketWrapper;

    #[test]
    fn test_memory_size() {
        let size = Heap::<PacketWrapper<MyPacket>, 32>::memory_size();
        let pool = Rc::new(Pool::new(vec![size]));
        let heap = Heap::<PacketWrapper<MyPacket>, 32>::new_uninit_in_pool(&pool);
        assert_eq!(heap.capacity(), 32);
    }

    #[test]
    fn test_push_pop() {
        let pool = Rc::new(Pool::new(vec![10]));
        let mut heap = Heap::<_, 5>::new_uninit_in_pool(&pool);
        
        assert!(heap.push(3));
        assert!(heap.push(1));
        assert!(heap.push(4));
        assert!(heap.push(2));
        assert!(heap.push(5));
        assert!(!heap.push(6)); // 超出容量,插入失败

        assert_eq!(heap.len(), 5);
        assert_eq!(heap.pop(), Some(1));
        assert_eq!(heap.pop(), Some(2));
        assert_eq!(heap.pop(), Some(3));
        assert_eq!(heap.pop(), Some(4));
        assert_eq!(heap.pop(), Some(5));
        assert_eq!(heap.pop(), None);
    }

    #[test]
    fn test_packet_ordering() {
        let pool = Rc::new(Pool::new(vec![10]));
        let mut heap = Heap::<PacketWrapper<MyPacket>, 5>::new_uninit_in_pool(&pool);

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 990,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 995,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        heap.push(PacketWrapper(packet1.clone()));
        heap.push(PacketWrapper(packet2.clone()));
        heap.push(PacketWrapper(packet3.clone()));

        assert_eq!(heap.pop().map(|p| p.0.sequence), Some(990));
        assert_eq!(heap.pop().map(|p| p.0.sequence), Some(995));
        assert_eq!(heap.pop().map(|p| p.0.sequence), Some(1000));
        assert_eq!(heap.pop(), None);
    }

    #[test]
    fn test_packet_ordering_with_syn_fin() {
        let pool = Rc::new(Pool::new(vec![10]));
        let mut heap = Heap::<PacketWrapper<MyPacket>, 5>::new_uninit_in_pool(&pool);

        let syn_packet = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 100,
            syn_flag: true,
            fin_flag: false,
            data: vec![],
        };

        let data_packet = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 101,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let fin_packet = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 104,
            syn_flag: false,
            fin_flag: true,
            data: vec![],
        };

        heap.push(PacketWrapper(fin_packet.clone()));
        heap.push(PacketWrapper(data_packet.clone()));
        heap.push(PacketWrapper(syn_packet.clone()));

        let first = heap.pop().unwrap().0;
        assert!(first.syn_flag);
        assert_eq!(first.sequence, 100);

        let second = heap.pop().unwrap().0;
        assert!(!second.syn_flag && !second.fin_flag);
        assert_eq!(second.sequence, 101);

        let third = heap.pop().unwrap().0;
        assert!(third.fin_flag);
        assert_eq!(third.sequence, 104);

        assert_eq!(heap.pop(), None);
    }

    #[test]
    fn test_heap_capacity_overflow() { 
        let pool = Rc::new(Pool::new(vec![10]));
        let mut heap = Heap::<_, 2>::new_uninit_in_pool(&pool);
        
        assert!(heap.push(1));     // ok, returns true
        assert!(heap.push(2));     // ok, returns true
        assert!(!heap.push(3));    // capacity exceeded, returns false
        
        assert_eq!(heap.len(), 2); // length should still be 2
        assert_eq!(heap.pop(), Some(1));
        assert_eq!(heap.pop(), Some(2));
        assert_eq!(heap.pop(), None);
    }
}
