#![allow(unused)]
use std::cmp::Ordering;
use std::mem::MaybeUninit;

#[derive(Debug)]
pub(crate) struct Heap<T> {
    data: Vec<MaybeUninit<T>>,
    len: usize,
    max_size: usize,
}

impl<T: Ord> Heap<T> {
    pub(crate) fn new(max_size: usize) -> Self {
        let mut data = Vec::with_capacity(max_size);
        for _ in 0..max_size {
            data.push(MaybeUninit::uninit());
        }

        Heap {
            data,
            len: 0,
            max_size,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.max_size
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn push(&mut self, item: T) -> bool {
        if self.len >= self.max_size {
            return false;
        }
        self.data[self.len].write(item);
        self.len += 1;
        self.sift_up(self.len - 1);
        true
    }

    pub(crate) fn peek(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            Some(unsafe { self.data[0].assume_init_ref() })
        }
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
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
                if self.data[pos]
                    .assume_init_ref()
                    .cmp(self.data[parent].assume_init_ref())
                    == Ordering::Greater
                {
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
                if left < len
                    && self.data[left]
                        .assume_init_ref()
                        .cmp(self.data[smallest].assume_init_ref())
                        == Ordering::Less
                {
                    smallest = left;
                }
                if right < len
                    && self.data[right]
                        .assume_init_ref()
                        .cmp(self.data[smallest].assume_init_ref())
                        == Ordering::Less
                {
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
    use crate::{L7Proto, PacketWrapper};
    use std::marker::PhantomData;
    use std::rc::Rc;

    #[test]
    fn test_memory_size() {
        let heap = Heap::<PacketWrapper<MyPacket, Rc<MyPacket>>>::new(32);
        assert_eq!(heap.capacity(), 32);
    }

    #[test]
    fn test_push_pop() {
        let mut heap = Heap::<_>::new(5);

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
        let mut heap = Heap::<PacketWrapper<MyPacket, Rc<MyPacket>>>::new(5);

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 990,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 995,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        heap.push(PacketWrapper {
            ptr: Rc::new(packet1.clone()),
            _phantom: PhantomData,
        });
        heap.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });
        heap.push(PacketWrapper {
            ptr: Rc::new(packet3.clone()),
            _phantom: PhantomData,
        });

        assert_eq!(heap.pop().map(|p| p.ptr.sequence), Some(990));
        assert_eq!(heap.pop().map(|p| p.ptr.sequence), Some(995));
        assert_eq!(heap.pop().map(|p| p.ptr.sequence), Some(1000));
        assert_eq!(heap.pop(), None);
    }

    #[test]
    fn test_packet_ordering_with_syn_fin() {
        let mut heap = Heap::<PacketWrapper<MyPacket, Rc<MyPacket>>>::new(5);

        let syn_packet = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 100,
            syn_flag: true,
            fin_flag: false,
            data: vec![],
        };

        let data_packet = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 101,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let fin_packet = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 104,
            syn_flag: false,
            fin_flag: true,
            data: vec![],
        };

        heap.push(PacketWrapper {
            ptr: Rc::new(fin_packet.clone()),
            _phantom: PhantomData,
        });
        heap.push(PacketWrapper {
            ptr: Rc::new(data_packet.clone()),
            _phantom: PhantomData,
        });
        heap.push(PacketWrapper {
            ptr: Rc::new(syn_packet.clone()),
            _phantom: PhantomData,
        });

        let first = heap.pop().unwrap().ptr;
        assert!(first.syn_flag);
        assert_eq!(first.sequence, 100);

        let second = heap.pop().unwrap().ptr;
        assert!(!second.syn_flag && !second.fin_flag);
        assert_eq!(second.sequence, 101);

        let third = heap.pop().unwrap().ptr;
        assert!(third.fin_flag);
        assert_eq!(third.sequence, 104);

        assert_eq!(heap.pop(), None);
    }

    #[test]
    fn test_heap_capacity_overflow() {
        let mut heap = Heap::<_>::new(2);

        assert!(heap.push(1)); // ok, returns true
        assert!(heap.push(2)); // ok, returns true
        assert!(!heap.push(3)); // capacity exceeded, returns false

        assert_eq!(heap.len(), 2); // length should still be 2
        assert_eq!(heap.pop(), Some(1));
        assert_eq!(heap.pop(), Some(2));
        assert_eq!(heap.pop(), None);
    }
}
