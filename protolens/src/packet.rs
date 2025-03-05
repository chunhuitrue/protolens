use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;

#[repr(C)]
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub enum L7Proto {
    OrdPacket,
    Smtp,
    #[cfg(test)]
    RawPacket,
    #[cfg(test)]
    StreamNext,
    #[cfg(test)]
    StreamRead,
    #[cfg(test)]
    StreamReadline,
    #[cfg(test)]
    StreamReadline2,
    #[cfg(test)]
    StreamReadn,
    #[cfg(test)]
    StreamReadn2,
    Unknown,
}

#[repr(C)]
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub enum TransProto {
    Tcp,
    Udp,
    Other,
}

#[repr(C)]
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub enum PktDirection {
    Client2Server,
    Server2Client,
    BiDirection,
    Unknown,
}

pub trait Packet: Clone {
    fn direction(&self) -> PktDirection;
    fn l7_proto(&self) -> L7Proto;
    fn trans_proto(&self) -> TransProto;
    // tcp或者udp的源端口。否则为0
    fn tu_sport(&self) -> u16;
    // tcp或者udp的目的端口。否则为0
    fn tu_dport(&self) -> u16;
    // tcp 的原始seq。否则为0
    fn seq(&self) -> u32;
    fn syn(&self) -> bool;
    fn fin(&self) -> bool;
    fn payload_len(&self) -> usize;
    fn payload(&self) -> &[u8];
}

pub trait PacketBind: Packet + Ord + Debug + 'static {}
impl<T: Packet + Ord + Debug + 'static> PacketBind for T {}

// 表示可以用作包装器的智能指针
pub trait PtrWrapper<T: ?Sized>: Clone + Deref<Target = T> {}
impl<T: ?Sized> PtrWrapper<T> for Rc<T> {}
impl<T: ?Sized> PtrWrapper<T> for Arc<T> {}

pub trait PtrNew<T>: PtrWrapper<T> {
    fn new(value: T) -> Self;
}

impl<T> PtrNew<T> for Rc<T> {
    fn new(value: T) -> Self {
        Rc::new(value)
    }
}

impl<T> PtrNew<T> for Arc<T> {
    fn new(value: T) -> Self {
        Arc::new(value)
    }
}

// 包装结构体，必须实现以seq比较，才能用于数据包排序
#[derive(Debug)]
pub struct PacketWrapper<T: Packet, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) ptr: P,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: Packet, P: PtrWrapper<T> + PtrNew<T>> PartialEq for PacketWrapper<T, P> {
    fn eq(&self, other: &PacketWrapper<T, P>) -> bool {
        self.ptr.seq() == other.ptr.seq()
    }
}

impl<T: Packet, P: PtrWrapper<T> + PtrNew<T>> Eq for PacketWrapper<T, P> {}

impl<T: Packet + Ord, P: PtrWrapper<T> + PtrNew<T>> PartialOrd for PacketWrapper<T, P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Packet + Ord, P: PtrWrapper<T> + PtrNew<T>> Ord for PacketWrapper<T, P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ptr.seq().cmp(&other.ptr.seq())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MyPacket;

    #[test]
    fn test_same_seq() {
        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 1000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert_eq!(
            PacketWrapper {
                ptr: Rc::new(packet1),
                _phantom: PhantomData
            },
            PacketWrapper {
                ptr: Rc::new(packet2),
                _phantom: PhantomData
            }
        );
    }

    #[test]
    fn test_different_seq() {
        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 2000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert_ne!(
            PacketWrapper {
                ptr: Rc::new(packet1),
                _phantom: PhantomData
            },
            PacketWrapper {
                ptr: Rc::new(packet2),
                _phantom: PhantomData
            }
        );
    }

    #[test]
    fn test_greater_than() {
        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 2000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 1000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert!(
            PacketWrapper {
                ptr: Rc::new(packet1),
                _phantom: PhantomData
            } > PacketWrapper {
                ptr: Rc::new(packet2),
                _phantom: PhantomData
            }
        );
    }

    #[test]
    fn test_less_than() {
        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 2000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert!(
            PacketWrapper {
                ptr: Rc::new(packet1),
                _phantom: PhantomData
            } < PacketWrapper {
                ptr: Rc::new(packet2),
                _phantom: PhantomData
            }
        );
    }
}
