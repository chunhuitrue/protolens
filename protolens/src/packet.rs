use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt::Debug;

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

pub trait Packet {
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

// 包装结构体，必须实现以seq比较，才能用于数据包排序
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct PacketWrapper<T>(pub T);

impl<T: Packet> PartialEq for PacketWrapper<T> {
    fn eq(&self, other: &PacketWrapper<T>) -> bool {
        self.0.seq() == other.0.seq()
    }
}

impl<T: Packet> Eq for PacketWrapper<T> {}

impl<T: Packet + Ord> PartialOrd for PacketWrapper<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Packet + Ord> Ord for PacketWrapper<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.seq().cmp(&other.0.seq())
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

        assert_eq!(PacketWrapper(packet1), PacketWrapper(packet2));
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

        assert_ne!(PacketWrapper(packet1), PacketWrapper(packet2));
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

        assert!(PacketWrapper(packet1) > PacketWrapper(packet2));
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

        assert!(PacketWrapper(packet1) < PacketWrapper(packet2));
    }
}
