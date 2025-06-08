use std::cmp::{Ord, Ordering, PartialOrd};
use std::fmt::Debug;
use std::net::IpAddr;

#[repr(C)]
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Hash)]
pub enum L7Proto {
    OrdPacket = 0,
    Smtp,
    Pop3,
    Imap,
    Http,
    FtpCmd,
    FtpData,
    Sip,
    DnsUdp,

    #[cfg(test)]
    RawPacket,
    #[cfg(test)]
    Byte,
    #[cfg(test)]
    Read,
    #[cfg(any(test, feature = "bench"))]
    Readline,
    #[cfg(test)]
    Readn,
    #[cfg(test)]
    ReadBdry,
    #[cfg(test)]
    ReadDash,
    #[cfg(test)]
    ReadOctet,
    #[cfg(test)]
    ReadEof,

    Unknown,
}

#[repr(C)]
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub enum TransProto {
    Tcp,
    Udp,
}

#[repr(C)]
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
pub enum Direction {
    C2s,
    S2c,
    BiDir,
    Unknown,
}

pub trait Packet: Clone {
    fn trans_proto(&self) -> TransProto;
    fn sip(&self) -> IpAddr;
    fn dip(&self) -> IpAddr;
    // tcp或者udp的源端口。否则为0。主机字节序
    fn tu_sport(&self) -> u16;
    // tcp或者udp的目的端口。否则为0。主机字节序
    fn tu_dport(&self) -> u16;
    // tcp 的原始seq。否则为0
    fn seq(&self) -> u32;
    fn syn(&self) -> bool;
    fn fin(&self) -> bool;
    fn payload_len(&self) -> usize;
    fn payload(&self) -> &[u8];
}

#[derive(Clone, Debug)]
pub(crate) struct SeqPacket<T: Packet>(T);

impl<T: Packet> SeqPacket<T> {
    pub(crate) fn new(packet: T) -> Self {
        SeqPacket(packet)
    }

    pub(crate) fn inner(&self) -> &T {
        &self.0
    }

    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Packet> PartialEq for SeqPacket<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.seq() == other.0.seq()
    }
}

impl<T: Packet> Eq for SeqPacket<T> {}

impl<T: Packet> PartialOrd for SeqPacket<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Packet> Ord for SeqPacket<T> {
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
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 1000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert_eq!(SeqPacket::new(packet1), SeqPacket::new(packet2));
    }

    #[test]
    fn test_different_seq() {
        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 2000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert_ne!(SeqPacket::new(packet1), SeqPacket::new(packet2));
    }

    #[test]
    fn test_greater_than() {
        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 2000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 1000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert!(SeqPacket::new(packet1) > SeqPacket::new(packet2));
    }

    #[test]
    fn test_less_than() {
        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 2000,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        assert!(SeqPacket::new(packet1) < SeqPacket::new(packet2));
    }
}
