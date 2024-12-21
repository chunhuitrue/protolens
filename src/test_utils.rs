use crate::{Packet, TransProto};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MyPacket {
    pub sport: u16,
    pub dport: u16,
    pub sequence: u32,
    pub syn_flag: bool,
    pub fin_flag: bool,
    pub data: Vec<u8>,
}

impl MyPacket {
    pub fn new(seq: u32, fin: bool) -> Self {
        MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: seq,
            syn_flag: false,
            fin_flag: fin,
            data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        }
    }
}

impl Packet for MyPacket {
    fn trans_proto(&self) -> TransProto {
        TransProto::Tcp
    }

    fn tu_sport(&self) -> u16 {
        self.sport
    }

    fn tu_dport(&self) -> u16 {
        self.dport
    }

    fn seq(&self) -> u32 {
        self.sequence
    }

    fn syn(&self) -> bool {
        self.syn_flag
    }

    fn fin(&self) -> bool {
        self.fin_flag
    }

    fn payload_len(&self) -> usize {
        self.data.len()
    }

    fn payload(&self) -> &[u8] {
        &self.data
    }
}
