use crate::Packet;
use crate::PacketWrapper;
use crate::TransProto;
use futures::future;
use futures::future::poll_fn;
use futures::Future;
use futures_util::stream::{Stream, StreamExt};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

const MAX_CACHE_PKTS: usize = 32;

#[derive(Debug, Clone)]
pub struct PktStrm<T>
where
    T: Packet,
    PacketWrapper<T>: PartialEq + Eq + PartialOrd + Ord,
{
    cache: BinaryHeap<Reverse<PacketWrapper<T>>>,
    next_seq: u32, // 下一个要读取的seq
    fin: bool,
}

impl<T> PktStrm<T>
where
    T: Packet,
    PacketWrapper<T>: PartialEq + Eq + PartialOrd + Ord,
{
    pub fn new() -> Self {
        PktStrm {
            cache: BinaryHeap::with_capacity(MAX_CACHE_PKTS),
            next_seq: 0,
            fin: false,
        }
    }

    pub fn push(&mut self, packet: T) {
        if packet.trans_proto() != TransProto::Tcp {
            return;
        }
        if self.cache.len() >= MAX_CACHE_PKTS {
            return;
        }

        let pkt = PacketWrapper(packet);
        self.cache.push(Reverse(pkt));
    }

    // 无论是否严格seq连续，peek一个当前最有序的包
    // 不更新next_seq
    pub fn peek(&self) -> Option<&T> {
        self.cache.peek().map(|r| &r.0 .0)
    }

    // 无论是否严格seq连续，都pop一个当前包。
    // 注意：next_seq由调用者负责
    pub fn pop(&mut self) -> Option<T> {
        if let Some(pkt) = self.cache.pop().map(|r| r.0 .0) {
            if pkt.fin() {
                self.fin = true;
            }
            return Some(pkt);
        }
        None
    }

    // top位置和当前next_seq对比并去重
    fn top_dedup(&mut self) {
        while let Some(pkt) = self.peek() {
            if (pkt.fin() && pkt.payload_len() == 0) || (pkt.syn() && pkt.payload_len() == 0) {
                return;
            }

            if pkt.seq() + pkt.payload_len() as u32 <= self.next_seq {
                self.pop();
                continue;
            }
            return;
        }
    }

    // 严格有序。peek一个seq严格有序的包，可能包含payload为0的。如果当前top有序，就peek，否则就none。
    pub fn peek_ord(&mut self) -> Option<&T> {
        if self.next_seq == 0 {
            if let Some(pkt) = self.peek() {
                self.next_seq = pkt.seq();
            }
            return self.peek();
        }

        self.top_dedup();
        if let Some(pkt) = self.peek() {
            if pkt.seq() <= self.next_seq {
                return Some(pkt);
            }
        }
        None
    }

    // 严格有序。弹出一个严格有序的包，可能包含载荷为0的。否则为none
    // 并不需要关心fin标记，这不是pkt这一层关心的问题
    pub fn pop_ord(&mut self) -> Option<T> {
        if let Some(pkt) = self.peek_ord() {
            let seq = pkt.seq();
            let payload_len = pkt.payload_len() as u32;
            if pkt.syn() && payload_len == 0 {
                self.next_seq += 1;
            } else if self.next_seq == seq {
                self.next_seq += payload_len;
            } else if self.next_seq > seq {
                self.next_seq += payload_len - (self.next_seq - seq);
            }
            return self.pop();
        }
        None
    }

    // 严格有序。peek出一个带数据的严格有序的包。否则为none
    pub fn peek_ord_data(&mut self) -> Option<&T> {
        while let Some(pkt) = self.peek_ord() {
            if pkt.payload_len() == 0 {
                self.pop_ord();
                continue;
            }

            break;
        }
        self.peek_ord()
    }

    // 严格有序。pop一个带数据的严格有序的包。否则为none
    pub fn pop_ord_data(&mut self) -> Option<T> {
        if let Some(pkt) = self.peek_ord_data() {
            let seq = pkt.seq();
            let payload_len = pkt.payload_len() as u32;
            match self.next_seq.cmp(&seq) {
                std::cmp::Ordering::Equal => self.next_seq += payload_len,
                std::cmp::Ordering::Greater => self.next_seq += payload_len - (self.next_seq - seq),
                std::cmp::Ordering::Less => {}
            }
            return self.pop();
        }
        None
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub async fn readn(&mut self, num: usize) -> Vec<u8> {
        self.take(num).collect::<Vec<u8>>().await
    }

    pub async fn readline(&mut self) -> Result<String, std::string::FromUtf8Error> {
        let mut res = self
            .take_while(|x| future::ready(*x != b'\n'))
            .collect::<Vec<u8>>()
            .await;
        if !res.is_empty() {
            res.push(b'\n');
        }
        String::from_utf8(res)
    }

    // 异步方式获取下一个原始顺序的包。包含载荷为0的。如果cache中每到来一个包，就调用，那就是原始到来的包顺序
    pub fn next_raw_pkt(&mut self) -> impl Future<Output = Option<T>> + '_ {
        poll_fn(|_cx| {
            if let Some(_pkt) = self.peek() {
                return Poll::Ready(self.pop());
            }
            Poll::Pending
        })
    }

    // 异步方式获取下一个严格有序的包。包含载荷为0的
    pub fn next_ord_pkt(&mut self) -> impl Future<Output = Option<T>> + '_ {
        poll_fn(|_cx| {
            if let Some(pkt) = self.pop_ord() {
                return Poll::Ready(Some(pkt));
            }
            if self.fin {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
    }
}

impl<T> Default for PktStrm<T>
where
    T: Packet,
    PacketWrapper<T>: PartialEq + Eq + PartialOrd + Ord,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for PktStrm<T>
where
    T: Packet,
    PacketWrapper<T>: PartialEq + Eq + PartialOrd + Ord,
{
    fn drop(&mut self) {
        self.cache.clear();
    }
}

impl<T> Unpin for PktStrm<T>
where
    T: Packet,
    PacketWrapper<T>: PartialEq + Eq + PartialOrd + Ord,
{
}

impl<T> Stream for PktStrm<T>
where
    T: Packet,
    PacketWrapper<T>: PartialEq + Eq + PartialOrd + Ord,
{
    type Item = u8;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        let (seq, payload_len) = if let Some(pkt) = this.peek_ord_data() {
            (pkt.seq(), pkt.payload_len())
        } else {
            return if this.fin {
                Poll::Ready(None)
            } else {
                Poll::Pending
            };
        };

        let index = this.next_seq - seq;
        if (index as usize) >= payload_len {
            return if this.fin {
                Poll::Ready(None)
            } else {
                Poll::Pending
            };
        }

        this.next_seq += 1;
        let pkt = this.peek_ord_data().unwrap();
        Poll::Ready(Some(pkt.payload()[index as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct MyPacket {
        sport: u16,
        dport: u16,
        sequence: u32,
        syn_flag: bool,
        fin_flag: bool,
        data: Vec<u8>,
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

    #[test]
    fn test_pktstrm_peek() {
        let mut pkt_strm = PktStrm::<MyPacket>::new();

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
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());

        if let Some(pkt) = pkt_strm.peek() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected a packet wrapper");
        }
    }

    #[test]
    fn test_pktstrm_peek2() {
        let mut stm = PktStrm::new();

        let pkt1 = MyPacket::new(1, false);
        stm.push(pkt1);

        let pkt2 = MyPacket::new(30, false);
        stm.push(pkt2);

        let pkt3 = MyPacket::new(80, false);
        stm.push(pkt3);

        assert_eq!(1, stm.peek().unwrap().seq());
        stm.pop();
        assert_eq!(30, stm.peek().unwrap().seq());
        stm.pop();
        assert_eq!(80, stm.peek().unwrap().seq());
        stm.pop();
        assert!(stm.is_empty());
    }

    #[test]
    fn test_pktstrm_pop() {
        let mut pkt_strm = PktStrm::<MyPacket>::new();

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
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1001,
            syn_flag: true,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet3.clone());

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(popped_packet, packet2);
        } else {
            panic!("Expected to pop a packet");
        }

        assert!(pkt_strm.fin);

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(popped_packet, packet1);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(popped_packet, packet3);
        } else {
            panic!("Expected to pop a packet");
        }

        assert_eq!(pkt_strm.pop(), None);
    }

    #[test]
    fn test_pktstrm_peek_ord() {
        let mut pkt_strm = PktStrm::<MyPacket>::new();

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet3.clone());
        pkt_strm.push(packet4.clone());

        if let Some(pkt) = pkt_strm.peek_ord() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1000;
        if let Some(pkt) = pkt_strm.peek_ord() {
            assert_eq!(*pkt, packet4);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1004;
        if let Some(pkt) = pkt_strm.peek_ord() {
            assert_eq!(*pkt, packet3);
        } else {
            panic!("Expected to peek a packet");
        }
    }

    #[test]
    fn test_pktstrm_peek_ord2() {
        let mut stm = PktStrm::new();
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, false);

        stm.push(pkt2.clone());
        stm.push(pkt3);
        stm.push(pkt1.clone());

        assert_eq!(seq1, stm.peek_ord().unwrap().seq());
        assert_eq!(seq1, stm.pop_ord().unwrap().seq());
        assert_eq!(seq2, stm.peek_ord().unwrap().seq());
        assert_eq!(seq2, stm.pop_ord().unwrap().seq());
        assert_eq!(seq3, stm.peek_ord().unwrap().seq());
        assert_eq!(seq3, stm.pop_ord().unwrap().seq());
        assert!(stm.is_empty());
    }

    // 插入的包有完整重传
    #[test]
    fn test_pktstrm_peek_ord_retrans() {
        let mut stm = PktStrm::new();
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11- 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, false);

        stm.push(pkt1.clone());
        stm.push(pkt2.clone());
        stm.push(pkt1.clone());
        stm.push(pkt3.clone());

        assert_eq!(4, stm.len());
        assert_eq!(0, stm.next_seq);

        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 按有序方式，看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().seq()); // 弹出pkt1, 通过pop_ord_pkt更新next_seq
        assert_eq!(seq2, stm.next_seq);

        assert_eq!(3, stm.len()); // 此时重复的pkt1，仍在里面，top上
        assert_eq!(seq1, stm.peek().unwrap().seq());
        assert_eq!(seq2, stm.next_seq);

        dbg!(stm.next_seq);
        assert_eq!(seq2, stm.peek_ord().unwrap().seq()); // 看到pkt2
        assert_eq!(2, stm.len()); // peek_ord清理了重复的pkt1
        assert_eq!(seq2, stm.next_seq); //  peek_ord不会更新next_seq

        assert_eq!(seq2, stm.pop_ord().unwrap().seq()); // 弹出pkt2, 通过pop_ord更新next_seq
        assert_eq!(1, stm.len());
        assert_eq!(seq3, stm.next_seq); //  peek_ord不会更新next_seq

        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(seq3, stm.peek_ord().unwrap().seq()); // 看到pkt3
        assert_eq!(seq3, stm.pop_ord().unwrap().seq()); // 弹出pkt3, 通过pop_ord更新next_seq
        assert_eq!(seq3 + pkt3.payload_len() as u32, stm.next_seq);

        assert!(stm.is_empty());
    }

    // 插入的包有覆盖重传
    #[test]
    fn test_pktstrm_peek_ord_cover() {
        let mut stm = PktStrm::new();
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 15 - 24
        let seq3 = 15;
        let pkt3 = MyPacket::new(seq3, false);
        // 25 - 34
        let seq4 = 25;
        let pkt4 = MyPacket::new(seq4, false);

        stm.push(pkt1.clone());
        stm.push(pkt2.clone());
        stm.push(pkt3.clone());
        stm.push(pkt4.clone());

        assert_eq!(4, stm.len());
        assert_eq!(0, stm.next_seq);

        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().seq()); // 弹出pkt1, 通过pop_ord更新next_seq
        assert_eq!(pkt1.seq() + pkt1.payload_len() as u32, stm.next_seq);

        assert_eq!(3, stm.len());
        assert_eq!(seq2, stm.peek().unwrap().seq()); // 此时pkt2在top
        assert_eq!(seq2, stm.pop_ord().unwrap().seq()); // 弹出pkt2, 通过pop_ord更新next_seq
        assert_eq!(seq2 + pkt2.payload_len() as u32, stm.next_seq);

        assert_eq!(2, stm.len());
        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(seq3, stm.pop_ord().unwrap().seq()); // 弹出pkt3, 通过pop_ord更新next_seq

        assert_eq!(seq3 + pkt3.payload_len() as u32, stm.next_seq);
        assert_eq!(1, stm.len());
        assert_eq!(seq4, stm.peek().unwrap().seq()); // 此时pkt4在top
        assert_eq!(seq4, stm.pop_ord().unwrap().seq()); // 弹出pkt4, 通过pop_ord更新next_seq

        assert_eq!(seq4 + pkt4.payload_len() as u32, stm.next_seq);
        assert!(stm.is_empty());
    }

    // 有中间丢包
    #[test]
    fn test_pktstrm_peek_drop() {
        let mut stm = PktStrm::new();
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11- 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, false);

        stm.push(pkt1.clone());
        stm.push(pkt3.clone());

        assert_eq!(2, stm.len());
        assert_eq!(0, stm.next_seq);
        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().seq()); // 弹出pkt1, 通过pop_ord更新next_seq
        assert_eq!(pkt1.seq() + pkt1.payload_len() as u32, stm.next_seq);

        assert_eq!(1, stm.len());
        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(None, stm.peek_ord()); // 但是通peek_ord_pkt 看不到pkt3
        assert_eq!(None, stm.pop_ord());
    }

    // 带数据，带fin。是否可以set fin标记？
    #[test]
    fn test_pkt_fin() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, true);

        let mut stm = PktStrm::new();
        stm.push(pkt1);

        let ret_pkt1 = stm.pop_ord_data();
        assert_eq!(seq1, ret_pkt1.unwrap().seq());
        assert!(stm.fin);
    }

    // 插入的包严格有序 1-10 11-20 21-30, 最后一个有数据而且带fin
    // 用pop_ord_data，才会设置fin
    #[test]
    fn test_3pkt_fin() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        println!("pkt1. seq1: {}, pkt1 seq: {}", seq1, pkt1.seq());
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        println!("pkt2. seq2: {}, pkt2 seq: {}", seq2, pkt2.seq());
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, true);
        println!("pkt3. seq3: {}, pkt3 seq: {}", seq3, pkt3.seq());

        let mut stm = PktStrm::new();
        stm.push(pkt2.clone());
        stm.push(pkt3);
        stm.push(pkt1.clone());

        assert_eq!(seq1, stm.pop_ord_data().unwrap().seq());
        assert!(!stm.fin);
        assert_eq!(seq2, stm.pop_ord_data().unwrap().seq());
        assert!(!stm.fin);
        assert_eq!(seq3, stm.pop_ord_data().unwrap().seq());
        assert!(stm.fin);
        assert!(stm.is_empty());
    }

    #[test]
    fn test_pktstrm_pop_ord() {
        let mut pkt_strm = PktStrm::<MyPacket>::new();

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 100,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 103,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 106,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 102,
            syn_flag: false,
            fin_flag: false,
            data: vec![5],
        };

        pkt_strm.push(packet4.clone());
        pkt_strm.push(packet3.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet1.clone());

        if let Some(popped_packet) = pkt_strm.pop_ord() {
            assert_eq!(popped_packet, packet1);
            assert_eq!(pkt_strm.next_seq, 103);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop_ord() {
            assert_eq!(popped_packet, packet2);
            assert_eq!(pkt_strm.next_seq, 106);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop_ord() {
            assert_eq!(popped_packet, packet3);
            assert_eq!(pkt_strm.next_seq, 109);
        } else {
            panic!("Expected to pop a packet");
        }

        assert_eq!(pkt_strm.pop_ord(), None);
        assert_eq!(pkt_strm.pop_ord(), None);
    }

    #[test]
    fn test_pktstrm_peek_ord_data() {
        let mut pkt_strm = PktStrm::<MyPacket>::new();

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet3.clone());
        pkt_strm.push(packet4.clone());

        if let Some(pkt) = pkt_strm.peek_ord_data() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1000;
        let res = pkt_strm.peek_ord_data();
        assert_eq!(res, None);
    }

    #[test]
    fn test_pktstrm_pop_ord_data() {
        let mut pkt_strm = PktStrm::<MyPacket>::new();

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet3.clone());
        pkt_strm.push(packet4.clone());

        if let Some(pkt) = pkt_strm.pop_ord_data() {
            assert_eq!(pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1000;
        let res = pkt_strm.pop_ord_data();
        assert_eq!(res, None);
    }
}
