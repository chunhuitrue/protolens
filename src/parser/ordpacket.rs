use crate::pool::Pool;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

type CallbackOrdPkt<T> = Arc<Mutex<dyn FnMut(T) + Send + Sync>>;

pub struct OrdPacketParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_ord_pkt: Option<CallbackOrdPkt<T>>,
    pool: Option<Arc<Pool>>,
}

impl<T: Packet + Ord + 'static> OrdPacketParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_ord_pkt: None,
            pool: None,
        }
    }

    pub fn set_callback_ord_pkt<F>(&mut self, callback: F)
    where
        F: FnMut(T) + Send + Sync + 'static,
    {
        self.callback_ord_pkt = Some(Arc::new(Mutex::new(callback)));
    }

    pub fn set_pool(&mut self, pool: Arc<Pool>) {
        self.pool = Some(pool);
    }

    fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("Pool not set").as_ref()
    }
}

impl<T: Packet + Ord + 'static> Default for OrdPacketParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for OrdPacketParser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new()
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        mut _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        let callback = self.callback_ord_pkt.clone();

        let future = self.pool().new_future(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
            }

            while !stm.fin() {
                let pkt = stm.next_ord_pkt().await;
                if let Some(ref callback) = callback {
                    if let Some(pkt) = pkt {
                        callback.lock().unwrap()(pkt);
                    }
                }
            }
            Ok(())
        });
        future
    }

    fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("Pool not set").as_ref()
    }

    fn set_pool(&mut self, pool: Arc<Pool>) {
        self.pool = Some(pool);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_ordpacket_parser() {
        println!("Starting test_ordpacket_parser");
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/res/smtp.pcap");
        println!("Opening pcap file: {:?}", file_path);
        let mut cap = Capture::init(file_path).unwrap();
        let dir = PktDirection::Client2Server;
        let count = Arc::new(Mutex::new(0));
        let count_clone = count.clone();

        let callback = move |pkt: CapPacket| {
            println!("Callback triggered with packet seq: {}", pkt.seq());
            let mut count = count_clone.lock().unwrap();
            *count += 1;
            println!("Current count: {}", *count);
            dbg!(pkt.seq(), *count);
            match *count {
                1 => assert_eq!(1341098158, pkt.seq()),
                2 => assert_eq!(1341098176, pkt.seq()),
                3 => assert_eq!(1341098188, pkt.seq()),
                4 => assert_eq!(1341098222, pkt.seq()),
                5 => assert_eq!(1341098236, pkt.seq()),
                6 => assert_eq!(1341098286, pkt.seq()),
                7 => assert_eq!(1341098323, pkt.seq()),
                8 => assert_eq!(1341098329, pkt.seq()),
                9 => assert_eq!(1341098728, pkt.seq()),
                10 => assert_eq!(1341100152, pkt.seq()),
                11 => assert_eq!(1341101576, pkt.seq()),
                12 => assert_eq!(1341102823, pkt.seq()),
                13 => assert_eq!(1341104247, pkt.seq()),
                14 => assert_eq!(1341105671, pkt.seq()),
                15 => assert_eq!(1341106918, pkt.seq()),
                16 => assert_eq!(1341108342, pkt.seq()),
                17 => assert_eq!(1341108886, pkt.seq()),
                18 => assert_eq!(1341108891, pkt.seq()),
                _ => panic!("too many packets"),
            }
        };

        println!("Creating ProtoLens and parser");
        let protolens = ProtoLens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<OrdPacketParser<CapPacket>>();
        println!("Setting callback");
        parser.set_callback_ord_pkt(callback);
        println!("Creating task");
        let mut task = protolens.new_task_with_parser(parser);
        println!("Task created");
        let mut push_count = 0;

        println!("Starting packet processing loop");
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let pkt = cap.next_packet(now);
            if pkt.is_none() {
                println!("No more packets");
                break;
            }
            let pkt = pkt.unwrap();
            if pkt.decode().is_err() {
                println!("Packet decode error");
                continue;
            }

            if pkt.header.borrow().as_ref().unwrap().dport() == SMTP_PORT_NET {
                push_count += 1;
                println!("Processing packet {}: seq={}", push_count, pkt.seq());
                task.run(pkt, dir.clone());
            }
        }

        println!("Loop finished. Final count: {}", *count.lock().unwrap());
        assert_eq!(*count.lock().unwrap(), 18);
    }

    #[test]
    fn test_ordpacket_out_of_order_with_fin() {
        // 创建四个序列号连续的包
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = build_pkt(seq3, false);
        let _ = pkt3.decode();
        let seq4 = seq3 + pkt3.payload_len() as u32;
        let pkt4 = build_pkt(seq4, true); // 最后一个包带 fin
        let _ = pkt4.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::<u8>::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |pkt: CapPacket| {
            // 获取包的payload并添加到结果向量中
            vec_clone.lock().unwrap().extend(pkt.payload());
        };

        let protolens = ProtoLens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<OrdPacketParser<CapPacket>>();
        parser.set_callback_ord_pkt(callback);
        let mut task = protolens.new_task_with_parser(parser);

        // 乱序发送包,但至少第一个包得先发送，否则起始seq就不是第一个了
        task.run(pkt1, dir.clone()); // seq1
        task.run(pkt3, dir.clone()); // seq3
        task.run(pkt4, dir.clone()); // seq4 with fin
        task.run(pkt2, dir.clone()); // seq2

        // 验证最终收到的数据应该是有序的
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第三个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第四个包的数据(带fin)
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    #[test]
    fn test_ordpacket_with_syn_out_of_order() {
        // 创建SYN包
        let syn_seq = 1;
        let pkt_syn = build_pkt_syn(syn_seq);
        let _ = pkt_syn.decode();

        // 创建两个数据包，序列号连续
        let seq1 = syn_seq + 1; // SYN占用一个序列号
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();

        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::<u8>::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |pkt: CapPacket| {
            // 获取包的payload并添加到结果向量中
            vec_clone.lock().unwrap().extend(pkt.payload());
        };

        let protolens = ProtoLens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<OrdPacketParser<CapPacket>>();
        parser.set_callback_ord_pkt(callback);
        let mut task = protolens.new_task_with_parser(parser);

        // 首先发送SYN包，然后乱序发送数据包
        task.run(pkt_syn, dir.clone()); // 先发送SYN包
        task.run(pkt2, dir.clone()); // 乱序发送数据包
        task.run(pkt1, dir.clone()); // 乱序发送数据包

        // 验证最终收到的数据应该是有序的
        let expected: Vec<u8> = vec![
            // SYN包没有payload
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个数据包
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个数据包
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }
}
