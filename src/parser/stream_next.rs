use crate::Parser;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures::Future;
use futures::StreamExt;
use futures_channel::mpsc;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

type CallbackStreamNext = Arc<Mutex<dyn FnMut(u8) + Send + Sync>>;

pub struct StreamNextParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_next_byte: Option<CallbackStreamNext>,
}

impl<T: Packet + Ord + 'static> StreamNextParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_next_byte: None,
        }
    }

    pub fn set_callback_next_byte<F>(&mut self, callback: F)
    where
        F: FnMut(u8) + Send + Sync + 'static,
    {
        self.callback_next_byte = Some(Arc::new(Mutex::new(callback)));
    }
}

impl<T: Packet + Ord + 'static> Default for StreamNextParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for StreamNextParser<T> {
    type PacketType = T;

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        mut _meta_tx: mpsc::Sender<Meta>,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        let callback = self.callback_next_byte.clone();

        Box::pin(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
            }

            while let Some(byte) = stm.next().await {
                if let Some(ref callback) = callback {
                    callback.lock().unwrap()(byte);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;

    // 原有的测试用例重命名为更具体的名称
    #[test]
    fn test_stream_next_single_packet() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            dbg!("in callback. push one byte");
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        task.run(pkt1, dir.clone());

        assert_eq!(*vec.lock().unwrap(), (1..=10).collect::<Vec<u8>>());
    }

    // 测试多个数据包的情况
    #[test]
    fn test_stream_next_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false); // 第一个包不带 fin
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true); // 第二个包带 fin
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        task.run(pkt1, dir.clone());
        task.run(pkt2, dir.clone());

        // 验证收到了两组相同的字节序列 (1-10, 1-10)
        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    // 测试空包的情况
    #[test]
    fn test_stream_next_empty_packet() {
        let pkt = build_pkt_nodata(1, true);
        let _ = pkt.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        task.run(pkt, dir.clone());

        // 验证没有收到任何字节
        assert_eq!(vec.lock().unwrap().len(), 0);
    }

    // 测试多个连续包加一个fin包的情况
    #[test]
    fn test_stream_next_sequential_with_fin() {
        // 创建三个带数据的包
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, false);
        let seq3 = 21;
        let pkt3 = build_pkt(seq3, false);
        // 创建一个不带数据的fin包
        let seq4 = 31;
        let pkt4 = build_pkt_nodata(seq4, true);

        // 解码所有包
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        // 按序发送所有包
        task.run(pkt1, dir.clone());
        task.run(pkt2, dir.clone());
        task.run(pkt3, dir.clone());
        task.run(pkt4, dir.clone());

        // 验证收到了三组相同的字节序列 (1-10 重复三次)
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, // 第三个包的数据
                // 第四个包没有数据，只有fin标志
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    // 测试带有纯ACK包的连续数据流
    #[test]
    fn test_stream_next_with_pure_ack() {
        // 创建两个带数据的包
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, false);
        // 创建一个纯ACK包（不带数据，确认seq15）
        let seq_ack = 21;
        let pkt_ack = build_pkt_ack(seq_ack, 15);
        // 创建最后一个数据包和FIN包，ack后续的包的seq应该和ack包的seq一样
        let seq3 = 21;
        let pkt3 = build_pkt(seq3, false);
        let seq4 = 41;
        let pkt4 = build_pkt_nodata(seq4, true);

        // 解码所有包
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        // 按序发送所有包，包括中间的ACK包
        task.run(pkt1, dir.clone());
        task.run(pkt2, dir.clone());
        task.run(pkt_ack, dir.clone()); // 中间插入ACK包
        task.run(pkt3, dir.clone());
        task.run(pkt4, dir.clone());

        // 验证收到了三组相同的字节序列，ACK包不产生数据
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            // ACK包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, // 第三个包的数据
                // 最后的FIN包没有数据
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    // 测试乱序到达的数据包
    #[test]
    fn test_stream_next_out_of_order() {
        // 创建相同的包
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, false);
        let seq_ack = 21;
        let pkt_ack = build_pkt_ack(seq_ack, 15);
        let seq3 = 21;
        let pkt3 = build_pkt(seq3, false);
        let seq4 = 41;
        let pkt4 = build_pkt_nodata(seq4, true);

        // 解码所有包
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        // 乱序发送包：
        // 1. 先发第二个数据包
        // 2. 再发ACK包
        // 3. 然后是第一个数据包
        // 4. 接着是第三个数据包
        // 5. 最后是FIN包
        task.run(pkt1, dir.clone()); // seq=1
        task.run(pkt3, dir.clone()); // seq=21, 带数据
        task.run(pkt2, dir.clone()); // seq=11
        task.run(pkt_ack, dir.clone()); // seq=21, 纯ACK包
        task.run(pkt4, dir.clone()); // seq=41, FIN包

        // 验证最终收到的数据应该是有序的，与顺序到达时相同
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            // ACK包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, // 第三个包的数据
                // 最后的FIN包没有数据
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    // 测试以SYN包开始的乱序数据流
    #[test]
    fn test_stream_next_syn_with_out_of_order() {
        // 创建SYN包
        let seq1 = 1;
        let pkt_syn = build_pkt_syn(seq1);
        // 创建数据包
        let seq2 = 2; // SYN占一个序列号，所以从2开始
        let pkt1 = build_pkt(seq2, false);
        let seq3 = 12;
        let pkt2 = build_pkt(seq3, false);
        // 创建ACK包
        let seq_ack = 22;
        let pkt_ack = build_pkt_ack(seq_ack, 15);
        // 创建最后的数据包和FIN包
        let seq4 = 22;
        let pkt3 = build_pkt(seq4, false);
        let seq5 = 32;
        let pkt4 = build_pkt_nodata(seq5, true);

        // 解码所有包
        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |byte: u8| {
            vec_clone.lock().unwrap().push(byte);
        };

        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_callback_next_byte(callback);
        let mut task = Task::new_with_parser(parser);

        // 发送包的顺序：
        // 1. 首先必须是SYN包
        // 2. 后续包乱序到达
        task.run(pkt_syn, dir.clone()); // seq=1, SYN包
        task.run(pkt2, dir.clone()); // seq=12, 第二个数据包
        task.run(pkt_ack, dir.clone()); // seq=22, 纯ACK包
        task.run(pkt1, dir.clone()); // seq=2, 第一个数据包
        task.run(pkt3, dir.clone()); // seq=22, 第三个数据包
        task.run(pkt4, dir.clone()); // seq=32, FIN包

        // 验证最终收到的数据应该是有序的
        let expected: Vec<u8> = vec![
            // SYN包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个数据包
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个数据包
            // ACK包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第三个
                // FIN包没有数据
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }
}
