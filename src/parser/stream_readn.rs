use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

type CallbackStreamReadn = Arc<Mutex<dyn FnMut(Vec<u8>) + Send + Sync>>;

pub struct StreamReadnParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_readn: Option<CallbackStreamReadn>,
    read_size: usize, // 每次读取的字节数
}

impl<T: Packet + Ord + 'static> StreamReadnParser<T> {
    pub fn new(read_size: usize) -> Self {
        Self {
            _phantom: PhantomData,
            callback_readn: None,
            read_size,
        }
    }

    pub fn set_callback_readn<F>(&mut self, callback: F)
    where
        F: FnMut(Vec<u8>) + Send + Sync + 'static,
    {
        self.callback_readn = Some(Arc::new(Mutex::new(callback)));
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadnParser<T> {
    fn default() -> Self {
        Self::new(10) // 默认读取10个字节
    }
}

impl<T: Packet + Ord + 'static> Parser for StreamReadnParser<T> {
    type PacketType = T;

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        mut _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        let callback = self.callback_readn.clone();
        let read_size = self.read_size;

        Box::pin(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
            }

            while !stm.fin() {
                let bytes = stm.readn(read_size).await;
                if bytes.is_empty() {
                    break;
                }
                if let Some(ref callback) = callback {
                    callback.lock().unwrap()(bytes);
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;

    #[test]
    fn test_stream_readn_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: Vec<u8>| {
            vec_clone.lock().unwrap().extend(bytes);
        };

        let mut parser = StreamReadnParser::<CapPacket>::new(5); // 每次读取5个字节
        parser.set_callback_readn(callback);
        let mut task = Task::new_with_parser(parser);

        task.run(pkt1, dir.clone());

        // 验证收到的数据是否正确
        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    #[test]
    fn test_stream_readn_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: Vec<u8>| {
            vec_clone.lock().unwrap().extend(bytes);
        };

        let mut parser = StreamReadnParser::<CapPacket>::new(8); // 每次读取8个字节
        parser.set_callback_readn(callback);
        let mut task = Task::new_with_parser(parser);

        task.run(pkt1, dir.clone());
        task.run(pkt2, dir.clone());

        // 验证收到的数据是否正确
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    #[test]
    fn test_stream_readn_with_syn() {
        // 创建SYN包
        let seq1 = 1;
        let pkt_syn = build_pkt_syn(seq1);

        // 创建数据包
        let seq2 = 2; // SYN占一个序列号
        let pkt1 = build_pkt(seq2, false);
        let seq3 = 12;
        let pkt2 = build_pkt(seq3, true);

        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: Vec<u8>| {
            vec_clone.lock().unwrap().extend(bytes);
        };

        let mut parser = StreamReadnParser::<CapPacket>::new(7); // 每次读取7个字节
        parser.set_callback_readn(callback);
        let mut task = Task::new_with_parser(parser);

        // 乱序发送包
        task.run(pkt_syn, dir.clone());
        task.run(pkt2, dir.clone());
        task.run(pkt1, dir.clone());

        // 验证收到的数据是否正确
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个数据包
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个数据包
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }
}
