use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::packet::*;
use futures::StreamExt;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait ByteCbFn: FnMut(u8, *mut c_void) {}
impl<F: FnMut(u8, *mut c_void)> ByteCbFn for F {}
pub(crate) type CbByte = Rc<RefCell<dyn ByteCbFn + 'static>>;

pub struct ByteParser<T>
where
    T: Packet,
{
    pub(crate) cb_next_byte: Option<CbByte>,
    _phantom_t: PhantomData<T>,
}

impl<T> ByteParser<T>
where
    T: Packet,
{
    pub fn new() -> Self {
        Self {
            cb_next_byte: None,
            _phantom_t: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        strm: *mut PktStrm<T>,
        cb_next_byte: Option<CbByte>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        while let Some(byte) = stm.next().await {
            if let Some(ref cb) = cb_next_byte {
                cb.borrow_mut()(byte, cb_ctx);
            }
        }
        Ok(())
    }
}

impl<T> Default for ByteParser<T>
where
    T: Packet,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Parser for ByteParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            strm,
            self.cb_next_byte.clone(),
            cb_ctx,
        )))
    }
}

pub(crate) struct ByteFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for ByteFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(ByteParser::new());
        parser.cb_next_byte = prolens.cb_byte.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_stream_next_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            dbg!("in callback. push one byte");
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        protolens.run_task(&mut task, pkt1);

        assert_eq!(*vec.borrow(), (1..=10).collect::<Vec<u8>>());
    }

    #[test]
    fn test_stream_next_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.borrow(), expected);
    }

    #[test]
    fn test_stream_next_empty_packet() {
        let pkt = build_pkt_nodata(1, true);
        let _ = pkt.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        protolens.run_task(&mut task, pkt);

        assert_eq!(vec.borrow().len(), 0);
    }

    // 测试多个连续包加一个fin包的情况
    #[test]
    fn test_stream_next_sequential_with_fin() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, false);
        let seq3 = 21;
        let pkt3 = build_pkt(seq3, false);
        let seq4 = 31;
        let pkt4 = build_pkt_nodata(seq4, true);

        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);
        protolens.run_task(&mut task, pkt4);

        // 验证收到了三组相同的字节序列 (1-10 重复三次)
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, // 第三个包的数据
                // 第四个包没有数据，只有fin标志
        ];
        assert_eq!(*vec.borrow(), expected);
    }

    // 测试带有纯ACK包的连续数据流
    #[test]
    fn test_stream_next_with_pure_ack() {
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

        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt_ack);
        protolens.run_task(&mut task, pkt3);
        protolens.run_task(&mut task, pkt4);

        // 验证收到了三组相同的字节序列，ACK包不产生数据
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            // ACK包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, // 第三个包的数据
                // 最后的FIN包没有数据
        ];
        assert_eq!(*vec.borrow(), expected);
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

        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        // 乱序发送包：
        // 1. 先发第二个数据包
        // 2. 再发ACK包
        // 3. 然后是第一个数据包
        // 4. 接着是第三个数据包
        // 5. 最后是FIN包
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt3);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt_ack);
        protolens.run_task(&mut task, pkt4);

        // 验证最终收到的数据应该是有序的，与顺序到达时相同
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个包的数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个包的数据
            // ACK包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, // 第三个包的数据
                // 最后的FIN包没有数据
        ];
        assert_eq!(*vec.borrow(), expected);
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

        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_byte(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Byte);

        protolens.run_task(&mut task, pkt_syn);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt_ack);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt3);
        protolens.run_task(&mut task, pkt4);

        // 验证最终收到的数据应该是有序的
        let expected: Vec<u8> = vec![
            // SYN包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个数据包
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个数据包
            // ACK包没有数据
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第三个
                // FIN包没有数据
        ];
        assert_eq!(*vec.borrow(), expected);
    }
}
