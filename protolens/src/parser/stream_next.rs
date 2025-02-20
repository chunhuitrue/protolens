use crate::pool::Pool;
use crate::Packet;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use futures::StreamExt;
use std::cell::RefCell;
use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;

pub trait StreamNextCbFn: FnMut(u8, *mut c_void) {}
impl<F: FnMut(u8, *mut c_void)> StreamNextCbFn for F {}
pub(crate) type CbStreamNext = Rc<RefCell<dyn StreamNextCbFn + 'static>>;

pub struct StreamNextParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    pub(crate) cb_next_byte: Option<CbStreamNext>,
}

impl<T: Packet + Ord + 'static> StreamNextParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            cb_next_byte: None,
        }
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.cb_next_byte.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while let Some(byte) = stm.next().await {
                if let Some(ref callback) = callback {
                    callback.borrow_mut()(byte, cb_ctx);
                }
            }
            Ok(())
        }
    }
}

impl<T: Packet + Ord + 'static> Default for StreamNextParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for StreamNextParser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new()
    }

    fn pool(&self) -> &Rc<Pool> {
        self.pool.as_ref().expect("Pool not set")
    }

    fn set_pool(&mut self, pool: Rc<Pool>) {
        self.pool = Some(pool);
    }

    fn c2s_parser_size(&self) -> usize {
        let stream_ptr = std::ptr::null();

        let future = self.c2s_parser_inner(stream_ptr, ptr::null_mut());
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        Some(
            self.pool()
                .alloc_future(self.c2s_parser_inner(stream, cb_ctx)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;

    #[test]
    fn test_stream_next_single_packet() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::StreamNext);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            dbg!("in callback. push one byte");
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);

        assert_eq!(*vec.borrow(), (1..=10).collect::<Vec<u8>>());
    }

    #[test]
    fn test_stream_next_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false); // 第一个包不带 fin
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true); // 第二个包带 fin
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::StreamNext);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 验证收到了两组相同的字节序列 (1-10, 1-10)
        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.borrow(), expected);
    }

    #[test]
    fn test_stream_next_empty_packet() {
        let pkt = build_pkt_nodata(1, true);
        let _ = pkt.decode();
        pkt.set_l7_proto(L7Proto::StreamNext);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt);

        // 验证没有收到任何字节
        assert_eq!(vec.borrow().len(), 0);
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
        pkt1.set_l7_proto(L7Proto::StreamNext);
        let _ = pkt2.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

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
        pkt1.set_l7_proto(L7Proto::StreamNext);
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
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

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

        // 解码所有包
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();
        pkt1.set_l7_proto(L7Proto::StreamNext);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

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

        // 解码所有包
        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        let _ = pkt_ack.decode();
        let _ = pkt3.decode();
        let _ = pkt4.decode();
        pkt_syn.set_l7_proto(L7Proto::StreamNext);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let callback = move |byte: u8, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(byte);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_next_byte(callback);
        let mut task = protolens.new_task();

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

    #[test]
    fn test_streamnext_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = StreamNextParser::<CapPacket>::new();
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<CbStreamNext>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<Option<CbStreamNext>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }
}
