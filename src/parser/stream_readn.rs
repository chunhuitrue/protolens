use crate::pool::Pool;
use crate::Packet;
use crate::ParserFuture;
use crate::ParserInner;
use crate::PktStrm;
use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

pub trait CallbackFn: FnMut(Vec<u8>, *const c_void) + Send + Sync {}
impl<F: FnMut(Vec<u8>, *const c_void) + Send + Sync> CallbackFn for F {}
type CallbackStreamReadn = Arc<Mutex<dyn CallbackFn>>;

pub struct StreamReadnParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    callback_readn: Option<CallbackStreamReadn>,
    read_size: usize, // 每次读取的字节数
}

impl<T: Packet + Ord + 'static> StreamReadnParser<T> {
    pub(crate) fn new(read_size: usize) -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            callback_readn: None,
            read_size,
        }
    }

    pub fn set_callback_readn<F>(&mut self, callback: F)
    where
        F: CallbackFn + 'static,
    {
        self.callback_readn = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *const c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.callback_readn.clone();
        let read_size = self.read_size;

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while !stm.fin() {
                let bytes = stm.readn(read_size).await;
                if bytes.is_empty() {
                    break;
                }
                if let Some(ref callback) = callback {
                    callback.lock().unwrap()(bytes, cb_ctx);
                }
            }
            Ok(())
        }
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadnParser<T> {
    fn default() -> Self {
        Self::new(10) // 默认读取10个字节
    }
}

impl<T: Packet + Ord + 'static> ParserInner for StreamReadnParser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new(10) // 使用默认大小 10
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
        cb_ctx: *const c_void,
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
    fn test_stream_readn_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: Vec<u8>, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend(bytes);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadnParser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1);

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

        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: Vec<u8>, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend(bytes);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadnParser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

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

        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: Vec<u8>, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend(bytes);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadnParser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser);

        // 乱序发送包
        protolens.run_task(&mut task, pkt_syn);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt1);

        // 验证收到的数据是否正确
        let expected: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第一个数据包
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // 第二个数据包
        ];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    #[test]
    fn test_readn_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = StreamReadnParser::<CapPacket>::new(10);
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<CallbackStreamReadn>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<Option<CallbackStreamReadn>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }
}
