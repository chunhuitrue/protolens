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

pub trait CallbackFn: FnMut(&[u8], u32, *const c_void) + Send + Sync {}
impl<F: FnMut(&[u8], u32, *const c_void) + Send + Sync> CallbackFn for F {}
type CallbackStreamReadline2 = Arc<Mutex<dyn CallbackFn>>;

pub struct StreamReadline2Parser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    callback_readline: Option<CallbackStreamReadline2>,
}

impl<T: Packet + Ord + 'static> StreamReadline2Parser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            callback_readline: None,
        }
    }

    pub fn set_callback_readline<F>(&mut self, callback: F)
    where
        F: CallbackFn + 'static,
    {
        self.callback_readline = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *const c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.callback_readline.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while !stm.fin() {
                let (line, seq) = stm.readline2().await?;
                if line.is_empty() {
                    break;
                }
                if let Some(ref callback) = callback {
                    callback.lock().unwrap()(line, seq, cb_ctx);
                }
            }
            Ok(())
        }
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadline2Parser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> ParserInner for StreamReadline2Parser<T> {
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
    fn test_stream_readline2_single_line() {
        // 创建一个包含一行数据的包
        let seq1 = 1;
        let payload = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b'l'];
        let pkt1 = build_pkt_line(seq1, payload);
        let _ = pkt1.decode();

        let lines = Arc::new(Mutex::new(Vec::new()));
        let seqs = Arc::new(Mutex::new(Vec::new()));

        let lines_clone = Arc::clone(&lines);
        let seqs_clone = Arc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *const c_void| {
            lines_clone.lock().unwrap().push(line.to_vec());
            seqs_clone.lock().unwrap().push(seq);
            dbg!(seq);
        };

        // 添加用于验证原始TCP流数据的变量
        let raw_data = Arc::new(Mutex::new(Vec::new()));
        let raw_seqs = Arc::new(Mutex::new(Vec::new()));

        // 添加原始TCP流的callback
        let raw_data_clone = Arc::clone(&raw_data);
        let raw_seqs_clone = Arc::clone(&raw_seqs);
        let stm_callback = move |data: &[u8], seq: u32, _cb_ctx: *const c_void| {
            raw_data_clone.lock().unwrap().push(data.to_vec());
            raw_seqs_clone.lock().unwrap().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadline2Parser<CapPacket>>();
        parser.set_callback_readline(callback);
        let mut task = protolens.new_task_with_parser(parser);

        // 设置原始TCP流callback
        protolens.task_set_c2s_callback(&mut task, stm_callback);

        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\n".to_vec()];
        let seq_expected = vec![1];
        dbg!(&seq_expected);
        assert_eq!(*lines.lock().unwrap(), line_expected);
        assert_eq!(*seqs.lock().unwrap(), seq_expected);

        // 验证原始TCP流数据是否正确
        let raw_data_expected = vec![b"Hello\n".to_vec()];
        let raw_seq_expected = vec![seq1];
        assert_eq!(*raw_data.lock().unwrap(), raw_data_expected);
        assert_eq!(*raw_seqs.lock().unwrap(), raw_seq_expected);
    }

    #[test]
    fn test_stream_readline2_multiple_packets() {
        // 第一个包包含 "Hello\nWor"
        let seq1 = 1;
        let payload1 = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b' '];
        let pkt1 = build_pkt_line(seq1, payload1);

        // 第二个包包含 "ld!\nBye\n"
        let seq2 = 11;
        let payload2 = [b'l', b'd', b'!', b'\n', b'B', b'y', b'e', b'\n', b'x', b'x'];
        let pkt2 = build_pkt_line(seq2, payload2);

        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let lines = Arc::new(Mutex::new(Vec::new()));
        let seqs = Arc::new(Mutex::new(Vec::new()));

        let lines_clone = Arc::clone(&lines);
        let seqs_clone = Arc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *const c_void| {
            lines_clone.lock().unwrap().push(line.to_vec());
            seqs_clone.lock().unwrap().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadline2Parser<CapPacket>>();
        parser.set_callback_readline(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 验证收到的行是否正确
        let line_expected = vec![
            b"Hello\n".to_vec(),
            b"Wor ld!\n".to_vec(),
            b"Bye\n".to_vec(),
        ];
        let seq_expected = vec![1, 7, 15];
        assert_eq!(*lines.lock().unwrap(), line_expected);
        assert_eq!(*seqs.lock().unwrap(), seq_expected);
    }

    #[test]
    fn test_stream_readline2_with_syn() {
        // 创建SYN包
        let seq1 = 1;
        let pkt_syn = build_pkt_syn(seq1);

        // 创建数据包
        let seq2 = 2; // SYN占一个序列号
        let payload1 = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b'l'];
        let pkt1 = build_pkt_line(seq2, payload1);

        let seq3 = 12;
        let payload2 = [b'd', b'!', b'\n', b'B', b'y', b'e', b'\n', b'x', b'x', b'x'];
        let pkt2 = build_pkt_line(seq3, payload2);

        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let lines = Arc::new(Mutex::new(Vec::new()));
        let seqs = Arc::new(Mutex::new(Vec::new()));

        let lines_clone = Arc::clone(&lines);
        let seqs_clone = Arc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *const c_void| {
            lines_clone.lock().unwrap().push(line.to_vec());
            seqs_clone.lock().unwrap().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadline2Parser<CapPacket>>();
        parser.set_callback_readline(callback);
        let mut task = protolens.new_task_with_parser(parser);

        // 乱序发送包
        protolens.run_task(&mut task, pkt_syn);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\n".to_vec(), b"World!\n".to_vec(), b"Bye\n".to_vec()];
        let seq_expected = vec![2, 8, 15];
        assert_eq!(*lines.lock().unwrap(), line_expected);
        assert_eq!(*seqs.lock().unwrap(), seq_expected);
    }

    #[test]
    fn test_readline2_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = StreamReadline2Parser::<CapPacket>::new();
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<CallbackStreamReadline2>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<Option<CallbackStreamReadline2>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }
}
