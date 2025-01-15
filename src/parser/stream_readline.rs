use crate::pool::Pool;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

type CallbackStreamReadline = Arc<Mutex<dyn FnMut(String) + Send + Sync>>;

pub struct StreamReadlineParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    callback_readline: Option<CallbackStreamReadline>,
}

impl<T: Packet + Ord + 'static> StreamReadlineParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            callback_readline: None,
        }
    }

    pub fn set_callback_readline<F>(&mut self, callback: F)
    where
        F: FnMut(String) + Send + Sync + 'static,
    {
        self.callback_readline = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.callback_readline.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while !stm.fin() {
                match stm.readline().await {
                    Ok(line) => {
                        if line.is_empty() {
                            break;
                        }
                        if let Some(ref callback) = callback {
                            callback.lock().unwrap()(line);
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(())
        }
    }

    fn s2c_parser_inner(
        &self,
        _stream: *const PktStrm<T>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> impl Future<Output = Result<(), ()>> {
        async { Ok(()) }
    }

    fn bdir_parser_inner(
        &self,
        _c2s_stream: *const PktStrm<T>,
        _s2c_stream: *const PktStrm<T>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> impl Future<Output = Result<(), ()>> {
        async { Ok(()) }
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadlineParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for StreamReadlineParser<T> {
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
        let (tx, _rx) = mpsc::channel(1);
        let stream_ptr = std::ptr::null();

        let future = self.c2s_parser_inner(stream_ptr, tx);
        std::mem::size_of_val(&future)
    }

    fn s2c_parser_size(&self) -> usize {
        let (tx, _rx) = mpsc::channel(1);
        let stream_ptr = std::ptr::null();

        let future = self.s2c_parser_inner(stream_ptr, tx);
        std::mem::size_of_val(&future)
    }

    fn bdir_parser_size(&self) -> usize {
        let (tx, _rx) = mpsc::channel(1);
        let stream_ptr = std::ptr::null();

        let future = self.bdir_parser_inner(stream_ptr, stream_ptr, tx);
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        self.pool()
            .alloc_future(self.c2s_parser_inner(stream, meta_tx))
    }

    fn s2c_parser(&self, stream: *const PktStrm<T>, meta_tx: mpsc::Sender<Meta>) -> ParserFuture {
        self.pool()
            .alloc_future(self.s2c_parser_inner(stream, meta_tx))
    }

    fn bdir_parser(
        &self,
        c2s_stream: *const PktStrm<T>,
        s2c_stream: *const PktStrm<T>,
        meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        self.pool()
            .alloc_future(self.bdir_parser_inner(c2s_stream, s2c_stream, meta_tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;

    #[test]
    fn test_stream_readline_single_line() {
        // 创建一个包含一行数据的包
        let seq1 = 1;
        let payload = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b'l'];
        let pkt1 = build_pkt_line(seq1, payload);
        let _ = pkt1.decode();

        let dir = PktDirection::Client2Server;
        let lines = Arc::new(Mutex::new(Vec::new()));

        let lines_clone = Arc::clone(&lines);
        let callback = move |line: String| {
            lines_clone.lock().unwrap().push(line);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadlineParser<CapPacket>>();
        parser.set_callback_readline(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1, dir.clone());

        // 验证收到的行是否正确
        let expected = vec!["Hello\n".to_string()];
        assert_eq!(*lines.lock().unwrap(), expected);
    }

    #[test]
    fn test_stream_readline_multiple_packets() {
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

        let dir = PktDirection::Client2Server;
        let lines = Arc::new(Mutex::new(Vec::new()));

        let lines_clone = Arc::clone(&lines);
        let callback = move |line: String| {
            lines_clone.lock().unwrap().push(line);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadlineParser<CapPacket>>();
        parser.set_callback_readline(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1, dir.clone());
        protolens.run_task(&mut task, pkt2, dir.clone());

        // 验证收到的行是否正确
        let expected = vec![
            "Hello\n".to_string(),
            "Wor ld!\n".to_string(),
            "Bye\n".to_string(),
        ];
        assert_eq!(*lines.lock().unwrap(), expected);
    }

    #[test]
    fn test_stream_readline_with_syn() {
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

        let dir = PktDirection::Client2Server;
        let lines = Arc::new(Mutex::new(Vec::new()));

        let lines_clone = Arc::clone(&lines);
        let callback = move |line: String| {
            lines_clone.lock().unwrap().push(line);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadlineParser<CapPacket>>();
        parser.set_callback_readline(callback);
        let mut task = protolens.new_task_with_parser(parser);

        // 乱序发送包
        protolens.run_task(&mut task, pkt_syn, dir.clone());
        protolens.run_task(&mut task, pkt2, dir.clone());
        protolens.run_task(&mut task, pkt1, dir.clone());

        // 验证收到的行是否正确
        let expected = vec![
            "Hello\n".to_string(),
            "World!\n".to_string(),
            "Bye\n".to_string(),
        ];
        assert_eq!(*lines.lock().unwrap(), expected);
    }

    #[test]
    fn test_readline_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = StreamReadlineParser::<CapPacket>::new();
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of mpsc::Sender: {} bytes",
            std::mem::size_of::<mpsc::Sender<Meta>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<CallbackStreamReadline>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<mpsc::Sender<Meta>>()
            + std::mem::size_of::<Option<CallbackStreamReadline>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }
}
