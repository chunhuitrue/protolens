use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;
use crate::pool::Pool;
use std::rc::Rc;

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

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        let callback = self.callback_readline.clone();

        self.pool().new_future(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
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
        })
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
}
