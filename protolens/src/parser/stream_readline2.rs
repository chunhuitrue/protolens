use crate::Packet;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait ReadLine2CbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> ReadLine2CbFn for F {}
pub(crate) type CbReadline2 = Rc<RefCell<dyn ReadLine2CbFn + 'static>>;

pub struct StreamReadline2Parser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pub(crate) cb_readline: Option<CbReadline2>,
}

impl<T: Packet + Ord + 'static> StreamReadline2Parser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            cb_readline: None,
        }
    }

    async fn c2s_parser_inner(
        cb_readline: Option<CbReadline2>,
        stream: *const PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T>);
        }

        while !stm.fin() {
            let (line, seq) = stm.readline2().await?;
            if line.is_empty() {
                break;
            }
            if let Some(ref cb) = cb_readline {
                cb.borrow_mut()(line, seq, cb_ctx);
            }
        }
        Ok(())
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadline2Parser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for StreamReadline2Parser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new()
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_readline.clone(),
            stream,
            cb_ctx,
        )))
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
        pkt1.set_l7_proto(L7Proto::StreamReadline2);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
            dbg!(seq);
        };

        // 添加用于验证原始TCP流数据的变量
        let raw_data = Rc::new(RefCell::new(Vec::new()));
        let raw_data_clone = Rc::clone(&raw_data);
        let raw_seqs = Rc::new(RefCell::new(Vec::new()));
        let raw_seqs_clone = Rc::clone(&raw_seqs);
        let stm_callback = move |data: &[u8], seq: u32, _cb_ctx: *const c_void| {
            raw_data_clone.borrow_mut().push(data.to_vec());
            raw_seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readline2(callback);
        let mut task = protolens.new_task();

        // 设置原始TCP流callback
        protolens.set_cb_task_c2s(&mut task, stm_callback);

        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\n".to_vec()];
        let seq_expected = vec![1];
        dbg!(&seq_expected);
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);

        // 验证原始TCP流数据是否正确
        let raw_data_expected = vec![b"Hello\n".to_vec()];
        let raw_seq_expected = vec![seq1];
        assert_eq!(*raw_data.borrow(), raw_data_expected);
        assert_eq!(*raw_seqs.borrow(), raw_seq_expected);
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
        pkt1.set_l7_proto(L7Proto::StreamReadline2);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readline2(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 验证收到的行是否正确
        let line_expected = vec![
            b"Hello\n".to_vec(),
            b"Wor ld!\n".to_vec(),
            b"Bye\n".to_vec(),
        ];
        let seq_expected = vec![1, 7, 15];
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);
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
        pkt_syn.set_l7_proto(L7Proto::StreamReadline2);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readline2(callback);
        let mut task = protolens.new_task();

        // 乱序发送包
        protolens.run_task(&mut task, pkt_syn);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\n".to_vec(), b"World!\n".to_vec(), b"Bye\n".to_vec()];
        let seq_expected = vec![2, 8, 15];
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);
    }
}
