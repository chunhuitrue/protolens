use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::packet::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait ReadLineCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> ReadLineCbFn for F {}
pub(crate) type CbReadline = Rc<RefCell<dyn ReadLineCbFn + 'static>>;

pub struct ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_readline: Option<CbReadline>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub fn new() -> Self {
        Self {
            cb_readline: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_readline: Option<CbReadline>,
        strm: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(strm as *mut PktStrm<T, P>);
        }

        while !stm.fin() {
            let (line, seq) = stm.readline().await?;
            dbg!(std::str::from_utf8(line).unwrap());

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

impl<T, P> Default for ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Parser for ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn c2s_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_readline.clone(),
            strm,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadlineFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for ReadlineFactory<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T, P>) -> Box<dyn Parser<PacketType = T, PtrType = P>> {
        let mut parser = Box::new(ReadlineParser::new());
        parser.cb_readline = prolens.cb_readline.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_READ_BUFF;
    use crate::test_utils::*;
    use nom::AsBytes;

    #[test]
    fn test_readline_single_line() {
        // 创建一个包含一行数据的包
        let seq1 = 1;
        let payload = [b'H', b'e', b'l', b'l', b'o', b'\r', b'\n', b'W', b'o', b'r'];
        let pkt1 = build_pkt_payload(seq1, &payload);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
            dbg!(line, seq);
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

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        // 设置原始TCP流callback
        protolens.set_cb_task_c2s(&mut task, stm_callback);

        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\r\n".to_vec()];
        let seq_expected = vec![1];
        dbg!(&seq_expected);
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);

        // 验证原始TCP流数据是否正确
        let raw_data_expected = vec![b"Hello\r\n".to_vec()];
        let raw_seq_expected = vec![seq1];
        assert_eq!(*raw_data.borrow(), raw_data_expected);
        assert_eq!(*raw_seqs.borrow(), raw_seq_expected);
    }

    #[test]
    fn test_readline_multiple_packets() {
        let seq1 = 1;
        let payload1 = [b'H', b'e', b'l', b'l', b'o', b'\r', b'\n', b'W', b'o', b'r'];
        let pkt1 = build_pkt_payload(seq1, &payload1);

        let seq2 = 11;
        let payload2 = [
            b'l', b'd', b'\r', b'\n', b'B', b'y', b'e', b'\r', b'\n', b'x',
        ];
        let pkt2 = build_pkt_payload(seq2, &payload2);

        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        dbg!("run1");
        protolens.run_task(&mut task, pkt1);
        dbg!("run2");
        protolens.run_task(&mut task, pkt2);

        // 验证收到的行是否正确
        let line_expected = vec![
            b"Hello\r\n".to_vec(),
            b"World\r\n".to_vec(),
            b"Bye\r\n".to_vec(),
        ];
        let seq_expected = vec![1, 8, 15];
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);
    }

    #[test]
    fn test_readline_with_syn() {
        // 创建SYN包
        let seq1 = 1;
        let pkt_syn = build_pkt_syn(seq1);

        // 创建数据包
        let seq2 = 2; // SYN占一个序列号
        let payload1 = [b'H', b'e', b'l', b'l', b'o', b'\r', b'\n', b'W', b'o', b'r'];
        let pkt1 = build_pkt_payload(seq2, &payload1);

        let seq3 = 12;
        let payload2 = [
            b'l', b'd', b'\r', b'\n', b'B', b'y', b'e', b'\r', b'\n', b'x',
        ];
        let pkt2 = build_pkt_payload(seq3, &payload2);

        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt_syn.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        // 乱序发送包
        protolens.run_task(&mut task, pkt_syn);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let line_expected = vec![
            b"Hello\r\n".to_vec(),
            b"World\r\n".to_vec(),
            b"Bye\r\n".to_vec(),
        ];
        let seq_expected = vec![2, 9, 16];
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);
    }

    // 验证多个同类型的task执行。当parser被建立时，它从prolens中获取callback的copy，而不是拿走callback。
    // 因为后续的同类型task还需要copy这些callback
    #[test]
    fn test_readline_multi_task() {
        // 创建一个包含一行数据的包
        let seq1 = 1;
        let payload = [b'H', b'e', b'l', b'l', b'o', b'\r', b'\n', b'W', b'o', b'r'];
        let pkt1 = build_pkt_payload(seq1, &payload);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().clear();
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().clear();
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task1 = protolens.new_task();
        let mut task2 = protolens.new_task();

        protolens.run_task(&mut task1, pkt1.clone());
        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\r\n".to_vec()];
        let seq_expected = vec![1];
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);

        protolens.run_task(&mut task2, pkt1);
        // 验证收到的行是否正确
        let line_expected = vec![b"Hello\r\n".to_vec()];
        let seq_expected = vec![1];
        assert_eq!(*lines.borrow(), line_expected);
        assert_eq!(*seqs.borrow(), seq_expected);
    }

    // 超过MAX_READ_BUFF大小的一行，应该读取失败
    #[test]
    fn test_readline_exceeds_buffer() {
        let seq1 = 1;
        let mut payload = Vec::with_capacity(MAX_READ_BUFF);
        for i in 0..MAX_READ_BUFF {
            payload.push(b'A' + (i % 26) as u8); // 使用字母A-Z循环填充
        }

        let pkt1 = build_pkt_payload(seq1, &payload);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let callback = move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);

        assert_eq!(
            lines.borrow().len(),
            0,
            "不应该读取到任何行，因为缓冲区中没有\\r\\n且已达到MAX_READ_BUFF"
        );
    }

    // fill_buff case 3。部分行在buff末尾，需要移动的情况
    #[test]
    fn test_readline_buff_move() {
        // 第一个包的内容：
        // - 498个字符 + \r\n (500字节)
        // - 12个字符 (剩余12字节，不带\r\n)
        // 总共512字节，正好填满 MAX_READ_BUFF
        let mut payload1 = Vec::new();
        for i in 0..MAX_READ_BUFF - 12 - 2 {
            payload1.push(b'A' + (i % 26) as u8);
        }
        payload1.extend_from_slice(b"\r\n"); // 第一行结束
        payload1.extend_from_slice(b"INCOMPLETE__"); // 第二行的前12个字符

        // 第二个包的内容
        let payload2 = b"LINE\r\n".to_vec();

        let seq1 = 1;
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let seq2 = seq1 + payload1.len() as u32;
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 2);

        assert_eq!(lines_result[0].len(), MAX_READ_BUFF - 12);
        assert_eq!(
            &lines_result[0][MAX_READ_BUFF - 12 - 2..MAX_READ_BUFF - 12],
            b"\r\n"
        );

        assert_eq!(lines_result[1], b"INCOMPLETE__LINE\r\n");

        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + (MAX_READ_BUFF - 12) as u32);
    }

    // fill_buff case 3。部分行在buff末尾，需要移动，同时覆盖区域有重叠的情况。
    #[test]
    fn test_readline_buff_move_noverlap() {
        let line1_len = MAX_READ_BUFF / 3; // 包含\r\n
        let line2_start_len = MAX_READ_BUFF - line1_len;
        let line2_end_len = 10; // 包含\r\n
        dbg!(line1_len, line2_start_len, line2_end_len);

        // 填充第一个包
        let mut payload1 = vec![b'a'; line1_len - 2];
        payload1.extend_from_slice(b"\r\n");

        // 添加第二行的开头
        payload1.extend_from_slice(&vec![b'b'; line2_start_len]);
        // 确保第一个包的总长度正确
        assert_eq!(payload1.len(), MAX_READ_BUFF);

        // 填充第二个包
        let mut payload2 = vec![b'b'; line2_end_len - 2];
        payload2.extend_from_slice(b"\r\n");

        let seq1 = 1;
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let seq2 = seq1 + payload1.len() as u32;
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        // 应该读取到两行
        assert_eq!(lines_result.len(), 2);

        // 验证第一行
        assert_eq!(lines_result[0].len(), line1_len);
        assert_eq!(&lines_result[0][line1_len - 2..line1_len], b"\r\n");

        // 验证第二行
        let mut expected_second_line = vec![b'b'; line2_start_len + line2_end_len - 2];
        expected_second_line.extend_from_slice(b"\r\n");
        assert_eq!(lines_result[1], expected_second_line);

        // 验证序列号
        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + line1_len as u32);
    }

    // 前面的数据把read_buff填满（不包含\r\n)，后面的包中包含正常的行.此时不应该读出任何数据
    #[test]
    fn test_readline_full_buffer_without_newline() {
        let seq1 = 1;
        let mut payload1 = Vec::with_capacity(MAX_READ_BUFF);
        for i in 0..MAX_READ_BUFF {
            payload1.push(b'A' + (i % 26) as u8); // 使用字母A-Z循环填充
        }
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"\r\nNormal line\r\n".to_vec();
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let lines_result = lines.borrow();

        assert_eq!(
            lines_result.len(),
            0,
            "不应该读取到任何行，因为第一个包已经填满缓冲区且不包含\\r\\n"
        );
    }

    // 最后一个包只包含fin的情况
    #[test]
    fn test_readline_with_fin() {
        let seq1 = 1;
        let payload1 = b"First line\r\nSecond line\r\n".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"Third line\r\n".to_vec();
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let seq3 = seq2 + payload2.len() as u32;
        let pkt3 = build_pkt_fin(seq3);
        let _ = pkt3.decode();

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 3);

        assert_eq!(&lines_result[0], b"First line\r\n");
        assert_eq!(&lines_result[1], b"Second line\r\n");
        assert_eq!(&lines_result[2], b"Third line\r\n");

        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + b"First line\r\n".len() as u32);
        assert_eq!(seqs_result[2], seq2);
    }

    #[test]
    fn test_readline_with_data_fin() {
        let seq1 = 1;
        let payload1 = b"First line\r\nSecond line\r\n".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"Last line with FIN\r\n".to_vec();
        let pkt2 = build_pkt_payload_fin(seq2, &payload2);
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        dbg!("run 1");
        protolens.run_task(&mut task, pkt1);
        dbg!("run 2");
        protolens.run_task(&mut task, pkt2);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 3);

        assert_eq!(&lines_result[0], b"First line\r\n");
        assert_eq!(&lines_result[1], b"Second line\r\n");
        assert_eq!(&lines_result[2], b"Last line with FIN\r\n");

        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + b"First line\r\n".len() as u32);
        assert_eq!(seqs_result[2], seq2);
    }

    #[test]
    fn test_readline_with_middle_fin() {
        let seq1 = 1;
        let payload1 = b"First line\r\n".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"Last valid line\r\n".to_vec();
        let pkt2 = build_pkt_payload_fin(seq2, &payload2);
        let _ = pkt2.decode();

        let seq3 = seq2 + payload2.len() as u32;
        let payload3 = b"Should not be read\r\n".to_vec();
        let pkt3 = build_pkt_payload(seq3, &payload3);
        let _ = pkt3.decode();

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 2);

        assert_eq!(&lines_result[0], b"First line\r\n");
        assert_eq!(&lines_result[1], b"Last valid line\r\n");

        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq2);

        assert!(
            !lines_result
                .iter()
                .any(|line| line == b"Should not be read\r\n")
        );
    }

    // 有空行的情况
    #[test]
    fn test_readline_with_empty_line() {
        let seq1 = 1;
        let payload1 = b"First line\r\n".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"Last valid line\r\n".to_vec();
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let seq3 = seq2 + payload2.len() as u32;
        let payload3 = b"\r\n".to_vec();
        let pkt3 = build_pkt_payload(seq3, &payload3);
        let _ = pkt3.decode();

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 3);

        assert_eq!(&lines_result[0], payload1.as_bytes());
        assert_eq!(&lines_result[1], payload2.as_bytes());
        assert_eq!(&lines_result[2], payload3.as_bytes());

        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq2);
        assert_eq!(seqs_result[2], seq3);
    }

    // fill的时候只copy了一半packet情况
    // 第一次copy pkt1 + 部分pkt2
    // 第二次copy 剩余部分pkt2
    #[test]
    fn test_readline_part_copy_pkt() {
        // 第一个包的内容：
        // - 一个完整行 + 第二行的开头(留半行，避免buff被读空) 同时buff也不能填满，以便copy pkt2 的一部分
        // - 总长度为 MAX_READ_BUFF - 10
        let second_line_start_len = 10; // 第二行开头在第一个包中的长度,不包括\r\n
        let space_len = 2;
        let first_line_len = MAX_READ_BUFF - second_line_start_len - space_len; // 第一行的长度（包括\r\n）

        let mut payload1 = vec![b'a'; first_line_len - 2];
        payload1.extend_from_slice(b"\r\n");

        // 添加第二行的开头
        payload1.extend_from_slice(&vec![b'b'; second_line_start_len]);
        // 确保第一个包的总长度正确
        assert_eq!(payload1.len(), MAX_READ_BUFF - space_len);

        // 第二个包的内容：第二行的剩余部分 + \r\n
        let mut payload2 = vec![b'b'; 10];
        payload2.extend_from_slice(b"\r\n");

        let seq1 = 1;
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let seq2 = seq1 + payload1.len() as u32;
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        // 应该读取到两行
        assert_eq!(lines_result.len(), 2);

        // 验证第一行
        assert_eq!(lines_result[0].len(), first_line_len);
        assert_eq!(
            &lines_result[0][first_line_len - 2..first_line_len],
            b"\r\n"
        );

        // 验证第二行
        let mut expected_second_line = vec![b'b'; 20];
        expected_second_line.extend_from_slice(b"\r\n");
        assert_eq!(lines_result[1], expected_second_line);

        // 验证序列号
        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + first_line_len as u32);
    }
}
