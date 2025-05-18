use crate::MAX_READ_BUFF;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::ReadRet;
use crate::packet::*;
use memchr::memmem::Finder;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

const BDRY: &str = "===boundary===";

pub trait ReadOctetCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> ReadOctetCbFn for F {}
pub(crate) type CbReadOctet = Rc<RefCell<dyn ReadOctetCbFn + 'static>>;

pub struct ReadOctetParser<T>
where
    T: Packet,
{
    pub(crate) cb_read: Option<CbReadOctet>,
    _phantom_t: PhantomData<T>,
}

impl<T> ReadOctetParser<T>
where
    T: Packet,
{
    pub fn new() -> Self {
        Self {
            cb_read: None,
            _phantom_t: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_read: Option<CbReadOctet>,
        strm: *mut PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };
        let finder = Finder::new(BDRY);

        loop {
            let (ret, bytes, seq) = stm.read_mime_octet2(&finder, BDRY).await?;
            if !bytes.is_empty() {
                if let Some(ref cb) = cb_read {
                    cb.borrow_mut()(bytes, seq, cb_ctx);
                }
            }

            match ret {
                ReadRet::Data => {}
                ReadRet::DashBdry => {
                    break;
                }
            }
        }
        Ok(())
    }
}

impl<T> Default for ReadOctetParser<T>
where
    T: Packet,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Parser for ReadOctetParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_read.clone(),
            strm,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadOctetFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for ReadOctetFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(ReadOctetParser::new());
        parser.cb_read = prolens.cb_readoctet.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // 以\r\n--bdry结尾
    // 并且bdry之后的内容不应该被读取
    #[test]
    fn test_octet_content() {
        let seq1 = 1;
        let content = b"content".to_vec();
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());
        payload.extend_from_slice(b"do not read");
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().extend_from_slice(bytes);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(data_result.len(), content.len());
        assert_eq!(&data_result[..], &content);
        assert_eq!(seqs_result[0], seq1);
    }

    // 以--bdry结尾
    #[test]
    fn test_octet_content_bdry() {
        let seq1 = 1;
        let content = b"content".to_vec();
        let mut payload = content.clone();
        payload.extend_from_slice(b"--");
        payload.extend_from_slice(BDRY.as_bytes());
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().push(bytes.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(data_result.len(), 1);
        assert_eq!(&data_result[0], &content);
        assert_eq!(seqs_result[0], seq1);
    }

    // 有内容，而且内容中包含-- \r\n
    #[test]
    fn test_octet_misc_content_crlf() {
        let seq1 = 1;
        let content = b"content\r\n --1234\r\n \r\n--abc\r\n".to_vec();
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback", std::str::from_utf8(line).unwrap_or("err"));
            lines_clone.borrow_mut().push(line.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt);

        let lines_result = lines.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 1);
        assert_eq!(&lines_result[0], &content);
        assert_eq!(seqs_result[0], seq1);
    }

    // 而且内容中包含bdry
    #[test]
    fn test_octet_misc_content_bdry() {
        let seq1 = 1;
        let content = format!("content\r\n --1234\r\n \r\n--abc\r\n{}\r\n", BDRY).into_bytes();
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback", std::str::from_utf8(bytes).unwrap_or(""));
            data_clone.borrow_mut().push(bytes.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt);

        let lines_result = data.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(lines_result.len(), 1);
        assert_eq!(&lines_result[0], &content);
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个包。一个包包含一部分（但不超过read buff）第二个包包含bdry
    #[test]
    fn test_octet_2pkts() {
        let seq1 = 1;
        let payload1 = b"ABCDEFGHIJKLMNOPQRST".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"1234567890".to_vec();
        payload2.extend_from_slice(b"\r\n--");
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            content_clone.borrow_mut().extend_from_slice(data);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let content_result = content.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(content_result.len(), (payload1.len() + 10));
        assert_eq!(&content_result[..], b"ABCDEFGHIJKLMNOPQRST1234567890");
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个包。一个包包含一部分（但不超过read buff）第二个包包含bdry
    // 后一个带数据带fin
    #[test]
    fn test_octet_2pkts_fin() {
        let seq1 = 1;
        let payload1 = b"ABCDEFGHIJKLMNOPQRST".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"1234567890".to_vec();
        payload2.extend_from_slice(b"\r\n--");
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload_fin(seq2, &payload2);
        let _ = pkt2.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            content_clone.borrow_mut().extend_from_slice(data);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let content_result = content.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(content_result.len(), (payload1.len() + 10));
        assert_eq!(&content_result[..], b"ABCDEFGHIJKLMNOPQRST1234567890");
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个包带数据。一个包包含一部分（但不超过read buff）第二个包包含bdry
    // 第三哥包只带fin
    #[test]
    fn test_octet_3pkts_fin() {
        let seq1 = 1;
        let payload1 = b"ABCDEFGHIJKLMNOPQRST".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"1234567890".to_vec();
        payload2.extend_from_slice(b"\r\n--");
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload_fin(seq2, &payload2);
        let _ = pkt2.decode();

        let seq3 = seq2 + payload2.len() as u32;
        let pkt3 = build_pkt_fin(seq3);
        let _ = pkt3.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            content_clone.borrow_mut().extend_from_slice(data);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);

        let content_result = content.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(content_result.len(), (payload1.len() + 10));
        assert_eq!(&content_result[..], b"ABCDEFGHIJKLMNOPQRST1234567890");
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个包。一个包包含一部分（但不超过read buff）比bdry短,第二个包包含bdry
    #[test]
    fn test_octet_2pkts_short() {
        let seq1 = 1;
        let payload1 = b"ABCD".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"1234567890".to_vec();
        payload2.extend_from_slice(b"\r\n--");
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().extend_from_slice(bytes);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(data_result.len(), (payload1.len() + 10));
        assert_eq!(&data_result[..], b"ABCD1234567890");
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个包，第一个包超过read buff的长度
    #[test]
    fn test_octet_exceed_read_buff() {
        let seq1 = 1;
        let payload1_len = MAX_READ_BUFF + 10;
        let payload1 = vec![b'a'; payload1_len];
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"1234567890".to_vec();
        payload2.extend_from_slice(b"\r\n--");
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            content_clone.borrow_mut().extend_from_slice(data);
            seqs_clone.borrow_mut().push(seq);
            dbg!(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let content_result = content.borrow();
        let mut expected_data = payload1;
        expected_data.extend_from_slice(b"1234567890");

        assert_eq!(content_result.len(), expected_data.len());
        assert_eq!(&content_result[..], expected_data);

        let seqs_result = seqs.borrow();
        assert_eq!(seqs_result[0], seq1);
    }

    // close bdry 跨越buff的边界
    #[test]
    fn test_octet_bdry_ovelay_buff() {
        let seq1 = 1;
        let content = vec![b'a'; MAX_READ_BUFF - 10];
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().push(bytes.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(data_result.len(), 1);
        assert_eq!(&data_result[0], &content);
        assert_eq!(seqs_result[0], seq1);
    }

    // dash bdry 跨越buff的边界
    #[test]
    fn test_octet_dash_bdry_ovelay_buff() {
        let seq1 = 1;
        let content = vec![b'a'; MAX_READ_BUFF - 8];
        let mut payload = content.clone();
        payload.extend_from_slice(b"--");
        payload.extend_from_slice(BDRY.as_bytes());
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().push(bytes.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        assert_eq!(data_result.len(), 1);
        assert_eq!(&data_result[0], &content);
        assert_eq!(seqs_result[0], seq1);
    }

    // bdry 跨越包的边界
    #[test]
    fn test_octet_split_bdry() {
        let bdry_bytes = BDRY.as_bytes();
        let mid_point = bdry_bytes.len() / 2;

        let seq1 = 1;
        let mut payload1 = b"1234567890".to_vec();
        payload1.extend_from_slice(b"\r\n--");
        payload1.extend_from_slice(&bdry_bytes[..mid_point]);
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = bdry_bytes[mid_point..].to_vec();
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().extend_from_slice(bytes);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        let expected_data = b"1234567890".to_vec();
        assert_eq!(&data_result[..], &expected_data[..]);
        assert_eq!(seqs_result[0], seq1);
    }

    // bdry 跨越包的边界。只有一个字节
    #[test]
    fn test_octet_split_bdry_1_byte() {
        let bdry_bytes = BDRY.as_bytes();

        let seq1 = 1;
        let payload1 = b"1234567890\r".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"\n--".to_vec();
        payload2.extend_from_slice(bdry_bytes);
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_clone.borrow_mut().extend_from_slice(bytes);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let data_result = data.borrow();
        let seqs_result = seqs.borrow();

        let expected_data = b"1234567890".to_vec();
        assert_eq!(&data_result[..], &expected_data[..]);
        assert_eq!(seqs_result[0], seq1);
    }
}
