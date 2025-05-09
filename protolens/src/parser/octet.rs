use crate::MAX_READ_BUFF;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::ReadRet;
use crate::packet::*;
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

        loop {
            let (ret, bytes, seq) = stm.read_mime_octet(BDRY).await?;
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

    #[test]
    fn test_octet_content() {
        let seq1 = 1;
        let content = b"content".to_vec();
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
        assert_eq!(&lines_result[0], &content); // 不包含dash bdry
        assert_eq!(seqs_result[0], seq1);
    }

    // 有内容，而且内容中包含-- \r\n
    #[test]
    fn test_octet_misc_content() {
        let seq1 = 1;
        let content = b"content\r\n --bdry\r\n \r\n--abc\r\n".to_vec();
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
        assert_eq!(&lines_result[0], &content); // 不包含dash bdry
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个包。一个包包含一部分（但不超过read buff）第二个包包含bdry
    #[test]
    fn test_octet_2pkts() {
        let seq1 = 1;
        let payload1 = b"ABCDEFGHIJKLMNOPQRST".to_vec(); // 20个字母
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = b"1234567890".to_vec(); // 10个字母
        payload2.extend_from_slice(b"\r\n--"); // 4个前缀
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback");
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

        // 验证总长度
        assert_eq!(content_result.len(), (payload1.len() + 10));
        // 验证前20个字符
        assert_eq!(&content_result[0..20], b"ABCDEFGHIJKLMNOPQRST");
        // 验证接下来的10个字符
        assert_eq!(&content_result[20..30], b"1234567890");

        assert_eq!(seqs_result.len(), 1);
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
        let mut payload2 = b"1234567890".to_vec(); // 10个字母
        payload2.extend_from_slice(b"\r\n--"); // 4个前缀
        payload2.extend_from_slice(BDRY.as_bytes());
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback");
            content_clone.borrow_mut().push(data.to_vec());
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

        // 第一次读取全部的read buff。第二次读取剩余的。共两次callback
        assert_eq!(content_result.len(), 2);

        // 验证第一次读取的内容。都是a
        let expected_first_data = vec![b'a'; MAX_READ_BUFF];
        assert_eq!(content_result[0], expected_first_data);

        // 验证第二次读取的内容。
        let expected_second_data = vec![b'a'; payload1_len - MAX_READ_BUFF];
        assert_eq!(
            &content_result[1][..payload1_len - MAX_READ_BUFF],
            &expected_second_data
        );
        assert_eq!(
            &content_result[1][payload1_len - MAX_READ_BUFF..],
            b"1234567890"
        );

        assert_eq!(seqs_result.len(), 2);
        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + MAX_READ_BUFF as u32);
    }
}
