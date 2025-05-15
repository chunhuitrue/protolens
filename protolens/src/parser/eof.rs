use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::ReadError;
use crate::packet::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait ReadEofCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> ReadEofCbFn for F {}
pub(crate) type CbReadEof = Rc<RefCell<dyn ReadEofCbFn + 'static>>;

pub struct ReadEofParser<T>
where
    T: Packet,
{
    pub(crate) cb_read: Option<CbReadEof>,
    _phantom_t: PhantomData<T>,
}

impl<T> ReadEofParser<T>
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
        cb_read: Option<CbReadEof>,
        strm: *mut PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        loop {
            match stm.read2eof().await {
                Ok((bytes, seq)) => {
                    if let Some(ref cb) = cb_read {
                        cb.borrow_mut()(bytes, seq, cb_ctx);
                    }
                }
                Err(ReadError::Eof) => {
                    break;
                }
                _ => {
                    continue;
                }
            }
        }
        Ok(())
    }
}

impl<T> Default for ReadEofParser<T>
where
    T: Packet,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Parser for ReadEofParser<T>
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

pub(crate) struct ReadEofFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for ReadEofFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(ReadEofParser::new());
        parser.cb_read = prolens.cb_readeof.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_READ_BUFF;
    use crate::test_utils::*;

    // 两个数据包，一个带数据，一个是fin
    #[test]
    fn test_eof_2pkt() {
        let seq1 = 1;
        let payload = b"content".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload.len() as u32;
        let pkt2 = build_pkt_fin(seq2);
        let _ = pkt2.decode();

        let data = Rc::new(RefCell::new(Vec::<u8>::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback", std::str::from_utf8(bytes).unwrap_or("err"));
            data_clone.borrow_mut().extend(bytes);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readeof(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadEof);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let data_result = data.borrow();
        assert_eq!(&*data_result, &payload);

        let seqs_result = seqs.borrow();
        assert_eq!(seqs_result.len(), 1);
        assert_eq!(seqs_result[0], seq1);
    }

    // 两个数据包，都带数据，一个还带fin
    #[test]
    fn test_eof_pkt_datafin() {
        let seq1 = 1;
        let payload1 = b"content1".to_vec();
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"content2".to_vec();
        let pkt2 = build_pkt_payload_fin(seq2, &payload2);
        let _ = pkt2.decode();

        let data = Rc::new(RefCell::new(Vec::<u8>::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback", std::str::from_utf8(bytes).unwrap_or("err"));
            data_clone.borrow_mut().extend(bytes);
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readeof(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadEof);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let data_result = data.borrow();
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(&payload1);
        expected_data.extend_from_slice(&payload2);
        assert_eq!(&*data_result, &expected_data);

        let seqs_result = seqs.borrow();
        assert_eq!(seqs_result.len(), 2);
        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq2);
    }

    // 一个pkt，带数据，带fin
    #[test]
    fn test_eof_1pkt() {
        let seq1 = 1;
        let payload = b"content".to_vec();
        let pkt = build_pkt_payload_fin(seq1, &payload);
        let _ = pkt.decode();

        let data = Rc::new(RefCell::new(Vec::new()));
        let data_clone = Rc::clone(&data);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            dbg!("in callback", std::str::from_utf8(bytes).unwrap_or("err"));
            data_clone.borrow_mut().push(bytes.to_vec());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readeof(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadEof);

        protolens.run_task(&mut task, pkt);

        let lines_result = data.borrow();
        assert_eq!(lines_result.len(), 1);
        assert_eq!(&lines_result[0], &payload);

        let seqs_result = seqs.borrow();
        assert_eq!(seqs_result.len(), 1);
        assert_eq!(seqs_result[0], seq1);
    }

    // 数据跨越buff
    #[test]
    fn test_eof_over_buff() {
        let seq1 = 1;
        let payload1_len = MAX_READ_BUFF + 10;
        let payload1 = vec![b'a'; payload1_len];
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = b"1234567890".to_vec();
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        let seq3 = seq2 + payload2.len() as u32;
        let pkt3 = build_pkt_fin(seq3);
        let _ = pkt3.decode();

        let seq4 = seq3 + 1;
        let payload4 = b"abcdef".to_vec();
        let pkt4 = build_pkt_payload(seq4, &payload4);
        let _ = pkt4.decode();

        let content = Rc::new(RefCell::new(Vec::new()));
        let content_clone = Rc::clone(&content);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |data: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            content_clone.borrow_mut().extend_from_slice(data);
            seqs_clone.borrow_mut().push(seq);
            dbg!(seq, data.len());
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readoctet(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::ReadOctet);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);
        protolens.run_task(&mut task, pkt4);

        let content_result = content.borrow();
        let mut expected_data = Vec::new(); // pkt4不应该被读到
        expected_data.extend_from_slice(&payload1);
        expected_data.extend_from_slice(&payload2);

        assert_eq!(content_result.len(), expected_data.len());
        assert_eq!(&content_result[..], expected_data);

        let seqs_result = seqs.borrow();
        assert_eq!(seqs_result.len(), 3);
        assert_eq!(seqs_result[0], seq1);
        assert_eq!(seqs_result[1], seq1 + MAX_READ_BUFF as u32);
        assert_eq!(seqs_result[2], seq2);
    }
}
