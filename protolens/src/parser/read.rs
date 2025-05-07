use crate::MAX_READ_BUFF;
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

const MAX_READ: usize = MAX_READ_BUFF + 10;

pub trait ReadCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> ReadCbFn for F {}
pub(crate) type CbRead = Rc<RefCell<dyn ReadCbFn + 'static>>;

pub struct ReadParser<T>
where
    T: Packet,
{
    pub(crate) cb_read: Option<CbRead>,
    _phantom_t: PhantomData<T>,
}

impl<T> ReadParser<T>
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
        cb_read: Option<CbRead>,
        read_size: usize,
        strm: *mut PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        while !stm.fin() {
            match stm.read_err(read_size).await {
                Ok((bytes, seq)) => {
                    if let Some(ref cb) = cb_read {
                        cb.borrow_mut()(bytes, seq, cb_ctx);
                    }
                }
                Err(_e) => break,
            }
        }
        Ok(())
    }
}

impl<T> Default for ReadParser<T>
where
    T: Packet,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Parser for ReadParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_read.clone(),
            MAX_READ,
            strm,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for ReadFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(ReadParser::new());
        parser.cb_read = prolens.cb_read.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_read_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_value = Rc::new(RefCell::new(0u32));
        let seq_clone = Rc::clone(&seq_value);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            *seq_clone.borrow_mut() = seq;
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_read(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Read);

        protolens.run_task(&mut task, pkt1);

        // The parser sets read_size to MAX_READ for each read, but the constructed packet is only 10 bytes long.
        // Therefore, it cannot be read out.
        // The behavior of read is: it attempts to read the given size, if this size exceeds the internal buffer,
        // it returns the buffer's length, expecting to continue reading subsequent data in the next attempt.
        // However, if there isn't enough data for the given size, and the size already exceeds the buffer size,
        // read will encounter the fin flag when attempting to read.
        // This is reasonable behavior.
        assert_eq!(*vec.borrow(), Vec::<u8>::new());
    }

    #[test]
    fn test_read_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_values = Rc::new(RefCell::new(Vec::new()));
        let seq_clone = Rc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            seq_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_read(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Read);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // The reason is the same as above
        assert_eq!(*vec.borrow(), Vec::<u8>::new());
    }

    // 因为n超过buff的长度。应该第一次读取buff的长度，第二次读取剩余的长度
    #[test]
    fn test_read_n() {
        // 填充超过buff的长度
        let payload_len = MAX_READ;
        let payload = vec![b'a'; payload_len];

        let seq1 = 1;
        let pkt1 = build_pkt_payload(seq1, &payload);
        let _ = pkt1.decode();

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.len());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_read(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Read);

        protolens.run_task(&mut task, pkt1);

        let lines_result = lines.borrow();

        // parser中每次都传入max read。所以剩余数据小于max read 不应该读出来。只有1次读取
        // parser中虽然可以传入大于buff的值，但不能传入没有的size。
        assert_eq!(lines_result.len(), 1);
    }
}
