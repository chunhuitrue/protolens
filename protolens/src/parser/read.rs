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

pub struct ReadParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_read: Option<CbRead>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ReadParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub fn new() -> Self {
        Self {
            cb_read: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_read: Option<CbRead>,
        read_size: usize,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        while !stm.fin() {
            match stm.read_err(read_size).await {
                Ok((bytes, seq)) => {
                    if let Some(ref cb) = cb_read {
                        cb.borrow_mut()(bytes, seq, cb_ctx);
                    }
                }
                Err(_) => break,
            }
        }
        Ok(())
    }
}

impl<T, P> Default for ReadParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Parser for ReadParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn c2s_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_read.clone(),
            MAX_READ,
            stream,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for ReadFactory<T, P>
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
        let mut parser = Box::new(ReadParser::new());
        parser.cb_read = prolens.cb_read.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // n如果小于read buff长度，和readn行为一样
    #[allow(dead_code)]
    fn test_read_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Read);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_value = Rc::new(RefCell::new(0u32));
        let seq_clone = Rc::clone(&seq_value);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            *seq_clone.borrow_mut() = seq;
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_read(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.borrow(), expected);
        assert_eq!(*seq_value.borrow(), seq1);
    }

    // n如果小于read buff长度，和readn行为一样
    #[allow(dead_code)]
    fn test_read_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Read);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_values = Rc::new(RefCell::new(Vec::new()));
        let seq_clone = Rc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            seq_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_read(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_seqs = vec![seq1, seq2];
        assert_eq!(*vec.borrow(), expected);
        assert_eq!(*seq_values.borrow(), expected_seqs);
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
        pkt1.set_l7_proto(L7Proto::Read);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let seqs = Rc::new(RefCell::new(Vec::new()));
        let seqs_clone = Rc::clone(&seqs);
        let callback = move |line: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line.len());
            seqs_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_read(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt1);

        let lines_result = lines.borrow();

        // parser中每次都传入max read。所以剩余数据小于max read 不应该读出来。只有1次读取
        // parser中虽然可以传入大于buff的值，但不能传入没有的size。
        assert_eq!(lines_result.len(), 1);
    }
}
