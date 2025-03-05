use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::packet::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait Readn2CbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> Readn2CbFn for F {}
pub(crate) type CbReadn2 = Rc<RefCell<dyn Readn2CbFn + 'static>>;

pub struct StreamReadn2Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_readn: Option<CbReadn2>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> StreamReadn2Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_readn: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_readn: Option<CbReadn2>,
        read_size: usize,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        while !stm.fin() {
            match stm.readn2(read_size).await {
                Ok((bytes, seq)) => {
                    if let Some(ref cb) = cb_readn {
                        cb.borrow_mut()(bytes, seq, cb_ctx);
                    }
                }
                Err(_) => break,
            }
        }
        Ok(())
    }
}

impl<T, P> Default for StreamReadn2Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Parser for StreamReadn2Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn new() -> Self {
        Self::new()
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_readn.clone(),
            10,
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
    fn test_stream_readn2_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::StreamReadn2);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_value = Rc::new(RefCell::new(0u32));
        let seq_clone = Rc::clone(&seq_value);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            *seq_clone.borrow_mut() = seq;
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readn2(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.borrow(), expected);
        assert_eq!(*seq_value.borrow(), seq1);
    }

    #[test]
    fn test_stream_readn2_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::StreamReadn2);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_values = Rc::new(RefCell::new(Vec::new()));
        let seq_clone = Rc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            seq_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readn2(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_seqs = vec![seq1, seq2];
        assert_eq!(*vec.borrow(), expected);
        assert_eq!(*seq_values.borrow(), expected_seqs);
    }
}
