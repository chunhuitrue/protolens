use crate::pool::Pool;
use crate::Packet;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

pub trait Rn2CallbackFn: FnMut(&[u8], u32, *const c_void) + Send + Sync {}
impl<F: FnMut(&[u8], u32, *const c_void) + Send + Sync> Rn2CallbackFn for F {}
type CallbackStreamReadn2 = Arc<Mutex<dyn Rn2CallbackFn>>;

pub struct StreamReadn2Parser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    callback_readn: Option<CallbackStreamReadn2>,
    read_size: usize,
}

impl<T: Packet + Ord + 'static> StreamReadn2Parser<T> {
    pub(crate) fn new(read_size: usize) -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            callback_readn: None,
            read_size,
        }
    }

    pub fn set_callback_readn<F>(&mut self, callback: F)
    where
        F: Rn2CallbackFn + 'static,
    {
        self.callback_readn = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *const c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.callback_readn.clone();
        let read_size = self.read_size;

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while !stm.fin() {
                match stm.readn2(read_size).await {
                    Ok((bytes, seq)) => {
                        if let Some(ref callback) = callback {
                            callback.lock().unwrap()(bytes, seq, cb_ctx);
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(())
        }
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadn2Parser<T> {
    fn default() -> Self {
        Self::new(5)
    }
}

impl<T: Packet + Ord + 'static> Parser for StreamReadn2Parser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new(10)
    }

    fn pool(&self) -> &Rc<Pool> {
        self.pool.as_ref().expect("Pool not set")
    }

    fn set_pool(&mut self, pool: Rc<Pool>) {
        self.pool = Some(pool);
    }

    fn c2s_parser_size(&self) -> usize {
        let stream_ptr = std::ptr::null();

        let future = self.c2s_parser_inner(stream_ptr, ptr::null_mut());
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        cb_ctx: *const c_void,
    ) -> Option<ParserFuture> {
        Some(
            self.pool()
                .alloc_future(self.c2s_parser_inner(stream, cb_ctx)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;
    use std::ptr;

    #[test]
    fn test_stream_readn2_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let vec = Arc::new(Mutex::new(Vec::new()));
        let seq_value = Arc::new(Mutex::new(0u32));

        let vec_clone = Arc::clone(&vec);
        let seq_clone = Arc::clone(&seq_value);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend_from_slice(bytes);
            *seq_clone.lock().unwrap() = seq;
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadn2Parser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser, ptr::null_mut());

        protolens.run_task(&mut task, pkt1);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.lock().unwrap(), expected);
        assert_eq!(*seq_value.lock().unwrap(), seq1);
    }

    #[test]
    fn test_stream_readn2_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let vec = Arc::new(Mutex::new(Vec::new()));
        let seq_values = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let seq_clone = Arc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend_from_slice(bytes);
            seq_clone.lock().unwrap().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadn2Parser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser, ptr::null_mut());

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_seqs = vec![seq1, seq2];
        assert_eq!(*vec.lock().unwrap(), expected);
        assert_eq!(*seq_values.lock().unwrap(), expected_seqs);
    }
}
