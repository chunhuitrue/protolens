use crate::pool::Pool;
use crate::Packet;
use crate::ParserFuture;
use crate::ParserInner;
use crate::PktStrm;
use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

pub trait StreamReadCbFn: FnMut(&[u8], usize, u32, *const c_void) + Send + Sync {}
impl<F: FnMut(&[u8], usize, u32, *const c_void) + Send + Sync> StreamReadCbFn for F {}
pub(crate) type CbStreamRead = Arc<Mutex<dyn StreamReadCbFn>>;

pub struct StreamReadParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    read_buff: Vec<u8>,
    pub(crate) cb_read: Option<CbStreamRead>,
}

impl<T: Packet + Ord + 'static> StreamReadParser<T> {
    pub fn new(read_size: usize) -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            read_buff: vec![0; read_size],
            cb_read: None,
        }
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *const c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.cb_read.clone();
        let mut read_buff = self.read_buff.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while !stm.fin() {
                match stm.read(&mut read_buff).await {
                    Ok((read_len, seq)) => {
                        if read_len > 0 {
                            if let Some(ref callback) = callback {
                                callback.lock().unwrap()(
                                    &read_buff[..read_len],
                                    read_len,
                                    seq,
                                    cb_ctx,
                                );
                            }
                        }
                        if read_len == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(())
        }
    }
}

impl<T: Packet + Ord + 'static> Default for StreamReadParser<T> {
    fn default() -> Self {
        Self::new(20)
    }
}

impl<T: Packet + Ord + 'static> ParserInner for StreamReadParser<T> {
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

    #[test]
    fn test_stream_read_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::StreamRead);

        let vec = Arc::new(Mutex::new(Vec::new()));
        let seq_value = Arc::new(Mutex::new(0u32));

        let vec_clone = Arc::clone(&vec);
        let seq_clone = Arc::clone(&seq_value);
        let callback = move |bytes: &[u8], len: usize, seq: u32, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend_from_slice(&bytes[..len]);
            *seq_clone.lock().unwrap() = seq;
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_read(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.lock().unwrap(), expected);
        assert_eq!(*seq_value.lock().unwrap(), seq1);
    }

    #[test]
    fn test_stream_read_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::StreamRead);

        let vec = Arc::new(Mutex::new(Vec::new()));
        let seq_values = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let seq_clone = Arc::clone(&seq_values);
        let callback = move |bytes: &[u8], len: usize, seq: u32, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().extend_from_slice(&bytes[..len]);
            seq_clone.lock().unwrap().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_stream_read(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_seqs = vec![seq1, seq2];
        assert_eq!(*vec.lock().unwrap(), expected);
        assert_eq!(*seq_values.lock().unwrap(), expected_seqs);
    }
}
