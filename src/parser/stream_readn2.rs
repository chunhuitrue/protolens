use crate::pool::Pool;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

pub trait CallbackFn: FnMut(&[u8]) + Send + Sync {}
impl<F: FnMut(&[u8]) + Send + Sync> CallbackFn for F {}
type CallbackStreamReadn2 = Arc<Mutex<dyn CallbackFn>>;

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
        F: CallbackFn + 'static,
    {
        self.callback_readn = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        _meta_tx: mpsc::Sender<Meta>,
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
                    Ok(bytes) => {
                        if let Some(ref callback) = callback {
                            callback.lock().unwrap()(bytes);
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
        let (tx, _rx) = mpsc::channel(1);
        let stream_ptr = std::ptr::null();

        let future = self.c2s_parser_inner(stream_ptr, tx);
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        meta_tx: mpsc::Sender<Meta>,
    ) -> Option<ParserFuture> {
        Some(
            self.pool()
                .alloc_future(self.c2s_parser_inner(stream, meta_tx)),
        )
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

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: &[u8]| {
            vec_clone.lock().unwrap().extend_from_slice(bytes);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadn2Parser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1, dir.clone());

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.lock().unwrap(), expected);
    }

    #[test]
    fn test_stream_readn2_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let dir = PktDirection::Client2Server;
        let vec = Arc::new(Mutex::new(Vec::new()));

        let vec_clone = Arc::clone(&vec);
        let callback = move |bytes: &[u8]| {
            vec_clone.lock().unwrap().extend_from_slice(bytes);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<StreamReadn2Parser<CapPacket>>();
        parser.set_callback_readn(callback);
        let mut task = protolens.new_task_with_parser(parser);

        protolens.run_task(&mut task, pkt1, dir.clone());
        protolens.run_task(&mut task, pkt2, dir.clone());

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.lock().unwrap(), expected);
    }
}
