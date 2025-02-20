use crate::pool::Pool;
use crate::Packet;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use std::cell::RefCell;
use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;

pub trait RawPktCbFn<T>: FnMut(T, *mut c_void) {}
impl<F, T> RawPktCbFn<T> for F where F: FnMut(T, *mut c_void) {}
pub(crate) type CbRawPkt<T> = Rc<RefCell<dyn RawPktCbFn<T> + 'static>>;

pub struct RawPacketParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    pub(crate) cb_raw_pkt: Option<CbRawPkt<T>>,
}

impl<T: Packet + Ord + 'static> RawPacketParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            pool: None,
            cb_raw_pkt: None,
        }
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback = self.cb_raw_pkt.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            while !stm.fin() {
                let pkt = stm.next_raw_pkt().await;
                if let Some(ref callback) = callback {
                    if let Some(pkt) = pkt {
                        callback.borrow_mut()(pkt, cb_ctx);
                    }
                }
            }
            Ok(())
        }
    }
}

impl<T: Packet + Ord + 'static> Default for RawPacketParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for RawPacketParser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new()
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

    fn c2s_parser(&self, stream: *const PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
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
    fn test_rawpacket_parser() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::RawPacket);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len();
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();
        pkt2.set_l7_proto(L7Proto::RawPacket);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len();
        let pkt3 = build_pkt(seq3, true);
        let _ = pkt3.decode();
        pkt3.set_l7_proto(L7Proto::RawPacket);

        let count = Rc::new(RefCell::new(0));
        let count_clone = count.clone();

        let callback = move |pkt: CapPacket, _cb_ctx: *mut c_void| {
            let mut count = count_clone.borrow_mut();
            *count += 1;
            dbg!(pkt.seq(), *count);
            match *count {
                1 => assert_eq!(21, pkt.seq()),
                2 => assert_eq!(11, pkt.seq()),
                3 => assert_eq!(1, pkt.seq()),
                _ => panic!("too many packets"),
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_raw_pkt(callback);
        let mut task = protolens.new_task();

        dbg!("1 task run");
        protolens.run_task(&mut task, pkt3);
        dbg!("2 task run");
        protolens.run_task(&mut task, pkt2);
        dbg!("3 task run");
        protolens.run_task(&mut task, pkt1);
        dbg!("4 task run");
        // run了三个包，但count是1
        // pktstrm中有对fin的控制。如果fin的包已经被按序读走，说明本条流已经结束。此后就不应该在push，或者pop了
        // 如果加上原始包顺序的接口和parser。这种机制就会影响对原始顺序包的读取。如果fin时候乱序到来的。fin以后的包就没办法读出。
        // 这样就影响了原始顺序的语意思。
        // 所以，count是1。
        assert_eq!(*count.borrow(), 1);
    }

    #[test]
    fn test_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = RawPacketParser::<CapPacket>::new();
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<CbRawPkt<CapPacket>>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<Option<CbRawPkt<CapPacket>>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }
}
