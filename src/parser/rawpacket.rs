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

pub trait RawPktCbFn<T>: FnMut(T, *mut c_void) {}
impl<F, T> RawPktCbFn<T> for F where F: FnMut(T, *mut c_void) {}
pub(crate) type CbRawPkt<T> = Rc<RefCell<dyn RawPktCbFn<T> + 'static>>;

pub(crate) struct RawPacketParser<T>
where
    T: Packet,
{
    pub(crate) cb_raw_pkt: Option<CbRawPkt<T>>,
}

impl<T> RawPacketParser<T>
where
    T: Packet,
{
    pub fn new() -> Self {
        Self { cb_raw_pkt: None }
    }

    async fn c2s_parser_inner(
        cb_raw_pkt: Option<CbRawPkt<T>>,
        strm: *mut PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        while !stm.fin() {
            let pkt = stm.next_raw_pkt().await;
            if let Some(ref cb) = cb_raw_pkt {
                if let Some(pkt) = pkt {
                    cb.borrow_mut()(pkt.clone(), cb_ctx);
                }
            }
        }
        Ok(())
    }
}

impl<T> Default for RawPacketParser<T>
where
    T: Packet,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Parser for RawPacketParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_raw_pkt.clone(),
            strm,
            cb_ctx,
        )))
    }
}

pub(crate) struct RawPacketFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for RawPacketFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(RawPacketParser::new());
        parser.cb_raw_pkt = prolens.cb_raw_pkt.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_rawpacket_parser() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();

        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len();
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();

        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len();
        let pkt3 = build_pkt(seq3, true);
        let _ = pkt3.decode();

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

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::RawPacket);

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
}
