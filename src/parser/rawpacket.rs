use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;
use crate::pool::Pool;
use crate::ProtoLens;
type CallbackRawPkt<T> = Arc<Mutex<dyn FnMut(T) + Send + Sync>>;

pub struct RawPacketParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_raw_pkt: Option<CallbackRawPkt<T>>,
    pool: Option<Arc<Pool>>,
}

impl<T: Packet + Ord + 'static> RawPacketParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_raw_pkt: None,
            pool: None,
        }
    }

    pub fn set_callback_raw_pkt<F>(&mut self, callback: F)
    where
        F: FnMut(T) + Send + Sync + 'static,
    {
        self.callback_raw_pkt = Some(Arc::new(Mutex::new(callback)));
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

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        mut _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        let callback = self.callback_raw_pkt.clone();

        self.pool().new_future(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
            }

            while !stm.fin() {
                let pkt = stm.next_raw_pkt().await;
                if let Some(ref callback) = callback {
                    if let Some(pkt) = pkt {
                        callback.lock().unwrap()(pkt);
                    }
                }
            }
            Ok(())
        })
    }

    fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("Pool not set").as_ref()
    }

    fn set_pool(&mut self, pool: Arc<Pool>) {
        self.pool = Some(pool);
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
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len();
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len();
        let pkt3 = build_pkt(seq3, true);
        let _ = pkt3.decode();

        let count = Arc::new(Mutex::new(0));
        let count_clone = count.clone();
        let dir = PktDirection::Client2Server;

        let callback = move |pkt: CapPacket| {
            let mut count = count_clone.lock().unwrap();
            *count += 1;
            dbg!(pkt.seq(), *count);
            match *count {
                1 => assert_eq!(21, pkt.seq()),
                2 => assert_eq!(11, pkt.seq()),
                3 => assert_eq!(1, pkt.seq()),
                _ => panic!("too many packets"),
            }
        };

        let protolens = ProtoLens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<RawPacketParser<CapPacket>>();
        parser.set_callback_raw_pkt(callback);
        let mut task = protolens.new_task_with_parser(parser);

        dbg!("1 task run");
        task.run(pkt3, dir.clone());
        dbg!("2 task run");
        task.run(pkt2, dir.clone());
        dbg!("3 task run");
        task.run(pkt1, dir.clone());
        dbg!("4 task run");
        // run了三个包，但count是1
        // pktstrm中有对fin的控制。如果fin的包已经被按序读走，说明本条流已经结束。此后就不应该在push，或者pop了
        // 如果加上原始包顺序的接口和parser。这种机制就会影响对原始顺序包的读取。如果fin时候乱序到来的。fin以后的包就没办法读出。
        // 这样就影响了原始顺序的语意思。
        // 所以，count是1。
        assert_eq!(*count.lock().unwrap(), 1);
    }
}
