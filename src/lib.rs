mod config;
// mod ffi;
mod heap;
mod packet;
mod parser;
mod pktstrm;
mod pool;
mod task;
#[cfg(test)]
mod test_utils;
mod util;

pub(crate) use config::*;
pub(crate) use heap::*;
pub(crate) use packet::*;
pub(crate) use parser::*;
pub(crate) use pktstrm::*;
pub(crate) use pool::*;
pub(crate) use task::*;

use std::marker::PhantomData;
use std::rc::Rc;

pub(crate) struct Stats {
    pub(crate) packet_count: usize,
    // 其他统计信息
}

impl Stats {
    pub(crate) fn new() -> Self {
        Stats {
            packet_count: 0,
            // 初始化其他统计信息
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Prolens<P> {
    config: Config,
    pool: Rc<Pool>,
    stats: Stats,
    _phantom: PhantomData<P>,
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> Prolens<P> {
    pub fn new(config: &Config) -> Self {
        // 计算不同组件所需的内存大小
        let heap_size = std::mem::size_of::<[P; 1]>() * config.heap_capacity;
        let pktstrm_size = std::mem::size_of::<PktStrm<P>>();
        let task_size = std::mem::size_of::<Task<P>>();
        let obj_sizes = vec![heap_size, pktstrm_size, task_size];

        Prolens {
            config: config.clone(),
            pool: Rc::new(Pool::new(obj_sizes)),
            stats: Stats::new(),
            _phantom: PhantomData,
        }
    }

    pub fn new_task(&self) -> PoolBox<Task<P>> {
        self.pool.alloc(|| Task::new(&self.pool))
    }

    pub fn new_parser<T: Parser<PacketType = P>>(&self) -> PoolBox<T> {
        self.pool.alloc(|| {
            let mut parser = T::new();
            parser.set_pool(Rc::clone(&self.pool));
            parser
        })
    }

    pub fn new_task_with_parser<T: Parser<PacketType = P>>(
        &self,
        parser: PoolBox<T>,
    ) -> PoolBox<Task<P>> {
        self.pool.alloc(|| Task::new_with_parser(parser))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn run_task(&mut self, task: &mut Task<P>, pkt: P, dir: PktDirection) {
        task.run(pkt, dir);

        self.stats.packet_count += 1;
    }
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> Default for Prolens<P> {
    fn default() -> Self {
        let config = Config::default();
        Self::new(&config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ordpacket::OrdPacketParser;
    use crate::parser::smtp::SmtpParser;
    use crate::test_utils::MyPacket;
    use crate::PktDirection;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_protolens_basic() {
        let mut protolens = Prolens::<MyPacket>::default();
        let mut task = protolens.new_task();

        let pkt = MyPacket::new(1, false);
        protolens.run_task(&mut task, pkt, PktDirection::Client2Server);
    }

    #[test]
    fn test_protolens_with_parser() {
        let mut protolens = Prolens::<MyPacket>::default();
        let parser = protolens.new_parser::<SmtpParser<MyPacket>>();
        let mut task = protolens.new_task_with_parser(parser);

        let pkt = MyPacket::new(1, false);
        protolens.run_task(&mut task, pkt, PktDirection::Client2Server);
    }

    #[test]
    fn test_protolens_config() {
        let config = Config {
            pool_size: 20,
            heap_capacity: 32,
        };
        let protolens = Prolens::<MyPacket>::new(&config);
        assert_eq!(protolens.config.pool_size, 20);
    }

    #[test]
    fn test_protolens_multiple_tasks() {
        let mut protolens = Prolens::<MyPacket>::default();

        let mut task1 = protolens.new_task();
        let mut task2 = protolens.new_task();

        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, false);

        protolens.run_task(&mut task1, pkt1, PktDirection::Client2Server);
        protolens.run_task(&mut task2, pkt2, PktDirection::Server2Client);
    }

    #[test]
    fn test_protolens_parser() {
        let mut protolens = Prolens::<MyPacket>::default();
        let parser = protolens.new_parser::<SmtpParser<MyPacket>>();
        let mut task = protolens.new_task_with_parser(parser);

        let pkt = MyPacket::new(1, false);
        protolens.run_task(&mut task, pkt, PktDirection::Client2Server);
    }

    #[test]
    fn test_protolens_lifetime() {
        let vec = Arc::new(Mutex::new(Vec::new()));
        let vec_clone = Arc::clone(&vec);

        let mut protolens = Prolens::<MyPacket>::default();
        let mut parser = protolens.new_parser::<OrdPacketParser<MyPacket>>();
        parser.set_callback_ord_pkt(move |pkt| {
            vec_clone.lock().unwrap().push(pkt.seq());
        });

        let mut task = protolens.new_task_with_parser(parser);

        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, true);

        protolens.run_task(&mut task, pkt1, PktDirection::Client2Server);
        protolens.run_task(&mut task, pkt2, PktDirection::Client2Server);

        assert_eq!(*vec.lock().unwrap(), vec![1, 2]);
    }
}
