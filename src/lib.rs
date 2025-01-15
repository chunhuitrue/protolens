mod config;
// mod ffi;
mod dynamic_heap;
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

use crate::ordpacket::OrdPacketParser;
#[cfg(test)]
use crate::rawpacket::RawPacketParser;
use crate::smtp::SmtpParser;
#[cfg(test)]
use crate::stream_next::StreamNextParser;
#[cfg(test)]
use crate::stream_readline::StreamReadlineParser;
#[cfg(test)]
use crate::stream_readn::StreamReadnParser;
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
        Prolens {
            config: config.clone(),
            pool: Rc::new(Pool::new(config.pool_size, Self::objs_size(config))),
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

    fn objs_size(_config: &Config) -> Vec<usize> {
        let mut res = Vec::new();

        let task_size = std::mem::size_of::<Task<P>>();
        res.push(task_size);
        let pktstrm_size = std::mem::size_of::<PktStrm<P>>();
        res.push(pktstrm_size);
        let heap_size = Heap::<P, MAX_CACHE_PKTS>::memory_size();
        res.push(heap_size);
        dbg!(task_size, pktstrm_size, heap_size);

        let pool = Rc::new(Pool::new(4096, vec![1]));

        get_parser_sizes::<P, OrdPacketParser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, RawPacketParser<P>>(&pool, &mut res);
        get_parser_sizes::<P, SmtpParser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, StreamNextParser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, StreamReadlineParser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, StreamReadnParser<P>>(&pool, &mut res);

        res.sort_unstable();
        res.dedup();
        res
    }
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> Default for Prolens<P> {
    fn default() -> Self {
        let config = Config::default();
        Self::new(&config)
    }
}

fn get_parser_sizes<P, T>(pool: &Rc<Pool>, res: &mut Vec<usize>)
where
    P: Packet + Ord + 'static,
    T: Parser<PacketType = P>,
{
    let mut parser = T::new();
    parser.set_pool(pool.clone());

    let c2s_size = parser.c2s_parser_size();
    let s2c_size = parser.s2c_parser_size();
    let bdir_size = parser.bdir_parser_size();
    res.push(c2s_size);
    res.push(s2c_size);
    res.push(bdir_size);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ordpacket::OrdPacketParser;
    use crate::parser::smtp::SmtpParser;
    use crate::test_utils::MyPacket;
    use crate::test_utils::{CapPacket, PacketRef};
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
            max_buf_packet: 32,
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

    #[test]
    fn test_objs_size() {
        let config = Config {
            pool_size: 20,
            max_buf_packet: 64,
        };

        let sizes = Prolens::<MyPacket>::objs_size(&config);
        println!("Object sizes: {:?}", sizes);

        // 验证返回的大小向量长度
        // 注意：由于去重，实际长度可能小于原来的预期值
        assert!(!sizes.is_empty(), "Size vector should not be empty");

        // 确保所有大小都大于0且已排序
        for i in 1..sizes.len() {
            assert!(sizes[i] > 0, "Size at index {} should be greater than 0", i);
            assert!(sizes[i] >= sizes[i - 1], "Sizes should be sorted");
        }
    }

    #[test]
    fn test_objs_size_with_packetref() {
        let config = Config {
            pool_size: 20,
            max_buf_packet: 64,
        };

        // 使用PacketRef<MyPacket>来初始化Prolens
        let sizes = Prolens::<PacketRef<MyPacket>>::objs_size(&config);
        println!("Object sizes with PacketRef: {:?}", sizes);

        // 验证返回的大小向量长度
        assert!(!sizes.is_empty(), "Size vector should not be empty");

        // 确保所有大小都大于0且已排序
        for i in 1..sizes.len() {
            assert!(sizes[i] > 0, "Size at index {} should be greater than 0", i);
            assert!(sizes[i] >= sizes[i - 1], "Sizes should be sorted");
        }

        // 添加一些具体的大小验证
        // PacketRef 只包含一个 Rc<MyPacket>，大小应该显著小于直接使用 MyPacket
        let packetref_size = std::mem::size_of::<PacketRef<MyPacket>>();
        let mypacket_size = std::mem::size_of::<MyPacket>();
        println!("PacketRef<MyPacket> size: {}", packetref_size);
        println!("MyPacket size: {}", mypacket_size);
        assert!(
            packetref_size < mypacket_size,
            "PacketRef should be smaller than MyPacket"
        );
    }

    #[test]
    fn test_objs_size_with_cappacket_ref() {
        let config = Config {
            pool_size: 20,
            max_buf_packet: 64,
        };

        // 使用PacketRef<CapPacket>来初始化Prolens
        let sizes = Prolens::<PacketRef<CapPacket>>::objs_size(&config);
        println!("Object sizes with PacketRef<CapPacket>: {:?}", sizes);

        // 验证返回的大小向量长度
        assert!(!sizes.is_empty(), "Size vector should not be empty");

        // 确保所有大小都大于0且已排序
        for i in 1..sizes.len() {
            assert!(sizes[i] > 0, "Size at index {} should be greater than 0", i);
            assert!(sizes[i] >= sizes[i - 1], "Sizes should be sorted");
        }

        // 添加具体的大小验证
        // PacketRef<CapPacket> 只包含一个 Rc<CapPacket>，大小应该显著小于直接使用 CapPacket
        let packetref_size = std::mem::size_of::<PacketRef<CapPacket>>();
        let cappacket_size = std::mem::size_of::<CapPacket>();
        println!("PacketRef<CapPacket> size: {}", packetref_size);
        println!("CapPacket size: {}", cappacket_size);
        assert!(
            packetref_size < cappacket_size,
            "PacketRef should be smaller than CapPacket"
        );

        // CapPacket 包含固定大小的数组和其他字段，大小应该比 MyPacket 大很多
        let mypacket_size = std::mem::size_of::<MyPacket>();
        println!("MyPacket size: {}", mypacket_size);
        assert!(
            cappacket_size > mypacket_size,
            "CapPacket should be larger than MyPacket"
        );
    }
}
