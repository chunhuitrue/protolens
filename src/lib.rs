mod config;
mod dynamic_heap;
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

pub use crate::packet::L7Proto;
pub use crate::packet::Packet;
pub use crate::packet::PktDirection;
pub use crate::packet::TransProto;
pub use crate::task::Task;

pub use crate::ordpacket::OrdPacketParser;
#[cfg(test)]
pub use crate::rawpacket::RawPacketParser;
pub use crate::smtp::SmtpParser;
#[cfg(test)]
pub use crate::stream_next::StreamNextParser;
#[cfg(test)]
pub use crate::stream_read::StreamReadParser;
#[cfg(test)]
pub use crate::stream_readline::StreamReadlineParser;
#[cfg(test)]
pub use crate::stream_readline2::StreamReadline2Parser;
#[cfg(test)]
pub use crate::stream_readn::StreamReadnParser;
#[cfg(test)]
pub use crate::stream_readn2::StreamReadn2Parser;

use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

use crate::ordpacket::*;
#[cfg(test)]
use crate::rawpacket::*;
use crate::smtp::*;
#[cfg(test)]
use crate::stream_next::*;
#[cfg(test)]
use crate::stream_read::*;
#[cfg(test)]
use crate::stream_readline::*;
#[cfg(test)]
use crate::stream_readline2::*;
#[cfg(test)]
use crate::stream_readn::*;
#[cfg(test)]
use crate::stream_readn2::*;
use crate::task::TaskInner;
use config::*;
use heap::*;
use packet::*;
use parser::*;
use pktstrm::*;
use pool::*;

pub(crate) struct Stats {
    pub(crate) packet_count: usize,
}

impl Stats {
    pub(crate) fn new() -> Self {
        Stats { packet_count: 0 }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Prolens<P> {
    _phantom: PhantomData<P>,
    config: Config,
    pool: Rc<Pool>,
    stats: Stats,

    cb_ord_pkt: Option<CbOrdPkt<P>>,

    #[cfg(test)]
    cb_raw_pkt: Option<CbRawPkt<P>>,

    #[cfg(test)]
    cb_stream_next_byte: Option<CbStreamNext>,

    #[cfg(test)]
    cb_stream_read: Option<CbStreamRead>,

    #[cfg(test)]
    cb_stream_readline: Option<CbReadline>,

    #[cfg(test)]
    cb_stream_readline2: Option<CbReadline2>,

    #[cfg(test)]
    cb_readn: Option<CbReadn>,

    #[cfg(test)]
    cb_readn2: Option<CbReadn2>,

    cb_smtp_user: Option<CbUser>,
    cb_smtp_pass: Option<CbPass>,
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> Prolens<P> {
    // 每个线程一个protolens
    pub fn new(config: &Config) -> Self {
        Prolens {
            _phantom: PhantomData,
            config: config.clone(),
            pool: Rc::new(Pool::new(config.pool_size, Self::objs_size(config))),
            stats: Stats::new(),

            cb_ord_pkt: None,

            #[cfg(test)]
            cb_raw_pkt: None,

            #[cfg(test)]
            cb_stream_next_byte: None,

            #[cfg(test)]
            cb_stream_read: None,

            #[cfg(test)]
            cb_stream_readline: None,

            #[cfg(test)]
            cb_stream_readline2: None,

            #[cfg(test)]
            cb_readn: None,

            #[cfg(test)]
            cb_readn2: None,

            cb_smtp_user: None,
            cb_smtp_pass: None,
        }
    }

    // 正常流程是：
    //     包到来，但暂时未识别：先new task
    //     然后task run（push 包）
    //     几个包过后已经识别，可以确认parser，这时：new_parser, task_set_parser，task_set_c2s_callback
    pub fn new_task(&self) -> Task<P> {
        self.new_task_inner(ptr::null_mut())
    }

    fn new_task_inner(&self, cb_ctx: *mut c_void) -> Task<P> {
        Task::new(self.pool.alloc(|| TaskInner::new(&self.pool, cb_ctx)))
    }

    fn new_parser<T: ParserInner<PacketType = P>>(&self) -> Parser<P, T> {
        Parser::new(self.pool.alloc(|| {
            let mut parser = T::new();
            parser.set_pool(Rc::clone(&self.pool));
            parser
        }))
    }

    // 为已存在的 task 设置 parser
    // 这个方法用于在运行了一些数据包并确定了合适的 parser 类型后调用
    fn task_set_parser<T: ParserInner<PacketType = P>>(
        &self,
        task: &mut Task<P>,
        parser: Parser<P, T>,
    ) {
        task.as_inner_mut().init_parser(parser.into_inner());
    }

    // task stream callback
    pub fn set_cb_task_c2s<F>(&self, task: &mut Task<P>, callback: F)
    where
        F: StmCallbackFn + 'static,
    {
        task.as_inner_mut().set_c2s_callback(callback);
    }

    pub fn set_cb_task_s2c<F>(&self, task: &mut Task<P>, callback: F)
    where
        F: StmCallbackFn + 'static,
    {
        task.as_inner_mut().set_s2c_callback(callback);
    }

    // ord packet callback
    pub fn set_cb_ord_pkt<F>(&mut self, callback: F)
    where
        F: OrdPktCbFn<P> + 'static,
    {
        self.cb_ord_pkt = Some(Arc::new(Mutex::new(callback)));
    }

    // raw packet callback
    #[cfg(test)]
    pub fn set_cb_raw_pkt<F>(&mut self, callback: F)
    where
        F: RawPktCbFn<P> + 'static,
    {
        self.cb_raw_pkt = Some(Arc::new(Mutex::new(callback)));
    }

    // stream next callback
    #[cfg(test)]
    pub fn set_cb_stream_next_byte<F>(&mut self, callback: F)
    where
        F: StreamNextCbFn + 'static,
    {
        self.cb_stream_next_byte = Some(Arc::new(Mutex::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_stream_read<F>(&mut self, callback: F)
    where
        F: StreamReadCbFn + 'static,
    {
        self.cb_stream_read = Some(Arc::new(Mutex::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readline<F>(&mut self, callback: F)
    where
        F: ReadLineCbFn + 'static,
    {
        self.cb_stream_readline = Some(Arc::new(Mutex::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readline2<F>(&mut self, callback: F)
    where
        F: ReadLine2CbFn + 'static,
    {
        self.cb_stream_readline2 = Some(Arc::new(Mutex::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readn<F>(&mut self, callback: F)
    where
        F: ReadnCbFn + 'static,
    {
        self.cb_readn = Some(Arc::new(Mutex::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readn2<F>(&mut self, callback: F)
    where
        F: Readn2CbFn + 'static,
    {
        self.cb_readn2 = Some(Arc::new(Mutex::new(callback)));
    }

    // smtp callback
    pub fn set_cb_smtp_user<F>(&mut self, callback: F)
    where
        F: SmtpCbFn + 'static,
    {
        self.cb_smtp_user = Some(Arc::new(Mutex::new(callback)));
    }

    pub fn set_cb_smtp_pass<F>(&mut self, callback: F)
    where
        F: SmtpCbFn + 'static,
    {
        self.cb_smtp_pass = Some(Arc::new(Mutex::new(callback)) as CbPass);
    }

    // // 如果第一个包就已经识别成功。可以确定用哪个parser。使用这个api
    // pub fn new_task_with_parser<T: ParserInner<PacketType = P>>(
    //     &self,
    //     parser: Parser<P, T>,
    // ) -> Task<P> {
    //     self.new_task_with_parser_inner(parser, ptr::null_mut())
    // }

    // fn new_task_with_parser_inner<T: ParserInner<PacketType = P>>(
    //     &self,
    //     parser: Parser<P, T>,
    //     cb_ctx: *mut c_void,
    // ) -> Task<P> {
    //     Task::new(
    //         self.pool
    //             .alloc(|| TaskInner::new_with_parser(parser.into_inner(), cb_ctx)),
    //     )
    // }

    // None - 表示解析器还在pending状态或没有parser
    // Some(Ok(())) - 表示解析成功完成
    // Some(Err(())) - 表示解析遇到错误
    pub fn run_task(&mut self, task: &mut Task<P>, pkt: P) -> Option<Result<(), ()>> {
        if !task.as_inner_mut().parser_inited && pkt.l7_proto() != L7Proto::Unknown {
            match pkt.l7_proto() {
                L7Proto::OrdPacket => {
                    let mut parser = self.new_parser::<OrdPacketParser<P>>();
                    parser.cb_ord_pkt = self.cb_ord_pkt.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::RawPacket => {
                    let mut parser = self.new_parser::<RawPacketParser<P>>();
                    parser.cb_raw_pkt = self.cb_raw_pkt.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamNext => {
                    let mut parser = self.new_parser::<StreamNextParser<P>>();
                    parser.cb_next_byte = self.cb_stream_next_byte.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamRead => {
                    let mut parser = self.new_parser::<StreamReadParser<P>>();
                    parser.cb_read = self.cb_stream_read.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadline => {
                    let mut parser = self.new_parser::<StreamReadlineParser<P>>();
                    parser.cb_readline = self.cb_stream_readline.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadline2 => {
                    let mut parser = self.new_parser::<StreamReadline2Parser<P>>();
                    parser.cb_readline = self.cb_stream_readline2.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadn => {
                    let mut parser = self.new_parser::<StreamReadnParser<P>>();
                    parser.cb_readn = self.cb_readn.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadn2 => {
                    let mut parser = self.new_parser::<StreamReadn2Parser<P>>();
                    parser.cb_readn = self.cb_readn2.take();
                    self.task_set_parser(task, parser);
                }
                L7Proto::Smtp => {
                    let mut parser = self.new_parser::<SmtpParser<P>>();
                    parser.cb_pass = self.cb_smtp_pass.take();
                    parser.cb_user = self.cb_smtp_user.take();
                    self.task_set_parser(task, parser);
                }
                L7Proto::Unknown => {}
            }
        }

        self.stats.packet_count += 1;
        task.as_inner_mut().run(pkt)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn objs_size(_config: &Config) -> Vec<usize> {
        let mut res = Vec::new();

        let task_size = std::mem::size_of::<TaskInner<P>>();
        res.push(task_size);
        let pktstrm_size = std::mem::size_of::<PktStrm<P>>();
        res.push(pktstrm_size);
        let heap_size = Heap::<P, MAX_PKT_BUFF>::array_size();
        res.push(heap_size);
        let strm_size = PktStrm::<P>::buff_size();
        res.push(strm_size);
        dbg!(task_size, pktstrm_size, heap_size, strm_size);

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
        get_parser_sizes::<P, StreamReadline2Parser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, StreamReadnParser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, StreamReadn2Parser<P>>(&pool, &mut res);
        #[cfg(test)]
        get_parser_sizes::<P, StreamReadParser<P>>(&pool, &mut res);

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
    T: ParserInner<PacketType = P>,
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
    use crate::parser::smtp::SmtpParser;
    use crate::test_utils::MyPacket;
    use crate::test_utils::{CapPacket, PacketRef};
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_protolens_basic() {
        let mut protolens = Prolens::<MyPacket>::default();
        let mut task = protolens.new_task();

        let pkt = MyPacket::new(L7Proto::Unknown, 1, false);
        protolens.run_task(&mut task, pkt);
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

        let pkt1 = MyPacket::new(L7Proto::Unknown, 1, false);
        let pkt2 = MyPacket::new(L7Proto::Unknown, 2, false);

        protolens.run_task(&mut task1, pkt1);
        protolens.run_task(&mut task2, pkt2);
    }

    #[test]
    fn test_protolens_lifetime() {
        let vec = Arc::new(Mutex::new(Vec::new()));
        let vec_clone = Arc::clone(&vec);

        let mut protolens = Prolens::<MyPacket>::default();
        protolens.set_cb_ord_pkt(move |pkt, _cb_ctx: *const c_void| {
            vec_clone.lock().unwrap().push(pkt.seq());
        });
        let mut task = protolens.new_task();

        let pkt1 = MyPacket::new(L7Proto::OrdPacket, 1, false);
        let pkt2 = MyPacket::new(L7Proto::OrdPacket, 2, true);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

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

    #[test]
    fn test_task_set_parser() {
        let mut protolens = Prolens::<MyPacket>::default();
        let mut task = protolens.new_task();

        // 先运行一些数据包
        let pkt1 = MyPacket::new(L7Proto::Unknown, 1, false);
        let pkt2 = MyPacket::new(L7Proto::Unknown, 2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // pkt2之后识别成功，设置 parser
        let parser = protolens.new_parser::<SmtpParser<MyPacket>>();
        protolens.task_set_parser(&mut task, parser);

        // 继续处理数据包
        let pkt3 = MyPacket::new(L7Proto::Unknown, 3, false);
        protolens.run_task(&mut task, pkt3);
    }
}
