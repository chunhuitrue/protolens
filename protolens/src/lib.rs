mod config;
mod ffi;
mod heap;
mod packet;
mod parser;
mod pktstrm;
mod stats;
mod task;
#[cfg(test)]
mod test_utils;

pub use crate::packet::L7Proto;
pub use crate::packet::Packet;
pub use crate::packet::PktDirection;
pub use crate::packet::TransProto;
pub use crate::task::Task;

use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;

use crate::config::*;
use crate::heap::*;
use crate::ordpacket::*;
use crate::packet::*;
use crate::parser::*;
use crate::pktstrm::*;
#[cfg(test)]
use crate::rawpacket::*;
use crate::smtp::*;
use crate::stats::*;
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

pub type ProlensRc<T> = Prolens<T, Rc<T>>;
pub type ProlensArc<T> = Prolens<T, Arc<T>>;

pub struct Prolens<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    config: Config,
    stats: Stats,
    _phantom: PhantomData<P>,

    cb_ord_pkt: Option<CbOrdPkt<T>>,
    #[cfg(test)]
    cb_raw_pkt: Option<CbRawPkt<T>>,
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

impl<T, P> Prolens<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    pub fn new(config: &Config) -> Self {
        Prolens {
            config: config.clone(),
            stats: Stats::new(),
            _phantom: PhantomData,

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
    pub fn new_task(&self) -> Box<Task<T, P>> {
        self.new_task_ffi(ptr::null_mut())
    }

    pub(crate) fn new_task_ffi(&self, cb_ctx: *mut c_void) -> Box<Task<T, P>> {
        Box::new(Task::new(cb_ctx))
    }

    // 这个方法用于在运行了一些数据包并确定了合适的 parser 类型后调用
    fn task_set_parser<Q>(&self, task: &mut Task<T, P>, parser: Q)
    where
        Q: Parser<PacketType = T, PtrType = P>,
    {
        task.init_parser(parser);
    }

    pub fn set_cb_task_c2s<F>(&self, task: &mut Task<T, P>, callback: F)
    where
        F: StmCbFn + 'static,
    {
        task.set_cb_c2s(callback);
    }

    pub fn set_cb_task_s2c<F>(&self, task: &mut Task<T, P>, callback: F)
    where
        F: StmCbFn + 'static,
    {
        task.set_cb_s2c(callback);
    }

    pub fn set_cb_ord_pkt<F>(&mut self, callback: F)
    where
        F: OrdPktCbFn<T> + 'static,
    {
        self.cb_ord_pkt = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_raw_pkt<F>(&mut self, callback: F)
    where
        F: RawPktCbFn<T> + 'static,
    {
        self.cb_raw_pkt = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_stream_next_byte<F>(&mut self, callback: F)
    where
        F: StreamNextCbFn + 'static,
    {
        self.cb_stream_next_byte = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_stream_read<F>(&mut self, callback: F)
    where
        F: StreamReadCbFn + 'static,
    {
        self.cb_stream_read = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readline<F>(&mut self, callback: F)
    where
        F: ReadLineCbFn + 'static,
    {
        self.cb_stream_readline = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readline2<F>(&mut self, callback: F)
    where
        F: ReadLine2CbFn + 'static,
    {
        self.cb_stream_readline2 = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readn<F>(&mut self, callback: F)
    where
        F: ReadnCbFn + 'static,
    {
        self.cb_readn = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readn2<F>(&mut self, callback: F)
    where
        F: Readn2CbFn + 'static,
    {
        self.cb_readn2 = Some(Rc::new(RefCell::new(callback)));
    }

    pub fn set_cb_smtp_user<F>(&mut self, callback: F)
    where
        F: SmtpCbFn + 'static,
    {
        self.cb_smtp_user = Some(Rc::new(RefCell::new(callback)));
    }

    pub fn set_cb_smtp_pass<F>(&mut self, callback: F)
    where
        F: SmtpCbFn + 'static,
    {
        self.cb_smtp_pass = Some(Rc::new(RefCell::new(callback)) as CbPass);
    }

    // None - 表示解析器还在pending状态或没有parser
    // Some(Ok(())) - 表示解析成功完成
    // Some(Err(())) - 表示解析遇到错误
    pub fn run_task(&mut self, task: &mut Task<T, P>, pkt: T) -> Option<Result<(), ()>> {
        if !task.parser_inited && pkt.l7_proto() != L7Proto::Unknown {
            match pkt.l7_proto() {
                L7Proto::OrdPacket => {
                    let mut parser = OrdPacketParser::<T, P>::new();
                    parser.cb_ord_pkt = self.cb_ord_pkt.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::RawPacket => {
                    let mut parser = RawPacketParser::<T, P>::new();
                    parser.cb_raw_pkt = self.cb_raw_pkt.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamNext => {
                    let mut parser = StreamNextParser::<T, P>::new();
                    parser.cb_next_byte = self.cb_stream_next_byte.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamRead => {
                    let mut parser = StreamReadParser::<T, P>::new();
                    parser.cb_read = self.cb_stream_read.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadline => {
                    let mut parser = StreamReadlineParser::<T, P>::new();
                    parser.cb_readline = self.cb_stream_readline.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadline2 => {
                    let mut parser = StreamReadline2Parser::<T, P>::new();
                    parser.cb_readline = self.cb_stream_readline2.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadn => {
                    let mut parser = StreamReadnParser::<T, P>::new();
                    parser.cb_readn = self.cb_readn.take();
                    self.task_set_parser(task, parser);
                }
                #[cfg(test)]
                L7Proto::StreamReadn2 => {
                    let mut parser = StreamReadn2Parser::<T, P>::new();
                    parser.cb_readn = self.cb_readn2.take();
                    self.task_set_parser(task, parser);
                }
                L7Proto::Smtp => {
                    let mut parser = SmtpParser::<T, P>::new();
                    parser.cb_pass = self.cb_smtp_pass.take();
                    parser.cb_user = self.cb_smtp_user.take();
                    self.task_set_parser(task, parser);
                }
                L7Proto::Unknown => {}
            }
        }

        self.stats.packet_count += 1;
        let wrapper = PacketWrapper {
            ptr: P::new(pkt),
            _phantom: PhantomData,
        };
        task.run(wrapper)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl<T, P> Default for Prolens<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn default() -> Self {
        let config = Config::default();
        Self::new(&config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::smtp::SmtpParser;
    use crate::test_utils::MyPacket;
    use std::cell::RefCell;

    #[test]
    fn test_protolens_basic() {
        let mut protolens = ProlensRc::<MyPacket>::default();

        let mut task = protolens.new_task();

        let pkt = MyPacket::new(L7Proto::Unknown, 1, false);
        protolens.run_task(&mut task, pkt);
    }

    #[test]
    fn test_protolens_multiple_tasks() {
        let mut protolens = ProlensRc::<MyPacket>::default();

        let mut task1 = protolens.new_task();
        let mut task2 = protolens.new_task();

        let pkt1 = MyPacket::new(L7Proto::Unknown, 1, false);
        let pkt2 = MyPacket::new(L7Proto::Unknown, 2, false);

        protolens.run_task(&mut task1, pkt1);
        protolens.run_task(&mut task2, pkt2);
    }

    #[test]
    fn test_protolens_lifetime() {
        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);

        let mut protolens = ProlensRc::<MyPacket>::default();
        protolens.set_cb_ord_pkt(move |pkt, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().push(pkt.seq());
        });
        let mut task = protolens.new_task();

        let pkt1 = MyPacket::new(L7Proto::OrdPacket, 1, false);
        let pkt2 = MyPacket::new(L7Proto::OrdPacket, 2, true);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        assert_eq!(*vec.borrow(), vec![1, 2]);
    }

    #[test]
    fn test_task_set_parser() {
        let mut protolens = ProlensRc::<MyPacket>::default();
        let mut task = protolens.new_task();

        // 先运行一些数据包
        let pkt1 = MyPacket::new(L7Proto::Unknown, 1, false);
        let pkt2 = MyPacket::new(L7Proto::Unknown, 2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // pkt2之后识别成功，设置 parser
        let parser = SmtpParser::<MyPacket, Rc<MyPacket>>::new();
        protolens.task_set_parser(&mut task, parser);

        // 继续处理数据包
        let pkt3 = MyPacket::new(L7Proto::Unknown, 3, false);
        protolens.run_task(&mut task, pkt3);
    }

    #[test]
    fn test_task_raw_conversion() {
        let mut protolens = ProlensRc::<MyPacket>::default();

        // 设置 OrdPacket 回调（可选）
        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        protolens.set_cb_ord_pkt(move |pkt, _| {
            vec_clone.borrow_mut().push(pkt.seq());
        });

        let mut task = protolens.new_task();

        // 使用 OrdPacket 协议类型
        let pkt1 = MyPacket::new(L7Proto::OrdPacket, 1, false);
        let pkt2 = MyPacket::new(L7Proto::OrdPacket, 2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 转换为原始指针
        let raw_ptr = Box::into_raw(task);
        assert!(!raw_ptr.is_null(), "Raw pointer should not be null");

        // 从原始指针恢复
        let mut recovered_task = unsafe { Box::from_raw(raw_ptr) };

        // 继续处理新数据包验证功能正常
        let pkt3 = MyPacket::new(L7Proto::OrdPacket, 3, true);
        let result = protolens.run_task(&mut recovered_task, pkt3);
        assert!(
            result.is_some(),
            "Should get parsing result after conversion"
        );

        // 验证最终状态和回调结果
        assert_eq!(
            *vec.borrow(),
            vec![1, 2, 3],
            "Should collect all sequence numbers"
        );
    }

    #[test]
    fn test_task_raw_conversion_ctx() {
        let mut protolens = Prolens::<MyPacket, Rc<MyPacket>>::default();

        let ctx = Rc::new(RefCell::new(std::ptr::null_mut::<c_void>()));
        let ctx_clone = Rc::clone(&ctx);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);

        protolens.set_cb_ord_pkt(move |pkt, cb_ctx| {
            *ctx_clone.borrow_mut() = cb_ctx;
            vec_clone.borrow_mut().push(pkt.seq());
        });

        let mut task = protolens.new_task_ffi(42 as *mut c_void);

        // 使用 OrdPacket 协议类型
        let pkt1 = MyPacket::new(L7Proto::OrdPacket, 1, false);
        let pkt2 = MyPacket::new(L7Proto::OrdPacket, 2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 转换为原始指针
        let raw_ptr = Box::into_raw(task);
        assert!(!raw_ptr.is_null(), "Raw pointer should not be null");

        // 从原始指针恢复
        let mut recovered_task = unsafe { Box::from_raw(raw_ptr) };

        // 继续处理新数据包验证功能正常
        let pkt3 = MyPacket::new(L7Proto::OrdPacket, 3, true);
        let result = protolens.run_task(&mut recovered_task, pkt3);
        assert!(
            result.is_some(),
            "Should get parsing result after conversion"
        );

        // 验证最终状态和回调结果
        assert_eq!(
            *vec.borrow(),
            vec![1, 2, 3],
            "Should collect all sequence numbers"
        );

        // 检查共享的上下文指针
        assert_eq!(
            *ctx.borrow(),
            42 as *mut c_void,
            "Callback context should match"
        );
    }
}
