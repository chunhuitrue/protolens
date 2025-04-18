mod config;
mod enum_map;
mod ffi;
mod heap;
mod packet;
mod parser;
mod pktstrm;
mod stats;
mod task;
#[cfg(any(test, feature = "bench"))]
mod test_utils;

#[cfg(test)]
use crate::byte::*;
#[cfg(test)]
use crate::octet::*;
#[cfg(test)]
use crate::rawpacket::*;
#[cfg(test)]
use crate::read::*;
#[cfg(test)]
use crate::readline::*;
#[cfg(test)]
use crate::readn::*;

use crate::config::*;
use crate::enum_map::EnumMap;
use crate::ftpcmd::*;
use crate::ftpdata::*;
use crate::heap::*;
use crate::http::*;
use crate::imap::*;
use crate::ordpacket::*;
use crate::packet::*;
use crate::parser::*;
use crate::pktstrm::*;
use crate::pop3::*;
use crate::smtp::*;
use crate::stats::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;

pub use crate::packet::Direction;
pub use crate::packet::L7Proto;
pub use crate::packet::Packet;
pub use crate::packet::TransProto;
pub use crate::task::Task;

pub type ProlensRc<T> = Prolens<T, Rc<T>>;
pub type ProlensArc<T> = Prolens<T, Arc<T>>;

pub struct Prolens<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    conf: Config,
    stats: Stats,
    parsers: EnumMap<Box<dyn ParserFactory<T, P>>>,
    _phantom: PhantomData<P>,

    cb_ord_pkt: Option<CbOrdPkt<T>>,

    cb_smtp_user: Option<CbUser>,
    cb_smtp_pass: Option<CbPass>,
    cb_smtp_mailfrom: Option<CbMailFrom>,
    cb_smtp_rcpt: Option<CbRcpt>,
    cb_smtp_header: Option<CbHeader>,
    cb_smtp_body_start: Option<CbBodyEvt>,
    cb_smtp_body: Option<CbBody>,
    cb_smtp_body_stop: Option<CbBodyEvt>,
    cb_smtp_srv: Option<CbSrv>,

    cb_pop3_header: Option<CbHeader>,
    cb_pop3_body_start: Option<CbBodyEvt>,
    cb_pop3_body: Option<CbBody>,
    cb_pop3_body_stop: Option<CbBodyEvt>,
    cb_pop3_clt: Option<CbClt>,
    cb_pop3_srv: Option<CbSrv>,

    cb_imap_header: Option<CbHeader>,
    cb_imap_body_start: Option<CbBodyEvt>,
    cb_imap_body: Option<CbBody>,
    cb_imap_body_stop: Option<CbBodyEvt>,
    cb_imap_clt: Option<CbClt>,
    cb_imap_srv: Option<CbSrv>,

    cb_http_start_line: Option<CbStartLine>,
    cb_http_header: Option<CbHeader>,
    cb_http_body_start: Option<CbBodyEvt>,
    cb_http_body: Option<CbHttpBody>,
    cb_http_body_stop: Option<CbBodyEvt>,

    cb_ftp_clt: Option<CbClt>,
    cb_ftp_srv: Option<CbSrv>,
    cb_ftp_link: Option<CbFtpLink>,

    cb_ftp_body_start: Option<CbBodyEvt>,
    cb_ftp_body: Option<CbFtpBody>,
    cb_ftp_body_stop: Option<CbBodyEvt>,

    #[cfg(test)]
    cb_raw_pkt: Option<CbRawPkt<T>>,
    #[cfg(test)]
    cb_byte: Option<CbByte>,
    #[cfg(test)]
    cb_read: Option<CbRead>,
    #[cfg(test)]
    cb_readline: Option<CbReadline>,
    #[cfg(test)]
    cb_readn: Option<CbReadn>,
    #[cfg(test)]
    cb_readoctet: Option<CbReadOctet>,
}

impl<T, P> Prolens<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    pub fn new(conf: Config) -> Self {
        let mut prolens = Prolens {
            conf,
            stats: Stats::new(),
            parsers: EnumMap::new(),
            _phantom: PhantomData,

            cb_ord_pkt: None,
            #[cfg(test)]
            cb_raw_pkt: None,
            #[cfg(test)]
            cb_byte: None,
            #[cfg(test)]
            cb_read: None,
            #[cfg(test)]
            cb_readline: None,
            #[cfg(test)]
            cb_readn: None,
            #[cfg(test)]
            cb_readoctet: None,
            cb_smtp_user: None,
            cb_smtp_pass: None,
            cb_smtp_mailfrom: None,
            cb_smtp_rcpt: None,
            cb_smtp_header: None,
            cb_smtp_body_start: None,
            cb_smtp_body: None,
            cb_smtp_body_stop: None,
            cb_smtp_srv: None,
            cb_pop3_header: None,
            cb_pop3_body_start: None,
            cb_pop3_body: None,
            cb_pop3_body_stop: None,
            cb_pop3_clt: None,
            cb_pop3_srv: None,
            cb_imap_header: None,
            cb_imap_body_start: None,
            cb_imap_body: None,
            cb_imap_body_stop: None,
            cb_imap_clt: None,
            cb_imap_srv: None,
            cb_http_start_line: None,
            cb_http_header: None,
            cb_http_body_start: None,
            cb_http_body: None,
            cb_http_body_stop: None,
            cb_ftp_clt: None,
            cb_ftp_srv: None,
            cb_ftp_link: None,
            cb_ftp_body_start: None,
            cb_ftp_body: None,
            cb_ftp_body_stop: None,
        };
        prolens.regist_parsers();
        prolens
    }

    pub fn config(&self) -> &Config {
        &self.conf
    }

    fn regist_parsers(&mut self) {
        self.parsers.insert(
            L7Proto::OrdPacket,
            Box::new(OrdPacketrFactory::<T, P>::new()),
        );
        self.parsers
            .insert(L7Proto::Smtp, Box::new(SmtpFactory::<T, P>::new()));
        self.parsers
            .insert(L7Proto::Pop3, Box::new(Pop3Factory::<T, P>::new()));
        self.parsers
            .insert(L7Proto::Imap, Box::new(ImapFactory::<T, P>::new()));
        self.parsers
            .insert(L7Proto::Http, Box::new(HttpFactory::<T, P>::new()));
        self.parsers
            .insert(L7Proto::FtpCmd, Box::new(FtpCmdFactory::<T, P>::new()));
        self.parsers
            .insert(L7Proto::FtpData, Box::new(FtpDataFactory::<T, P>::new()));

        #[cfg(test)]
        {
            self.parsers.insert(
                L7Proto::RawPacket,
                Box::new(RawPacketFactory::<T, P>::new()),
            );
            self.parsers
                .insert(L7Proto::Byte, Box::new(ByteFactory::<T, P>::new()));
            self.parsers
                .insert(L7Proto::Read, Box::new(ReadFactory::<T, P>::new()));
            self.parsers
                .insert(L7Proto::Readline, Box::new(ReadlineFactory::<T, P>::new()));
            self.parsers
                .insert(L7Proto::Readn, Box::new(ReadnFactory::<T, P>::new()));
            self.parsers.insert(
                L7Proto::ReadOctet,
                Box::new(ReadOctetFactory::<T, P>::new()),
            );
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
        Box::new(Task::new(&self.conf, cb_ctx))
    }

    pub fn run_task(&mut self, task: &mut Task<T, P>, pkt: T) -> Option<Result<(), ()>> {
        let mut parser = None;
        if !task.parser_inited && pkt.l7_proto() != L7Proto::Unknown {
            let proto = pkt.l7_proto();
            if self.parsers.contains_key(&proto) {
                parser = self.parsers.get(&proto).map(|factory| factory.create(self));
            }
        }

        self.stats.packet_count += 1;
        let wrapper = PacketWrapper {
            ptr: P::new(pkt),
            _phantom: PhantomData,
        };
        task.run(wrapper, parser)
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
    pub fn set_cb_byte<F>(&mut self, callback: F)
    where
        F: ByteCbFn + 'static,
    {
        self.cb_byte = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_read<F>(&mut self, callback: F)
    where
        F: ReadCbFn + 'static,
    {
        self.cb_read = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readline<F>(&mut self, callback: F)
    where
        F: ReadLineCbFn + 'static,
    {
        self.cb_readline = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readn<F>(&mut self, callback: F)
    where
        F: ReadnCbFn + 'static,
    {
        self.cb_readn = Some(Rc::new(RefCell::new(callback)));
    }

    #[cfg(test)]
    pub fn set_cb_readoctet<F>(&mut self, callback: F)
    where
        F: ReadOctetCbFn + 'static,
    {
        self.cb_readoctet = Some(Rc::new(RefCell::new(callback)));
    }

    pub fn set_cb_smtp_user<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_smtp_user = Some(Rc::new(RefCell::new(callback)));
    }

    pub fn set_cb_smtp_pass<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_smtp_pass = Some(Rc::new(RefCell::new(callback)) as CbPass);
    }

    pub fn set_cb_smtp_mailfrom<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_smtp_mailfrom = Some(Rc::new(RefCell::new(callback)) as CbMailFrom);
    }

    pub fn set_cb_smtp_rcpt<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_smtp_rcpt = Some(Rc::new(RefCell::new(callback)) as CbRcpt);
    }

    pub fn set_cb_smtp_header<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_smtp_header = Some(Rc::new(RefCell::new(callback)) as CbHeader);
    }

    pub fn set_cb_smtp_body_start<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_smtp_body_start = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_smtp_body<F>(&mut self, callback: F)
    where
        F: BodyCbFn + 'static,
    {
        self.cb_smtp_body = Some(Rc::new(RefCell::new(callback)) as CbBody);
    }

    pub fn set_cb_smtp_body_stop<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_smtp_body_stop = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_smtp_srv<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_smtp_srv = Some(Rc::new(RefCell::new(callback)) as CbSrv);
    }

    pub fn set_cb_pop3_header<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_pop3_header = Some(Rc::new(RefCell::new(callback)) as CbHeader);
    }

    pub fn set_cb_pop3_body_start<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_pop3_body_start = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_pop3_body<F>(&mut self, callback: F)
    where
        F: BodyCbFn + 'static,
    {
        self.cb_pop3_body = Some(Rc::new(RefCell::new(callback)) as CbBody);
    }

    pub fn set_cb_pop3_body_stop<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_pop3_body_stop = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_pop3_clt<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_pop3_clt = Some(Rc::new(RefCell::new(callback)) as CbSrv);
    }

    pub fn set_cb_pop3_srv<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_pop3_srv = Some(Rc::new(RefCell::new(callback)) as CbSrv);
    }

    pub fn set_cb_imap_header<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_imap_header = Some(Rc::new(RefCell::new(callback)) as CbHeader);
    }

    pub fn set_cb_imap_body_start<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_imap_body_start = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_imap_body<F>(&mut self, callback: F)
    where
        F: BodyCbFn + 'static,
    {
        self.cb_imap_body = Some(Rc::new(RefCell::new(callback)) as CbBody);
    }

    pub fn set_cb_imap_body_stop<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_imap_body_stop = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_imap_clt<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_imap_clt = Some(Rc::new(RefCell::new(callback)) as CbClt);
    }

    pub fn set_cb_imap_srv<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_imap_srv = Some(Rc::new(RefCell::new(callback)) as CbSrv);
    }

    pub fn set_cb_http_start_line<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_http_start_line = Some(Rc::new(RefCell::new(callback)) as CbStartLine);
    }

    pub fn set_cb_http_header<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_http_header = Some(Rc::new(RefCell::new(callback)) as CbHeader);
    }

    pub fn set_cb_http_body_start<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_http_body_start = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_http_body<F>(&mut self, callback: F)
    where
        F: HttpBodyCbFn + 'static,
    {
        self.cb_http_body = Some(Rc::new(RefCell::new(callback)) as CbHttpBody);
    }

    pub fn set_cb_http_body_stop<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_http_body_stop = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_ftp_clt<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_ftp_clt = Some(Rc::new(RefCell::new(callback)) as CbClt);
    }

    pub fn set_cb_ftp_srv<F>(&mut self, callback: F)
    where
        F: DataCbFn + 'static,
    {
        self.cb_ftp_srv = Some(Rc::new(RefCell::new(callback)) as CbSrv);
    }

    pub fn set_cb_ftp_link<F>(&mut self, callback: F)
    where
        F: FtpLinkCbFn + 'static,
    {
        self.cb_ftp_link = Some(Rc::new(RefCell::new(callback)) as CbFtpLink);
    }

    pub fn set_cb_ftp_body_start<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_ftp_body_start = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_ftp_body<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_ftp_body = Some(Rc::new(RefCell::new(callback)) as CbFtpBody);
    }

    pub fn set_cb_ftp_body_stop<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_ftp_body_stop = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }
}

impl<T, P> Default for Prolens<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn default() -> Self {
        let conf = Config::default();
        Self::new(conf)
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
        let mut conf = Config::new();
        conf.pkt_buff = MAX_PKT_BUFF;
        conf.read_buff = MAX_READ_BUFF;
        let mut protolens = ProlensRc::<MyPacket>::new(conf);

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
        protolens.set_cb_ord_pkt(move |pkt, _cb_ctx: *mut c_void, _dir: Direction| {
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
        task.init_parser(Some(Box::new(parser)));

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
        protolens.set_cb_ord_pkt(move |pkt, _, _dir| {
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

        let pkt3 = MyPacket::new(L7Proto::OrdPacket, 3, true);
        let result = protolens.run_task(&mut recovered_task, pkt3);
        assert!(
            result.is_some(),
            "Should get parsing result after conversion"
        );

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

        protolens.set_cb_ord_pkt(move |pkt, cb_ctx, _dir| {
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

        let pkt3 = MyPacket::new(L7Proto::OrdPacket, 3, true);
        let result = protolens.run_task(&mut recovered_task, pkt3);
        assert!(
            result.is_some(),
            "Should get parsing result after conversion"
        );

        assert_eq!(
            *vec.borrow(),
            vec![1, 2, 3],
            "Should collect all sequence numbers"
        );

        assert_eq!(
            *ctx.borrow(),
            42 as *mut c_void,
            "Callback context should match"
        );
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    use super::*;
    use crate::test_utils::Capture;
    use crate::test_utils::build_pkt_payload;
    use criterion::{Criterion, Throughput, black_box};
    use std::env;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use test_utils::CapPacket;

    pub fn task_new(c: &mut Criterion) {
        let protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let mut group = c.benchmark_group("task_new");
        group.throughput(Throughput::Elements(1));
        group.bench_function("task_new", |b| b.iter(|| black_box(protolens.new_task())));
        group.finish();
    }

    pub fn task_init(c: &mut Criterion) {
        let protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let mut group = c.benchmark_group("task_init");
        group.throughput(Throughput::Elements(1));
        group.bench_function("task_init", |b| {
            b.iter(|| {
                let mut task = black_box(protolens.new_task());

                if let Some(factory) = black_box(protolens.get_parser_factory(L7Proto::Http)) {
                    let parser = Some(factory.create(&protolens));
                    task.init_parser(parser);
                }
            })
        });
        group.finish();
    }

    pub fn readline100(c: &mut Criterion) {
        readline(c, 100);
    }

    pub fn readline500(c: &mut Criterion) {
        readline(c, 500);
    }

    pub fn readline1000(c: &mut Criterion) {
        readline(c, 1000);
    }

    fn readline(c: &mut Criterion, pkt_len: usize) {
        let pkt_len = pkt_len.max(100);
        let lines_per_pkt = pkt_len / 10;

        let mut payload = Vec::with_capacity(pkt_len);
        for _ in 0..lines_per_pkt {
            payload.extend_from_slice(&[b'A'; 8]);
            payload.extend_from_slice(b"\r\n");
        }

        let mut packets = Vec::with_capacity(100);
        let mut seq = 1000;
        for _ in 0..100 {
            let pkt = build_pkt_payload(seq, &payload);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Readline);
            packets.push(pkt);
            seq += payload.len() as u32;
        }

        let mut protolens = black_box(Prolens::<CapPacket, Rc<CapPacket>>::default());
        let mut task = black_box(protolens.new_task());

        let mut group = c.benchmark_group("readline");
        group.throughput(Throughput::Bytes((payload.len() * 100) as u64));
        group.bench_function(format!("readline{}", pkt_len), |b| {
            b.iter_with_setup(
                || packets.clone(),
                |packets| {
                    for pkt in packets {
                        black_box(protolens.run_task(&mut task, pkt));
                    }
                },
            )
        });
        group.finish();
    }

    pub fn http(c: &mut Criterion) {
        bench_proto(c, "http", "http_mime", L7Proto::Http, 80);
    }

    pub fn smtp(c: &mut Criterion) {
        bench_proto(c, "smtp", "smtp", L7Proto::Smtp, 25);
    }

    pub fn pop3(c: &mut Criterion) {
        bench_proto(c, "pop3", "pop3", L7Proto::Pop3, 110);
    }

    pub fn imap(c: &mut Criterion) {
        bench_proto(c, "imap", "imap", L7Proto::Imap, 143);
    }

    fn bench_proto(c: &mut Criterion, name: &str, pcap_name: &str, proto: L7Proto, _port: u16) {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join(format!("tests/pcap/{}.pcap", pcap_name));
        let mut cap = Capture::init(file_path).unwrap();

        let mut total_bytes = 0;
        let mut packets = Vec::new();
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let pkt = cap.next_packet(now);
            if pkt.is_none() {
                break;
            }
            let pkt = pkt.unwrap();
            if pkt.decode().is_err() {
                continue;
            }
            pkt.set_l7_proto(proto);

            total_bytes += pkt.payload_len();
            packets.push(pkt);
        }

        let mut protolens = black_box(Prolens::<CapPacket, Rc<CapPacket>>::default());
        let mut task = black_box(protolens.new_task());

        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Bytes(total_bytes.into()));
        group.bench_function(name, |b| {
            b.iter_with_setup(
                || packets.clone(),
                |packets| {
                    for pkt in packets {
                        black_box(protolens.run_task(&mut task, pkt));
                    }
                },
            )
        });
        group.finish();
    }

    impl<T, P> Prolens<T, P>
    where
        T: PacketBind,
        P: PtrWrapper<T> + PtrNew<T> + 'static,
        PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
    {
        pub(crate) fn get_parser_factory(
            &self,
            proto: L7Proto,
        ) -> Option<&dyn ParserFactory<T, P>> {
            self.parsers.get(&proto).map(|v| &**v)
        }
    }
}
