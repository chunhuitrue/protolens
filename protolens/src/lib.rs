mod config;
mod enum_map;
mod ffi;
mod heap;
mod packet;
mod parser;
mod pktdata;
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
#[cfg(any(test, feature = "bench"))]
use crate::readline::*;
#[cfg(test)]
use crate::readn::*;

#[cfg(feature = "jemalloc")]
use jemallocator::Jemalloc;

use crate::config::*;
use crate::enum_map::EnumMap;
use crate::ftpcmd::*;
use crate::ftpdata::*;
use crate::heap::*;
use crate::http::*;
use crate::imap::*;
use crate::ordpacket::*;
use crate::parser::*;
use crate::pktstrm::*;
use crate::pop3::*;
use crate::sip::*;
use crate::smtp::*;
use crate::stats::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;

pub use crate::packet::Direction;
pub use crate::packet::L7Proto;
pub use crate::packet::Packet;
pub use crate::packet::TransProto;
pub use crate::task::Task;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub struct Prolens<T>
where
    T: Packet,
{
    conf: Config,
    stats: Stats,
    parsers: EnumMap<Box<dyn ParserFactory<T>>>,
    _phantom: PhantomData<T>,

    cb_task_c2s: Option<CbStrm>,
    cb_task_s2c: Option<CbStrm>,

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

    cb_sip_start_line: Option<CbStartLine>,
    cb_sip_header: Option<CbHeader>,
    cb_sip_body_start: Option<CbBodyEvt>,
    cb_sip_body: Option<CbSipBody>,
    cb_sip_body_stop: Option<CbBodyEvt>,

    #[cfg(test)]
    cb_raw_pkt: Option<CbRawPkt<T>>,
    #[cfg(test)]
    cb_byte: Option<CbByte>,
    #[cfg(test)]
    cb_read: Option<CbRead>,
    #[cfg(any(test, feature = "bench"))]
    cb_readline: Option<CbReadline>,
    #[cfg(test)]
    cb_readn: Option<CbReadn>,
    #[cfg(test)]
    cb_readoctet: Option<CbReadOctet>,
}

impl<T> Prolens<T>
where
    T: Packet + 'static,
{
    pub fn new(conf: Config) -> Self {
        let mut prolens = Prolens {
            conf,
            stats: Stats::new(),
            parsers: EnumMap::new(),
            _phantom: PhantomData,

            cb_task_c2s: None,
            cb_task_s2c: None,
            cb_ord_pkt: None,
            #[cfg(test)]
            cb_raw_pkt: None,
            #[cfg(test)]
            cb_byte: None,
            #[cfg(test)]
            cb_read: None,
            #[cfg(any(test, feature = "bench"))]
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
            cb_sip_start_line: None,
            cb_sip_header: None,
            cb_sip_body_start: None,
            cb_sip_body: None,
            cb_sip_body_stop: None,
        };
        prolens.regist_parsers();
        prolens
    }

    pub fn config(&self) -> &Config {
        &self.conf
    }

    fn regist_parsers(&mut self) {
        self.parsers
            .insert(L7Proto::OrdPacket, Box::new(OrdPacketrFactory::<T>::new()));
        self.parsers
            .insert(L7Proto::Smtp, Box::new(SmtpFactory::<T>::new()));
        self.parsers
            .insert(L7Proto::Pop3, Box::new(Pop3Factory::<T>::new()));
        self.parsers
            .insert(L7Proto::Imap, Box::new(ImapFactory::<T>::new()));
        self.parsers
            .insert(L7Proto::Http, Box::new(HttpFactory::<T>::new()));
        self.parsers
            .insert(L7Proto::FtpCmd, Box::new(FtpCmdFactory::<T>::new()));
        self.parsers
            .insert(L7Proto::FtpData, Box::new(FtpDataFactory::<T>::new()));
        self.parsers
            .insert(L7Proto::Sip, Box::new(SipFactory::<T>::new()));

        #[cfg(test)]
        {
            self.parsers
                .insert(L7Proto::RawPacket, Box::new(RawPacketFactory::<T>::new()));
            self.parsers
                .insert(L7Proto::Byte, Box::new(ByteFactory::<T>::new()));
            self.parsers
                .insert(L7Proto::Read, Box::new(ReadFactory::<T>::new()));
            self.parsers
                .insert(L7Proto::Readn, Box::new(ReadnFactory::<T>::new()));
            self.parsers
                .insert(L7Proto::ReadOctet, Box::new(ReadOctetFactory::<T>::new()));
        }
        #[cfg(any(test, feature = "bench"))]
        self.parsers
            .insert(L7Proto::Readline, Box::new(ReadlineFactory::<T>::new()));
    }

    pub fn new_task(&self, l4_proto: TransProto) -> Task<T> {
        let mut task = Task::new(&self.conf, ptr::null_mut(), l4_proto);
        if let Some(cb) = &self.cb_task_c2s {
            task.set_cb_strm_c2s(cb.clone());
        }
        if let Some(cb) = &self.cb_task_s2c {
            task.set_cb_strm_s2c(cb.clone());
        }
        task
    }

    fn new_task_ffi(&self, l4_proto: TransProto, cb_ctx: *mut c_void) -> Box<Task<T>> {
        let mut task = Box::new(Task::new(&self.conf, cb_ctx, l4_proto));
        if let Some(cb) = &self.cb_task_c2s {
            task.set_cb_strm_c2s(cb.clone());
        }
        if let Some(cb) = &self.cb_task_s2c {
            task.set_cb_strm_s2c(cb.clone());
        }
        task
    }

    pub fn set_task_parser(&self, task: &mut Task<T>, l7_proto: L7Proto) {
        if task.parser_set()
            || l7_proto == L7Proto::Unknown
            || !self.parsers.contains_key(&l7_proto)
        {
            return;
        }

        let parser = self
            .parsers
            .get(&l7_proto)
            .map(|factory| factory.create(self));
        if let Some(parser) = parser {
            task.set_parser(parser);
        }
    }

    pub fn run_task(&mut self, task: &mut Task<T>, pkt: T) -> Option<Result<(), ()>> {
        self.stats.packet_count += 1;
        task.run(pkt)
    }

    pub fn set_cb_task_c2s<F>(&mut self, callback: F)
    where
        F: StmCbFn + 'static,
    {
        self.cb_task_c2s = Some(Rc::new(RefCell::new(callback)));
    }

    pub fn set_cb_task_s2c<F>(&mut self, callback: F)
    where
        F: StmCbFn + 'static,
    {
        self.cb_task_s2c = Some(Rc::new(RefCell::new(callback)));
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

    #[cfg(any(test, feature = "bench"))]
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

    pub fn set_cb_sip_start_line<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_sip_start_line = Some(Rc::new(RefCell::new(callback)) as CbStartLine);
    }

    pub fn set_cb_sip_header<F>(&mut self, callback: F)
    where
        F: DataCbDirFn + 'static,
    {
        self.cb_sip_header = Some(Rc::new(RefCell::new(callback)) as CbHeader);
    }

    pub fn set_cb_sip_body_start<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_sip_body_start = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }

    pub fn set_cb_sip_body<F>(&mut self, callback: F)
    where
        F: SipBodyCbFn + 'static,
    {
        self.cb_sip_body = Some(Rc::new(RefCell::new(callback)) as CbSipBody);
    }

    pub fn set_cb_sip_body_stop<F>(&mut self, callback: F)
    where
        F: EvtCbFn + 'static,
    {
        self.cb_sip_body_stop = Some(Rc::new(RefCell::new(callback)) as CbBodyEvt);
    }
}

impl<T> Default for Prolens<T>
where
    T: Packet + 'static,
{
    fn default() -> Self {
        let conf = Config::default();
        Self::new(conf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MyPacket;
    use std::cell::RefCell;

    #[test]
    fn test_protolens_basic() {
        let mut conf = Config::new();
        conf.pkt_buff = MAX_PKT_BUFF;
        conf.read_buff = MAX_READ_BUFF;
        let mut protolens = Prolens::<MyPacket>::new(conf);

        let mut task = protolens.new_task(TransProto::Tcp);

        let pkt = MyPacket::new(1, false);
        protolens.run_task(&mut task, pkt);
    }

    #[test]
    fn test_protolens_multiple_tasks() {
        let mut protolens = Prolens::<MyPacket>::default();

        let mut task1 = protolens.new_task(TransProto::Tcp);
        let mut task2 = protolens.new_task(TransProto::Tcp);

        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, false);

        protolens.run_task(&mut task1, pkt1);
        protolens.run_task(&mut task2, pkt2);
    }

    #[test]
    fn test_protolens_lifetime() {
        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, true);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);

        let mut protolens = Prolens::<MyPacket>::default();
        protolens.set_cb_ord_pkt(move |pkt, _cb_ctx: *mut c_void, _dir: Direction| {
            vec_clone.borrow_mut().push(pkt.seq());
        });

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::OrdPacket);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        assert_eq!(*vec.borrow(), vec![1, 2]);
    }

    #[test]
    fn test_protolens_boxed_packet() {
        let pkt1 = Box::new(MyPacket::new(1, false));
        let pkt2 = Box::new(MyPacket::new(2, true));

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);

        let mut protolens = Prolens::<Box<MyPacket>>::default();
        protolens.set_cb_ord_pkt(move |pkt, _cb_ctx: *mut c_void, _dir: Direction| {
            vec_clone.borrow_mut().push(pkt.seq());
        });

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::OrdPacket);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        assert_eq!(*vec.borrow(), vec![1, 2]);
    }

    #[test]
    fn test_task_set_parser() {
        let mut protolens = Prolens::<MyPacket>::default();
        let mut task = protolens.new_task(TransProto::Tcp);

        // 先运行一些数据包
        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // pkt2之后识别成功，设置 parser
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        // 继续处理数据包
        let pkt3 = MyPacket::new(3, false);
        protolens.run_task(&mut task, pkt3);
    }

    #[test]
    fn test_task_raw_conversion_no_ctx() {
        let mut protolens = Prolens::<MyPacket>::default();

        // 设置 OrdPacket 回调（可选）
        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        protolens.set_cb_ord_pkt(move |pkt, _, _dir| {
            vec_clone.borrow_mut().push(pkt.seq());
        });

        let mut task = protolens.new_task_ffi(TransProto::Tcp, ptr::null_mut());
        protolens.set_task_parser(&mut task, L7Proto::OrdPacket);

        // 使用 OrdPacket 协议类型
        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 转换为原始指针
        let raw_ptr = Box::into_raw(task);
        assert!(!raw_ptr.is_null(), "Raw pointer should not be null");

        // 从原始指针恢复
        let mut recovered_task = unsafe { Box::from_raw(raw_ptr) };

        let pkt3 = MyPacket::new(3, true);
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
        let mut protolens = Prolens::<MyPacket>::default();

        let ctx = Rc::new(RefCell::new(std::ptr::null_mut::<c_void>()));
        let ctx_clone = Rc::clone(&ctx);

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);

        protolens.set_cb_ord_pkt(move |pkt, cb_ctx, _dir| {
            *ctx_clone.borrow_mut() = cb_ctx;
            vec_clone.borrow_mut().push(pkt.seq());
        });

        let mut task = protolens.new_task_ffi(TransProto::Tcp, 42 as *mut c_void);
        protolens.set_task_parser(task.as_mut(), L7Proto::OrdPacket);

        // 使用 OrdPacket 协议类型
        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, false);
        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 转换为原始指针
        let raw_ptr = Box::into_raw(task);
        assert!(!raw_ptr.is_null(), "Raw pointer should not be null");

        // 从原始指针恢复
        let mut recovered_task = unsafe { Box::from_raw(raw_ptr) };

        let pkt3 = MyPacket::new(3, true);
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
    use crate::test_utils::CapPacket;
    use crate::test_utils::Capture;
    use crate::test_utils::build_pkt_payload;
    use criterion::{Criterion, Throughput, black_box};
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn new_task(c: &mut Criterion) {
        let protolens = Prolens::<Box<CapPacket>>::default();

        let mut group = c.benchmark_group("new_task");
        group.throughput(Throughput::Elements(1));
        group.bench_function("new_task", |b| {
            b.iter(|| {
                let mut task = black_box(protolens.new_task(TransProto::Tcp));
                protolens.set_task_parser(&mut task, L7Proto::Http);
                black_box(());
            })
        });
        group.finish();
    }

    pub fn new_task_flame(c: &mut Criterion) {
        let protolens = Prolens::<Box<CapPacket>>::default();

        let num = 100000;
        let mut group = c.benchmark_group("new_task_flame");
        group.throughput(Throughput::Elements(num));
        group.bench_function("new_task_flame", |b| {
            b.iter(|| {
                for _ in 0..num {
                    let mut task = black_box(protolens.new_task(TransProto::Tcp));
                    protolens.set_task_parser(&mut task, L7Proto::Http);
                    black_box(());
                }
            })
        });
        group.finish();
    }

    pub fn readline100(c: &mut Criterion) {
        readline(c, 100, "readline100");
    }

    pub fn readline100_new_task(c: &mut Criterion) {
        readline_new_task(c, 100, "readline100_new_task");
    }

    pub fn readline500(c: &mut Criterion) {
        readline(c, 500, "readline500");
    }

    pub fn readline500_new_task(c: &mut Criterion) {
        readline_new_task(c, 500, "readline500_new_task");
    }

    pub fn readline1000(c: &mut Criterion) {
        readline(c, 1000, "readline1000");
    }

    pub fn readline1000_new_task(c: &mut Criterion) {
        readline_new_task(c, 1000, "readline1000_new_task");
    }

    const PKT_NUM: usize = 100;
    const LINE_LEN: usize = 10;

    fn readline(c: &mut Criterion, payload_len: usize, name: &str) {
        let packets = readline_packets(payload_len);

        let mut group = c.benchmark_group("readline");
        group.throughput(Throughput::Bytes((payload_len * PKT_NUM) as u64));
        group.bench_function(name, |b| {
            b.iter_with_setup(
                || {
                    let packets_clone = packets.clone();

                    let protolens = black_box(Prolens::<Box<CapPacket>>::default());
                    let mut task = black_box(protolens.new_task(TransProto::Tcp));
                    protolens.set_task_parser(&mut task, L7Proto::Readline);

                    (protolens, task, packets_clone)
                },
                |(mut protolens, mut task, packets)| {
                    for pkt in packets {
                        black_box(protolens.run_task(&mut task, pkt));
                    }
                },
            )
        });
        group.finish();
    }

    fn readline_new_task(c: &mut Criterion, payload_len: usize, name: &str) {
        let packets = readline_packets(payload_len);

        let mut group = c.benchmark_group("readline");
        group.throughput(Throughput::Bytes((payload_len * PKT_NUM) as u64));
        group.bench_function(name, |b| {
            b.iter_with_setup(
                || {
                    let packets_clone = packets.clone();
                    let protolens = black_box(Prolens::<Box<CapPacket>>::default());

                    (protolens, packets_clone)
                },
                |(mut protolens, packets)| {
                    let mut task = black_box(protolens.new_task(TransProto::Tcp));
                    protolens.set_task_parser(&mut task, L7Proto::Readline);

                    for pkt in packets {
                        black_box(protolens.run_task(&mut task, pkt));
                    }
                },
            )
        });
        group.finish();
    }

    fn readline_packets(payload_len: usize) -> Vec<Box<CapPacket>> {
        let lines_per_pkt = payload_len / LINE_LEN;

        let mut payload = Vec::with_capacity(payload_len);
        for _ in 0..lines_per_pkt {
            payload.extend_from_slice(&[b'A'; LINE_LEN - 2]);
            payload.extend_from_slice(b"\r\n");
        }

        let mut packets = Vec::with_capacity(PKT_NUM);
        let mut seq = 1000;
        for _ in 0..PKT_NUM {
            let pkt = build_pkt_payload(seq, &payload);
            let _ = pkt.decode();
            packets.push(Box::new(pkt));
            seq += payload.len() as u32;
        }

        packets
    }

    // 预先分配task，只测解码过程
    pub fn http(c: &mut Criterion) {
        bench_proto(c, "http", "http_mime", TransProto::Tcp, L7Proto::Http);
    }

    // 不预先分配task
    pub fn http_new_task(c: &mut Criterion) {
        bench_proto_new_task(
            c,
            "http_new_task",
            "http_mime",
            TransProto::Tcp,
            L7Proto::Http,
        );
    }

    // 不预先分配task，多次执行采集perf数据
    pub fn http_new_task_flame(c: &mut Criterion) {
        bench_proto_task_flame(
            c,
            "http_new_task_flame",
            "http_mime",
            TransProto::Tcp,
            L7Proto::Http,
        );
    }

    pub fn smtp(c: &mut Criterion) {
        bench_proto(c, "smtp", "smtp", TransProto::Tcp, L7Proto::Smtp);
    }

    // smtp.pcap比http_mime.pcap更有代表性
    pub fn smtp_new_task(c: &mut Criterion) {
        bench_proto_new_task(c, "smtp_new_task", "smtp", TransProto::Tcp, L7Proto::Smtp);
    }

    // smtp.pcap比http_mime.pcap更有代表性
    pub fn smtp_new_task_flame(c: &mut Criterion) {
        bench_proto_task_flame(
            c,
            "smtp_new_task_flame",
            "smtp",
            TransProto::Tcp,
            L7Proto::Smtp,
        );
    }

    pub fn pop3(c: &mut Criterion) {
        bench_proto(c, "pop3", "pop3", TransProto::Tcp, L7Proto::Pop3);
    }

    pub fn pop3_new_task(c: &mut Criterion) {
        bench_proto_new_task(c, "pop3_new_task", "pop3", TransProto::Tcp, L7Proto::Pop3);
    }

    pub fn imap(c: &mut Criterion) {
        bench_proto(c, "imap", "imap", TransProto::Tcp, L7Proto::Imap);
    }

    pub fn imap_new_task(c: &mut Criterion) {
        bench_proto_new_task(c, "imap_new_task", "imap", TransProto::Tcp, L7Proto::Imap);
    }

    pub fn sip(c: &mut Criterion) {
        bench_proto(c, "sip", "sip", TransProto::Udp, L7Proto::Sip);
    }

    pub fn sip_new_task(c: &mut Criterion) {
        bench_proto_new_task(c, "sip_new_task", "sip", TransProto::Udp, L7Proto::Sip);
    }

    fn bench_proto(c: &mut Criterion, name: &str, pcap_name: &str, l4: TransProto, l7: L7Proto) {
        let (packets, total_bytes) = read_pcap_packets(pcap_name);

        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_function(name, |b| {
            b.iter_with_setup(
                || {
                    let packets_clone = packets.clone();

                    let protolens = black_box(Prolens::<Box<CapPacket>>::default());
                    let mut task = black_box(protolens.new_task(l4));
                    protolens.set_task_parser(&mut task, l7);

                    (protolens, task, packets_clone)
                },
                |(mut protolens, mut task, packets)| {
                    for pkt in packets {
                        black_box(protolens.run_task(&mut task, pkt));
                    }
                },
            )
        });
        group.finish();
    }

    fn bench_proto_new_task(
        c: &mut Criterion,
        name: &str,
        pcap_name: &str,
        l4: TransProto,
        l7: L7Proto,
    ) {
        let (packets, total_bytes) = read_pcap_packets(pcap_name);

        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_function(name, |b| {
            b.iter_with_setup(
                || {
                    let packets_clone = packets.clone();
                    let protolens = black_box(Prolens::<Box<CapPacket>>::default());

                    (protolens, packets_clone)
                },
                |(mut protolens, packets)| {
                    let mut task = black_box(protolens.new_task(l4));
                    protolens.set_task_parser(&mut task, l7);

                    for pkt in packets {
                        black_box(protolens.run_task(&mut task, pkt));
                    }
                },
            )
        });
        group.finish();
    }

    fn bench_proto_task_flame(
        c: &mut Criterion,
        name: &str,
        pcap_name: &str,
        l4: TransProto,
        l7: L7Proto,
    ) {
        let (packets, total_bytes) = read_pcap_packets(pcap_name);

        let mut protolens = black_box(Prolens::<Box<CapPacket>>::default());

        let num = 10000;
        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Bytes(total_bytes as u64 * num));
        group.bench_function(name, |b| {
            b.iter_with_setup(
                || packets.clone(),
                |packets| {
                    for _ in 0..num {
                        let mut task = black_box(protolens.new_task(l4));
                        protolens.set_task_parser(&mut task, l7);

                        for pkt in &packets {
                            black_box(protolens.run_task(&mut task, pkt.clone()));
                        }
                    }
                },
            )
        });
        group.finish();
    }

    fn read_pcap_packets(pcap_name: &str) -> (Vec<Box<CapPacket>>, usize) {
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

            total_bytes += pkt.payload_len();
            packets.push(Box::new(pkt));
        }

        (packets, total_bytes.try_into().unwrap())
    }
}
