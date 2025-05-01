use crate::CbStrm;
use crate::DirConfirmFn;
use crate::PacketWrapper;
use crate::Parser;
use crate::ParserFuture;
use crate::PktDirConfirmFn;
use crate::PktStrm;
use crate::UdpParserFn;
use crate::config::Config;
use crate::packet::*;
use core::{
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use std::ffi::c_void;
use std::fmt;
use std::net::IpAddr;

pub enum Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    Tcp(Box<TcpTask<T, P>>),
    Udp(UdpTask<T, P>),
}

impl<T, P> Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    pub(crate) fn new(conf: &Config, cb_ctx: *mut c_void, proto: TransProto) -> Self {
        match proto {
            TransProto::Tcp => Task::Tcp(Box::new(TcpTask::new(conf, cb_ctx))),
            TransProto::Udp => Task::Udp(UdpTask::new(cb_ctx)),
        }
    }

    pub(crate) fn set_cb_strm_c2s(&mut self, callback: CbStrm) {
        if let Task::Tcp(task) = self {
            task.set_cb_c2s(callback)
        }
    }

    pub(crate) fn set_cb_strm_s2c(&mut self, callback: CbStrm) {
        if let Task::Tcp(task) = self {
            task.set_cb_s2c(callback)
        }
    }

    pub(crate) fn set_parser(&mut self, parser: Box<dyn Parser<PacketType = T, PtrType = P>>) {
        match self {
            Task::Tcp(task) => task.set_parser(parser),
            Task::Udp(task) => task.set_parser(parser),
        }
    }

    pub(crate) fn parser_set(&self) -> bool {
        match self {
            Task::Tcp(task) => task.parser_set,
            Task::Udp(task) => task.parser_set,
        }
    }

    pub(crate) fn run(&mut self, pkt: PacketWrapper<T, P>) -> Option<Result<(), ()>> {
        match self {
            Task::Tcp(task) => task.run(pkt),
            Task::Udp(task) => task.run(pkt),
        }
    }

    pub(crate) fn debug_info(&self) {
        match self {
            Task::Tcp(task) => task.debug_info(),
            Task::Udp(task) => task.debug_info(),
        }
    }
}

impl<T, P> fmt::Debug for Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Task::Tcp(task) => f
                .debug_struct("TcpTask")
                .field("c2s_ip", &task.c2s_ip)
                .field("s2c_ip", &task.s2c_ip)
                .field("c2s_port", &task.c2s_port)
                .field("s2c_port", &task.s2c_port)
                .field("cb_ctx", &task.cb_ctx)
                .field("c2s_stream", &task.strm_c2s)
                .field("s2c_stream", &task.strm_s2c)
                .field("stream_c2s_state", &task.c2s_state)
                .field("stream_s2c_state", &task.s2c_state)
                .field("stream_bdir_state", &task.bdir_state)
                .finish(),
            Task::Udp(task) => f
                .debug_struct("UdpTask")
                .field("c2s_ip", &task.c2s_ip)
                .field("s2c_ip", &task.s2c_ip)
                .field("c2s_port", &task.c2s_port)
                .field("s2c_port", &task.s2c_port)
                .field("cb_ctx", &task.cb_ctx)
                .finish(),
        }
    }
}

pub struct TcpTask<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    dir_confirm: bool,
    c2s_ip: Option<IpAddr>,
    s2c_ip: Option<IpAddr>,
    c2s_port: u16,
    s2c_port: u16,

    strm_c2s: PktStrm<T, P>,
    strm_s2c: PktStrm<T, P>,

    parser_set: bool,
    dir_confirm_parser: Option<DirConfirmFn<T, P>>,
    c2s_parser: Option<ParserFuture>,
    s2c_parser: Option<ParserFuture>,
    bdir_parser: Option<ParserFuture>,

    c2s_state: TaskState,
    s2c_state: TaskState,
    bdir_state: TaskState,
    cb_ctx: *mut c_void,
}

impl<T, P> TcpTask<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn new(conf: &Config, cb_ctx: *mut c_void) -> Self {
        TcpTask {
            dir_confirm: false,
            c2s_ip: None,
            s2c_ip: None,
            c2s_port: 0,
            s2c_port: 0,

            strm_c2s: PktStrm::new(conf.pkt_buff, conf.read_buff, cb_ctx),
            strm_s2c: PktStrm::new(conf.pkt_buff, conf.read_buff, cb_ctx),

            parser_set: false,
            dir_confirm_parser: None,
            c2s_parser: None,
            s2c_parser: None,
            bdir_parser: None,

            c2s_state: TaskState::Start,
            s2c_state: TaskState::Start,
            bdir_state: TaskState::Start,
            cb_ctx,
        }
    }

    fn set_cb_c2s(&mut self, callback: CbStrm) {
        self.strm_c2s.set_cb(callback);
    }

    fn set_cb_s2c(&mut self, callback: CbStrm) {
        self.strm_s2c.set_cb(callback);
    }

    fn set_parser(&mut self, parser: Box<dyn Parser<PacketType = T, PtrType = P>>) {
        self.dir_confirm_parser = Some(parser.dir_confirm());
        self.c2s_parser = parser.c2s_parser(&self.strm_c2s, self.cb_ctx);
        self.s2c_parser = parser.s2c_parser(&self.strm_s2c, self.cb_ctx);
        self.bdir_parser = parser.bdir_parser(&self.strm_c2s, &self.strm_s2c, self.cb_ctx);
        self.parser_set = true;
    }

    fn confirm_dir(&mut self) {
        if let Some(dir_confirm_parser) = &self.dir_confirm_parser {
            if let Some(c2s_dir) =
                dir_confirm_parser(&self.strm_c2s, &self.strm_s2c, self.c2s_port, self.s2c_port)
            {
                if !c2s_dir {
                    std::mem::swap(&mut self.c2s_ip, &mut self.s2c_ip);
                    std::mem::swap(&mut self.c2s_port, &mut self.s2c_port);
                    std::mem::swap(&mut self.strm_c2s, &mut self.strm_s2c);
                }
                self.dir_confirm = true;
            }
        }
    }

    // None - 表示解析器还在pending状态或没有parser
    // Some(Ok(())) - 表示解析成功完成
    // Some(Err(())) - 表示解析遇到错误
    fn run(&mut self, pkt: PacketWrapper<T, P>) -> Option<Result<(), ()>> {
        if pkt.ptr.trans_proto() != TransProto::Tcp {
            return None;
        }

        if self.c2s_ip.is_none() {
            self.c2s_ip = Some(pkt.ptr.sip());
            self.s2c_ip = Some(pkt.ptr.dip());
            self.c2s_port = pkt.ptr.tu_sport();
            self.s2c_port = pkt.ptr.tu_dport();
        }
        let pkt_sip = pkt.ptr.sip();
        let pkt_sport = pkt.ptr.tu_sport();

        if pkt_sip == self.c2s_ip.unwrap() && pkt_sport == self.c2s_port {
            self.strm_c2s.push(pkt);
        } else {
            self.strm_s2c.push(pkt);
        }

        if !self.dir_confirm {
            self.confirm_dir();
            if !self.dir_confirm {
                return None;
            }
        }

        if let Some(c2s_ip) = self.c2s_ip.as_ref() {
            let is_c2s = pkt_sip == *c2s_ip && pkt_sport == self.c2s_port;
            match (
                is_c2s,
                self.c2s_parser.as_ref(),
                self.s2c_parser.as_ref(),
                self.bdir_parser.as_ref(),
            ) {
                (true, Some(_), _, _) => self.c2s_run(),
                (false, _, Some(_), _) => self.s2c_run(),
                (_, _, _, Some(_)) => self.bdir_run(),
                _ => None,
            }
        } else {
            None
        }
    }

    fn c2s_run(&mut self) -> Option<Result<(), ()>> {
        if self.c2s_state == TaskState::End || self.c2s_state == TaskState::Error {
            return None;
        }

        if let Some(parser) = &mut self.c2s_parser {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);
            match Pin::as_mut(parser).poll(&mut context) {
                Poll::Ready(Ok(())) => {
                    self.c2s_state = TaskState::End;
                    Some(Ok(()))
                }
                Poll::Ready(Err(())) => {
                    self.c2s_state = TaskState::Error;
                    Some(Err(()))
                }
                Poll::Pending => None,
            }
        } else {
            None
        }
    }

    fn s2c_run(&mut self) -> Option<Result<(), ()>> {
        if self.s2c_state == TaskState::End || self.s2c_state == TaskState::Error {
            return None;
        }

        if let Some(parser) = &mut self.s2c_parser {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);
            match Pin::as_mut(parser).poll(&mut context) {
                Poll::Ready(Ok(())) => {
                    self.s2c_state = TaskState::End;
                    Some(Ok(()))
                }
                Poll::Ready(Err(())) => {
                    self.s2c_state = TaskState::Error;
                    Some(Err(()))
                }
                Poll::Pending => None,
            }
        } else {
            None
        }
    }

    fn bdir_run(&mut self) -> Option<Result<(), ()>> {
        if self.bdir_state == TaskState::End || self.bdir_state == TaskState::Error {
            return None;
        }

        if let Some(parser) = &mut self.bdir_parser {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);
            match Pin::as_mut(parser).poll(&mut context) {
                Poll::Ready(Ok(())) => {
                    self.bdir_state = TaskState::End;
                    Some(Ok(()))
                }
                Poll::Ready(Err(())) => {
                    self.bdir_state = TaskState::Error;
                    Some(Err(()))
                }
                Poll::Pending => None,
            }
        } else {
            None
        }
    }

    fn debug_info(&self) {
        if self.c2s_parser.is_none() {
            eprintln!(
                "task debug info: c2s parser is none. state: {:?}, parser_inited: {:?}, cb_ctx: {:?}",
                self.c2s_state, self.parser_set, self.cb_ctx
            );
        } else {
            eprintln!(
                "task debug info: c2s parser is some. state: {:?}, parser_inited: {:?}, cb_ctx: {:?}",
                self.c2s_state, self.parser_set, self.cb_ctx
            );
        }

        if self.s2c_parser.is_none() {
            eprintln!("task debug info: s2c parser is none");
        } else {
            eprintln!("task debug info: s2c parser is some");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TaskState {
    Start,
    End,
    Error,
}

fn dummy_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        dummy_raw_waker()
    }

    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null::<()>(), vtable)
}

fn dummy_waker() -> Waker {
    unsafe { Waker::from_raw(dummy_raw_waker()) }
}

pub struct UdpTask<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    dir_confirm: bool,
    c2s_ip: Option<IpAddr>,
    s2c_ip: Option<IpAddr>,
    c2s_port: u16,
    s2c_port: u16,

    parser_set: bool,
    dir_confirm_parser: Option<PktDirConfirmFn<T, P>>,
    c2s_parser: Option<UdpParserFn<T, P>>,
    s2c_parser: Option<UdpParserFn<T, P>>,
    bdir_parser: Option<UdpParserFn<T, P>>,

    cb_ctx: *mut c_void,
}

impl<T, P> UdpTask<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn new(cb_ctx: *mut c_void) -> Self {
        UdpTask {
            dir_confirm: false,
            c2s_ip: None,
            s2c_ip: None,
            c2s_port: 0,
            s2c_port: 0,

            parser_set: false,
            dir_confirm_parser: None,
            c2s_parser: None,
            s2c_parser: None,
            bdir_parser: None,

            cb_ctx,
        }
    }

    fn set_parser(&mut self, parser: Box<dyn Parser<PacketType = T, PtrType = P>>) {
        self.dir_confirm_parser = Some(parser.pkt_dir_confirm());
        self.c2s_parser = parser.pkt_c2s_parser();
        self.s2c_parser = parser.pkt_s2c_parser();
        self.bdir_parser = parser.pkt_bdir_parser();
        self.parser_set = true;
    }

    fn confirm_dir(&mut self, pkt: &PacketWrapper<T, P>) {
        if let Some(dir_confirm_parser) = &self.dir_confirm_parser {
            if let Some(c2s_dir) = dir_confirm_parser(pkt) {
                if !c2s_dir {
                    std::mem::swap(&mut self.c2s_ip, &mut self.s2c_ip);
                    std::mem::swap(&mut self.c2s_port, &mut self.s2c_port);
                }
                self.dir_confirm = true;
            }
        }
    }

    fn run(&mut self, pkt: PacketWrapper<T, P>) -> Option<Result<(), ()>> {
        if pkt.ptr.trans_proto() != TransProto::Udp {
            return None;
        }

        if self.c2s_ip.is_none() {
            self.c2s_ip = Some(pkt.ptr.sip());
            self.s2c_ip = Some(pkt.ptr.dip());
            self.c2s_port = pkt.ptr.tu_sport();
            self.s2c_port = pkt.ptr.tu_dport();
        }
        let pkt_sip = pkt.ptr.sip();
        let pkt_sport = pkt.ptr.tu_sport();

        if !self.dir_confirm {
            self.confirm_dir(&pkt);
            if !self.dir_confirm {
                return None;
            }
        }

        if let Some(c2s_ip) = self.c2s_ip.as_ref() {
            let is_c2s = pkt_sip == *c2s_ip && pkt_sport == self.c2s_port;
            match (
                is_c2s,
                self.c2s_parser.as_ref(),
                self.s2c_parser.as_ref(),
                self.bdir_parser.as_ref(),
            ) {
                (true, Some(parser), _, _) => Some(parser.parse(pkt, self.cb_ctx)),
                (false, _, Some(parser), _) => Some(parser.parse(pkt, self.cb_ctx)),
                (_, _, _, Some(parser)) => Some(parser.parse(pkt, self.cb_ctx)),
                _ => None,
            }
        } else {
            None
        }
    }

    fn debug_info(&self) {
        if self.c2s_parser.is_none() {
            eprintln!(
                "udp task debug info: c2s parser is none. parser_inited: {:?}, cb_ctx: {:?}",
                self.parser_set, self.cb_ctx
            );
        } else {
            eprintln!(
                "udp task debug info: c2s parser is some. parser_inited: {:?}, cb_ctx: {:?}",
                self.parser_set, self.cb_ctx
            );
        }

        if self.s2c_parser.is_none() {
            eprintln!("udp task debug info: s2c parser is none");
        } else {
            eprintln!("udp task debug info: s2c parser is some");
        }

        if self.bdir_parser.is_none() {
            eprintln!("udp task debug info: bdir parser is none");
        } else {
            eprintln!("udp task debug info: bdir parser is some");
        }
    }
}
