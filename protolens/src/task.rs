use crate::CbStrm;
use crate::DirConfirmFn;
use crate::PacketWrapper;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::config::Config;
use crate::packet::*;
use core::{
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use std::ffi::c_void;
use std::fmt;
use std::net::IpAddr;

pub struct Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    strm_c2s_ip: Option<IpAddr>,
    strm_s2c_ip: Option<IpAddr>,
    strm_c2s_port: u16,
    strm_s2c_port: u16,
    strm_c2s: PktStrm<T, P>,
    strm_s2c: PktStrm<T, P>,

    dir_confirm_parser: Option<DirConfirmFn<T, P>>,
    c2s_parser: Option<ParserFuture>,
    s2c_parser: Option<ParserFuture>,
    bdir_parser: Option<ParserFuture>,

    pub(crate) parser_set: bool,
    dir_confirm: bool,
    c2s_state: TaskState,
    s2c_state: TaskState,
    bdir_state: TaskState,

    cb_ctx: *mut c_void,
}

impl<T, P> Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    pub(crate) fn new(
        conf: &Config,
        _l4_proto: TransProto,
        cb_c2s: Option<CbStrm>,
        cb_s2c: Option<CbStrm>,
        cb_ctx: *mut c_void,
    ) -> Self {
        let mut strm_c2s = PktStrm::new(conf.pkt_buff, conf.read_buff, cb_ctx);
        if let Some(cb) = cb_c2s {
            strm_c2s.set_cb(cb);
        }
        let mut strm_s2c = PktStrm::new(conf.pkt_buff, conf.read_buff, cb_ctx);
        if let Some(cb) = cb_s2c {
            strm_s2c.set_cb(cb);
        }

        Task {
            strm_c2s_ip: None,
            strm_s2c_ip: None,
            strm_c2s_port: 0,
            strm_s2c_port: 0,
            strm_c2s,
            strm_s2c,

            dir_confirm_parser: None,
            c2s_parser: None,
            s2c_parser: None,
            bdir_parser: None,

            parser_set: false,
            dir_confirm: false,
            c2s_state: TaskState::Start,
            s2c_state: TaskState::Start,
            bdir_state: TaskState::Start,

            cb_ctx,
        }
    }

    pub(crate) fn debug_info(&self) {
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

    pub(crate) fn set_parser(&mut self, parser: Box<dyn Parser<PacketType = T, PtrType = P>>) {
        self.dir_confirm_parser = Some(parser.dir_confirm());
        self.c2s_parser = parser.c2s_parser(&self.strm_c2s, self.cb_ctx);
        self.s2c_parser = parser.s2c_parser(&self.strm_s2c, self.cb_ctx);
        self.bdir_parser = parser.bdir_parser(&self.strm_c2s, &self.strm_s2c, self.cb_ctx);
        self.parser_set = true;
    }

    fn confirm_dir(&mut self) {
        if let Some(dir_confirm_parser) = &self.dir_confirm_parser {
            if let Some(c2s_dir) = dir_confirm_parser(
                &self.strm_c2s,
                &self.strm_s2c,
                self.strm_c2s_port,
                self.strm_s2c_port,
            ) {
                if !c2s_dir {
                    std::mem::swap(&mut self.strm_c2s_ip, &mut self.strm_s2c_ip);
                    std::mem::swap(&mut self.strm_c2s_port, &mut self.strm_s2c_port);
                    std::mem::swap(&mut self.strm_c2s, &mut self.strm_s2c);
                    std::mem::swap(&mut self.c2s_state, &mut self.s2c_state);
                }
                self.dir_confirm = true;
            }
        }
    }

    // None - 表示解析器还在pending状态或没有parser
    // Some(Ok(())) - 表示解析成功完成
    // Some(Err(())) - 表示解析遇到错误
    pub(crate) fn run(&mut self, pkt: PacketWrapper<T, P>) -> Option<Result<(), ()>> {
        if self.strm_c2s_ip.is_none() {
            self.strm_c2s_ip = Some(pkt.ptr.sip());
            self.strm_s2c_ip = Some(pkt.ptr.dip());
            self.strm_c2s_port = pkt.ptr.tu_sport();
            self.strm_s2c_port = pkt.ptr.tu_dport();
        }
        let pkt_sip = pkt.ptr.sip();
        let pkt_sport = pkt.ptr.tu_sport();

        if pkt_sip == self.strm_c2s_ip.unwrap() && pkt_sport == self.strm_c2s_port {
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

        if let Some(strm_c2s_ip) = self.strm_c2s_ip.as_ref() {
            let is_c2s = pkt_sip == *strm_c2s_ip && pkt_sport == self.strm_c2s_port;
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
}

impl<T, P> fmt::Debug for Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("c2s_stream", &self.strm_c2s)
            .field("s2c_stream", &self.strm_s2c)
            .field("stream_c2s_state", &self.c2s_state)
            .field("stream_s2c_state", &self.s2c_state)
            .field("stream_bdir_state", &self.bdir_state)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum TaskState {
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
