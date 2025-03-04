use crate::Packet;
use crate::PacketWrapper;
use crate::Parser;
use crate::ParserFuture;
use crate::PktDirection;
use crate::PktStrm;
use crate::PtrNew;
use crate::PtrWrapper;
use crate::StmCbFn;
use core::{
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use std::ffi::c_void;
use std::fmt;

pub trait PacketBind: Packet + Ord + std::fmt::Debug + 'static {}
impl<T: Packet + Ord + std::fmt::Debug + 'static> PacketBind for T {}

pub struct Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    stream_c2s: PktStrm<T, P>,
    stream_s2c: PktStrm<T, P>,
    c2s_parser: Option<ParserFuture>,
    s2c_parser: Option<ParserFuture>,
    bdir_parser: Option<ParserFuture>,
    pub(crate) parser_inited: bool,
    c2s_state: TaskState,
    s2c_state: TaskState,
    bdir_state: TaskState,
    cb_ctx: *mut c_void, // 只在c语言api中使用
}

impl<T, P> Task<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    pub(crate) fn new(cb_ctx: *mut c_void) -> Self {
        Task {
            stream_c2s: PktStrm::new(cb_ctx),
            stream_s2c: PktStrm::new(cb_ctx),
            c2s_parser: None,
            s2c_parser: None,
            bdir_parser: None,
            parser_inited: false,
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
                self.c2s_state, self.parser_inited, self.cb_ctx
            );
        } else {
            eprintln!(
                "task debug info: c2s parser is some. state: {:?}, parser_inited: {:?}, cb_ctx: {:?}",
                self.c2s_state, self.parser_inited, self.cb_ctx
            );
        }

        if self.s2c_parser.is_none() {
            eprintln!("task debug info: s2c parser is none");
        } else {
            eprintln!("task debug info: s2c parser is some");
        }
    }

    pub(crate) fn init_parser<Q>(&mut self, parser: Q)
    where
        Q: Parser<PacketType = T, PtrType = P>,
    {
        let p_stream_c2s: *const PktStrm<T, P> = &self.stream_c2s;
        let p_stream_s2c: *const PktStrm<T, P> = &self.stream_s2c;

        self.c2s_parser = parser.c2s_parser(p_stream_c2s, self.cb_ctx);
        self.s2c_parser = parser.s2c_parser(p_stream_s2c, self.cb_ctx);
        self.bdir_parser = parser.bdir_parser(p_stream_c2s, p_stream_s2c, self.cb_ctx);

        self.parser_inited = true;
    }

    pub(crate) fn set_cb_c2s<F>(&mut self, callback: F)
    where
        F: StmCbFn + 'static,
    {
        self.stream_c2s.set_cb(callback);
    }

    pub(crate) fn set_cb_s2c<F>(&mut self, callback: F)
    where
        F: StmCbFn + 'static,
    {
        self.stream_s2c.set_cb(callback);
    }

    // None - 表示解析器还在pending状态或没有parser
    // Some(Ok(())) - 表示解析成功完成
    // Some(Err(())) - 表示解析遇到错误
    pub(crate) fn run(&mut self, pkt: PacketWrapper<T, P>) -> Option<Result<(), ()>> {
        match pkt.ptr.direction() {
            PktDirection::Client2Server => {
                self.stream_c2s.push(pkt);
                return self.c2s_run();
            }
            PktDirection::Server2Client => {
                self.stream_s2c.push(pkt);
                return self.s2c_run();
            }
            PktDirection::BiDirection => None,
            _ => Some(Err::<T, ()>(())),
        };
        self.bdir_run()
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
            .field("c2s_stream", &self.stream_c2s)
            .field("s2c_stream", &self.stream_s2c)
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
