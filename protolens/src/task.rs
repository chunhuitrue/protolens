use crate::Packet;
use crate::Parser;
use crate::ParserFuture;
use crate::PktDirection;
use crate::PktStrm;
use crate::Pool;
use crate::PoolBox;
use crate::StmCbFn;
use core::{
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use std::ffi::c_void;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

pub trait PacketBind: Packet + Ord + std::fmt::Debug + 'static {}
impl<T: Packet + Ord + std::fmt::Debug + 'static> PacketBind for T {}

// 为了不对用户暴露Poolbox<Task>,屏蔽poolbox
#[repr(transparent)]
pub struct Task<P: PacketBind>(PoolBox<TaskInner<P>>);

impl<P: PacketBind> Task<P> {
    pub(crate) fn new(inner: PoolBox<TaskInner<P>>) -> Self {
        Self(inner)
    }

    pub(crate) fn as_inner_mut(&mut self) -> &mut PoolBox<TaskInner<P>> {
        &mut self.0
    }

    pub(crate) fn into_raw(self) -> *mut Task<P> {
        self.0.into_raw() as *mut Task<P>
    }

    pub(crate) unsafe fn from_raw(ptr: *mut Task<P>, pool: Rc<Pool>) -> Self {
        unsafe { Self(PoolBox::from_raw(ptr as *mut TaskInner<P>, &pool)) }
    }
}

impl<P: PacketBind> fmt::Debug for Task<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskHandle")
            .field("inner", &self.0)
            .finish()
    }
}

impl<P: PacketBind> Deref for Task<P> {
    type Target = TaskInner<P>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: PacketBind> DerefMut for Task<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct TaskInner<T: PacketBind> {
    stream_c2s: PoolBox<PktStrm<T>>,
    stream_s2c: PoolBox<PktStrm<T>>,
    c2s_parser: Option<ParserFuture>,
    s2c_parser: Option<ParserFuture>,
    bdir_parser: Option<ParserFuture>,
    pub(crate) parser_inited: bool,
    c2s_state: TaskState,
    s2c_state: TaskState,
    bdir_state: TaskState,
    cb_ctx: *mut c_void, // 只在c语言api中使用
}

impl<T: PacketBind> TaskInner<T> {
    pub(crate) fn new(pool: &Rc<Pool>, cb_ctx: *mut c_void) -> Self {
        let stream_c2s = pool.alloc(|| PktStrm::new(pool, cb_ctx));
        let stream_s2c = pool.alloc(|| PktStrm::new(pool, cb_ctx));

        TaskInner {
            stream_c2s,
            stream_s2c,
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

    pub(crate) fn init_parser<P: Parser<PacketType = T>>(&mut self, parser: PoolBox<P>) {
        let p_stream_c2s: *const PktStrm<T> = &*self.stream_c2s;
        let p_stream_s2c: *const PktStrm<T> = &*self.stream_s2c;

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
    pub(crate) fn run(&mut self, pkt: T) -> Option<Result<(), ()>> {
        match pkt.direction() {
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

    #[allow(dead_code)]
    pub(crate) fn parser_state(&self, dir: PktDirection) -> TaskState {
        match dir {
            PktDirection::Client2Server => self.c2s_state,
            PktDirection::Server2Client => self.s2c_state,
            PktDirection::BiDirection => self.bdir_state,
            PktDirection::Unknown => TaskState::Error,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn streeam_len(&self, dir: PktDirection) -> usize {
        match dir {
            PktDirection::Client2Server => self.stream_c2s.len(),
            PktDirection::Server2Client => self.stream_s2c.len(),
            _ => 0,
        }
    }
}

impl<T: Packet + Ord + std::fmt::Debug + 'static> fmt::Debug for TaskInner<T> {
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
