use crate::Meta;
use crate::Packet;
use crate::Parser;
use crate::PktDirection;
use crate::PktStrm;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use futures_channel::mpsc;
use std::fmt;

const MAX_CHANNEL_SIZE: usize = 64;

pub struct Task<T: Packet + Ord + std::fmt::Debug + 'static> {
    stream_c2s: Box<PktStrm<T>>,
    stream_s2c: Box<PktStrm<T>>,
    c2s_parser: Option<Pin<Box<dyn Future<Output = ()>>>>,
    s2c_parser: Option<Pin<Box<dyn Future<Output = ()>>>>,
    bdir_parser: Option<Pin<Box<dyn Future<Output = ()>>>>,
    c2s_state: TaskState,
    s2c_state: TaskState,
    bdir_state: TaskState,
    meta_rx: Option<mpsc::Receiver<Meta>>,
}

impl<T: Packet + Ord + std::fmt::Debug + 'static> Task<T> {
    pub fn new() -> Self {
        let stream_c2s = Box::new(PktStrm::new());
        let stream_s2c = Box::new(PktStrm::new());

        Task {
            stream_c2s,
            stream_s2c,
            c2s_parser: None,
            s2c_parser: None,
            bdir_parser: None,
            c2s_state: TaskState::Start,
            s2c_state: TaskState::Start,
            bdir_state: TaskState::Start,
            meta_rx: None,
        }
    }

    pub fn new_with_parser(parser: impl Parser<PacketType = T>) -> Self {
        let stream_c2s = Box::new(PktStrm::new());
        let stream_s2c = Box::new(PktStrm::new());
        let (tx, rx) = mpsc::channel(MAX_CHANNEL_SIZE);
        let p_stream_c2s: *const PktStrm<T> = &*stream_c2s;
        let p_stream_s2c: *const PktStrm<T> = &*stream_s2c;
        let c2s_parser = parser.c2s_parser(p_stream_c2s, tx.clone());
        let s2c_parser = parser.s2c_parser(p_stream_s2c, tx.clone());
        let bdir_parser = parser.bdir_parser(p_stream_c2s, p_stream_s2c, tx.clone());

        Task {
            stream_c2s,
            stream_s2c,
            c2s_parser: Some(c2s_parser),
            s2c_parser: Some(s2c_parser),
            bdir_parser: Some(bdir_parser),
            c2s_state: TaskState::Start,
            s2c_state: TaskState::Start,
            bdir_state: TaskState::Start,
            meta_rx: Some(rx),
        }
    }

    pub fn init_parser(&mut self, parser: impl Parser<PacketType = T>) {
        let p_stream_c2s: *const PktStrm<T> = &*(self.stream_c2s);
        let p_stream_s2c: *const PktStrm<T> = &*(self.stream_s2c);
        let (tx, rx) = mpsc::channel(MAX_CHANNEL_SIZE);
        let c2s_parser = parser.c2s_parser(p_stream_c2s, tx.clone());
        let s2c_parser = parser.s2c_parser(p_stream_s2c, tx.clone());
        let bdir_parser = parser.bdir_parser(p_stream_c2s, p_stream_s2c, tx.clone());

        self.c2s_parser = Some(c2s_parser);
        self.s2c_parser = Some(s2c_parser);
        self.bdir_parser = Some(bdir_parser);
        self.meta_rx = Some(rx);
    }

    pub fn run(&mut self, pkt: T, pkt_dir: PktDirection) {
        match pkt_dir {
            PktDirection::Client2Server => {
                self.stream_c2s.push(pkt);
                self.c2s_run();
            }
            PktDirection::Server2Client => {
                self.stream_s2c.push(pkt);
                self.s2c_run();
            }
            _ => return,
        }
        self.bdir_run();
    }

    fn c2s_run(&mut self) {
        if self.c2s_state == TaskState::End {
            return;
        }

        if let Some(parser) = &mut self.c2s_parser {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);
            match Pin::as_mut(parser).poll(&mut context) {
                Poll::Ready(()) => {
                    self.c2s_state = TaskState::End;
                }
                Poll::Pending => {}
            }
        }
    }

    fn s2c_run(&mut self) {
        if self.s2c_state == TaskState::End {
            return;
        }

        if let Some(parser) = &mut self.s2c_parser {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);
            match Pin::as_mut(parser).poll(&mut context) {
                Poll::Ready(()) => self.s2c_state = TaskState::End,
                Poll::Pending => {}
            }
        }
    }

    fn bdir_run(&mut self) {
        if self.bdir_state == TaskState::End {
            return;
        }

        if let Some(parser) = &mut self.bdir_parser {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);
            match Pin::as_mut(parser).poll(&mut context) {
                Poll::Ready(()) => self.bdir_state = TaskState::End,
                Poll::Pending => {}
            }
        }
    }

    pub fn get_meta(&mut self) -> Option<Meta> {
        self.meta_rx.as_ref()?;

        if let Some(rx) = self.meta_rx.as_mut() {
            rx.try_next().unwrap_or_default()
        } else {
            None
        }
    }

    pub fn parser_state(&self, dir: PktDirection) -> TaskState {
        match dir {
            PktDirection::Client2Server => self.c2s_state,
            PktDirection::Server2Client => self.s2c_state,
            PktDirection::BiDirection => self.bdir_state,
            PktDirection::Unknown => TaskState::Error,
        }
    }

    pub fn streeam_len(&self, dir: PktDirection) -> usize {
        match dir {
            PktDirection::Client2Server => self.stream_c2s.len(),
            PktDirection::Server2Client => self.stream_s2c.len(),
            _ => 0,
        }
    }
}

impl<T: Packet + Ord + std::fmt::Debug + 'static> Default for Task<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + std::fmt::Debug + 'static> fmt::Debug for Task<T> {
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
pub enum TaskState {
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
