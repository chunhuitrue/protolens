pub mod common;
pub mod dnstcp;
pub mod dnsudp;
pub mod ftpcmd;
pub mod ftpdata;
pub mod http;
pub mod imap;
pub mod ordpacket;
pub mod pop3;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod tls;

#[cfg(test)]
pub mod byte;
#[cfg(test)]
pub mod eof;
#[cfg(test)]
pub mod octet;
#[cfg(test)]
pub mod rawpacket;
#[cfg(test)]
pub mod read;
#[cfg(any(test, feature = "bench"))]
pub mod readline;
#[cfg(test)]
pub mod readn;

use crate::{Packet, PktStrm, Prolens};
use futures::Future;
use std::ffi::c_void;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

pub(crate) type ParserFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;
pub(crate) type DirConfirmFn<T> = fn(*mut PktStrm<T>, *mut PktStrm<T>, u16, u16) -> Option<bool>;
pub(crate) type PktDirConfirmFn<T> = fn(&T) -> Option<bool>;

pub(crate) trait Parser {
    type T: Packet;

    fn dir_confirm(&self) -> DirConfirmFn<Self::T> {
        |_c2s_strm, _s2c_strm, _c2s_port, _s2c_port| {
            Some(true) // The default is that the first package to arrive is c2s.
        }
    }

    fn c2s_parser(
        &self,
        _strm: *mut PktStrm<Self::T>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn s2c_parser(
        &self,
        _strm: *mut PktStrm<Self::T>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn bdir_parser(
        &self,
        _c2s_strm: *mut PktStrm<Self::T>,
        _s2c_strm: *mut PktStrm<Self::T>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn pkt_dir_confirm(&self) -> PktDirConfirmFn<Self::T> {
        |_pkt| {
            Some(true) // The default is that the first package to arrive is c2s.
        }
    }

    fn pkt_c2s_parser(&self) -> Option<UdpParserFn<Self::T>> {
        None
    }

    fn pkt_s2c_parser(&self) -> Option<UdpParserFn<Self::T>> {
        None
    }

    fn pkt_bdir_parser(&self) -> Option<UdpParserFn<Self::T>> {
        None
    }
}

pub trait UdpParser {
    type T: Packet;

    fn parse(&self, pkt: Self::T, cb_ctx: *mut c_void) -> Result<(), ()>;
}
pub type UdpParserFn<T> = Box<dyn UdpParser<T = T>>;

pub(crate) trait ParserFactory<T>
where
    T: Packet,
{
    fn new() -> Self
    where
        Self: Sized;
    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>>;
}

pub(crate) struct SharedState<T> {
    data: Option<T>,
}

impl<T> SharedState<T> {
    pub(crate) fn new() -> Self {
        Self { data: None }
    }

    #[allow(unused)]
    pub(crate) fn is_ready(&self) -> bool {
        self.data.is_some()
    }

    pub(crate) fn get(&self) -> Option<&T> {
        self.data.as_ref()
    }

    pub(crate) fn set(&mut self, data: T) {
        self.data = Some(data);
    }
}

pub(crate) struct SharedStateFuture<T> {
    shared_state: Arc<Mutex<SharedState<T>>>,
}

impl<T: Clone> SharedStateFuture<T> {
    pub(crate) fn new(shared_state: Arc<Mutex<SharedState<T>>>) -> Self {
        Self { shared_state }
    }
}

impl<T: Clone> Future for SharedStateFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Ok(state) = self.shared_state.try_lock() {
            if let Some(data) = state.get() {
                Poll::Ready(data.clone())
            } else {
                Poll::Pending
            }
        } else {
            Poll::Pending
        }
    }
}

pub(crate) struct SharedStateManager<T> {
    state: Arc<Mutex<SharedState<T>>>,
}

impl<T: Clone> SharedStateManager<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SharedState::new())),
        }
    }

    pub(crate) fn wait_for(&self) -> SharedStateFuture<T> {
        SharedStateFuture::new(Arc::clone(&self.state))
    }

    pub(crate) fn set(&self, data: T) -> Result<(), &'static str> {
        if let Ok(mut state) = self.state.try_lock() {
            state.set(data);
            Ok(())
        } else {
            Err("Failed to acquire lock")
        }
    }

    #[allow(unused)]
    pub(crate) fn is_ready(&self) -> bool {
        if let Ok(state) = self.state.try_lock() {
            state.is_ready()
        } else {
            false
        }
    }

    #[allow(unused)]
    pub(crate) fn try_get(&self) -> Option<T>
    where
        T: Clone,
    {
        if let Ok(state) = self.state.try_lock() {
            state.get().cloned()
        } else {
            None
        }
    }
}

impl<T> Clone for SharedStateManager<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}
