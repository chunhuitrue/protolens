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
pub mod smtp;

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
