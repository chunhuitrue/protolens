pub mod ordpacket;
#[cfg(test)]
pub mod rawpacket;
pub mod smtp;
#[cfg(test)]
pub mod stream_next;
#[cfg(test)]
pub mod stream_read;
#[cfg(test)]
pub mod stream_readline;
#[cfg(test)]
pub mod stream_readline2;
#[cfg(test)]
pub mod stream_readn;
#[cfg(test)]
pub mod stream_readn2;

use crate::PtrNew;
use crate::PtrWrapper;
use crate::Packet;
use crate::PktStrm;
use futures::Future;
use std::ffi::c_void;
use std::pin::Pin;

pub(crate) type ParserFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;

pub(crate) trait Parser {
    type PacketType: Packet + Ord + 'static;
    type PtrType: PtrWrapper<Self::PacketType> + PtrNew<Self::PacketType>;

    fn new() -> Self
    where
        Self: Sized;

    fn c2s_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn s2c_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn bdir_parser(
        &self,
        _c2s_stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _s2c_stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }
}
