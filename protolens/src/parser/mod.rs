pub mod ordpacket;
pub mod smtp;

#[cfg(test)]
pub mod bdry;
#[cfg(test)]
pub mod byte;
#[cfg(test)]
pub mod rawpacket;
#[cfg(test)]
pub mod read;
#[cfg(test)]
pub mod readdash;
#[cfg(test)]
pub mod readline;
#[cfg(test)]
pub mod readn;

use crate::PacketBind;
use crate::PktStrm;
use crate::Prolens;
use crate::PtrNew;
use crate::PtrWrapper;
use futures::Future;
use std::ffi::c_void;
use std::pin::Pin;

pub(crate) type ParserFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;

pub(crate) trait Parser {
    type PacketType: PacketBind;
    type PtrType: PtrWrapper<Self::PacketType> + PtrNew<Self::PacketType>;

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

pub(crate) trait ParserFactory<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn new() -> Self
    where
        Self: Sized;
    fn create(&self, prolens: &Prolens<T, P>) -> Box<dyn Parser<PacketType = T, PtrType = P>>;
}
