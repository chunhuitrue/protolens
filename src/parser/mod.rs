use crate::pool::Pool;
use crate::pool::PoolBox;
use crate::Packet;
use crate::PktStrm;
use futures::Future;
use std::pin::Pin;
use std::rc::Rc;

pub mod ordpacket;
#[cfg(test)]
pub mod rawpacket;
#[cfg(test)]
pub mod smtp;
pub mod smtp2;
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

pub(crate) type ParserFuture = Pin<PoolBox<dyn Future<Output = Result<(), ()>>>>;

pub trait Parser {
    type PacketType: Packet + Ord + 'static;

    fn new() -> Self
    where
        Self: Sized;

    fn pool(&self) -> &Rc<Pool>;

    fn set_pool(&mut self, pool: Rc<Pool>);

    fn c2s_parser_size(&self) -> usize {
        0
    }

    fn s2c_parser_size(&self) -> usize {
        0
    }

    fn bdir_parser_size(&self) -> usize {
        0
    }

    fn c2s_parser(&self, _stream: *const PktStrm<Self::PacketType>) -> Option<ParserFuture> {
        None
    }

    fn s2c_parser(&self, _stream: *const PktStrm<Self::PacketType>) -> Option<ParserFuture> {
        None
    }

    fn bdir_parser(
        &self,
        _c2s_stream: *const PktStrm<Self::PacketType>,
        _s2c_stream: *const PktStrm<Self::PacketType>,
    ) -> Option<ParserFuture> {
        None
    }
}
