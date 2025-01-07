use self::smtp::MetaSmtp;
use crate::pool::Pool;
use crate::pool::PoolBox;
use crate::Packet;
use crate::PktStrm;
use futures::Future;
use futures_channel::mpsc;
use std::pin::Pin;
use std::rc::Rc;

pub mod ordpacket;
#[cfg(test)]
pub mod rawpacket;
pub mod smtp;
#[cfg(test)]
pub mod stream_next;
#[cfg(test)]
pub mod stream_readline;
#[cfg(test)]
pub mod stream_readn;

#[derive(Debug)]
pub enum MetaHttp {}

#[derive(Debug)]
pub enum Meta {
    Smtp(MetaSmtp),
    Http(MetaHttp),
}

pub(crate) type ParserFuture = Pin<PoolBox<dyn Future<Output = Result<(), ()>>>>;

pub trait Parser {
    type PacketType: Packet + Ord + 'static;

    fn pool(&self) -> &Rc<Pool>;
    fn set_pool(&mut self, pool: Rc<Pool>);

    fn new() -> Self
    where
        Self: Sized;

    fn c2s_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        self.pool().new_future(async { Ok(()) })
    }

    fn s2c_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        self.pool().new_future(async { Ok(()) })
    }

    fn bdir_parser(
        &self,
        _c2s_stream: *const PktStrm<Self::PacketType>,
        _s2c_stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        self.pool().new_future(async { Ok(()) })
    }
}
