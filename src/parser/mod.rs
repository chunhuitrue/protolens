use self::smtp::MetaSmtp;
use crate::Packet;
use crate::PktStrm;
use futures::Future;
use futures_channel::mpsc;
use std::pin::Pin;

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

pub type ParserFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;

pub trait Parser {
    type PacketType: Packet + Ord + 'static;

    fn c2s_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        Box::pin(async { Ok(()) })
    }

    fn s2c_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        Box::pin(async { Ok(()) })
    }

    fn bdir_parser(
        &self,
        _c2s_stream: *const PktStrm<Self::PacketType>,
        _s2c_stream: *const PktStrm<Self::PacketType>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        Box::pin(async { Ok(()) })
    }
}
