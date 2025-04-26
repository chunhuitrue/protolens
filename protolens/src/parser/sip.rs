use crate::Parser;
use crate::ParserFactory;
use crate::Prolens;
use crate::UdpParserFn;
use crate::packet::*;
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct SipParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> SipParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    fn bdir_parser(_pkt: &PacketWrapper<T, P>, _cb_ctx: *mut c_void) -> Result<(), ()> {
        dbg!("in sip bidr_parser");
        Ok(())
    }
}

impl<T, P> Parser for SipParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn pkt_bidr_parser(&self) -> Option<UdpParserFn<T, P>> {
        Some(Self::bdir_parser)
    }
}

pub(crate) struct SipFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for SipFactory<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    fn create(&self, _prolens: &Prolens<T, P>) -> Box<dyn Parser<PacketType = T, PtrType = P>> {
        Box::new(SipParser::new())
        // let parser = Box::new(SipParser::new());
        // // parser.cb_read = prolens.cb_read.clone();
        // parser
    }
}
