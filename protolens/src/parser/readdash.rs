use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::packet::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

const BDRY: &str = "--boundary--";

pub trait ReadDashCbFn: FnMut(bool, *mut c_void) {}
impl<F: FnMut(bool, *mut c_void)> ReadDashCbFn for F {}
pub(crate) type CbReadDash = Rc<RefCell<dyn ReadDashCbFn + 'static>>;

pub struct ReadDashParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_read: Option<CbReadDash>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ReadDashParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub fn new() -> Self {
        Self {
            cb_read: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_read: Option<CbReadDash>,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        stm.read_dash_bdry(BDRY).await?;
        let dash = stm.read_dash().await?;
        if let Some(ref cb) = cb_read {
            cb.borrow_mut()(dash, cb_ctx);
        }
        Ok(())
    }
}

impl<T, P> Default for ReadDashParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Parser for ReadDashParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn c2s_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_read.clone(),
            stream,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadDashFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for ReadDashFactory<T, P>
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

    fn create(&self, prolens: &Prolens<T, P>) -> Box<dyn Parser<PacketType = T, PtrType = P>> {
        let mut parser = Box::new(ReadDashParser::new());
        parser.cb_read = prolens.cb_readdash.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // 简单情况，bdry后跟着dash
    #[test]
    fn test_bdry_dash() {
        let seq1 = 1;
        let content = b"content".to_vec();
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());
        payload.extend_from_slice(b"--");
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();
        pkt.set_l7_proto(L7Proto::ReadDash);

        let result = Rc::new(RefCell::new(Vec::new()));
        let result_clone = Rc::clone(&result);
        let callback = move |dash: bool, _cb_ctx: *mut c_void| {
            dbg!("in callback", dash);
            result_clone.borrow_mut().push(dash);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readdash(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt);

        let dash_result = result.borrow();

        assert_eq!(dash_result.len(), 1);
        assert!(dash_result[0]);
    }

    // 只有bdry
    #[test]
    fn test_bdry_no_dash() {
        let seq1 = 1;
        let content = b"content".to_vec();
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());

        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();
        pkt.set_l7_proto(L7Proto::ReadDash);

        let result = Rc::new(RefCell::new(Vec::new()));
        let result_clone = Rc::clone(&result);
        let callback = move |dash: bool, _cb_ctx: *mut c_void| {
            result_clone.borrow_mut().push(dash);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readdash(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt);

        let dash_result = result.borrow();

        assert_eq!(dash_result.len(), 0);
    }

    // 只有bdry,不是dash
    #[test]
    fn test_bdry_not_dash() {
        let seq1 = 1;
        let content = b"content".to_vec();
        let mut payload = content.clone();
        payload.extend_from_slice(b"\r\n--");
        payload.extend_from_slice(BDRY.as_bytes());
        payload.extend_from_slice(b"-+");

        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();
        pkt.set_l7_proto(L7Proto::ReadDash);

        let result = Rc::new(RefCell::new(Vec::new()));
        let result_clone = Rc::clone(&result);
        let callback = move |dash: bool, _cb_ctx: *mut c_void| {
            dbg!(dash);
            result_clone.borrow_mut().push(dash);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readdash(callback);
        let mut task = protolens.new_task();
        protolens.run_task(&mut task, pkt);

        let dash_result = result.borrow();

        assert_eq!(dash_result.len(), 1);
        assert!(!dash_result[0]);
    }
}
