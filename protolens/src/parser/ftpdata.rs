use crate::CbBodyEvt;
use crate::CbFtpBody;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::ReadError;
use crate::packet::*;
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct FtpDataParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbFtpBody>,
    cb_body_stop: Option<CbBodyEvt>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> FtpDataParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_body_start: None,
            cb_body: None,
            cb_body_stop: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn parser_inner(
        strm: *const PktStrm<T, P>,
        cb_body_start: Option<CbBodyEvt>,
        cb_body: Option<CbFtpBody>,
        cb_body_stop: Option<CbBodyEvt>,
        dir: Direction,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(strm as *mut PktStrm<T, P>);
        }

        if let Some(cb) = cb_body_start {
            cb.borrow_mut()(cb_ctx, dir);
        }
        loop {
            match stm.read2eof().await {
                Ok((bytes, seq)) => {
                    if let Some(ref cb) = cb_body {
                        cb.borrow_mut()(bytes, seq, cb_ctx, dir);
                    }
                }
                Err(ReadError::Eof) => {
                    break;
                }
                Err(ReadError::NoData) => {
                    continue;
                }
            }
        }
        if let Some(cb) = cb_body_stop {
            cb.borrow_mut()(cb_ctx, dir);
        }
        Ok(())
    }
}

impl<T, P> Parser for FtpDataParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn c2s_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::parser_inner(
            strm,
            self.cb_body_start.clone(),
            self.cb_body.clone(),
            self.cb_body_stop.clone(),
            Direction::C2s,
            cb_ctx,
        )))
    }

    fn s2c_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::parser_inner(
            strm,
            self.cb_body_start.clone(),
            self.cb_body.clone(),
            self.cb_body_stop.clone(),
            Direction::S2c,
            cb_ctx,
        )))
    }
}

pub(crate) struct FtpDataFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for FtpDataFactory<T, P>
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
        let mut parser = Box::new(FtpDataParser::new());
        parser.cb_body_start = prolens.cb_ftp_body_start.clone();
        parser.cb_body = prolens.cb_ftp_body.clone();
        parser.cb_body_stop = prolens.cb_ftp_body_stop.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::env;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_ftp_data() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/ftp_pasv.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::C2s {
                    let mut body_guard = current_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                    dbg!("body start");
                }
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::C2s {
                    let mut body_guard = current_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);
                    dbg!("body ", body.len());
                }
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::C2s {
                    let body_guard = current_body_clone.borrow();
                    let mut bodies_guard = bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                    dbg!("body end");
                }
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_ftp_body_start(body_start_callback);
        protolens.set_cb_ftp_body(body_callback);
        protolens.set_cb_ftp_body_stop(body_stop_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(task.as_mut(), L7Proto::FtpData);

        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let pkt = cap.next_packet(now);
            if pkt.is_none() {
                break;
            }
            let pkt = pkt.unwrap();
            if pkt.decode().is_err() {
                continue;
            }

            if pkt.header.borrow().as_ref().unwrap().dport() == 56281
                && pkt.header.borrow().as_ref().unwrap().sport() == 22578
            {
                protolens.run_task(&mut task, pkt);
            }
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 1);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert!(body0_str.contains(" Feb 29  2020 1"));
        assert!(body0_str.contains("aa-20200217-1801-USB.iso"));
        assert!(body0_str.contains("wget-log.1"));
        assert!(body0_str.contains(" 4096 May 05  2010 音乐\r\n"));
    }
}
