use crate::CbBodyEvt;
use crate::CbHeader;
use crate::CbSipBody;
use crate::CbStartLine;
use crate::Parser;
use crate::ParserFactory;
use crate::Prolens;
use crate::UdpParser;
use crate::UdpParserFn;
use crate::content_length;
use crate::packet::*;
use crate::pktdata::*;
use phf::phf_set;
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct SipParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    cb_start_line: Option<CbStartLine>,
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbSipBody>,
    cb_body_stop: Option<CbBodyEvt>,
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
            cb_start_line: None,
            cb_header: None,
            cb_body_start: None,
            cb_body: None,
            cb_body_stop: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    fn bdir_parser(
        pkt: PacketWrapper<T, P>,
        cb_sip: SipCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let dir = Self::pkt_dir(&pkt);
        if dir == Direction::Unknown {
            return Ok(());
        }

        let mut pktdata = PktData::new(pkt);
        while pktdata.remain_data() {
            let (start_line, offset) = pktdata.readline_str()?;
            if let Some(ref cb) = cb_sip.start_line {
                cb.borrow_mut()(start_line.as_bytes(), offset as u32, cb_ctx, dir);
            }

            let header_ret = Self::header(&mut pktdata, dir, &cb_sip, cb_ctx)?;

            if header_ret.content_len > 0 {
                if let Some(ref cb) = cb_sip.body_start {
                    cb.borrow_mut()(cb_ctx, dir);
                }
                Self::body(&mut pktdata, header_ret.content_len, dir, &cb_sip, cb_ctx)?;
                if let Some(ref cb) = cb_sip.body_stop {
                    cb.borrow_mut()(cb_ctx, dir);
                }
            }
        }
        Ok(())
    }

    fn pkt_dir(pkt: &PacketWrapper<T, P>) -> Direction {
        let payload = pkt.ptr.payload();
        if req(unsafe { std::str::from_utf8_unchecked(payload) }) {
            return Direction::C2s;
        } else if rsp(unsafe { std::str::from_utf8_unchecked(payload) }) {
            return Direction::S2c;
        }
        Direction::Unknown
    }

    fn header(
        pktdata: &mut PktData<T, P>,
        dir: Direction,
        cb_sip: &SipCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<HeaderRet, ()> {
        let mut content_len = None;

        loop {
            let (line, offset) = pktdata.readline_str()?;

            if let Some(ref cb) = cb_sip.header {
                cb.borrow_mut()(line.as_bytes(), offset as u32, cb_ctx, dir);
            }

            if line == "\r\n" {
                break;
            }

            if content_len.is_none() {
                content_len = content_length(line);
            }
        }
        Ok(HeaderRet {
            content_len: content_len.unwrap_or(0),
            content_type: ContentType::Sdp,
        })
    }

    fn body(
        pktdata: &mut PktData<T, P>,
        size: usize,
        dir: Direction,
        cb_sip: &SipCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let (bytes, offset) = pktdata.readn(size)?;

        if let Some(ref cb) = cb_sip.body {
            cb.borrow_mut()(bytes, offset as u32, cb_ctx, dir);
        }

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

    fn pkt_bdir_parser(&self) -> Option<UdpParserFn<T, P>> {
        struct ParserImpl<T, P> {
            cb_sip: SipCallbacks,
            _phantom: PhantomData<(T, P)>,
        }

        impl<T, P> UdpParser for ParserImpl<T, P>
        where
            T: PacketBind,
            P: PtrWrapper<T> + PtrNew<T>,
        {
            type PacketType = T;
            type PtrType = P;

            fn parse(
                &self,
                pkt: PacketWrapper<Self::PacketType, Self::PtrType>,
                cb_ctx: *mut c_void,
            ) -> Result<(), ()> {
                SipParser::<T, P>::bdir_parser(pkt, self.cb_sip.clone(), cb_ctx)
            }
        }

        let cb_sip = SipCallbacks {
            start_line: self.cb_start_line.clone(),
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
        };

        Some(Box::new(ParserImpl {
            cb_sip,
            _phantom: PhantomData,
        }))
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

    fn create(&self, prolens: &Prolens<T, P>) -> Box<dyn Parser<PacketType = T, PtrType = P>> {
        let mut parser = Box::new(SipParser::new());
        parser.cb_start_line = prolens.cb_sip_start_line.clone();
        parser.cb_header = prolens.cb_sip_header.clone();
        parser.cb_body_start = prolens.cb_sip_body_start.clone();
        parser.cb_body = prolens.cb_sip_body.clone();
        parser.cb_body_stop = prolens.cb_sip_body_stop.clone();
        parser
    }
}

#[derive(Clone)]
pub(crate) struct SipCallbacks {
    pub(crate) start_line: Option<CbStartLine>,
    pub(crate) header: Option<CbHeader>,
    pub(crate) body_start: Option<CbBodyEvt>,
    pub(crate) body: Option<CbSipBody>,
    pub(crate) body_stop: Option<CbBodyEvt>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum ContentType {
    Sdp,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct HeaderRet {
    content_len: usize,
    content_type: ContentType,
}

static SIP_METHODS: phf::Set<&'static str> = phf_set! {
    "INVITE", "PUBLISH", "REGISTER", "ACK", "CANCEL", "OPTIONS", "BYE",
    "MESSAGE", "REFER", "NOTIFY", "SUBSCRIBE", "UPDATE", "INFO", "PRACK",
};

fn req(input: &str) -> bool {
    if input.len() < 3 {
        return false;
    }

    let search_range = &input[..input.len().min(10)];
    let method = match search_range.split_once(|c| [' ', '\r', '\n'].contains(&c)) {
        Some((method, _)) => method,
        None => search_range,
    };

    SIP_METHODS.contains(method)
}

fn rsp(input: &str) -> bool {
    if input.len() < 7 {
        return false;
    }

    if input.starts_with("SIP/2.0") {
        return true;
    }
    false
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
    fn test_sip_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/sip.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let req_start_line = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let req_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let req_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let req_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let rsp_start_line = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let rsp_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let rsp_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let rsp_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let start_line_callback = {
            let req_start_line_clone = req_start_line.clone();
            let rsp_start_line_clone = rsp_start_line.clone();
            move |line: &[u8], _offset: u32, _cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut rsp_start_line_guard = rsp_start_line_clone.borrow_mut();
                    rsp_start_line_guard.push(line.to_vec());
                } else {
                    let mut req_start_line_guard = req_start_line_clone.borrow_mut();
                    req_start_line_guard.push(line.to_vec());
                }
            }
        };

        let header_callback = {
            let req_headers_clone = req_headers.clone();
            let rsp_headers_clone = rsp_headers.clone();
            move |header: &[u8], _offset: u32, _cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut rsp_headers_guard = rsp_headers_clone.borrow_mut();
                    rsp_headers_guard.push(header.to_vec());
                } else {
                    if header == b"\r\n" {
                        dbg!("header cb. header end");
                    }
                    dbg!(std::str::from_utf8(header).unwrap());
                    let mut req_headers_guard = req_headers_clone.borrow_mut();
                    req_headers_guard.push(header.to_vec());
                }
            }
        };

        let body_start_callback = {
            let current_rsp_body_clone = rsp_body.clone();
            let current_req_body_clone = req_body.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut body_guard = current_rsp_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                } else {
                    let mut body_guard = current_req_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                }
            }
        };

        let body_callback = {
            let current_rsp_body_clone = rsp_body.clone();
            let current_req_body_clone = req_body.clone();
            move |body: &[u8], _offset: u32, _cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut body_guard = current_rsp_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);
                } else {
                    let mut body_guard = current_req_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);
                }
            }
        };

        let body_stop_callback = {
            let current_rsp_body_clone = rsp_body.clone();
            let rsp_bodies_clone = rsp_bodies.clone();
            let current_req_body_clone = req_body.clone();
            let req_bodies_clone = req_bodies.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let body_guard = current_rsp_body_clone.borrow();
                    let mut bodies_guard = rsp_bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                } else {
                    let body_guard = current_req_body_clone.borrow();
                    let mut bodies_guard = req_bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                }
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_sip_start_line(start_line_callback);
        protolens.set_cb_sip_header(header_callback);
        protolens.set_cb_sip_body_start(body_start_callback);
        protolens.set_cb_sip_body(body_callback);
        protolens.set_cb_sip_body_stop(body_stop_callback);

        let mut task = protolens.new_task(TransProto::Udp);
        protolens.set_task_parser(task.as_mut(), L7Proto::Sip);

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

            protolens.run_task(&mut task, pkt);
        }

        let expected_req_start_lines = [
            "INVITE sip:francisco@bbbbbb.com:55060 SIP/2.0\r\n",
            "ACK sip:francisco@222.55.7.204:5061 SIP/2.0\r\n",
            "REGISTER sip:bbbbbb.com SIP/2.0\r\n",
            "INVITE sip:francisco@bbbbbb.com:55060 SIP/2.0\r\n",
        ];
        let req_start_line_guard = req_start_line.borrow();
        assert_eq!(req_start_line_guard.len(), expected_req_start_lines.len());
        for (idx, expected) in expected_req_start_lines.iter().enumerate() {
            assert_eq!(
                std::str::from_utf8(&req_start_line_guard[idx]).unwrap(),
                *expected
            );
        }

        let expected_rsp_start_lines = [
            "SIP/2.0 100 Trying\r\n",
            "SIP/2.0 180 Ringing\r\n",
            "SIP/2.0 200 Ok\r\n",
            "SIP/2.0 200 OK\r\n",
            "SIP/2.0 100 Trying\r\n",
            "SIP/2.0 180 Ringing\r\n",
        ];
        let rsp_start_line_guard = rsp_start_line.borrow();
        assert_eq!(rsp_start_line_guard.len(), expected_rsp_start_lines.len());
        for (idx, expected) in expected_rsp_start_lines.iter().enumerate() {
            assert_eq!(
                std::str::from_utf8(&rsp_start_line_guard[idx]).unwrap(),
                *expected
            );
        }

        let expected_req_headers = [
            "Via: SIP/2.0/UDP 222.55.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0\r\n",
            "From: <sip:222.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>\r\n",
            "Call-ID: 12013223@222.55.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:222.55.7.195:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length:   229\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195;branch=z9hG4bK0f496e3b6e7bd140e0b701071c1245ab\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195:55061;branch=z9hG4bKa829b54f167d2bb5b96662b4efa0bbc6\r\n",
            "From: <sip:222.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>;tag=298852044\r\n",
            "Call-ID: 12013223@222.55.7.195\r\n",
            "CSeq: 1 ACK\r\n",
            "Contact: <sip:200.57.7.195:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 200.57.7.204:5061;rport;branch=z9hG4bK4E76DAE7C5584B21BF8C5F687296CCA5\r\n",
            "From: america <sip:francisco@bbbbbb.com>;tag=3848902025\r\n",
            "To: america <sip:francisco@bbbbbb.com>\r\n",
            "Contact: \"america\" <sip:francisco@200.57.7.204:5061>\r\n",
            "Call-ID: D3A26FC3974B44ECB5A96E07282903E3@bbbbbb.com\r\n",
            "CSeq: 39241 REGISTER\r\n",
            "Expires: 1800\r\n",
            "Max-Forwards: 70\r\n",
            "User-Agent: X-Lite release 1103m\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195;branch=z9hG4bK9a86043a5daf59f4e9afd83eff9fc6e8\r\n",
            "Via: SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bKf3abad1ad86c86fc9f3fae7f49548564\r\n",
            "From: \"Ivan Alizade\" <sip:5514540002@200.57.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>\r\n",
            "Call-ID: 12015624@200.57.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:222.55.7.195:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length:   205\r\n",
            "\r\n",
        ];
        let req_headers_guard = req_headers.borrow();
        assert_eq!(req_headers_guard.len(), expected_req_headers.len());
        for (idx, expected) in expected_req_headers.iter().enumerate() {
            assert_eq!(
                std::str::from_utf8(&req_headers_guard[idx]).unwrap(),
                *expected
            );
        }

        let expected_rsp_headers = [
            "Via: SIP/2.0/UDP 222.55.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0\r\n",
            "From: <sip:222.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>;tag=298852044\r\n",
            "Contact: <sip:francisco@222.55.7.204:5061>\r\n",
            "Call-ID: 12013223@222.55.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Server: X-Lite release 1103m\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0\r\n",
            "From: <sip:2ss.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>;tag=298852044\r\n",
            "Contact: <sip:francisco@222.55.7.204:5061>\r\n",
            "Call-ID: 12013223@222.55.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Server: X-Lite release 1103m\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290\r\n",
            "Via: SIP/2.0/UDP 222.55.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0\r\n",
            "From: <sip:222.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>;tag=298852044\r\n",
            "Contact: <sip:francisco@222.55.7.204:5061>\r\n",
            "Call-ID: 12013223@222.55.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Type: application/sdp\r\n",
            "Server: X-Lite release 1103m\r\n",
            "Content-Length: 298\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 200.57.7.204:5061;received=200.57.7.204;rport=5061;branch=z9hG4bK4E76DAE7C5584B21BF8C5F687296CCA5\r\n",
            "From: \"america\" <sip:francisco@bbbbbb.com>;tag=3848902025\r\n",
            "To: \"america\" <sip:francisco@bbbbbb.com>\r\n",
            "Call-ID: DDD26FC3974B44ECB5A96E07282903E3@bbbbbb.com\r\n",
            "CSeq: 39241 REGISTER\r\n",
            "Contact: \"america\" <sip:francisco@222.55.7.204:5061>\r\n",
            "expires: 20\r\n",
            "max-forwards: 70\r\n",
            "user-agent: X-Lite release 1103m\r\n",
            "Allow: REFER, INFO, BYE, CANCEL, INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 200.57.7.195;branch=z9hG4bK9a86043a5daf59f4e9afd83eff9fc6e8\r\n",
            "Via: SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bKf3abad1ad86c86fc9f3fae7f49548564\r\n",
            "From: \"Ivan Alizade\" <sip:5514540002@222.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>;tag=4098209679\r\n",
            "Contact: <sip:francisco@200.57.7.204:5061>\r\n",
            "Call-ID: 12015624@200.57.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Server: X-Lite release 1103m\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
            "Via: SIP/2.0/UDP 200.57.7.195;branch=z9hG4bK9a86043a5daf59f4e9afd83eff9fc6e8\r\n",
            "Via: SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bKf3abad1ad86c86fc9f3fae7f49548564\r\n",
            "From: \"Ivan Alizade\" <sip:5514540002@222.55.7.195:55061;user=phone>;tag=GR52RWG346-34\r\n",
            "To: \"francisco@bbbbbb.com\" <sip:francisco@bbbbbb.com:55060>;tag=4098209679\r\n",
            "Contact: <sip:francisco@200.57.7.204:5061>\r\n",
            "Call-ID: 12015624@200.57.7.195\r\n",
            "CSeq: 1 INVITE\r\n",
            "Server: X-Lite release 1103m\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ];
        let rsp_headers_guard = rsp_headers.borrow();
        assert_eq!(rsp_headers_guard.len(), expected_rsp_headers.len());
        for (idx, expected) in expected_rsp_headers.iter().enumerate() {
            assert_eq!(
                std::str::from_utf8(&rsp_headers_guard[idx]).unwrap(),
                *expected
            );
        }

        let bodies_guard = req_bodies.borrow();
        assert_eq!(bodies_guard.len(), 2);

        let expected_req_body0 = [
            "v=0\r\n",
            "o=Clarent 120386 120387 IN IP4 222.55.7.196\r\n",
            "s=Clarent C5CM\r\n",
            "c=IN IP4 222.55.7.196\r\n",
            "t=0 0\r\n",
            "m=audio 40376 RTP/AVP 8 18 4 0\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:18 G729/8000\r\n",
            "a=rtpmap:4 G723/8000\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=SendRecv\r\n",
        ];
        let req_bodies_guard = req_bodies.borrow();
        let body0 = &req_bodies_guard[0];
        let expected_body = expected_req_body0.join("").as_bytes().to_vec();
        assert_eq!(body0, &expected_body);

        let expected_req_body1 = [
            "v=0\r\n",
            "o=Clarent 121082 121083 IN IP4 222.55.7.196\r\n",
            "s=Clarent C5CM\r\n",
            "c=IN IP4 200.57.7.196\r\n",
            "t=0 0\r\n",
            "m=audio 40360 RTP/AVP 8 18 4\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:18 G729/8000\r\n",
            "a=rtpmap:4 G723/8000\r\n",
            "a=SendRecv\r\n",
        ];
        let req_bodies_guard = req_bodies.borrow();
        let body1 = &req_bodies_guard[1];
        let expected_body = expected_req_body1.join("").as_bytes().to_vec();
        assert_eq!(body1, &expected_body);

        let bodies_guard = rsp_bodies.borrow();
        assert_eq!(bodies_guard.len(), 1);

        let expected_rsp_body0 = [
            "v=0\r\n",
            "o=francisco 13004970 13013442 IN IP4 222.55.7.204\r\n",
            "s=X-Lite\r\n",
            "c=IN IP4 222.55.7.204\r\n",
            "t=0 0\r\n",
            "m=audio 8000 RTP/AVP 8 0 3 98 97 101\r\n",
            "a=rtpmap:0 pcmu/8000\r\n",
            "a=rtpmap:8 pcma/8000\r\n",
            "a=rtpmap:3 gsm/8000\r\n",
            "a=rtpmap:98 iLBC/8000\r\n",
            "a=rtpmap:97 speex/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=fmtp:101 0-15\r\n",
        ];
        let rsp_bodies_guard = rsp_bodies.borrow();
        let body0 = &rsp_bodies_guard[0];
        let expected_body = expected_rsp_body0.join("").as_bytes().to_vec();
        assert_eq!(body0, &expected_body);
    }
}
