use crate::Callbacks;
use crate::CbBody;
use crate::CbBodyEvt;
use crate::CbClt;
use crate::CbHeader;
use crate::CbSrv;
use crate::Direction;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::body;
use crate::header;
use crate::multi_body;
use crate::packet::*;
use nom::{
    IResult,
    bytes::complete::{tag, take_till},
    character::complete::{digit1, multispace1},
    combinator::map,
    combinator::{map_res, recognize},
    sequence::{preceded, terminated},
};
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct Pop3Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_clt: Option<CbClt>,
    cb_srv: Option<CbSrv>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> Pop3Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_header: None,
            cb_body_start: None,
            cb_body: None,
            cb_body_stop: None,
            cb_clt: None,
            cb_srv: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        stream: *const PktStrm<T, P>,
        cb_pop3: Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.read_clean_line_str().await?;

            if let Some(ref cb) = cb_pop3.clt {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            if line == "QUIT" || line == "STLS" {
                break;
            }
        }
        Ok(())
    }

    async fn s2c_parser_inner(
        stream: *const PktStrm<T, P>,
        cb_pop3: Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.read_clean_line_str().await?;

            if let Some(ref cb) = cb_pop3.srv {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            if stls_answer(line) {
                break;
            }

            if retr_answer(line) {
                Self::parser_inner(stm, &cb_pop3, cb_ctx).await?;
            }
        }
        Ok(())
    }

    async fn parser_inner(
        stm: &mut PktStrm<T, P>,
        cb_pop3: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let (boundary, te) = header(stm, cb_pop3.header.as_ref(), cb_ctx, Direction::S2c).await?;
        if let Some(bdry) = boundary {
            multi_body(stm, &bdry, &bdry, cb_pop3, cb_ctx).await?;
        } else {
            body(
                stm,
                te,
                cb_pop3.body_start.as_ref(),
                cb_pop3.body.as_ref(),
                cb_pop3.body_stop.as_ref(),
                cb_ctx,
                cb_pop3.dir,
            )
            .await?;
        }
        Ok(())
    }
}

impl<T, P> Parser for Pop3Parser<T, P>
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
        let cb_pop3 = Callbacks {
            header: None,
            body_start: None,
            body: None,
            body_stop: None,
            clt: self.cb_clt.clone(),
            srv: None,
            dir: Direction::C2s,
        };

        Some(Box::pin(Self::c2s_parser_inner(stream, cb_pop3, cb_ctx)))
    }

    fn s2c_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        let cb_pop3 = Callbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
            clt: None,
            srv: self.cb_srv.clone(),
            dir: Direction::S2c,
        };

        Some(Box::pin(Self::s2c_parser_inner(stream, cb_pop3, cb_ctx)))
    }
}

pub(crate) struct Pop3Factory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for Pop3Factory<T, P>
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
        let mut parser = Box::new(Pop3Parser::new());
        parser.cb_header = prolens.cb_pop3_header.clone();
        parser.cb_body_start = prolens.cb_pop3_body_start.clone();
        parser.cb_body = prolens.cb_pop3_body.clone();
        parser.cb_body_stop = prolens.cb_pop3_body_stop.clone();
        parser.cb_clt = prolens.cb_pop3_clt.clone();
        parser.cb_srv = prolens.cb_pop3_srv.clone();
        parser
    }
}

fn retr_answer(input: &str) -> bool {
    fn parse_ok_tag(input: &str) -> IResult<&str, &str> {
        tag("+OK")(input)
    }

    fn parse_number(input: &str) -> IResult<&str, u32> {
        map_res(recognize(digit1), str::parse)(input)
    }

    fn parse_octets(input: &str) -> IResult<&str, &str> {
        tag("octets")(input)
    }

    fn parse_retr_response(input: &str) -> IResult<&str, u32> {
        preceded(
            preceded(parse_ok_tag, multispace1),
            terminated(parse_number, preceded(multispace1, parse_octets)),
        )(input)
    }

    parse_retr_response(input).is_ok()
}

fn stls_answer(input: &str) -> bool {
    fn parse_ok_tag(input: &str) -> IResult<&str, &str> {
        tag("+OK")(input)
    }

    fn parse_stls_response(input: &str) -> IResult<&str, bool> {
        map(
            preceded(parse_ok_tag, take_till(|_| false)),
            |rest: &str| rest.to_lowercase().contains("tls"),
        )(input)
    }

    parse_stls_response(input).is_ok_and(|(_, contains_tls)| contains_tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransferEncoding;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::env;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_retr_answer() {
        assert!(retr_answer("+OK 6750 octets"));
        assert!(retr_answer("+OK 123 octets"));
        assert!(retr_answer("+OK 1 octets"));

        assert!(!retr_answer("+OK"));
        assert!(!retr_answer("+OK message follows"));
        assert!(!retr_answer("+OK 6750"));
        assert!(!retr_answer("+OK octets"));
        assert!(!retr_answer("+OK 6750 bytes"));
        assert!(!retr_answer("-ERR no such message"));
        assert!(!retr_answer(""));
    }

    #[test]
    fn test_stls_answer() {
        // 有效的STLS响应
        assert!(stls_answer("+OK Begin TLS negotiation"));
        assert!(stls_answer("+OK Ready to start TLS"));
        assert!(stls_answer("+OK TLS"));
        assert!(stls_answer("+OK Begin tls"));

        // 无效的STLS响应
        assert!(!stls_answer("+OK"));
        assert!(!stls_answer("+OK Ready to proceed"));
        assert!(!stls_answer("-ERR TLS not available"));
        assert!(!stls_answer(""));
    }

    #[test]
    fn test_pop3_body() {
        let retr_answer = ["+OK 111 octets\r\n"];
        let header = [
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "\r\n",
        ];
        let body = ["mail body line1.\r\n", "mail body line2.\r\n"];
        let quit = [".\r\n"];
        let lines = retr_answer
            .iter()
            .chain(header.iter())
            .chain(body.iter())
            .chain(quit.iter());

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_body = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
                dbg!("header cb. push", std::str::from_utf8(header).unwrap());
            }
        };

        let body_callback = {
            let body_clone = captured_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  _te: Option<TransferEncoding>| {
                let mut body_guard = body_clone.borrow_mut();
                body_guard.push(body.to_vec());
            }
        };

        protolens.set_cb_pop3_header(header_callback);
        protolens.set_cb_pop3_body(body_callback);

        let mut task = protolens.new_task();

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Pop3);
            pkt.set_direction(Direction::S2c);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), header.len());
        for (idx, expected) in header.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let body_guard = captured_body.borrow();
        assert_eq!(body_guard.len(), body.len());
        for (idx, expected) in body.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&body_guard[idx]).unwrap(), *expected);
        }
    }

    #[test]
    fn test_pop3_multi_retr() {
        let lines = [
            "+OK 111 octets\r\n",
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            "------=_001_NextPart572182624333_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "content 1",
            "------=_001_NextPart572182624333_=------\r\n", // 最后的\r\n属于epilogue
            "This is the epilogue 1.\r\n",
            "This is the epilogue 2.\r\n",
            ".\r\n",
            "+OK\r\n",
            "+OK\r\n",
            "+OK 222 octets\r\n",
            "From: sender2@example.com\r\n",
            "To: recipient2@example.com\r\n",
            "Subject: Email Subject2\r\n",
            "\r\n",
            "mail body line1.\r\n",
            "mail body line2.\r\n",
            ".\r\n",
        ];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                dbg!("callback header", std::str::from_utf8(header).unwrap());
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                // 创建新的body缓冲区
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                println!("Body start callback triggered");
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  _te: Option<TransferEncoding>| {
                // 将内容追加到当前body
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                // 将当前body添加到bodies列表
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
            }
        };

        let mut task = protolens.new_task();

        protolens.set_cb_pop3_header(header_callback);
        protolens.set_cb_pop3_body_start(body_start_callback);
        protolens.set_cb_pop3_body(body_callback);
        protolens.set_cb_pop3_body_stop(body_stop_callback);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Pop3);
            pkt.set_direction(Direction::S2c);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let expected_headers = [
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "From: sender2@example.com\r\n",
            "To: recipient2@example.com\r\n",
            "Subject: Email Subject2\r\n",
            "\r\n",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 2);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        dbg!(body0_str);
        assert!(body0_str.contains("content 1"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        dbg!(body1_str);
        assert!(body1_str.contains("mail body line1.\r\n"));
        assert!(body1_str.contains("mail body line2.\r\n"));
    }

    #[test]
    fn test_pop3_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/pop3.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_clt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_te = Rc::new(RefCell::new(None));
        let captured_tes = Rc::new(RefCell::new(Vec::new()));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            let current_te = current_te.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                *current_te.borrow_mut() = None;
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            let current_te = current_te.clone();
            let captured_tes = captured_tes.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  te: Option<TransferEncoding>| {
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                // dbg!(te.clone(), std::str::from_utf8(body).unwrap());

                let mut current_te = current_te.borrow_mut();
                if current_te.is_none() {
                    *current_te = te.clone();
                    captured_tes.borrow_mut().push(te);
                } else {
                    assert_eq!(*current_te, te, "TransferEncoding changed within same body");
                }
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                // 将当前body添加到bodies列表
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                dbg!("Body stop callback triggered", body_guard.len());
            }
        };

        let clt_callback = {
            let clt_clone = captured_clt.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                // dbg!("in clt callback", std::str::from_utf8(line).unwrap());
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        protolens.set_cb_pop3_header(header_callback);
        protolens.set_cb_pop3_body_start(body_start_callback);
        protolens.set_cb_pop3_body(body_callback);
        protolens.set_cb_pop3_body_stop(body_stop_callback);
        protolens.set_cb_pop3_clt(clt_callback);
        protolens.set_cb_pop3_srv(srv_callback);

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
            pkt.set_l7_proto(L7Proto::Pop3);
            if pkt.header.borrow().as_ref().unwrap().dport() == POP3_PORT {
                pkt.set_direction(Direction::C2s);
            } else {
                pkt.set_direction(Direction::S2c);
            }

            protolens.run_task(&mut task, pkt);
        }

        let expected_headers = [
            "Received: from qq.com (unknown [183.3.255.59])\r\n",
            "\tby mx7 (Coremail) with SMTP id OcCowACXsZS0C3VgxNvcDw--.34051S3;\r\n",
            "\tTue, 13 Apr 2021 11:10:44 +0800 (CST)\r\n",
            "X-QQ-mid: bizesmtp23t1618283442tu0iybdh\r\n",
            "Received: from Z640100480 (unknown [222.128.113.199])\r\n",
            "\tby esmtp6.qq.com (ESMTP) with \r\n",
            "\tid ; Tue, 13 Apr 2021 11:10:41 +0800 (CST)\r\n",
            "X-QQ-SSF: B170000A002000H0F000B00A0000000\r\n",
            "X-QQ-FEAT: a5Sfq5qTxp2z0xM/vdov6YOwWvqhVGJAxu+mkDi73Trd40z/7aUGANPgXgvia\r\n",
            "\ttlfsV7zhFLNx2sEnZCKuAaeDuGlY3/5nMtXLNvf3Euw0+17WXnb8Y1vxxdV2Ncy8AFYY43P\r\n",
            "\tLdOZM3Xm6RSgCPNupjasujVLjZFHI5En85q/y5g4kzvHoiVWD51M+GbRPWKvg1kOBCYIuVq\r\n",
            "\tDa7nzktTzOrR6JCElhf472kmMEwpd58dhMpy1LeOYdkC50DMsXBJ1KWmWeAtFlzVwZFbR00\r\n",
            "\thCU6UgKlgDfjZxC2icxY4Ckl2yl5ywNqSWveOkrp7otL4pLnly88J5HhrjV8H/R4h2xA==\r\n",
            "X-QQ-GoodBg: 0\r\n",
            "Date: Tue, 13 Apr 2021 11:10:43 +0800\r\n",
            "From: \"yuuminmin@serverdata.com.cn\" <yuuminmin@serverdata.com.cn>\r\n",
            "To: xiaomingming <xiaomingming@163.com>\r\n",
            "Cc: 625293369 <625293369@qq.com>\r\n",
            "Subject: yishengyishiyishuangren\r\n",
            "X-Priority: 3\r\n",
            "X-GUID: B02C26D8-2D59-4053-96B9-D9462BA83F28\r\n",
            "X-Has-Attach: yes\r\n",
            "X-Mailer: Foxmail 7.2.18.111[cn]\r\n",
            "Mime-Version: 1.0\r\n",
            "Message-ID: <202104131110426530121@serverdata.com.cn>+F9E8617B1B816279\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"----=_001_NextPart500622418632_=----\"\r\n",
            "X-QQ-SENDSIZE: 520\r\n",
            "Feedback-ID: bizesmtp:serverdata.com.cn:qybgweb:qybgweb10\r\n",
            "X-CM-TRANSID:OcCowACXsZS0C3VgxNvcDw--.34051S3\r\n",
            "Authentication-Results: mx7; spf=pass smtp.mail=yuuminmin@serverdata.c\r\n",
            "\tom.cn;\r\n",
            "X-Coremail-Antispam: 1Uf129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7v73\r\n",
            "\tVFW2AGmfu7bjvjm3AaLaJ3UbIYCTnIWIevJa73UjIFyTuYvjxUff-BDUUUU\r\n",
            "\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_002_NextPart174447020822_=----\"\r\n",
            "\r\n",
            "Content-Type: text/plain;\r\n",
            "\tcharset=\"us-ascii\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"us-ascii\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Content-Type: application/octet-stream;\r\n",
            "\tname=\"zaicao.txt\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Disposition: attachment;\r\n",
            "\tfilename=\"zaicao.txt\"\r\n",
            "\r\n",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 3);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert!(body0_str.contains(
            "ZGFtb2d1eWFuemhpDQpjaGFuZ2hlbHVvcml5dWFuDQoNCg0KDQp5dWV5YW55YW5AaGFvaGFuZGF0\r\n"
        ));
        assert!(body0_str.contains("YS5jb20uY24NCg==\r\n"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains(
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n"
        ));
        assert!(body1_str.contains("..com.cn</span></div>=0A</body></html>")); // 最后的\r\n不属于body

        let body2 = &bodies_guard[2];
        let body2_str = std::str::from_utf8(body2).unwrap();
        assert!(body2_str.contains(
            "44CK6I+c5qC56LCt44CLLS3lmrzlvpfoj5zmoLnvvIznmb7kuovlj6/lgZrvvIENCuaWh+eroOWB\r\n"
        ));
        assert!(body2_str.contains(
            "heWQm+WtkOS6i+adpeiAjOW/g+Wni+eOsO+8jOS6i+WOu+iAjOW/g+maj+epuuOAgg0KDQoNCg==\r\n"
        ));

        let clt_guard = captured_clt.borrow();
        assert_eq!(clt_guard.len(), 7);
        assert_eq!(
            std::str::from_utf8(&clt_guard[0]).unwrap(),
            "USER xiaomingming@163.com"
        );
        assert_eq!(std::str::from_utf8(&clt_guard[2]).unwrap(), "STAT");
        assert_eq!(std::str::from_utf8(&clt_guard[6]).unwrap(), "QUIT");

        let srv_guard = captured_srv.borrow();
        assert_eq!(
            std::str::from_utf8(&srv_guard[0]).unwrap(),
            "+OK Welcome to coremail Mail Pop3 Server (163coms[10774b260cc7a37d26d71b52404dcf5cs])"
        );
        assert_eq!(
            std::str::from_utf8(&srv_guard[13]).unwrap(),
            "+OK 7 3044427"
        );
        assert_eq!(
            std::str::from_utf8(&srv_guard[22]).unwrap(),
            "+OK 6750 octets"
        );

        let tes = captured_tes.borrow();
        assert_eq!(tes.len(), 3);
        assert_eq!(tes[0], Some(TransferEncoding::Base64));
        assert_eq!(tes[1], Some(TransferEncoding::QuotedPrintable));
        assert_eq!(tes[2], Some(TransferEncoding::Base64));
    }
}
