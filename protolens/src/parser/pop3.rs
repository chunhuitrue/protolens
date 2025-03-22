use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::body;
use crate::header;
use crate::multi_body;
use crate::packet::*;
use crate::parser::epilogue;
use nom::{
    IResult,
    bytes::complete::tag,
    character::complete::{digit1, multispace1},
    combinator::{map_res, recognize},
    sequence::{preceded, terminated},
};
use std::ffi::c_void;
use std::marker::PhantomData;

use crate::CbBody;
use crate::CbBodyEvt;
use crate::CbClt;
use crate::CbHeader;

#[derive(Clone)]
pub(crate) struct Pop3Callbacks {
    pub(crate) header: Option<CbHeader>,
    pub(crate) body_start: Option<CbBodyEvt>,
    pub(crate) body: Option<CbBody>,
    pub(crate) body_stop: Option<CbBodyEvt>,
}

pub struct Pop3Parser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_header: Option<CbHeader>,
    pub(crate) cb_body_start: Option<CbBodyEvt>,
    pub(crate) cb_body: Option<CbBody>,
    pub(crate) cb_body_stop: Option<CbBodyEvt>,
    pub(crate) cb_clt: Option<CbClt>,
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
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        stream: *const PktStrm<T, P>,
        cb_clt: Option<CbClt>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.read_clean_line_str().await?;

            if let Some(ref cb) = cb_clt {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            if line == "QUIT" {
                break;
            }
        }
        Ok(())
    }

    async fn s2c_parser_inner(
        stream: *const PktStrm<T, P>,
        cb: Pop3Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        loop {
            let (line, _seq) = stm.read_clean_line_str().await?;

            if retr_answer(line) {
                mail(stm, cb.clone(), cb_ctx).await?;
            }
        }
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
        Some(Box::pin(Self::c2s_parser_inner(
            stream,
            self.cb_clt.clone(),
            cb_ctx,
        )))
    }

    fn s2c_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        let cb = Pop3Callbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
        };

        Some(Box::pin(Self::s2c_parser_inner(stream, cb, cb_ctx)))
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
        parser
    }
}

async fn mail<T, P>(
    stm: &mut PktStrm<T, P>,
    cb: Pop3Callbacks,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let boundary = header(stm, cb.header.clone(), cb_ctx).await?;
    if let Some(bdry) = boundary {
        dbg!("to multi body2");
        multi_body(
            stm,
            &bdry,
            cb.header,
            cb.body_start,
            cb.body,
            cb.body_stop,
            cb_ctx,
        )
        .await?;
        epilogue(stm).await?;
    } else {
        body(stm, cb.body_start, cb.body, cb.body_stop, cb_ctx).await?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
                dbg!("header cb. push", std::str::from_utf8(header).unwrap());
            }
        };

        let body_callback = {
            let body_clone = captured_body.clone();
            move |body: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
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
            pkt.set_direction(PktDirection::Server2Client);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), header.len());
        for (idx, expected) in header.iter().enumerate() {
            assert_eq!(
                std::str::from_utf8(&headers_guard[idx]).unwrap(),
                expected.trim_end_matches("\r\n")
            );
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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                dbg!("callback header", std::str::from_utf8(header).unwrap());
                if header.is_empty() {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void| {
                // 创建新的body缓冲区
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                println!("Body start callback triggered");
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                // 将内容追加到当前body
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void| {
                // 将当前body添加到bodies列表
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                println!(
                    "Body stop callback triggered, body size: {} bytes",
                    body_guard.len()
                );
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
            pkt.set_direction(PktDirection::Server2Client);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let expected_headers = [
            "From: sender@example.com",
            "To: recipient@example.com",
            "Subject: Email Subject",
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"",
            "",
            "Content-Type: text/html;",
            "\tcharset=\"GB2312\"",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "From: sender2@example.com",
            "To: recipient2@example.com",
            "Subject: Email Subject2",
            "",
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

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                if header.is_empty() {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void| {
                // 创建新的body缓冲区
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                println!("Body start callback triggered");
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                // 将内容追加到当前body
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void| {
                // 将当前body添加到bodies列表
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                println!(
                    "Body stop callback triggered, body size: {} bytes",
                    body_guard.len()
                );
            }
        };

        let clt_callback = {
            let clt_clone = captured_clt.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                // dbg!("in clt callback", std::str::from_utf8(line).unwrap());
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        protolens.set_cb_pop3_header(header_callback);
        protolens.set_cb_pop3_body_start(body_start_callback);
        protolens.set_cb_pop3_body(body_callback);
        protolens.set_cb_pop3_body_stop(body_stop_callback);
        protolens.set_cb_pop3_clt(clt_callback);

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
                pkt.set_direction(PktDirection::Client2Server);
            } else {
                pkt.set_direction(PktDirection::Server2Client);
            }

            protolens.run_task(&mut task, pkt);
        }

        let expected_headers = [
            "Received: from qq.com (unknown [183.3.255.59])",
            "\tby mx7 (Coremail) with SMTP id OcCowACXsZS0C3VgxNvcDw--.34051S3;",
            "\tTue, 13 Apr 2021 11:10:44 +0800 (CST)",
            "X-QQ-mid: bizesmtp23t1618283442tu0iybdh",
            "Received: from Z640100480 (unknown [222.128.113.199])",
            "\tby esmtp6.qq.com (ESMTP) with ",
            "\tid ; Tue, 13 Apr 2021 11:10:41 +0800 (CST)",
            "X-QQ-SSF: B170000A002000H0F000B00A0000000",
            "X-QQ-FEAT: a5Sfq5qTxp2z0xM/vdov6YOwWvqhVGJAxu+mkDi73Trd40z/7aUGANPgXgvia",
            "\ttlfsV7zhFLNx2sEnZCKuAaeDuGlY3/5nMtXLNvf3Euw0+17WXnb8Y1vxxdV2Ncy8AFYY43P",
            "\tLdOZM3Xm6RSgCPNupjasujVLjZFHI5En85q/y5g4kzvHoiVWD51M+GbRPWKvg1kOBCYIuVq",
            "\tDa7nzktTzOrR6JCElhf472kmMEwpd58dhMpy1LeOYdkC50DMsXBJ1KWmWeAtFlzVwZFbR00",
            "\thCU6UgKlgDfjZxC2icxY4Ckl2yl5ywNqSWveOkrp7otL4pLnly88J5HhrjV8H/R4h2xA==",
            "X-QQ-GoodBg: 0",
            "Date: Tue, 13 Apr 2021 11:10:43 +0800",
            "From: \"yuuminmin@serverdata.com.cn\" <yuuminmin@serverdata.com.cn>",
            "To: xiaomingming <xiaomingming@163.com>",
            "Cc: 625293369 <625293369@qq.com>",
            "Subject: yishengyishiyishuangren",
            "X-Priority: 3",
            "X-GUID: B02C26D8-2D59-4053-96B9-D9462BA83F28",
            "X-Has-Attach: yes",
            "X-Mailer: Foxmail 7.2.18.111[cn]",
            "Mime-Version: 1.0",
            "Message-ID: <202104131110426530121@serverdata.com.cn>+F9E8617B1B816279",
            "Content-Type: multipart/mixed;",
            "\tboundary=\"----=_001_NextPart500622418632_=----\"",
            "X-QQ-SENDSIZE: 520",
            "Feedback-ID: bizesmtp:serverdata.com.cn:qybgweb:qybgweb10",
            "X-CM-TRANSID:OcCowACXsZS0C3VgxNvcDw--.34051S3",
            "Authentication-Results: mx7; spf=pass smtp.mail=yuuminmin@serverdata.c",
            "\tom.cn;",
            "X-Coremail-Antispam: 1Uf129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7v73",
            "\tVFW2AGmfu7bjvjm3AaLaJ3UbIYCTnIWIevJa73UjIFyTuYvjxUff-BDUUUU",
            "",
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_002_NextPart174447020822_=----\"",
            "",
            "Content-Type: text/plain;",
            "\tcharset=\"us-ascii\"",
            "Content-Transfer-Encoding: base64",
            "",
            "Content-Type: text/html;",
            "\tcharset=\"us-ascii\"",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "Content-Type: application/octet-stream;",
            "\tname=\"zaicao.txt\"",
            "Content-Transfer-Encoding: base64",
            "Content-Disposition: attachment;",
            "\tfilename=\"zaicao.txt\"",
            "",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 4);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        dbg!(body0_str);
        assert!(body0_str.contains(
            "ZGFtb2d1eWFuemhpDQpjaGFuZ2hlbHVvcml5dWFuDQoNCg0KDQp5dWV5YW55YW5AaGFvaGFuZGF0\r\n"
        ));
        assert!(body0_str.contains("YS5jb20uY24NCg==\r\n"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        dbg!(body1_str);
        assert!(body1_str.contains(
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n"
        ));
        assert!(body1_str.contains("..com.cn</span></div>=0A</body></html>")); // 最后的\r\n不属于body

        let body2 = &bodies_guard[2];
        let body2_str = std::str::from_utf8(body2).unwrap();
        dbg!(body2_str);
        assert!(body2_str == "\r\n");

        let body3 = &bodies_guard[3];
        let body3_str = std::str::from_utf8(body3).unwrap();
        dbg!(body3_str);
        assert!(body3_str.contains(
            "44CK6I+c5qC56LCt44CLLS3lmrzlvpfoj5zmoLnvvIznmb7kuovlj6/lgZrvvIENCuaWh+eroOWB\r\n"
        ));
        assert!(body3_str.contains(
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
    }
}
