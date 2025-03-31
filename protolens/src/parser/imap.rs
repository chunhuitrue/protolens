use crate::MailCallbacks;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::header;
use crate::multi_body;
use crate::packet::*;
use imap_proto::{parse_follow_rsp_fetch, parse_rsp_fetch};
use nom::{
    IResult,
    bytes::complete::{tag, take_while1},
    character::complete::{char, digit1, space1},
    combinator::map_res,
    sequence::{delimited, tuple},
};
use std::ffi::c_void;
use std::marker::PhantomData;

use crate::CbBody;
use crate::CbBodyEvt;
use crate::CbClt;
use crate::CbHeader;

pub struct ImapParser<T, P>
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

impl<T, P> ImapParser<T, P>
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
        cb_mail: MailCallbacks,
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

            let (is_append, mail_size) = append(line);
            if is_append && append_ok(stm).await? {
                imap_mail(stm, mail_size, &cb_mail, cb_ctx).await?;

                // command = tag SP (command-any / command-auth / command-nonauth /
                //           command-select) CRLF
                let (byte, _seq) = stm.readn(2).await?;
                if byte != b"\r\n" {
                    return Err(());
                }
            }
        }
    }

    async fn s2c_parser_inner(
        stream: *const PktStrm<T, P>,
        cb: MailCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.readline_str().await?;

            let tail_seq = seq + line.len() as u32;
            if let Some(fetch_ret) = parse_rsp_fetch(line) {
                dbg!("rsp fetch", line);
                if let Some(data) = fetch_ret.data() {
                    quoted_body(data, tail_seq - data.len() as u32, &cb, cb_ctx)?;
                } else {
                    let size = fetch_ret.literal_size();
                    let header = fetch_ret.is_header();
                    Self::handle_fetch_ret(stm, size, header, &cb, cb_ctx).await?;
                }
            } else if let Some(fetch_ret) = parse_follow_rsp_fetch(line) {
                dbg!("follow rsp fetch", line);
                if let Some(data) = fetch_ret.data() {
                    quoted_body(data, tail_seq - data.len() as u32, &cb, cb_ctx)?;
                } else {
                    let size = fetch_ret.literal_size();
                    let header = fetch_ret.is_header();
                    Self::handle_fetch_ret(stm, size, header, &cb, cb_ctx).await?;
                }
            }

            let (byte, _seq) = stm.readn(1).await?;
            if byte == b")" {
                return Ok(());
            }
        }
    }

    async fn handle_fetch_ret(
        stm: &mut PktStrm<T, P>,
        size: Option<usize>,
        header: bool,
        cb: &MailCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        if size.is_none() {
            return Ok(());
        }
        let literal_size = size.unwrap();

        if header {
            fetch_header(stm, cb, cb_ctx).await?;
            return Ok(());
        }

        size_body(stm, literal_size, cb, cb_ctx).await?;
        Ok(())
    }
}

impl<T, P> Parser for ImapParser<T, P>
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
        let cb_mail = MailCallbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
        };

        Some(Box::pin(Self::c2s_parser_inner(
            stream,
            cb_mail,
            self.cb_clt.clone(),
            cb_ctx,
        )))
    }

    fn s2c_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        let cb_mail = MailCallbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
        };

        Some(Box::pin(Self::s2c_parser_inner(stream, cb_mail, cb_ctx)))
    }
}

pub(crate) struct ImapFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for ImapFactory<T, P>
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
        let mut parser = Box::new(ImapParser::new());
        parser.cb_header = prolens.cb_imap_header.clone();
        parser.cb_body_start = prolens.cb_imap_body_start.clone();
        parser.cb_body = prolens.cb_imap_body.clone();
        parser.cb_body_stop = prolens.cb_imap_body_stop.clone();
        parser.cb_clt = prolens.cb_imap_clt.clone();
        parser
    }
}

async fn imap_mail<T, P>(
    stm: &mut PktStrm<T, P>,
    mail_size: usize,
    cb: &MailCallbacks,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let start_size = stm.get_read_size();
    let boundary = header(stm, cb.header.as_ref(), cb_ctx).await?;
    if let Some(bdry) = boundary {
        multi_body(
            stm,
            &bdry,
            cb.header.as_ref(),
            cb.body_start.as_ref(),
            cb.body.as_ref(),
            cb.body_stop.as_ref(),
            cb_ctx,
        )
        .await?;
        imap_epilogue(stm, mail_size, start_size).await?;
    } else {
        let head_size = stm.get_read_size() - start_size;
        let body_size = mail_size - head_size;
        size_body(stm, body_size, cb, cb_ctx).await?;
    }
    dbg!("imap_mail end");
    Ok(())
}

async fn size_body<T, P>(
    stm: &mut PktStrm<T, P>,
    size: usize,
    cb: &MailCallbacks,
    cb_ctx: *mut c_void,
) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let mut remain_size = size;

    dbg!("size_body start");
    if let Some(cb) = &cb.body_start {
        cb.borrow_mut()(cb_ctx);
    }
    while remain_size > 0 {
        let (bytes, seq) = stm.read(remain_size).await?;
        remain_size -= bytes.len();

        if let Some(cb) = &cb.body {
            cb.borrow_mut()(bytes, seq, cb_ctx);
        }
    }
    if let Some(cb) = &cb.body_stop {
        cb.borrow_mut()(cb_ctx);
    }
    dbg!("size_body end");
    Ok(true)
}

fn quoted_body(data: &[u8], seq: u32, cb: &MailCallbacks, cb_ctx: *mut c_void) -> Result<(), ()> {
    if let Some(cb) = &cb.body_start {
        cb.borrow_mut()(cb_ctx);
    }
    if let Some(cb) = &cb.body {
        cb.borrow_mut()(data, seq, cb_ctx);
    }
    if let Some(cb) = &cb.body_stop {
        cb.borrow_mut()(cb_ctx);
    }
    Ok(())
}

async fn imap_epilogue<T, P>(
    stm: &mut PktStrm<T, P>,
    mail_size: usize,
    start_size: usize,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let remain_size = mail_size.saturating_sub(stm.get_read_size() - start_size);
    dbg!(remain_size);
    if remain_size != 0 {
        stm.readn(remain_size).await?;
    }
    Ok(())
}

fn append(input: &str) -> (bool, usize) {
    // 解析命令ID（一个或多个非空白字符）
    fn command_id(input: &str) -> IResult<&str, &str> {
        take_while1(|c: char| !c.is_whitespace())(input)
    }

    // 解析APPEND命令
    fn append_command(input: &str) -> IResult<&str, &str> {
        tag("APPEND")(input)
    }

    // 解析大小信息 {数字}
    fn size_info(input: &str) -> IResult<&str, usize> {
        delimited(
            char('{'),
            map_res(digit1, |s: &str| s.parse::<usize>()),
            char('}'),
        )(input)
    }

    // 尝试从字符串末尾解析大小信息
    fn extract_size(input: &str) -> Option<usize> {
        let trimmed = input.trim_end();
        if !trimmed.ends_with('}') {
            return None;
        }

        // 从右向左查找 '{'
        if let Some(start_pos) = trimmed.rfind('{') {
            let size_part = &trimmed[start_pos..];
            if let Ok((_, size)) = size_info(size_part) {
                return Some(size);
            }
        }
        None
    }

    // 组合解析器：命令ID + 空格 + APPEND
    fn is_append_command(input: &str) -> bool {
        // dbg!(input);
        tuple((command_id, space1, append_command))(input).is_ok()
    }

    // 判断是否是APPEND命令并提取大小
    let is_append = is_append_command(input);
    let size = if is_append {
        extract_size(input).unwrap_or(0)
    } else {
        0
    };

    (is_append, size)
}

// server应答append有可能是出错。如果是这种情况，那么append的后续内容就不是邮件而是其他的命令
// 判断是否是邮件头，如果是邮件头说明是邮件内容
async fn append_ok<T, P>(stm: &mut PktStrm<T, P>) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let line = stm.peekline_str().await?;
    Ok(line.contains(':'))
}

async fn fetch_header<T, P>(
    stm: &mut PktStrm<T, P>,
    cb: &MailCallbacks,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, seq) = stm.readline_str().await?;

        if let Some(cb) = &cb.header {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
        }

        if line == "\r\n" {
            return Ok(());
        }
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
    fn test_append() {
        // 测试有效的APPEND命令
        assert_eq!(
            append("C59 APPEND \"Drafts\" (\\Seen) \"26-Jul-2022 17:49:09 +0800\" {2142}"),
            (true, 2142)
        );
        assert_eq!(append("A01 APPEND INBOX {310}"), (true, 310));
        assert_eq!(append("tag1 APPEND mailbox (\\Seen) {2048}"), (true, 2048));
        assert_eq!(
            append(
                "longtagname123 APPEND \"My Mailbox\" (\\Draft \\Seen) \"01-Jan-2023 12:00:00 +0000\" {1024}"
            ),
            (true, 1024)
        );

        // 测试无效的命令或格式错误
        assert_eq!(append("B append inbox {100}"), (false, 0)); // 小写命令
        assert_eq!(append("C59 STORE 1:* +FLAGS (\\Seen)"), (false, 0)); // 不是APPEND命令
        assert_eq!(append("A02 SELECT INBOX"), (false, 0)); // 不是APPEND命令
        assert_eq!(append("tag1 APPEND mailbox (\\Seen)"), (true, 0)); // 没有大小信息
        assert_eq!(append("tag1 APPEND mailbox {abc}"), (true, 0)); // 大小格式错误
        assert_eq!(append("APPEND mailbox {100}"), (false, 0)); // 缺少命令ID
        assert_eq!(append("tag"), (false, 0)); // 不完整的命令
        assert_eq!(append(""), (false, 0)); // 空字符串
    }

    #[test]
    fn test_imap_size_body() {
        let lines = [
            "C59 APPEND \"Drafts\" \"26-Jul-2022 17:49:09 +0800\" {72}\r\n",
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "\r\n",
            "mail body line.\r\n",
            "\r\n",
        ];

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

        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);
        protolens.set_cb_imap_clt(clt_callback);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Imap);
            pkt.set_direction(PktDirection::Client2Server);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let expected_headers = ["From: sender@example.com", "To: recipient@example.com", ""];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 1);

        let body = &bodies_guard[0];
        let body_str = std::str::from_utf8(body).unwrap();
        dbg!(body_str);
        assert!(body_str == "mail body line.\r\n");
    }

    #[test]
    fn test_imap_append_pcap() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/imap_append.pcap");
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

        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);
        protolens.set_cb_imap_clt(clt_callback);

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
            pkt.set_l7_proto(L7Proto::Imap);
            if pkt.header.borrow().as_ref().unwrap().dport() == IMAP_PORT {
                pkt.set_direction(PktDirection::Client2Server);
            } else {
                pkt.set_direction(PktDirection::Server2Client);
            }

            protolens.run_task(&mut task, pkt);
        }

        let expected_headers = [
            "X-CUID: 7F07679F-B77A-44FA-92A6-BC0C7833DD78",
            "Date: Tue, 26 Jul 2022 17:49:08 +0800",
            "From: \"sender123@serverdata.com\" <sender123@serverdata.com>",
            "To: sender123 <sender123@serverdata.com.cn>",
            "Subject: test imap",
            "X-Priority: 3",
            "X-GUID: 7F07679F-B77A-44FA-92A6-BC0C7833DD78",
            "X-Has-Attach: no",
            "X-Mailer: Ffffail 3.4.22.121[cn]",
            "Mime-Version: 1.0",
            "Message-ID: <202207261749087393300@serverdata.com>",
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_001_NextPart376676228212_=----\"",
            "",
            "Content-Type: text/plain;",
            "\tcharset=\"GB2312\"",
            "Content-Transfer-Encoding: base64",
            "",
            "Content-Type: text/html;",
            "\tcharset=\"GB2312\"",
            "Content-Transfer-Encoding: quoted-printable",
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
        // dbg!(body0_str);
        assert!(body0_str.contains(
            "DQq63LbguavLvtTnvs2/qsq81NrG5Mv7tdi3vb+q0dC3otbQ0MTBy6Gjuty24Lmry77U577Nv6rK\r\n"
        ));
        assert!(body0_str.contains("aHVuaHVpQGhhb2hhbmRhdGEuY29tDQo=\r\n"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        // dbg!(body1_str);
        assert!(body1_str.contains(
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n"
        ));
        assert!(body1_str.contains("rdata.com</div></div></span></div>=0A</body></html>")); // 最后的\r\n不属于body

        let clt_guard = captured_clt.borrow();
        assert_eq!(clt_guard.len(), 33);

        assert_eq!(
            std::str::from_utf8(&clt_guard[14]).unwrap(),
            "C59 APPEND \"Drafts\" (\\Seen) \"26-Jul-2022 17:49:09 +0800\" {2142}"
        );
        assert_eq!(std::str::from_utf8(&clt_guard[32]).unwrap(), "C77 NOOP");
    }

    #[test]
    fn test_imap_pcap() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/imap.pcap");
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

        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);
        protolens.set_cb_imap_clt(clt_callback);

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
            pkt.set_l7_proto(L7Proto::Imap);
            if pkt.header.borrow().as_ref().unwrap().dport() == IMAP_PORT {
                pkt.set_direction(PktDirection::Client2Server);
            } else {
                pkt.set_direction(PktDirection::Server2Client);
            }

            protolens.run_task(&mut task, pkt);
        }
    }
}
