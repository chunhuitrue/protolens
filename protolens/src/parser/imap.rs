use crate::Callbacks;
use crate::CbBody;
use crate::CbBodyEvt;
use crate::CbClt;
use crate::CbHeader;
use crate::CbSrv;
use crate::DirConfirmFn;
use crate::Direction;
use crate::IMAP_PORT;
use crate::MimeBodyParams;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::TransferEncoding;
use crate::dash_bdry;
use crate::header;
use crate::mime_body;
use crate::packet::*;
use crate::preamble;
use imap_proto::{
    AttributeValue2, BodyStructParser2, ContentEncoding, follow_rsp_fetch, rsp_fetch,
};
use nom::{
    IResult,
    bytes::complete::{tag, take_while1},
    character::complete::{char, digit1, space1},
    combinator::map_res,
    sequence::{delimited, tuple},
};
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct ImapParser<T>
where
    T: Packet,
{
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_clt: Option<CbClt>,
    cb_srv: Option<CbSrv>,
    _phantom_t: PhantomData<T>,
}

impl<T> ImapParser<T>
where
    T: Packet,
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
        }
    }

    async fn c2s_parser_inner(
        stream: *const PktStrm<T>,
        cb_imap: Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T>);
        }

        loop {
            let (line, seq) = stm.read_clean_line_str().await?;

            if let Some(ref cb) = cb_imap.clt {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            let (is_append, mail_size) = append(line);
            if is_append && append_ok(stm).await? {
                Self::append_mail(stm, mail_size, &cb_imap, cb_ctx).await?;

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
        stream: *const PktStrm<T>,
        cb_imap: Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T>);
        }
        let mut bds_parser = None;

        loop {
            let (line, seq) = stm.readline_str().await?;

            if let Some(ref cb) = cb_imap.srv {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            let fetch_ret = rsp_fetch(line).or_else(|| follow_rsp_fetch(line));
            if let Some(fetch_ret) = fetch_ret {
                if let Some(data) = fetch_ret.data() {
                    let tail_seq = seq + line.len() as u32;
                    Self::quoted_body(data, tail_seq - data.len() as u32, &cb_imap, cb_ctx)?;
                } else {
                    let size = fetch_ret.literal_size();
                    let header = fetch_ret.is_header();
                    let body_section = fetch_ret.body_section_parts();

                    let body_structure = fetch_ret.attrs.into_iter().find_map(|attr| {
                        if let AttributeValue2::BodyStructure(body) = attr {
                            Some(body.into_owned())
                        } else {
                            None
                        }
                    });
                    if let Some(body_structure) = body_structure {
                        bds_parser = Some(BodyStructParser2::new(body_structure));
                    }
                    let cnt_encoding =
                        if let (Some(parser), Some(section)) = (&bds_parser, &body_section) {
                            parser.get_transfer_encoding(section)
                        } else {
                            None
                        };
                    let te = cnt_encoding.and_then(|enc| match enc {
                        ContentEncoding::SevenBit => Some(TransferEncoding::Bit7),
                        ContentEncoding::EightBit => Some(TransferEncoding::Bit8),
                        ContentEncoding::Binary => Some(TransferEncoding::Binary),
                        ContentEncoding::Base64 => Some(TransferEncoding::Base64),
                        ContentEncoding::QuotedPrintable => Some(TransferEncoding::QuotedPrintable),
                        _ => None,
                    });

                    Self::handle_fetch_ret(stm, size, header, te, &cb_imap, cb_ctx).await?;
                }
            }
        }
    }

    async fn append_mail(
        stm: &mut PktStrm<T>,
        mail_size: usize,
        cb_imap: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let start_size = stm.get_read_size();
        let (boundary, te) = header(stm, cb_imap.header.as_ref(), cb_ctx, Direction::C2s).await?;
        if let Some(bdry) = boundary {
            Self::multi_body(stm, mail_size, start_size, &bdry, &bdry, cb_imap, cb_ctx).await?;
        } else {
            let head_size = stm.get_read_size() - start_size;
            let body_size = mail_size - head_size;
            Self::size_body(stm, body_size, te, cb_imap, cb_ctx).await?;
        }
        Ok(())
    }

    async fn multi_body(
        stm: &mut PktStrm<T>,
        mail_size: usize,
        start_size: usize,
        out_bdry: &str,
        bdry: &str,
        cb: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        preamble(stm, bdry).await?;
        loop {
            let (boundary, te) = header(stm, cb.header.as_ref(), cb_ctx, cb.dir).await?;

            if let Some(new_bdry) = boundary {
                Box::pin(Self::multi_body(
                    stm, mail_size, start_size, out_bdry, &new_bdry, cb, cb_ctx,
                ))
                .await?;
                continue;
            } else {
                let params = MimeBodyParams {
                    te,
                    bdry,
                    cb_body_start: cb.body_start.as_ref(),
                    cb_body: cb.body.as_ref(),
                    cb_body_stop: cb.body_stop.as_ref(),
                    cb_ctx,
                    dir: cb.dir,
                };
                mime_body(stm, params).await?;
            }

            let (byte, _seq) = stm.readn(2).await?;
            if byte == b"--" {
                break;
            } else if byte == b"\r\n" {
                continue;
            } else {
                return Err(());
            }
        }
        Self::epilogue(stm, out_bdry, mail_size, start_size).await?;
        Ok(())
    }

    async fn size_body(
        stm: &mut PktStrm<T>,
        size: usize,
        te: Option<TransferEncoding>,
        cb_imap: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<bool, ()> {
        let mut remain_size = size;

        if let Some(cb) = &cb_imap.body_start {
            cb.borrow_mut()(cb_ctx, cb_imap.dir);
        }
        while remain_size > 0 {
            let (bytes, seq) = stm.read(remain_size).await?;
            remain_size -= bytes.len();

            if let Some(cb) = &cb_imap.body {
                cb.borrow_mut()(bytes, seq, cb_ctx, cb_imap.dir, te.clone());
            }
        }
        if let Some(cb) = &cb_imap.body_stop {
            cb.borrow_mut()(cb_ctx, cb_imap.dir);
        }
        Ok(true)
    }

    fn quoted_body(
        data: &[u8],
        seq: u32,
        cb_imap: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        if let Some(cb) = &cb_imap.body_start {
            cb.borrow_mut()(cb_ctx, cb_imap.dir);
        }
        if let Some(cb) = &cb_imap.body {
            cb.borrow_mut()(data, seq, cb_ctx, cb_imap.dir, None);
        }
        if let Some(cb) = &cb_imap.body_stop {
            cb.borrow_mut()(cb_ctx, cb_imap.dir);
        }
        Ok(())
    }

    async fn handle_fetch_ret(
        stm: &mut PktStrm<T>,
        size: Option<usize>,
        header: bool,
        te: Option<TransferEncoding>,
        cb_imap: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        if size.is_none() {
            return Ok(());
        }
        let literal_size = size.unwrap();

        if header {
            Self::fetch_header(stm, cb_imap, cb_ctx).await?;
        } else {
            Self::size_body(stm, literal_size, te, cb_imap, cb_ctx).await?;
        }

        let (byte, _seq) = stm.readn(1).await?;
        if byte == b")" {
            return Ok(());
        }
        Ok(())
    }

    async fn fetch_header(
        stm: &mut PktStrm<T>,
        cb_imap: &Callbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        loop {
            let (line, seq) = stm.readline_str().await?;

            if let Some(cb) = &cb_imap.header {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx, cb_imap.dir);
            }

            if line == "\r\n" {
                return Ok(());
            }
        }
    }

    async fn epilogue(
        stm: &mut PktStrm<T>,
        bdry: &str,
        mail_size: usize,
        start_size: usize,
    ) -> Result<(), ()> {
        loop {
            let remain_size = mail_size.saturating_sub(stm.get_read_size() - start_size);
            if remain_size < bdry.len() && remain_size != 0 {
                stm.readn(remain_size).await?;
                break;
            }

            let (line, _seq) = stm.readline_str().await?;
            if dash_bdry(line, bdry) {
                break;
            }
        }
        Ok(())
    }
}

impl<T> Parser for ImapParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn dir_confirm(&self) -> DirConfirmFn<Self::T> {
        |c2s_strm, s2c_strm, c2s_port, s2c_port| {
            let stm_c2s;
            let stm_s2c;
            unsafe {
                stm_c2s = &mut *(c2s_strm as *mut PktStrm<T>);
                stm_s2c = &mut *(s2c_strm as *mut PktStrm<T>);
            }

            if s2c_port == IMAP_PORT {
                return Some(true);
            } else if c2s_port == IMAP_PORT {
                return Some(false);
            }

            let payload_c2s = stm_c2s.peek_payload();
            let payload_s2c = stm_s2c.peek_payload();

            if payload_c2s.is_err() && payload_s2c.is_err() {
                return None;
            }

            if let Ok(payload) = payload_s2c {
                if payload.len() >= 5 && (payload.starts_with(b"* OK ")) {
                    return Some(true);
                }

                if payload.len() >= 10 && clt_cmd(unsafe { std::str::from_utf8_unchecked(payload) })
                {
                    return Some(false);
                }
            }

            if let Ok(payload) = payload_c2s {
                if payload.len() >= 5 && (payload.starts_with(b"* OK ")) {
                    return Some(false);
                }
            }

            Some(true)
        }
    }

    fn c2s_parser(&self, stream: *const PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb_imap = Callbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
            clt: self.cb_clt.clone(),
            srv: None,
            dir: Direction::C2s,
        };
        Some(Box::pin(Self::c2s_parser_inner(stream, cb_imap, cb_ctx)))
    }

    fn s2c_parser(&self, stream: *const PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb_imap = Callbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
            clt: None,
            srv: self.cb_srv.clone(),
            dir: Direction::S2c,
        };
        Some(Box::pin(Self::s2c_parser_inner(stream, cb_imap, cb_ctx)))
    }
}

pub(crate) struct ImapFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for ImapFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(ImapParser::new());
        parser.cb_header = prolens.cb_imap_header.clone();
        parser.cb_body_start = prolens.cb_imap_body_start.clone();
        parser.cb_body = prolens.cb_imap_body.clone();
        parser.cb_body_stop = prolens.cb_imap_body_stop.clone();
        parser.cb_clt = prolens.cb_imap_clt.clone();
        parser.cb_srv = prolens.cb_imap_srv.clone();
        parser
    }
}

fn append(input: &str) -> (bool, usize) {
    fn command_id(input: &str) -> IResult<&str, &str> {
        take_while1(|c: char| !c.is_whitespace())(input)
    }

    fn append_command(input: &str) -> IResult<&str, &str> {
        tag("APPEND")(input)
    }

    fn size_info(input: &str) -> IResult<&str, usize> {
        delimited(
            char('{'),
            map_res(digit1, |s: &str| s.parse::<usize>()),
            char('}'),
        )(input)
    }

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

    fn is_append_command(input: &str) -> bool {
        tuple((command_id, space1, append_command))(input).is_ok()
    }

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
async fn append_ok<T>(stm: &mut PktStrm<T>) -> Result<bool, ()>
where
    T: Packet,
{
    let line = stm.peekline_str().await?;
    Ok(line.contains(':'))
}

fn clt_cmd(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }

    if !input.chars().next().unwrap().is_alphanumeric() {
        return false;
    }

    if let Some(space_pos) = input.chars().take(10).position(|c| c == ' ') {
        let tag = &input[..space_pos];
        let rest = &input[space_pos + 1..];
        !tag.is_empty()
            && tag
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '+' || c == '-')
            && !rest.is_empty()
            && rest.chars().next().unwrap().is_uppercase()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TransferEncoding, test_utils::*};
    use std::cell::RefCell;
    use std::env;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_is_imap_command() {
        assert!(clt_cmd("a001 LOGIN user pass"));
        assert!(clt_cmd("001 LOGIN user pass"));
        assert!(clt_cmd("tag1 FETCH 1:* ALL"));
        assert!(clt_cmd("A123.456 SELECT INBOX"));
        assert!(clt_cmd("B-789 LOGOUT"));

        assert!(!clt_cmd(""));
        assert!(!clt_cmd("LOGIN user pass"));
        assert!(!clt_cmd(" tag FETCH"));
        assert!(!clt_cmd("tag@1 SELECT"));
    }

    #[test]
    fn test_append() {
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
    fn test_imap_s2c() {
        let lines = [
            "* OK IMAP4\r\n",
            "* LIST (\\HasNoChildren) \"/\" INBOX\r\n",
            "* 1 EXISTS\r\n",
        ];

        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                dbg!("in srv callback", std::str::from_utf8(line).unwrap());
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_imap_srv(srv_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Imap);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let clt_guard = captured_srv.borrow();
        assert_eq!(clt_guard.len(), lines.len());
        for (idx, expected) in lines.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&clt_guard[idx]).unwrap(), *expected);
        }
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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                if header.is_empty() {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
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
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
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
                dbg!("in clt callback", std::str::from_utf8(line).unwrap());
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);
        protolens.set_cb_imap_clt(clt_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Imap);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let expected_headers = [
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "\r\n",
        ];

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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::C2s {
                    if header.is_empty() {
                        dbg!("header cb. header end", header);
                    }
                    let mut headers_guard = headers_clone.borrow_mut();
                    headers_guard.push(header.to_vec());
                }
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::C2s {
                    let mut body_guard = current_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                }
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  dir: Direction,
                  _te: Option<TransferEncoding>| {
                if dir == Direction::C2s {
                    let mut body_guard = current_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);
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
                }
            }
        };

        let clt_callback = {
            let clt_clone = captured_clt.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);
        protolens.set_cb_imap_clt(clt_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Imap);

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

        let expected_headers = [
            "X-CUID: 7F07679F-B77A-44FA-92A6-BC0C7833DD78\r\n",
            "Date: Tue, 26 Jul 2022 17:49:08 +0800\r\n",
            "From: \"sender123@serverdata.com\" <sender123@serverdata.com>\r\n",
            "To: sender123 <sender123@serverdata.com.cn>\r\n",
            "Subject: test imap\r\n",
            "X-Priority: 3\r\n",
            "X-GUID: 7F07679F-B77A-44FA-92A6-BC0C7833DD78\r\n",
            "X-Has-Attach: no\r\n",
            "X-Mailer: Ffffail 3.4.22.121[cn]\r\n",
            "Mime-Version: 1.0\r\n",
            "Message-ID: <202207261749087393300@serverdata.com>\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart376676228212_=----\"\r\n",
            "\r\n",
            "Content-Type: text/plain;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
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
        assert!(body0_str.contains(
            "DQq63LbguavLvtTnvs2/qsq81NrG5Mv7tdi3vb+q0dC3otbQ0MTBy6Gjuty24Lmry77U577Nv6rK\r\n"
        ));
        assert!(body0_str.contains("aHVuaHVpQGhhb2hhbmRhdGEuY29tDQo=\r\n"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
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
    fn test_imap_append_nest() {
        let lines = [
            "C59 APPEND \"Drafts\" (\\Seen) \"26-Jul-2022 17:49:09 +0800\" {1616}\r\n",
            "Date: Tue, 13 Apr 2021 11:10:43 +0800\r\n",
            "From: \"yuuminmin@serverdata.com.cn\" <yuuminmin@serverdata.com.cn>\r\n",
            "To: xiaomingming <xiaomingming@aaa.com>\r\n",
            "Subject: yishengyishiyishuangren\r\n",
            "Mime-Version: 1.0\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"----=_001_NextPart500622418632_=----\"\r\n",
            "Authentication-Results: mx7; spf=pass smtp.mail=yuuminmin@serverdata.c\r\n",
            "\tom.cn;\r\n",
            "\r\n",
            "This is a multi-part message in MIME format.\r\n",
            "\r\n",
            "------=_001_NextPart500622418632_=----\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_002_NextPart174447020822_=----\"\r\n",
            "\r\n",
            "\r\n", //按照定义这里是body，body又是一个multi body，那么这里是preamble，因为有\r\n
            "------=_002_NextPart174447020822_=----\r\n",
            "Content-Type: text/plain;\r\n",
            "\tcharset=\"us-ascii\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "ZGFtb2d1eWFuemhpDQpjaGFuZ2hlbHVvcml5dWFuDQoNCg0KDQp5dWV5YW55YW5AaGFvaGFuZGF0\r\n",
            "YS5jb20uY24NCg==\r\n",
            "\r\n",
            "------=_002_NextPart174447020822_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"us-ascii\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n",
            "t=3Dus-ascii\"><style>body { line-height: 1.5; }body { font-size: 14px; fon=\r\n",
            "..com.cn</span></div>=0A</body></html>\r\n",
            "------=_002_NextPart174447020822_=------\r\n",
            "\r\n", //上面的close bdry 结尾有\r\n。所以这里是epilogue
            "------=_001_NextPart500622418632_=----\r\n",
            "Content-Type: application/octet-stream;\r\n",
            "\tname=\"zaicao.txt\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Disposition: attachment;\r\n",
            "\tfilename=\"zaicao.txt\"\r\n",
            "\r\n",
            "44CK6I+c5qC56LCt44CLLS3lmrzlvpfoj5zmoLnvvIznmb7kuovlj6/lgZrvvIENCuaWh+eroOWB\r\n",
            "muWIsOaegeWkhO+8jOaXoOacieS7luWlh++8jOWPquaYr+aBsOWlve+8mw0K5Lq65ZOB5YGa5Yiw\r\n",
            "heWQm+WtkOS6i+adpeiAjOW/g+Wni+eOsO+8jOS6i+WOu+iAjOW/g+maj+epuuOAgg0KDQoNCg==\r\n",
            "\r\n",
            "------=_001_NextPart500622418632_=------\r\n",
            "\r\n", //上面的close bdry 结尾有\r\n。所以这里是epilogue
        ];

        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                if header.is_empty() {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
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
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                println!(
                    "Body stop callback triggered, body size: {} bytes",
                    body_guard.len()
                );
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Imap);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let expected_headers = [
            "Date: Tue, 13 Apr 2021 11:10:43 +0800\r\n",
            "From: \"yuuminmin@serverdata.com.cn\" <yuuminmin@serverdata.com.cn>\r\n",
            "To: xiaomingming <xiaomingming@aaa.com>\r\n",
            "Subject: yishengyishiyishuangren\r\n",
            "Mime-Version: 1.0\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"----=_001_NextPart500622418632_=----\"\r\n",
            "Authentication-Results: mx7; spf=pass smtp.mail=yuuminmin@serverdata.c\r\n",
            "\tom.cn;\r\n",
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
        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_tes = Rc::new(RefCell::new(Vec::<Option<TransferEncoding>>::new()));
        let current_te = Rc::new(RefCell::new(None::<TransferEncoding>));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(header).unwrap());
                if dir == Direction::S2c {
                    if header == b"\r\n" {
                        dbg!("header cb. header end");
                    }
                    let mut headers_guard = headers_clone.borrow_mut();
                    headers_guard.push(header.to_vec());
                }
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            let current_te_clone = current_te.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut body_guard = current_body_clone.borrow_mut();
                    *body_guard = Vec::new();

                    let mut te_guard = current_te_clone.borrow_mut();
                    *te_guard = None;
                }
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            let current_te_clone = current_te.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  dir: Direction,
                  te: Option<TransferEncoding>| {
                if dir == Direction::S2c {
                    let mut body_guard = current_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);

                    if te.is_some() {
                        let mut te_guard = current_te_clone.borrow_mut();
                        *te_guard = te;
                    }
                }
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            let current_te_clone = current_te.clone();
            let tes_clone = captured_tes.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let body_guard = current_body_clone.borrow();
                    let mut bodies_guard = bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());

                    let te_guard = current_te_clone.borrow();
                    let mut tes_guard = tes_clone.borrow_mut();
                    tes_guard.push(te_guard.clone());
                }
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
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_imap_header(header_callback);
        protolens.set_cb_imap_body_start(body_start_callback);
        protolens.set_cb_imap_body(body_callback);
        protolens.set_cb_imap_body_stop(body_stop_callback);
        protolens.set_cb_imap_clt(clt_callback);
        protolens.set_cb_imap_srv(srv_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Imap);

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

        let expected_headers = [
            "From: sendmail <sendmail@test.act>\r\n",
            "Subject: =?utf-8?B?6L2s5Y+ROiDmlofmnKznsbvmoLfmnKz=?=\r\n",
            "Date: Sat, 2 Jul 2022 21:29:15 +0800\r\n",
            "Importance: normal\r\n",
            "X-Priority: 3\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"_4805B00C-044E-4966-B0DA-ED690B999A97_\"\r\n",
            "\r\n",
            "Return-Path: <sendmail@test.act>\r\n",
            "Received: from [IPv6:::ffff:192.168.0.110] ([223.102.87.186])\r\n",
            "\tby mail.test.act (8.14.7/8.14.7) with ESMTP id 262DUNZr039188\r\n",
            "\tfor <sendmail@test.act>; Sat, 2 Jul 2022 21:30:23 +0800\r\n",
            "Message-Id: <202207021330.262DUNZr039188@mail.test.act>\r\n",
            "MIME-Version: 1.0\r\n",
            "To: sendmail <sendmail@test.act>\r\n",
            "From: sendmail <sendmail@test.act>\r\n",
            "Subject: =?utf-8?B?6L2s5Y+ROiDmlofmnKznsbvmoLfmnKz=?=\r\n",
            "Date: Sat, 2 Jul 2022 21:29:15 +0800\r\n",
            "Importance: normal\r\n",
            "X-Priority: 3\r\n",
            "References: <202207022059022721750@test.act>\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"_4805B00C-044E-4966-B0DA-ED690B999A97_\"\r\n",
            "\r\n",
            "From: sendmail <sendmail@test.act>\r\n",
            "Subject: =?utf-8?B?6L2s5Y+ROiDmlofmnKznsbvmoLfmnKz=?=\r\n",
            "Date: Sat, 2 Jul 2022 21:28:18 +0800\r\n",
            "Importance: normal\r\n",
            "X-Priority: 3\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"_26A40801-CA53-432D-92AD-3D34157EAF72_\"\r\n",
            "\r\n",
            "MIME-Version: 1.0\r\n",
            "To: sendmail <sendmail@test.act>\r\n",
            "From: sendmail <sendmail@test.act>\r\n",
            "Subject: =?utf-8?B?6L2s5Y+ROiDmlofmnKznsbvmoLfmnKz=?=\r\n",
            "Date: Sat, 2 Jul 2022 21:28:18 +0800\r\n",
            "Importance: normal\r\n",
            "X-Priority: 3\r\n",
            "In-Reply-To: <202207021322.262DMr0f038643@mail.test.act>\r\n",
            "References: <202207022059022721750@test.act>\r\n",
            " <202207021322.262DMr0f038643@mail.test.act>\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"_26A40801-CA53-432D-92AD-3D34157EAF72_\"\r\n",
            "\r\n",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 10);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert!(body0_str.contains(
            "<html xmlns:v=3D\"urn:schemas-microsoft-com:vml\" xmlns:o=3D\"urn:schemas-micr=\r\n"
        ));
        assert!(body0_str.contains(
            ">=E6=96=87=E6=9C=AC=E7=B1=BB=E6=A0=B7=E6=9C=AC</p></div><p class=3DMsoNorm=\r\n"
        ));
        assert!(body0_str.contains("</html>="));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains(
            "iVBORw0KGgoAAAANSUhEUgAAANIAAAABCAYAAACrM/DDAAAAAXNSR0IArs4c6QAAAARnQU1BAACx\r\n"
        ));
        assert!(body1_str.contains(
            "jwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAARSURBVDhPYxgFo2AUUAoYGAADSQABJmPiTQAA\r\n"
        ));

        let body2 = &bodies_guard[2];
        let body2_str = std::str::from_utf8(body2).unwrap();
        assert!(body2_str.contains(
            "5Liq5Lq65aeT5ZCNOuS5oOiCsuWnrA0K55Sf5pelOjIwMDIwMjI1DQrmgKfliKs655S3DQrmsJHm\r\n"
        ));
        assert!(body2_str.contains(
            "jZXkvY06576O5rqQ5Lyv5qC55YWs5Y+4DQrpk7booYzotKbmiLc6NjY2NzY0NFhYWDA3NjQxNg0K\r\n"
        ));
        assert!(body2_str.contains("j7I65bey5amaDQo=\r\n"));

        let body3 = &bodies_guard[3];
        let body3_str = std::str::from_utf8(body3).unwrap();
        assert!(body3_str.contains(
            "iVBORw0KGgoAAAANSUhEUgAAAUcAAADhCAMAAABspYceAAADAFBMVEXy9PbEuKipopelnpKrpJqm\r\n"
        ));
        assert!(body3_str.contains(
            "ng66jOwo/kd8Q9/+l69tr/CjR+MusNJaBetRM6/bkjuuJKkeohoiKWYunNH/DmwIfEyPMOJXrjBg\r\n"
        ));
        assert!(body3_str.contains("DyN5xfEvr0CMOwnVoAYAAAAASUVORK5CYII=\r\n"));

        let body4 = &bodies_guard[4];
        let body4_str = std::str::from_utf8(body4).unwrap();
        assert!(body4_str.contains(
            "UEsDBAoAAAAAAIdO4kAAAAAAAAAAAAAAAAAJAAAAZG9jUHJvcHMvUEsDBBQAAAAIAIdO4kD2HAbf\r\n"
        ));
        assert!(body4_str.contains(
            "MPcnSeienE9M3C2EDl1zt1Bi5bczSUE9ictlK8IWzZsUJRKFOMHSU8/YGGPH6u4SYsX1gAw5E2wk\r\n"
        ));
        assert!(body4_str.contains("bWUvdGhlbWUxLnhtbFBLBQYAAAAAFQAVABkFAACbLAAAAAA=\r\n"));

        let body5 = &bodies_guard[5];
        let body5_str = std::str::from_utf8(body5).unwrap();
        assert!(body5_str.contains(
            "<html xmlns:v=3D\"urn:schemas-microsoft-com:vml\" xmlns:o=3D\"urn:schemas-micr=\r\n"
        ));
        assert!(body5_str.contains(
            "ze:12.0pt;font-family:SimSun'><o:p>&nbsp;</o:p></span></p><div style=3D'mso=\r\n"
        ));
        assert!(body5_str.contains("</html>=\r\n"));

        let body6 = &bodies_guard[6];
        let body6_str = std::str::from_utf8(body6).unwrap();
        assert!(body6_str.contains(
            "iVBORw0KGgoAAAANSUhEUgAAANIAAAABCAYAAACrM/DDAAAAAXNSR0IArs4c6QAAAARnQU1BAACx\r\n"
        ));
        assert!(body6_str.contains(
            "jwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAARSURBVDhPYxgFo2AUUAoYGAADSQABJmPiTQAA\r\n"
        ));
        assert!(body6_str.contains("AABJRU5ErkJggg==\r\n"));

        let body7 = &bodies_guard[7];
        let body7_str = std::str::from_utf8(body7).unwrap();
        assert!(body7_str.contains(
            "5Liq5Lq65aeT5ZCNOuS5oOiCsuWnrA0K55Sf5pelOjIwMDIwMjI1DQrmgKfliKs655S3DQrmsJHm\r\n"
        ));
        assert!(body7_str.contains(
            "jZXkvY06576O5rqQ5Lyv5qC55YWs5Y+4DQrpk7booYzotKbmiLc6NjY2NzY0NFhYWDA3NjQxNg0K\r\n"
        ));
        assert!(body7_str.contains("j7I65bey5amaDQo=\r\n"));

        let body8 = &bodies_guard[8];
        let body8_str = std::str::from_utf8(body8).unwrap();
        assert!(body8_str.contains(
            "iVBORw0KGgoAAAANSUhEUgAAAUcAAADhCAMAAABspYceAAADAFBMVEXy9PbEuKipopelnpKrpJqm\r\n"
        ));
        assert!(body8_str.contains(
            "cA/cXJgZF2foaowp2FFrlMsNkJP6MWo0PkMfP6pOSWEERzX7QwWpZWpK9eUCWqk0XyIt1+vL9ed1\r\n"
        ));
        assert!(body8_str.contains("DyN5xfEvr0CMOwnVoAYAAAAASUVORK5CYII=\r\n"));

        let body9 = &bodies_guard[9];
        let body9_str = std::str::from_utf8(body9).unwrap();
        assert!(body9_str.contains(
            "UEsDBAoAAAAAAIdO4kAAAAAAAAAAAAAAAAAJAAAAZG9jUHJvcHMvUEsDBBQAAAAIAIdO4kD2HAbf\r\n"
        ));
        assert!(body9_str.contains(
            "ABAAAACgKQAAd29yZC9fcmVscy9QSwECFAAUAAAACACHTuJAOQqq9PwAAAA2AwAAHAAAAAAAAAAB\r\n"
        ));
        assert!(body9_str.contains("bWUvdGhlbWUxLnhtbFBLBQYAAAAAFQAVABkFAACbLAAAAAA=\r\n"));

        let clt_guard = captured_clt.borrow();
        assert_eq!(std::str::from_utf8(&clt_guard[0]).unwrap(), "DONE");
        assert_eq!(
            std::str::from_utf8(&clt_guard[3]).unwrap(),
            "A53 SELECT \"INBOX\" (CONDSTORE)"
        );
        assert_eq!(
            std::str::from_utf8(&clt_guard[7]).unwrap(),
            "A57 UID FETCH 55 (RFC822.HEADER BODY.PEEK[1.2] BODY.PEEK[2] BODY.PEEK[3] BODY.PEEK[4] BODY.PEEK[5])"
        );

        let srv_guard = captured_srv.borrow();
        assert_eq!(
            std::str::from_utf8(&srv_guard[0]).unwrap(),
            "* OK Still here\r\n"
        );
        assert_eq!(
            std::str::from_utf8(&srv_guard[6]).unwrap(),
            "A52 OK List completed (0.001 + 0.000 secs).\r\n"
        );
        assert_eq!(
            std::str::from_utf8(&srv_guard[18]).unwrap(),
            "A54 OK Search completed (0.001 + 0.000 secs).\r\n"
        );

        let tes_guard = captured_tes.borrow();
        assert_eq!(tes_guard.len(), 10);

        let expected_tes = [
            Some(TransferEncoding::QuotedPrintable),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::QuotedPrintable),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::Base64),
            Some(TransferEncoding::Base64),
        ];

        for (idx, expected) in expected_tes.iter().enumerate() {
            assert_eq!(tes_guard[idx], *expected);
        }
    }

    // 开始三个包中附带option和pad
    #[test]
    fn test_imap_fetch_pcap() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/imap_fetch.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_clt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let clt_callback = {
            let clt_clone = captured_clt.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_imap_clt(clt_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Imap);

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

        let clt_guard = captured_clt.borrow();
        assert_eq!(std::str::from_utf8(&clt_guard[0]).unwrap(), "1 capability");
    }
}
