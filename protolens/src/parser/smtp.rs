use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::ReadRet;
use crate::packet::*;
use nom::{
    IResult, Offset,
    bytes::complete::{tag, take_till, take_while},
};
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait SmtpCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> SmtpCbFn for F {}

pub trait SmtpCbEvtFn: FnMut(*mut c_void) {}
impl<F: FnMut(*mut c_void)> SmtpCbEvtFn for F {}

pub(crate) type CbUser = Rc<RefCell<dyn SmtpCbFn + 'static>>;
pub(crate) type CbPass = Rc<RefCell<dyn SmtpCbFn + 'static>>;
pub(crate) type CbMailFrom = Rc<RefCell<dyn SmtpCbFn + 'static>>;
pub(crate) type CbRcpt = Rc<RefCell<dyn SmtpCbFn + 'static>>;
pub(crate) type CbHeader = Rc<RefCell<dyn SmtpCbFn + 'static>>;
pub(crate) type CbBodyEvt = Rc<RefCell<dyn SmtpCbEvtFn + 'static>>;
pub(crate) type CbBody = Rc<RefCell<dyn SmtpCbFn + 'static>>;

pub(crate) struct SmtpCallbacks {
    pub(crate) user: Option<CbUser>,
    pub(crate) pass: Option<CbPass>,
    pub(crate) mailfrom: Option<CbMailFrom>,
    pub(crate) rcpt: Option<CbRcpt>,
    pub(crate) header: Option<CbHeader>,
    pub(crate) body_start: Option<CbBodyEvt>,
    pub(crate) body: Option<CbBody>,
    pub(crate) body_stop: Option<CbBodyEvt>,
}

pub struct SmtpParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_user: Option<CbUser>,
    pub(crate) cb_pass: Option<CbPass>,
    pub(crate) cb_mailfrom: Option<CbMailFrom>,
    pub(crate) cb_rcpt: Option<CbRcpt>,
    pub(crate) cb_header: Option<CbHeader>,
    pub(crate) cb_body_start: Option<CbBodyEvt>,
    pub(crate) cb_body: Option<CbBody>,
    pub(crate) cb_body_stop: Option<CbBodyEvt>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> SmtpParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_user: None,
            cb_pass: None,
            cb_mailfrom: None,
            cb_rcpt: None,
            cb_header: None,
            cb_body_start: None,
            cb_body: None,
            cb_body_stop: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        stream: *const PktStrm<T, P>,
        cb: SmtpCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        // 验证起始HELO/EHLO命令, 如果命令不正确，则返回错误，无法继续解析
        let (helo_line, _) = stm.readline().await?;
        if !starts_with_helo(helo_line) {
            return Err(());
        }

        let (line, seq) = stm.read_clean_line_str().await?;
        if line.eq_ignore_ascii_case("STARTTLS") {
            return Err(());
        } else if line.eq_ignore_ascii_case("AUTH LOGIN") {
            // user
            let (user, seq) = stm.read_clean_line().await?;
            if let Some(cb) = cb.user {
                cb.borrow_mut()(user, seq, cb_ctx);
            }

            // pass
            let (pass, seq) = stm.read_clean_line().await?;
            if let Some(cb) = cb.pass.clone() {
                cb.borrow_mut()(pass, seq, cb_ctx);
            }

            // mail from。暂且不管有没有扩展参数
            let (from, seq) = stm.read_clean_line_str().await?;

            if let Ok((_, (mail, offset))) = mail_from(from) {
                let mailfrom_seq = seq + offset as u32;
                if let Some(cb) = cb.mailfrom.clone() {
                    cb.borrow_mut()(mail.as_bytes(), mailfrom_seq, cb_ctx);
                }
            }
        } else if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            // 没有auth，直接到mail from的情况
            if let Ok((_, (mail, offset))) = mail_from(line) {
                let mailfrom_seq = seq + offset as u32;
                if let Some(cb) = cb.mailfrom.clone() {
                    cb.borrow_mut()(mail.as_bytes(), mailfrom_seq, cb_ctx);
                }
            }
        } else {
            // 其他auth情况。AUTH PLAIN，AUTH CRAM-MD5
            // 清空mail from之前或有或无的命令
            read_to_from(stm, cb.mailfrom, cb_ctx).await?;
        }

        multi_rcpt_to(stm, cb.rcpt, cb_ctx).await?;

        let boundary = header(stm, cb.header.clone(), cb_ctx).await?;

        if let Some(bdry) = boundary {
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
        } else {
            body(stm, cb.body_start, cb.body, cb.body_stop, cb_ctx).await?;
        }

        Ok(())
    }
}

impl<T, P> Default for SmtpParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Parser for SmtpParser<T, P>
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
        let cb = SmtpCallbacks {
            user: self.cb_user.clone(),
            pass: self.cb_pass.clone(),
            mailfrom: self.cb_mailfrom.clone(),
            rcpt: self.cb_rcpt.clone(),
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
        };

        Some(Box::pin(Self::c2s_parser_inner(stream, cb, cb_ctx)))
    }
}

pub(crate) struct SmtpFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for SmtpFactory<T, P>
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
        let mut parser = Box::new(SmtpParser::new());
        parser.cb_user = prolens.cb_smtp_user.clone();
        parser.cb_pass = prolens.cb_smtp_pass.clone();
        parser.cb_mailfrom = prolens.cb_smtp_mailfrom.clone();
        parser.cb_rcpt = prolens.cb_smtp_rcpt.clone();
        parser.cb_header = prolens.cb_smtp_header.clone();
        parser.cb_body_start = prolens.cb_smtp_body_start.clone();
        parser.cb_body = prolens.cb_smtp_body.clone();
        parser.cb_body_stop = prolens.cb_smtp_body_stop.clone();
        parser
    }
}

async fn read_to_from<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_mailfrom: Option<CbMailFrom>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            if let Ok((_, (mail, offset))) = mail_from(line) {
                let mailfrom_seq = seq + offset as u32;
                if let Some(cb) = cb_mailfrom.clone() {
                    cb.borrow_mut()(mail.as_bytes(), mailfrom_seq, cb_ctx);
                }
            }

            return Ok(());
        }
    }
}

async fn multi_rcpt_to<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_rcpt: Option<CbRcpt>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        if line.eq_ignore_ascii_case("DATA") {
            break;
        }

        if let Ok((_, (mail, offset))) = rcpt_to(line) {
            let mail_seq = seq + offset as u32;
            if let Some(cb) = cb_rcpt.clone() {
                cb.borrow_mut()(mail.as_bytes(), mail_seq, cb_ctx);
            }
        } else {
            return Err(());
        }
    }
    Ok(())
}

async fn body<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_ctx: *mut c_void,
) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("body start");
    if let Some(cb) = cb_body_start.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        if line == (".") {
            break;
        }

        dbg!(line);
        if let Some(cb) = cb_body.clone() {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
        }
    }
    if let Some(cb) = cb_body_stop.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    dbg!("body end");
    Ok(true)
}

async fn multi_body<T, P>(
    stm: &mut PktStrm<T, P>,
    bdry: &str,
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    preamble(stm, bdry).await?;
    loop {
        if let Some(new_bdry) = header(stm, cb_header.clone(), cb_ctx).await? {
            Box::pin(multi_body(
                stm,
                &new_bdry,
                cb_header.clone(),
                cb_body_start.clone(),
                cb_body.clone(),
                cb_body_stop.clone(),
                cb_ctx,
            ))
            .await?;
        }

        mime_body(
            stm,
            bdry,
            cb_body_start.clone(),
            cb_body.clone(),
            cb_body_stop.clone(),
            cb_ctx,
        )
        .await?;

        let (byte, _seq) = stm.readn(2).await?;
        if byte.starts_with(b"--") {
            dbg!("muti_body end");
            break;
        } else if byte.starts_with(b"\r\n") {
            continue;
        } else {
            return Err(());
        }
    }
    Ok(())
}

async fn preamble<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    mime_body(stm, bdry, None, None, None, std::ptr::null_mut()).await?;

    let (byte, _seq) = stm.readn(2).await?;
    if byte.starts_with(b"\r\n") {
        Ok(())
    } else {
        Err(())
    }
}

async fn header<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_header: Option<CbHeader>,
    cb_ctx: *mut c_void,
) -> Result<Option<String>, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let mut cont_type = false;
    let mut boundary = String::new();

    dbg!("header. start");
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        // 空行也回调。调用者知道header结束
        if let Some(cb) = cb_header.clone() {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
        }
        dbg!(line);

        if line.is_empty() {
            let ret_bdry = if boundary.is_empty() {
                None
            } else {
                Some(boundary)
            };
            dbg!("header. end");
            return Ok(ret_bdry);
        }

        // content-type ext
        // 放在content-type前面是因为。只有content-type结束之后才能作这个判断。
        // 放在前面，cont_type 肯定为false
        if cont_type && boundary.is_empty() {
            match content_type_ext(line) {
                Ok((_, bdry)) => {
                    boundary = bdry.to_string();
                }
                Err(_err) => {}
            }
        }
        // content-type
        match content_type(line) {
            Ok((_input, Some(bdry))) => {
                cont_type = true;
                boundary = bdry.to_string();
            }
            Ok((_input, None)) => {
                cont_type = true;
            }
            Err(_err) => {}
        }
    }
}

async fn mime_body<T, P>(
    stm: &mut PktStrm<T, P>,
    bdry: &str,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("mime body start");
    if let Some(cb) = cb_body_start.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    loop {
        let (ret, content, seq) = stm.read_mime_octet(bdry).await?;
        dbg!(std::str::from_utf8(content).unwrap_or(""));
        if let Some(cb) = cb_body.clone() {
            cb.borrow_mut()(content, seq, cb_ctx);
        }

        if ret == ReadRet::DashBdry {
            break;
        }
    }
    if let Some(cb) = cb_body_stop.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    dbg!("mime body end");
    Ok(())
}

// MAIL FROM: <user12345@example123.com> SIZE=10557
fn mail_from(input: &str) -> IResult<&str, (&str, usize)> {
    let original_input = input;
    let (input, _) = tag("MAIL FROM: <")(input)?;

    let start_pos = original_input.offset(input);
    let (input, mail) = take_while(|c| c != '>')(input)?;

    Ok((input, (mail, start_pos)))
}

// RCPT TO: <user12345@example123.com>
fn rcpt_to(input: &str) -> IResult<&str, (&str, usize)> {
    let original_input = input;
    let (input, _) = tag("RCPT TO: <")(input)?;

    let start_pos = original_input.offset(input);
    let (input, mail) = take_while(|c| c != '>')(input)?;
    let (input, _) = tag(">")(input)?;

    Ok((input, (mail, start_pos)))
}

#[allow(dead_code)]
fn subject(input: &str) -> IResult<&str, (&str, usize)> {
    let original_input = input;
    let (input, _) = tag("Subject: ")(input)?;

    let start_pos = original_input.offset(input);
    let (input, subject) = take_till(|c| c == '\r')(input)?;

    Ok((input, (subject, start_pos)))
}

// 如果是content type 且带boundary: Content-Type: multipart/mixed; boundary="abc123"
// 返回: (input, some(bdry))
// 如果是content type 不带bdry: Content-Type: multipart/mixed;
// 返回: (input, None)
// 如果不是content type 返回err
fn content_type(input: &str) -> IResult<&str, Option<&str>> {
    let (input, _) = tag("Content-Type: ")(input)?;

    if let Some(start) = input.find("boundary=\"") {
        let input = &input[start..];

        let (input, _) = tag("boundary=\"")(input)?;
        let (input, bdry) = take_till(|c| c == '"')(input)?;
        let (input, _) = tag("\"")(input)?;

        Ok((input, Some(bdry)))
    } else {
        Ok((input, None))
    }
}

// \tboundary="----=_001_NextPart572182624333_=----"
fn content_type_ext(input: &str) -> IResult<&str, &str> {
    let (input, _) = tag("\tboundary=\"")(input)?;
    let (input, bdry) = take_till(|c| c == '"')(input)?;
    Ok((input, bdry))
}

fn starts_with_helo(input: &[u8]) -> bool {
    if input.len() < 4 {
        return false;
    }
    let upper = input[..4].to_ascii_uppercase();
    upper == b"EHLO" || upper == b"HELO"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_mail_from_with_size() {
        // 用例1: 带size
        let input = "MAIL FROM: <user12345@example123.com> SIZE=10557";
        let result = mail_from(input);

        assert!(result.is_ok());
        let (_, (mail, start)) = result.unwrap();
        assert_eq!(mail, "user12345@example123.com");
        assert_eq!(start, 12);

        // 用例2: 不带size
        let input = "MAIL FROM: <user12345@example123.com>";
        let result = mail_from(input);

        assert!(result.is_ok());
        let (_, (mail, start)) = result.unwrap();
        assert_eq!(mail, "user12345@example123.com");
        assert_eq!(start, 12);
    }

    #[test]
    fn test_rcpt_to() {
        let input = "RCPT TO: <user12345@example123.com>";
        let result = rcpt_to(input);

        assert!(result.is_ok());
        let (_, (mail, start)) = result.unwrap();

        assert_eq!(mail, "user12345@example123.com");
        assert_eq!(start, 10); // "RCPT TO: <" 的长度
        println!("邮件地址: '{}' (起始位置: {})", mail, start);
    }

    #[test]
    fn test_subject() {
        let input = "Subject: Test email subject\r\n";
        let result = subject(input);

        assert!(result.is_ok());
        let (_, (subject, start)) = result.unwrap();

        assert_eq!(subject, "Test email subject");
        assert_eq!(start, 9); // "Subject: " 的长度
        println!("主题: '{}' (起始位置: {})", subject, start);
    }

    #[test]
    fn test_content_type() {
        // 测试用例1: 包含 boundary 的正常情况
        let input = "Content-Type: multipart/mixed; charset=utf-8; boundary=\"abc123\"";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("abc123"));
        assert!(rest.is_empty());

        // 测试用例2: 包含 boundary 且后面还有其他参数
        let input = "Content-Type: multipart/mixed; boundary=\"xyz789\"; other=value";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("xyz789"));
        assert_eq!(rest, "; other=value");

        // 测试用例3: 不包含 boundary 的情况
        let input = "Content-Type: text/plain; charset=utf-8";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, None);
        assert_eq!(rest, "text/plain; charset=utf-8");

        // 测试用例4: 特殊字符的 boundary
        let input = "Content-Type: multipart/mixed; boundary=\"----=_NextPart_000_0000_01D123456.789ABCDE\"";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("----=_NextPart_000_0000_01D123456.789ABCDE"));
        assert!(rest.is_empty());

        // 测试用例5: 错误格式 - 不是以 Content-Type: 开头
        let input = "Wrong-Type: multipart/mixed; boundary=\"abc123\"";
        let result = content_type(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_starts_with_ehlo() {
        // 正确的情况
        assert!(starts_with_helo(b"EHLO example.com"));
        assert!(starts_with_helo(b"ehlo example.com"));
        assert!(starts_with_helo(b"EhLo example.com"));
        assert!(starts_with_helo(b"HELO example.com"));
        assert!(starts_with_helo(b"HelO example.com"));

        // 错误的情况
        assert!(!starts_with_helo(b"Hel example.com"));
        assert!(!starts_with_helo(b"EHL"));
        assert!(!starts_with_helo(b""));
        assert!(!starts_with_helo(b"MAIL FROM:"));
    }

    #[test]
    fn test_smtp_helo_ehlo() {
        let seq1 = 1;
        let wrong_command = *b"HELO tes\r\n";
        let pkt1 = build_pkt_payload(seq1, &wrong_command);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Smtp);

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        let result = protolens.run_task(&mut task, pkt1);
        assert_eq!(result, None, "none is ok");

        let seq2 = 1;
        let correct_commands = *b"EHLO tes\r\n";
        let pkt2 = build_pkt_payload(seq2, &correct_commands);
        let _ = pkt2.decode();

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        let result = protolens.run_task(&mut task, pkt2);
        assert_eq!(result, None, "none is ok");
    }

    #[test]
    fn test_smtp_auth_login() {
        let cmd = [
            "EHLO client.example.com\r\n",
            "AUTH LOGIN\r\n",
            "c2VuZGVyQGV4YW1wbGUuY29t\r\n", // user
            "cGFzc3dvcmQxMjM=\r\n",         // pass
            "MAIL FROM: <sender@example.com>\r\n",
            "RCPT TO: <recipient1@example.com>\r\n",
            "RCPT TO: <recipient2@example.com>\r\n",
            "DATA\r\n",
        ];
        let header = [
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "\r\n",
        ];
        let body = ["mail body line1.\r\n", "mail body line2.\r\n"];
        let quit = [".\r\n", "QUIT\r\n"];
        let lines = cmd
            .iter()
            .chain(header.iter())
            .chain(body.iter())
            .chain(quit.iter());

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_user_seq = Rc::new(RefCell::new(0u32));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_pass_seq = Rc::new(RefCell::new(0u32));
        let captured_mailfrom = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_rcpt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_body = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_raw = Rc::new(RefCell::new(Vec::<u8>::new()));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *user_guard = user.to_vec();
                *seq_guard = seq;
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
            }
        };

        let mailfrom_callback = {
            let mailfrom_clone = captured_mailfrom.clone();
            move |mailfrom: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut mailfrom_guard = mailfrom_clone.borrow_mut();
                *mailfrom_guard = mailfrom.to_vec();
            }
        };

        let rcpt_callback = {
            let rcpt_clone = captured_rcpt.clone();
            move |rcpt: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut rcpt_guard = rcpt_clone.borrow_mut();
                rcpt_guard.push(rcpt.to_vec());
            }
        };

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

        let body_callback = {
            let body_clone = captured_body.clone();
            move |body: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut body_guard = body_clone.borrow_mut();
                body_guard.push(body.to_vec());
            }
        };

        let raw_callback = {
            let raw_clone = captured_raw.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *const c_void| {
                let mut raw_guard = raw_clone.borrow_mut();
                raw_guard.extend_from_slice(data);
            }
        };

        let mut task = protolens.new_task();

        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_task_c2s(&mut task, raw_callback);

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Smtp);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        assert_eq!(
            std::str::from_utf8(&captured_user.borrow()).unwrap(),
            "c2VuZGVyQGV4YW1wbGUuY29t"
        );
        assert_eq!(
            std::str::from_utf8(&captured_pass.borrow()).unwrap(),
            "cGFzc3dvcmQxMjM="
        );
        assert!(*captured_user_seq.borrow() > 1000);
        assert!(*captured_pass_seq.borrow() > 1000);
        assert_eq!(
            std::str::from_utf8(&captured_mailfrom.borrow()).unwrap(),
            "sender@example.com"
        );

        let rcpt_guard = captured_rcpt.borrow();
        assert_eq!(rcpt_guard.len(), 2);
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[0]).unwrap(),
            "recipient1@example.com"
        );
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[1]).unwrap(),
            "recipient2@example.com"
        );

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
            assert_eq!(
                std::str::from_utf8(&body_guard[idx]).unwrap(),
                expected.trim_end_matches("\r\n")
            );
        }

        let raw_guard = captured_raw.borrow();
        let cmd_bytes_len: usize = cmd.iter().map(|line| line.len()).sum();
        let header_bytes_len: usize = header.iter().map(|line| line.len()).sum();
        let body_bytes_len: usize = body.iter().map(|line| line.len()).sum();
        assert_eq!(
            raw_guard.len(),
            cmd_bytes_len + header_bytes_len + body_bytes_len + 3 // .\r\n三个字节
        );

        let raw_str = std::str::from_utf8(&raw_guard).unwrap();
        assert!(raw_str.contains("EHLO client.example.com\r\n"));
        assert!(raw_str.contains("Subject: Email Subject\r\n"));
        assert!(raw_str.contains("mail body line2.\r\n"));
        assert!(raw_str.contains(".\r\n"));
        assert!(!raw_str.contains("QUIT\r\n")); // 解码器没有读取后续内容
    }

    #[test]
    fn test_smtp_no_auth() {
        let lines = [
            "EHLO client.example.com\r\n",
            "MAIL FROM: <sender@example.com>\r\n",
            "RCPT TO: <recipient1@example.com>\r\n",
            "RCPT TO: <recipient2@example.com>\r\n",
            "DATA\r\n",
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "\r\n",
            "mail body line1.\r\n",
            "mail body line2.\r\n",
            ".\r\n",
            "QUIT\r\n",
        ];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_user_seq = Rc::new(RefCell::new(0u32));
        let captured_pass_seq = Rc::new(RefCell::new(0u32));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_mailfrom = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_rcpt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *user_guard = user.to_vec();
                *seq_guard = seq;
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
            }
        };

        let mailfrom_callback = {
            let mailfrom_clone = captured_mailfrom.clone();
            move |mailfrom: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut mailfrom_guard = mailfrom_clone.borrow_mut();
                *mailfrom_guard = mailfrom.to_vec();
            }
        };

        let rcpt_callback = {
            let rcpt_clone = captured_rcpt.clone();
            move |rcpt: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut rcpt_guard = rcpt_clone.borrow_mut();
                rcpt_guard.push(rcpt.to_vec());
            }
        };

        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);

        let mut task = protolens.new_task();

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Smtp);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        // 没有auth，应该为空
        assert_eq!(std::str::from_utf8(&captured_user.borrow()).unwrap(), "");
        assert_eq!(std::str::from_utf8(&captured_pass.borrow()).unwrap(), "");
        assert!(*captured_user_seq.borrow() == 0);
        assert!(*captured_pass_seq.borrow() == 0);
        assert_eq!(
            std::str::from_utf8(&captured_mailfrom.borrow()).unwrap(),
            "sender@example.com"
        );

        let rcpt_guard = captured_rcpt.borrow();
        assert_eq!(rcpt_guard.len(), 2);
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[0]).unwrap(),
            "recipient1@example.com"
        );
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[1]).unwrap(),
            "recipient2@example.com"
        );
    }

    #[test]
    fn test_smtp_tls() {
        let lines = [
            "EHLO client.example.com\r\n",
            "STARTTLS\r\n",
            "AUTH LOGIN\r\n",
            "c2VuZGVyQGV4YW1wbGUuY29t\r\n", // user
            "cGFzc3dvcmQxMjM=\r\n",         // pass
        ];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_user_seq = Rc::new(RefCell::new(0u32));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_pass_seq = Rc::new(RefCell::new(0u32));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *user_guard = user.to_vec();
                *seq_guard = seq;
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
            }
        };

        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);

        let mut task = protolens.new_task();

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Smtp);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        assert_eq!(std::str::from_utf8(&captured_user.borrow()).unwrap(), "");
        assert_eq!(std::str::from_utf8(&captured_pass.borrow()).unwrap(), "");
        assert!(*captured_user_seq.borrow() == 0);
        assert!(*captured_pass_seq.borrow() == 0);
    }

    #[test]
    fn test_smtp_mime_no_preamble_header_end() {
        let lines = [
            "EHLO client.example.com\r\n",
            "MAIL FROM: <sender@example.com>\r\n",
            "RCPT TO: <recipient1@example.com>\r\n",
            "DATA\r\n",
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            "------=_001_NextPart572182624333_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n", // 只有head,跟close bdry
            "------=_001_NextPart572182624333_=------\r\n",
            "This is the epilogue 1.\r\n",
            "This is the epilogue 2.\r\n",
            ".\r\n",
            "QUIT\r\n",
            "\r\n",
        ];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                dbg!(std::str::from_utf8(header).unwrap_or(""));
                if header.is_empty() {
                    dbg!("header cb. header end");
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let mut task = protolens.new_task();

        protolens.set_cb_smtp_header(header_callback);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Smtp);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        let expected_headers = [
            // 主题header
            "From: sender@example.com",
            "To: recipient@example.com",
            "Subject: Email Subject",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000",
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"",
            "",
            // 第二个 part 的 header
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
    }

    #[test]
    fn test_smtp_mime_flat() {
        let lines = [
            "EHLO client.example.com\r\n",
            "MAIL FROM: <sender@example.com>\r\n",
            "RCPT TO: <recipient1@example.com>\r\n",
            "RCPT TO: <recipient2@example.com>\r\n",
            "DATA\r\n",
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            "This is the preamble1.\r\n",
            "This is the preamble2.\r\n",
            "\r\n",
            "------=_001_NextPart572182624333_=----\r\n",
            "\r\n", // head 为空
            "aGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRk\r\n",
            "ZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVs\r\n",
            "\r\n",
            "------=_001_NextPart572182624333_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n", // 只有head
            "------=_001_NextPart572182624333_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<html> line 1\r\n",
            "line 2</html>\r\n", // 最后的\r\n不属于body
            "------=_001_NextPart572182624333_=------\r\n",
            "This is the epilogue 1.\r\n",
            "This is the epilogue 2.\r\n",
            ".\r\n",
            "QUIT\r\n",
            "\r\n",
        ];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_user_seq = Rc::new(RefCell::new(0u32));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_pass_seq = Rc::new(RefCell::new(0u32));
        let captured_mailfrom = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_rcpt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_raw = Rc::new(RefCell::new(Vec::<u8>::new()));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *user_guard = user.to_vec();
                *seq_guard = seq;
                println!(
                    "User callback: {}, seq: {}",
                    std::str::from_utf8(user).unwrap_or("invalid utf8"),
                    seq
                );
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
                println!(
                    "Pass callback: {}, seq: {}",
                    std::str::from_utf8(pass).unwrap_or("invalid utf8"),
                    seq
                );
            }
        };

        let mailfrom_callback = {
            let mailfrom_clone = captured_mailfrom.clone();
            move |mailfrom: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut mailfrom_guard = mailfrom_clone.borrow_mut();
                *mailfrom_guard = mailfrom.to_vec();
            }
        };

        let rcpt_callback = {
            let rcpt_clone = captured_rcpt.clone();
            move |rcpt: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut rcpt_guard = rcpt_clone.borrow_mut();
                rcpt_guard.push(rcpt.to_vec());
            }
        };

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                dbg!(std::str::from_utf8(header).unwrap_or("err"));
                if header.is_empty() {
                    dbg!("header cb. header end");
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

        let raw_callback = {
            let raw_clone = captured_raw.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *const c_void| {
                let mut raw_guard = raw_clone.borrow_mut();
                raw_guard.extend_from_slice(data);
            }
        };

        let mut task = protolens.new_task();

        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);
        protolens.set_cb_task_c2s(&mut task, raw_callback);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Smtp);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        assert_eq!(std::str::from_utf8(&captured_user.borrow()).unwrap(), "");
        assert_eq!(std::str::from_utf8(&captured_pass.borrow()).unwrap(), "");
        assert!(*captured_user_seq.borrow() == 0);
        assert!(*captured_pass_seq.borrow() == 0);
        assert_eq!(
            std::str::from_utf8(&captured_mailfrom.borrow()).unwrap(),
            "sender@example.com"
        );

        let rcpt_guard = captured_rcpt.borrow();
        assert_eq!(rcpt_guard.len(), 2);
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[0]).unwrap(),
            "recipient1@example.com"
        );
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[1]).unwrap(),
            "recipient2@example.com"
        );

        let expected_headers = [
            // 主题header
            "From: sender@example.com",
            "To: recipient@example.com",
            "Subject: Email Subject",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000",
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"",
            "",
            // 第一个 part 的 header,空
            "",
            // 第二个 part 的 header
            "Content-Type: text/html;",
            "\tcharset=\"GB2312\"",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            // 第三个 part 的 header
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
        assert_eq!(bodies_guard.len(), 3);

        let body1 = &bodies_guard[0];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains(
            "aGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRk\r\n"
        ));
        assert!(body1_str.contains(
            "ZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVs\r\n"
        ));

        let body2 = &bodies_guard[1];
        assert!(body2.is_empty());

        let body3 = &bodies_guard[2];
        let body3_str = std::str::from_utf8(body3).unwrap();
        assert!(body3_str.contains("<html>"));
        assert!(body3_str.contains("line 1"));
        assert!(body3_str.contains("line 2</html>"));

        let raw_guard = captured_raw.borrow();
        let lines_bytes_len: usize = lines.iter().map(|line| line.len()).sum();
        dbg!(std::str::from_utf8(&raw_guard).unwrap());
        assert_eq!(raw_guard.len(), lines_bytes_len - 63); // 减去后续没读的\r\n 到最后

        let raw_str = std::str::from_utf8(&raw_guard).unwrap();
        assert!(raw_str.contains("EHLO client.example.com\r\n"));
        assert!(raw_str.contains("Content-Type: text/html;\r\n"));
        assert!(raw_str.contains("<html> line 1\r\n"));
        assert!(!raw_str.contains("This is the epilogue 2.\r\n"));
        assert!(!raw_str.contains("QUIT\r\n")); // 解码器没有读取后续内容
    }

    #[test]
    fn test_smtp_mime_nest() {
        let lines = [
            "EHLO client.example.com\r\n",
            "MAIL FROM: <sender@example.com>\r\n",
            "RCPT TO: <recipient1@example.com>\r\n",
            "DATA\r\n",
            "From: \"sender\" <sender@example.in>\r\n",
            "To: <recipient1@example.com>\r\n",
            "Subject: SMTP\r\n",
            "Date: Mon, 5 Oct 2009 11:36:07 +0530\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"----=_NextPart_000_0004_01CA45B0.095693F0\"\r\n",
            "\r\n",
            "This is the preamble.\r\n",
            "\r\n",
            "------=_NextPart_000_0004_01CA45B0.095693F0\r\n", // 外层
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_NextPart_001_0005_01CA45B0.095693F0\"\r\n",
            "\r\n",
            "\r\n", // 这个\r\n不属于body。此中情况body为空
            "------=_NextPart_001_0005_01CA45B0.095693F0\r\n", // 内层
            "Content-Type: text/plain;\r\n",
            "Content-Transfer-Encoding: 7bit\r\n",
            "\r\n",
            "I send u smtp pcap file \r\n",
            "Find the attachment\r\n",
            "\r\n",
            "\r\n",
            "------=_NextPart_001_0005_01CA45B0.095693F0\r\n", // 内层
            "Content-Type: text/html;\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<html\r\n",
            "</html>\r\n",
            "\r\n",                                              // 不属于body
            "------=_NextPart_001_0005_01CA45B0.095693F0--\r\n", // 内层结束
            "\r\n",                                              // bdry的开始
            "------=_NextPart_000_0004_01CA45B0.095693F0\r\n",   // 外层
            "Content-Type: text/plain;\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "* Profiling support\r\n",
            "* Lots of bugfixes\r\n",
            "\r\n",
            "------=_NextPart_000_0004_01CA45B0.095693F0--\r\n", // 外层结束
            "\r\n",
            ".\r\n",
            "QUIT\r\n",
        ];
        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_user_seq = Rc::new(RefCell::new(0u32));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_pass_seq = Rc::new(RefCell::new(0u32));
        let captured_mailfrom = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_rcpt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *user_guard = user.to_vec();
                *seq_guard = seq;
                println!(
                    "User callback: {}, seq: {}",
                    std::str::from_utf8(user).unwrap_or("invalid utf8"),
                    seq
                );
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
                println!(
                    "Pass callback: {}, seq: {}",
                    std::str::from_utf8(pass).unwrap_or("invalid utf8"),
                    seq
                );
            }
        };

        let mailfrom_callback = {
            let mailfrom_clone = captured_mailfrom.clone();
            move |mailfrom: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut mailfrom_guard = mailfrom_clone.borrow_mut();
                *mailfrom_guard = mailfrom.to_vec();
            }
        };

        let rcpt_callback = {
            let rcpt_clone = captured_rcpt.clone();
            move |rcpt: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut rcpt_guard = rcpt_clone.borrow_mut();
                rcpt_guard.push(rcpt.to_vec());
            }
        };

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

        // 新增：body_stop回调
        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void| {
                // 将当前body添加到bodies列表
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                println!(
                    "Body stop callback triggered, body size: {} bytes, content: {}",
                    body_guard.len(),
                    std::str::from_utf8(&body_guard).unwrap_or("invalid utf8")
                );
            }
        };

        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);

        let mut task = protolens.new_task();

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Smtp);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        assert_eq!(std::str::from_utf8(&captured_user.borrow()).unwrap(), "");
        assert_eq!(std::str::from_utf8(&captured_pass.borrow()).unwrap(), "");
        assert!(*captured_user_seq.borrow() == 0);
        assert!(*captured_pass_seq.borrow() == 0);
        assert_eq!(
            std::str::from_utf8(&captured_mailfrom.borrow()).unwrap(),
            "sender@example.com"
        );

        let rcpt_guard = captured_rcpt.borrow();
        assert_eq!(rcpt_guard.len(), 1);
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[0]).unwrap(),
            "recipient1@example.com"
        );

        let expected_headers = [
            // 主邮件头
            "From: \"sender\" <sender@example.in>",
            "To: <recipient1@example.com>",
            "Subject: SMTP",
            "Date: Mon, 5 Oct 2009 11:36:07 +0530",
            "MIME-Version: 1.0",
            "Content-Type: multipart/mixed;",
            "\tboundary=\"----=_NextPart_000_0004_01CA45B0.095693F0\"",
            "",
            // 第一个嵌套部分的头
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_NextPart_001_0005_01CA45B0.095693F0\"",
            "",
            // 第二个嵌套部分的头
            "Content-Type: text/plain;",
            "Content-Transfer-Encoding: 7bit",
            "",
            // 第三个嵌套部分的头
            "Content-Type: text/html;",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            // 最后一个部分的头
            "Content-Type: text/plain;",
            "Content-Transfer-Encoding: quoted-printable",
            "",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 4);

        // 第一个是嵌套内层第一个
        let body1 = &bodies_guard[0];
        dbg!(body1.len(), std::str::from_utf8(body1).unwrap());
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains("I send u smtp pcap file"));
        assert!(body1_str.contains("Find the attachment"));

        // 第二个是内层第二个。内层结束
        let body2 = &bodies_guard[1];
        let body2_str = std::str::from_utf8(body2).unwrap();
        assert!(body2_str.contains("<html"));
        assert!(body2_str.contains("</html>\r\n"));

        // 第三个是外层第一个
        let body3 = &bodies_guard[2];
        dbg!(body3.len(), std::str::from_utf8(body3).unwrap());
        assert!(body3.is_empty() || body3.len() < 5);

        // 第四个是外层第二个。外层结束
        let bodyr = &bodies_guard[3];
        let body4_str = std::str::from_utf8(bodyr).unwrap();
        assert!(body4_str.contains("* Profiling support\r\n"));
        assert!(body4_str.contains("* Lots of bugfixes\r\n"));
    }

    #[test]
    fn test_smtp2_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/smtp.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_user_seq = Rc::new(RefCell::new(0u32));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_pass_seq = Rc::new(RefCell::new(0u32));
        let captured_mailfrom = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_rcpt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *user_guard = user.to_vec();
                *seq_guard = seq;
                dbg!("in callback", std::str::from_utf8(user).unwrap(), seq);
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                let mut seq_guard = seq_clone.borrow_mut();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
                dbg!("pass callback", std::str::from_utf8(pass).unwrap(), seq);
            }
        };

        let mailfrom_callback = {
            let mailfrom_clone = captured_mailfrom.clone();
            move |mailfrom: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut mailfrom_guard = mailfrom_clone.borrow_mut();
                *mailfrom_guard = mailfrom.to_vec();
            }
        };

        let rcpt_callback = {
            let rcpt_clone = captured_rcpt.clone();
            move |rcpt: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut rcpt_guard = rcpt_clone.borrow_mut();
                rcpt_guard.push(rcpt.to_vec());
            }
        };

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

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);

        let mut task = protolens.new_task();

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
            pkt.set_l7_proto(L7Proto::Smtp);

            if pkt.header.borrow().as_ref().unwrap().dport() == SMTP_PORT_NET {
                protolens.run_task(&mut task, pkt);
            }
        }

        assert_eq!(
            captured_user.borrow().as_slice(),
            b"dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t"
        );
        assert_eq!(*captured_user_seq.borrow(), 1341098188);
        assert_eq!(captured_pass.borrow().as_slice(), b"MTIzNDU2Nzg=");
        assert_eq!(*captured_pass_seq.borrow(), 1341098222);
        assert_eq!(
            std::str::from_utf8(&captured_mailfrom.borrow()).unwrap(),
            "user12345@example123.com"
        );

        let rcpt_guard = captured_rcpt.borrow();
        assert_eq!(rcpt_guard.len(), 1);
        assert_eq!(
            std::str::from_utf8(&rcpt_guard[0]).unwrap(),
            "user12345@example123.com"
        );

        let expected_headers = [
            "Date: Mon, 27 Jun 2022 17:01:55 +0800",
            "From: \"user12345@example123.com\" <user12345@example123.com>",
            "To: =?GB2312?B?wO60urvU?= <user12345@example123.com>",
            "Subject: biaoti",
            "X-Priority: 3",
            "X-Has-Attach: no",
            "X-Mailer: Foxmail 7.2.19.158[cn]",
            "Mime-Version: 1.0",
            "Message-ID: <202206271701548584972@example123.com>",
            "Content-Type: multipart/alternative;",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"",
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

        let body1 = &bodies_guard[0];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains(
            "aGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRk\r\n"
        ));
        assert!(body1_str.contains(
            "ZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRk\r\n"
        ));
        assert!(body1_str.contains("DQo=\r\n"));

        let body2 = &bodies_guard[1];
        let body2_str = std::str::from_utf8(body2).unwrap();
        assert!(body2_str.contains(
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n"
        ));
        assert!(body2_str.contains(
            "nd-color: transparent;\">hello dddddddddddddddddd</span><span style=3D\"line=\r\n"
        ));
        assert!(body2_str.contains("y></html>")); // 最后的\r\n不属于body
    }
}
