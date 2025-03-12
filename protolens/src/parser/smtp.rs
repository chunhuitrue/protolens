use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::packet::*;
use nom::{
    IResult, Offset,
    bytes::complete::{tag, take_till, take_while},
    character::complete::digit1,
    combinator::map_res,
    error::context,
};
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

pub trait SmtpCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> SmtpCbFn for F {}
pub(crate) type CbUser = Rc<RefCell<dyn SmtpCbFn + 'static>>;
pub(crate) type CbPass = Rc<RefCell<dyn SmtpCbFn + 'static>>;

pub struct SmtpParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_user: Option<CbUser>,
    pub(crate) cb_pass: Option<CbPass>,
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
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_user: Option<CbUser>,
        cb_pass: Option<CbPass>,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        // 验证起始HELO/EHLO命令, 如果命令不正确，则返回错误，无法继续解析
        let (helo_line, _) = stm.readline2().await?;
        if !starts_with_helo(helo_line) {
            dbg!("First line is not HELO/EHLO command");
            return Err(());
        }

        let (line, _seq) = stm.read_clean_line_str().await?;
        if line.eq_ignore_ascii_case("STARTTLS") {
            dbg!("STARTTLS。return error。");
            return Err(());
        } else if line.eq_ignore_ascii_case("AUTH LOGIN") {
            // user
            let (user, seq) = stm.read_clean_line().await?;
            if let Some(cb) = cb_user {
                cb.borrow_mut()(user, seq, cb_ctx);
            }

            // pass
            let (pass, seq) = stm.read_clean_line().await?;
            if let Some(cb) = cb_pass.clone() {
                cb.borrow_mut()(pass, seq, cb_ctx);
            }
            dbg!(std::str::from_utf8(pass).expect("need utf8"), seq);

            // mail from。暂且不管有没有扩展参数
            let (_from, _seq) = stm.read_clean_line_str().await?;
            // if let Ok((_, ((mail, offset), size))) = mail_from(from) {
            //     let mail_seq = seq + offset as u32;
            //     dbg!("from", mail, size, mail_seq);
            // } else {
            //     dbg!("from return err");
            //     return Err(());
            // }
        } else if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            // 没有auth，直接到mail from的情况
        } else {
            // 其他auth情况。AUTH PLAIN，AUTH CRAM-MD5
            // 清空mail from之前或有或无的命令
            read_to_from(stm).await?;
        }

        multi_rcpt_to(stm).await?;

        let (_, boundary) = head(stm, "").await?;

        if let Some(bdry) = boundary {
            mime(stm, &bdry).await?;
        } else {
            body(stm).await?;
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
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_user.clone(),
            self.cb_pass.clone(),
            stream,
            cb_ctx,
        )))
    }
}

async fn read_to_from<T, P>(stm: &mut PktStrm<T, P>) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;

        if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            // mail from callback
            return Ok(());
        }
    }
}

async fn multi_rcpt_to<T, P>(stm: &mut PktStrm<T, P>) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;

        if line.eq_ignore_ascii_case("DATA") {
            break;
        }

        if let Ok((_, (_mail, _offset))) = rcpt_to(line) {
            // let mail_seq = seq + offset as u32;
        } else {
            return Err(());
        }
    }
    Ok(())
}

async fn body<T, P>(stm: &mut PktStrm<T, P>) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;
        dbg!(line);

        if line == (".") {
            break;
        }
    }
    Ok(true)
}

async fn mime<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("mime start");
    preamble(stm, bdry).await?;
    loop {
        match head(stm, bdry).await? {
            (HeadRet::Head, bdry) => {
                if let Some(bdry) = bdry {
                    Box::pin(mime(stm, &bdry)).await?;
                }
            }
            (HeadRet::Bdry, bdry) => {
                if let Some(bdry) = bdry {
                    Box::pin(mime(stm, &bdry)).await?;
                }
                continue;
            }
            (HeadRet::CloseBdry, bdry) => {
                if let Some(bdry) = bdry {
                    Box::pin(mime(stm, &bdry)).await?;
                }
                break;
            }
        }
        if mime_body(stm, bdry).await? {
            dbg!("body break");
            break;
        }
    }
    dbg!("mime end");
    Ok(())
}

async fn preamble<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("preamble start.");
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;
        dbg!(line);

        if line.starts_with("--")
            && line.len() >= bdry.len() + 2
            && &line[2..2 + bdry.len()] == bdry
        {
            dbg!("preamble end.");
            break;
        }
    }
    Ok(())
}

#[derive(Debug)]
enum HeadRet {
    Head,      // 常规head结束
    Bdry,      // 只有head，没空行.读到boundary
    CloseBdry, // 只有head，没空行.读到结束boundary
}

async fn head<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(HeadRet, Option<String>), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let mut cont_type = false;
    let mut boundary = String::new();

    dbg!("head start.");
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;
        dbg!(line);

        if line.is_empty() {
            let ret_bdry = if boundary.is_empty() {
                dbg!("head end. none");
                None
            } else {
                dbg!("head end. bdry");
                Some(boundary)
            };
            return Ok((HeadRet::Head, ret_bdry));
        }
        if line.starts_with("--")
            && line.len() >= bdry.len() + 2
            && &line[2..2 + bdry.len()] == bdry
        {
            let ret_bdry = if boundary.is_empty() {
                None
            } else {
                Some(boundary)
            };
            if line.len() >= bdry.len() + 4 && &line[2 + bdry.len()..2 + bdry.len() + 2] == "--" {
                dbg!("head end. close bdry");
                return Ok((HeadRet::CloseBdry, ret_bdry));
            }
            dbg!("head end. bdry");
            return Ok((HeadRet::Bdry, ret_bdry));
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

// 返回true。表示最后的boundary
// 返回false。表示--boundary
async fn mime_body<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("body start.");
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;
        dbg!(line);

        if line.starts_with("--")
            && line.len() >= bdry.len() + 2
            && &line[2..2 + bdry.len()] == bdry
        {
            if line.len() >= bdry.len() + 4 && &line[2 + bdry.len()..2 + bdry.len() + 2] == "--" {
                dbg!("body end close bdry.");
                return Ok(true);
            }
            dbg!("body end  bdry.");
            return Ok(false);
        }
    }
}

// MAIL FROM: <user12345@example123.com> SIZE=10557
#[allow(dead_code)]
fn mail_from(input: &str) -> IResult<&str, ((&str, usize), usize)> {
    let original_input = input;
    let (input, _) = tag("MAIL FROM: <")(input)?;

    let start_pos = original_input.offset(input);
    let (input, mail) = take_while(|c| c != '>')(input)?;

    let (input, _) = tag("> SIZE=")(input)?;
    let (input, size) = context(
        "invalid SIZE value",
        map_res(digit1, |s: &str| s.parse::<usize>()),
    )(input)?;

    Ok((input, ((mail, start_pos), size)))
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

// Subject: biaoti
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
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_mail_from() {
        let input = "MAIL FROM: <user12345@example123.com> SIZE=10557";
        let result = mail_from(input);

        assert!(result.is_ok());
        let (_, ((mail, start), size)) = result.unwrap();

        assert_eq!(mail, "user12345@example123.com");
        assert_eq!(size, 10557);
        assert_eq!(start, 12);
        println!("mail: '{}' (offset: {})", mail, start);
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
        let lines = [
            "EHLO client.example.com\r\n",
            "AUTH LOGIN\r\n",
            "c2VuZGVyQGV4YW1wbGUuY29t\r\n", // user
            "cGFzc3dvcmQxMjM=\r\n",         // pass
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

        assert_eq!(
            std::str::from_utf8(&captured_user.borrow()).unwrap(),
            "c2VuZGVyQGV4YW1wbGUuY29t",
            "User should match expected value"
        );
        assert_eq!(
            std::str::from_utf8(&captured_pass.borrow()).unwrap(),
            "cGFzc3dvcmQxMjM=",
            "Password should match expected value"
        );
        assert!(
            *captured_user_seq.borrow() > 0,
            "User sequence number should be captured"
        );
        assert!(
            *captured_pass_seq.borrow() > 0,
            "Password sequence number should be captured"
        );
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

        assert_eq!(
            std::str::from_utf8(&captured_user.borrow()).unwrap(),
            "",
            "no user"
        );
        assert_eq!(
            std::str::from_utf8(&captured_pass.borrow()).unwrap(),
            "",
            "no pass"
        );
        assert!(
            *captured_user_seq.borrow() == 0,
            "User sequence number should be 0"
        );
        assert!(
            *captured_pass_seq.borrow() == 0,
            "Password sequence number should be 0"
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

        assert_eq!(
            std::str::from_utf8(&captured_user.borrow()).unwrap(),
            "",
            "no user"
        );
        assert_eq!(
            std::str::from_utf8(&captured_pass.borrow()).unwrap(),
            "",
            "no pass"
        );
        assert!(
            *captured_user_seq.borrow() == 0,
            "User sequence number should be 0"
        );
        assert!(
            *captured_pass_seq.borrow() == 0,
            "Password sequence number should be 0"
        );
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
            "\r\n", // 只有head,带空行
            "------=_001_NextPart572182624333_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n", // 只有head,不带空行
            "------=_001_NextPart572182624333_=----\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<html> line 1\r\n",
            "line 2</html>\r\n",
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

        assert_eq!(
            std::str::from_utf8(&captured_user.borrow()).unwrap(),
            "",
            "no user"
        );
        assert_eq!(
            std::str::from_utf8(&captured_pass.borrow()).unwrap(),
            "",
            "no pass"
        );
        assert!(
            *captured_user_seq.borrow() == 0,
            "User sequence number should be 0"
        );
        assert!(
            *captured_pass_seq.borrow() == 0,
            "Password sequence number should be 0"
        );
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
            "\r\n",                                            // bdry前缀。目前算空行body
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
            "\r\n",
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

        assert_eq!(
            std::str::from_utf8(&captured_user.borrow()).unwrap(),
            "",
            "no user"
        );
        assert_eq!(
            std::str::from_utf8(&captured_pass.borrow()).unwrap(),
            "",
            "no pass"
        );
        assert!(
            *captured_user_seq.borrow() == 0,
            "User sequence number should be 0"
        );
        assert!(
            *captured_pass_seq.borrow() == 0,
            "Password sequence number should be 0"
        );
    }

    #[test]
    fn test_smtp2_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/res/smtp.pcap");
        let mut cap = Capture::init(file_path).unwrap();

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

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        let mut task = protolens.new_task();
        let mut push_count = 0;

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
                push_count += 1;
                dbg!(push_count, pkt.seq());
                protolens.run_task(&mut task, pkt);
            }
        }

        assert_eq!(
            captured_user.borrow().as_slice(),
            b"dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t",
            "User should match expected value"
        );
        assert_eq!(
            *captured_user_seq.borrow(),
            1341098188,
            "Sequence number should match packet sequence"
        );

        assert_eq!(
            captured_pass.borrow().as_slice(),
            b"MTIzNDU2Nzg=",
            "Password should match expected value"
        );
        assert_eq!(
            *captured_pass_seq.borrow(),
            1341098222,
            "Password sequence number should match packet sequence"
        );
    }
}
