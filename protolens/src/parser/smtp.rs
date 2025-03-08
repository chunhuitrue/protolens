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

#[derive(Debug)]
enum ContentType {
    Unknown,
    Alt,
}

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
            // mail from callback
        } else if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            // 没有auth，直接到mail from的情况
            // mail from callback
            dbg!(line);
        } else {
            // 其他auth情况。AUTH PLAIN，AUTH CRAM-MD5
            // 清空mail from之前或有或无的命令
            read_to_from(stm).await?;
        }

        multi_rcpt_to(stm).await?;

        // mail head
        let (content_type, bdry) = mail_head(stm).await?;
        dbg!(&content_type, bdry);

        match content_type {
            ContentType::Unknown => {
                body(stm).await?;
            }
            ContentType::Alt => {}
        }

        let (_quit, _seq) = stm.read_clean_line_str().await?;

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

async fn multi_rcpt_to<T, P>(stm: &mut PktStrm<T, P>) -> Result<(), ()>
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
            dbg!("rcpt", mail, mail_seq);
        } else {
            return Err(());
        }
    }
    Ok(())
}

async fn mail_head<T, P>(stm: &mut PktStrm<T, P>) -> Result<(ContentType, String), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let mut cont_type_ok = false;
    let mut cont_type = ContentType::Unknown;
    let mut boundary = String::new();

    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;

        // 头结束
        if line.is_empty() {
            break;
        }
        dbg!(line);

        // // subject
        // match subject(line) {
        //     Ok((_, _subject)) => {}
        //     Err(_err) => {}
        // }

        // content type
        match content_type(line) {
            Ok((_, contenttype)) => {
                cont_type_ok = true;
                cont_type = contenttype;
            }
            Err(_err) => {}
        }

        // content type ext
        match content_type_ext(line, cont_type_ok) {
            Ok((_, bdry)) => {
                boundary = bdry.to_string();
            }
            Err(_err) => {}
        }
    }
    Ok((cont_type, boundary))
}

async fn body<T, P>(stm: &mut PktStrm<T, P>) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    loop {
        let (line, _seq) = stm.read_clean_line_str().await?;

        if line == (".") {
            break;
        }

        dbg!(line);
    }
    Ok(())
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

// Content-Type: multipart/alternative;
fn content_type(input: &str) -> IResult<&str, ContentType> {
    let (input, _) = tag("Content-Type: ")(input)?;
    if input.contains("multipart/alternative;") {
        Ok((input, (ContentType::Alt)))
    } else {
        Ok((input, (ContentType::Unknown)))
    }
}

// \tboundary="----=_001_NextPart572182624333_=----"
fn content_type_ext(input: &str, cont_rady: bool) -> IResult<&str, &str> {
    if !cont_rady {
        return Ok((input, ""));
    }

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

#[allow(dead_code)]
fn starts_with_auth_login(input: &[u8]) -> bool {
    if input.len() < 10 {
        return false;
    }
    let upper = input[..10].to_ascii_uppercase();
    upper == b"AUTH LOGIN"
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
    fn test_starts_with_auth_login() {
        // 正确的情况
        assert!(starts_with_auth_login(b"AUTH LOGIN"));
        assert!(starts_with_auth_login(b"auth login"));
        assert!(starts_with_auth_login(b"Auth Login credentials"));

        // 错误的情况
        assert!(!starts_with_auth_login(b"AUTH PLAIN")); // 错误的认证方式
        assert!(!starts_with_auth_login(b"AUTH")); // 不完整
        assert!(!starts_with_auth_login(b"")); // 空输入
        assert!(!starts_with_auth_login(b"LOGIN")); // 缺少AUTH前缀
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
