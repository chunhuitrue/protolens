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

        // 验证EHLO命令,如果EHLO命令不正确，则返回错误，无法继续解析
        let (ehlo_line, _) = stm.readline2().await?;
        if !starts_with_ehlo(ehlo_line) {
            dbg!("First line is not EHLO command");
            return Err(());
        }

        // 读取AUTH LOGIN命令
        let (auth_line, _) = stm.readline2().await?;
        if !starts_with_auth_login(auth_line) {
            dbg!("Second line is not AUTH LOGIN command");
            return Err(());
        }

        // user
        let (user, seq) = stm.read_clean_line().await?;
        if let Some(cb) = cb_user {
            cb.borrow_mut()(user, seq, cb_ctx);
        }
        dbg!(user, seq);

        // pass
        let (pass, seq) = stm.read_clean_line().await?;
        if let Some(cb) = cb_pass.clone() {
            cb.borrow_mut()(pass, seq, cb_ctx);
        }
        dbg!(std::str::from_utf8(pass).expect("need utf8"), seq);

        // mail from
        let (from, seq) = stm.read_clean_line_str().await?;
        if let Ok((_, ((mail, offset), size))) = mail_from(from) {
            let mail_seq = seq + offset as u32;
            dbg!("from", mail, size, mail_seq);
        } else {
            dbg!("from return err");
            return Err(());
        }

        // rcpt to
        let (rcpt, seq) = stm.read_clean_line_str().await?;
        if let Ok((_, (mail, offset))) = rcpt_to(rcpt) {
            let mail_seq = seq + offset as u32;
            dbg!("rcpt", mail, mail_seq);
        } else {
            dbg!("rcpt return err");
            return Err(());
        }

        // DATA
        let (data, seq) = stm.readline2().await?;
        dbg!(std::str::from_utf8(data).expect("no"), seq);

        // mail head
        let (content_type, bdry) = mail_head(stm).await?;
        dbg!(content_type, bdry);

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

// MAIL FROM: <user12345@example123.com> SIZE=10557
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
        if line == "\r\n" {
            break;
        }

        // subject
        match subject(line) {
            Ok((_, subject)) => {
                dbg!(subject);
            }
            Err(_err) => {}
        }

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

// Subject: biaoti
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

fn starts_with_ehlo(input: &[u8]) -> bool {
    if input.len() < 4 {
        return false;
    }
    let upper = input[..4].to_ascii_uppercase();
    upper == b"EHLO"
}

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
        assert!(starts_with_ehlo(b"EHLO example.com"));
        assert!(starts_with_ehlo(b"ehlo example.com"));
        assert!(starts_with_ehlo(b"EhLo example.com"));

        // 错误的情况
        assert!(!starts_with_ehlo(b"HELO example.com")); // 错误的命令
        assert!(!starts_with_ehlo(b"EHL")); // 太短
        assert!(!starts_with_ehlo(b"")); // 空输入
        assert!(!starts_with_ehlo(b"MAIL FROM:")); // 完全不同的命令
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
    fn test_smtp_command_sequence() {
        // 构造错误的SMTP命令序列包
        let seq1 = 1;
        let wrong_command = *b"HELO tes\r\n";
        let pkt1 = build_pkt_line(seq1, wrong_command);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Smtp);

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        // 运行解析器，应该会因为不是EHLO命令而失败
        let result = protolens.run_task(&mut task, pkt1);
        assert_eq!(result, Some(Err(())), "应该返回错误,因为命令不是EHLO");

        // 构造正确的SMTP命令序列包作为对比
        let seq2 = 1;
        let correct_commands = *b"EHLO tes\r\n";
        let pkt2 = build_pkt_line(seq2, correct_commands);
        let _ = pkt2.decode();

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        // 运行解析器，应该成功处理正确的命令序列
        let result = protolens.run_task(&mut task, pkt2);
        assert_eq!(result, None, "应该返回None,因为解析器还在等待更多数据");
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
