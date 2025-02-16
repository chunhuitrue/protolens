use crate::pool::Pool;
use crate::Packet;
use crate::ParserFuture;
use crate::ParserInner;
use crate::PktStrm;
use nom::{
    bytes::complete::{tag, take_till, take_while},
    character::complete::digit1,
    combinator::map_res,
    error::context,
    IResult, Offset,
};
use std::ffi::c_void;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug)]
enum ContentType {
    Unknown,
    Alt,
}

pub trait SmtpCbFn: FnMut(&[u8], u32, *const c_void) + Send + Sync {}
impl<F: FnMut(&[u8], u32, *const c_void) + Send + Sync> SmtpCbFn for F {}
pub type CbUser = Arc<Mutex<dyn SmtpCbFn>>;
pub(crate) type CbPass = Arc<Mutex<dyn SmtpCbFn>>;

pub struct SmtpParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    pool: Option<Rc<Pool>>,
    pub(crate) cb_user: Option<CbUser>,
    pub(crate) cb_pass: Option<CbPass>,
}

impl<T: Packet + Ord + 'static> SmtpParser<T> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
            cb_user: None,
            cb_pass: None,
            pool: None,
        }
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *const c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback_user = self.cb_user.clone();
        let callback_pass = self.cb_pass.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
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
            if let Some(cb) = callback_user {
                cb.lock().unwrap()(user, seq, cb_ctx);
            }
            dbg!(user, seq);

            // pass
            let (pass, seq) = stm.read_clean_line().await?;
            if let Some(cb) = callback_pass.clone() {
                cb.lock().unwrap()(pass, seq, cb_ctx);
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
}

impl<T: Packet + Ord + 'static> Default for SmtpParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> ParserInner for SmtpParser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new()
    }

    fn pool(&self) -> &Rc<Pool> {
        self.pool.as_ref().expect("Pool not set")
    }

    fn set_pool(&mut self, pool: Rc<Pool>) {
        self.pool = Some(pool);
    }

    fn c2s_parser_size(&self) -> usize {
        let stream_ptr = std::ptr::null();

        let future = self.c2s_parser_inner(stream_ptr, ptr::null_mut());
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        cb_ctx: *const c_void,
    ) -> Option<ParserFuture> {
        Some(
            self.pool()
                .alloc_future(self.c2s_parser_inner(stream, cb_ctx)),
        )
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

async fn mail_head<T: Packet + Ord + 'static>(
    stm: &mut PktStrm<T>,
) -> Result<(ContentType, String), ()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::*;
    use std::env;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_smtp2_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = SmtpParser::<CapPacket>::new();
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<CbUser>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<Option<CbUser>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }

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
        let wrong_command = *b"HELO tes\r\n"; // 使用数组而不是Vec
        let pkt1 = build_pkt_line(seq1, wrong_command);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Smtp);

        let mut protolens = Prolens::<CapPacket>::default();
        let mut task = protolens.new_task();

        // 运行解析器，应该会因为不是EHLO命令而失败
        let result = protolens.run_task(&mut task, pkt1);
        assert_eq!(result, Some(Err(())), "应该返回错误,因为命令不是EHLO");

        // 构造正确的SMTP命令序列包作为对比
        let seq2 = 1;
        let correct_commands = *b"EHLO tes\r\n";
        let pkt2 = build_pkt_line(seq2, correct_commands);
        let _ = pkt2.decode();

        let mut protolens = Prolens::<CapPacket>::default();
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

        let captured_user = Arc::new(Mutex::new(Vec::<u8>::new()));
        let captured_user_seq = Arc::new(Mutex::new(0u32));
        let captured_pass = Arc::new(Mutex::new(Vec::<u8>::new()));
        let captured_pass_seq = Arc::new(Mutex::new(0u32));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32, _cb_ctx: *const c_void| {
                let mut user_guard = user_clone.lock().unwrap();
                let mut seq_guard = seq_clone.lock().unwrap();
                *user_guard = user.to_vec();
                *seq_guard = seq;
                dbg!("in callback", std::str::from_utf8(user).unwrap(), seq);
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            let seq_clone = captured_pass_seq.clone();
            move |pass: &[u8], seq: u32, _cb_ctx: *const c_void| {
                let mut pass_guard = pass_clone.lock().unwrap();
                let mut seq_guard = seq_clone.lock().unwrap();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
                dbg!("pass callback", std::str::from_utf8(pass).unwrap(), seq);
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
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
            captured_user.lock().unwrap().as_slice(),
            b"dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t",
            "User should match expected value"
        );
        assert_eq!(
            *captured_user_seq.lock().unwrap(),
            1341098188,
            "Sequence number should match packet sequence"
        );

        assert_eq!(
            captured_pass.lock().unwrap().as_slice(),
            b"MTIzNDU2Nzg=",
            "Password should match expected value"
        );
        assert_eq!(
            *captured_pass_seq.lock().unwrap(),
            1341098222,
            "Password sequence number should match packet sequence"
        );
    }
}
