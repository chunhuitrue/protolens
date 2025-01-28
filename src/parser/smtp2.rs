#![allow(unused)]

use crate::pktstrm::*;
use crate::pool::Pool;
use crate::Packet;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use nom::{
    bytes::complete::{tag, take_till, take_while},
    character::complete::digit1,
    combinator::map_res,
    error::context,
    error::ErrorKind,
    sequence::tuple,
    IResult, InputIter, InputLength, InputTake, Offset, Slice,
};
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug)]
enum ContentType {
    Unknown,
    Alt,
}

pub trait CallbackFn: FnMut(&[u8], u32) + Send + Sync {}
impl<F: FnMut(&[u8], u32) + Send + Sync> CallbackFn for F {}
type UserCallback = Arc<Mutex<dyn CallbackFn>>;
type PassCallback = Arc<Mutex<dyn CallbackFn>>;

pub struct SmtpParser2<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_user: Option<UserCallback>,
    callback_pass: Option<PassCallback>,
    pool: Option<Rc<Pool>>,
}

impl<T: Packet + Ord + 'static> SmtpParser2<T> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_user: None,
            callback_pass: None,
            pool: None,
        }
    }

    pub fn set_callback_user<F>(&mut self, callback: F)
    where
        F: CallbackFn + 'static,
    {
        self.callback_user = Some(Arc::new(Mutex::new(callback)));
    }

    pub fn set_callback_pass<F>(&mut self, callback: F)
    where
        F: CallbackFn + 'static,
    {
        self.callback_pass = Some(Arc::new(Mutex::new(callback)) as PassCallback);
    }

    fn c2s_parser_inner(&self, stream: *const PktStrm<T>) -> impl Future<Output = Result<(), ()>> {
        let callback_user = self.callback_user.clone();
        let callback_pass = self.callback_pass.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            // 忽略前面不需要的命令
            let _ = stm.readline2().await?;
            let _ = stm.readline2().await?;

            // user
            let (user, seq) = stm.read_clean_line().await?;
            if let Some(cb) = callback_user {
                cb.lock().unwrap()(user, seq);
            }
            dbg!(user, seq);

            // pass
            let (pass, seq) = stm.read_clean_line().await?;
            if let Some(cb) = callback_pass.clone() {
                cb.lock().unwrap()(pass, seq);
            }
            dbg!(std::str::from_utf8(pass).expect("应该是utf8"), seq);

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

impl<T: Packet + Ord + 'static> Default for SmtpParser2<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for SmtpParser2<T> {
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

        let future = self.c2s_parser_inner(stream_ptr);
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(&self, stream: *const PktStrm<Self::PacketType>) -> Option<ParserFuture> {
        Some(self.pool().alloc_future(self.c2s_parser_inner(stream)))
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
        let (line, seq) = stm.read_clean_line_str().await?;

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
        let mut parser = SmtpParser2::<CapPacket>::new();
        parser.set_pool(pool);

        println!(
            "Size of stream pointer: {} bytes",
            std::mem::size_of::<*const PktStrm<CapPacket>>()
        );
        println!(
            "Size of callback: {} bytes",
            std::mem::size_of::<Option<UserCallback>>()
        );

        let c2s_size = parser.c2s_parser_size();
        let s2c_size = parser.s2c_parser_size();
        let bdir_size = parser.bdir_parser_size();
        println!("c2s size: {} bytes", c2s_size);
        println!("s2c size: {} bytes", s2c_size);
        println!("bdir size: {} bytes", bdir_size);

        let min_size = std::mem::size_of::<*const PktStrm<CapPacket>>()
            + std::mem::size_of::<Option<UserCallback>>();

        assert!(
            c2s_size >= min_size,
            "Future size should be at least as large as its components"
        );
    }

    #[test]
    fn test_smtp2_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/res/smtp.pcap");
        let mut cap = Capture::init(file_path).unwrap();
        let dir = PktDirection::Client2Server;

        let captured_user = Arc::new(Mutex::new(Vec::<u8>::new()));
        let captured_user_seq = Arc::new(Mutex::new(0u32));
        let captured_pass = Arc::new(Mutex::new(Vec::<u8>::new()));
        let captured_pass_seq = Arc::new(Mutex::new(0u32));

        let user_callback = {
            let user_clone = captured_user.clone();
            let seq_clone = captured_user_seq.clone();
            move |user: &[u8], seq: u32| {
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
            move |pass: &[u8], seq: u32| {
                let mut pass_guard = pass_clone.lock().unwrap();
                let mut seq_guard = seq_clone.lock().unwrap();
                *pass_guard = pass.to_vec();
                *seq_guard = seq;
                dbg!("pass callback", std::str::from_utf8(pass).unwrap(), seq);
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<SmtpParser2<CapPacket>>();
        parser.set_callback_user(user_callback);
        parser.set_callback_pass(pass_callback);
        let mut task = protolens.new_task_with_parser(parser);
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
}
