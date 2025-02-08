#![allow(unused)]

use crate::pktstrm::*;
use crate::pool::Pool;
use crate::Packet;
use crate::ParserFuture;
use crate::ParserInner;
use crate::PktStrm;
use futures_util::SinkExt;
use nom::{
    bytes::complete::{tag, take_till, take_while},
    character::complete::digit1,
    combinator::map_res,
    IResult,
};
use std::ffi::c_void;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

pub enum MetaSmtp {
    User(String),
    Pass(String),
    MailFrom(String, usize),
    RcptTo(String),
    Subject(String),
}

impl fmt::Debug for MetaSmtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaSmtp::User(user) => f.debug_tuple("User").field(user).finish(),
            MetaSmtp::Pass(pass) => f.debug_tuple("Pass").field(pass).finish(),
            MetaSmtp::MailFrom(mail, mail_size) => f
                .debug_tuple("MailFrom")
                .field(mail)
                .field(mail_size)
                .finish(),
            MetaSmtp::RcptTo(mail) => f.debug_tuple("RcptTo").field(mail).finish(),
            MetaSmtp::Subject(subject) => f.debug_tuple("Subject").field(subject).finish(),
        }
    }
}

pub trait CallbackFn: FnMut(String, *const c_void) + Send + Sync {}
impl<F: FnMut(String, *const c_void) + Send + Sync> CallbackFn for F {}
type UserCallback = Arc<Mutex<dyn CallbackFn>>;

pub struct SmtpParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_user: Option<UserCallback>,
    pool: Option<Rc<Pool>>,
}

impl<T: Packet + Ord + 'static> SmtpParser<T> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_user: None,
            pool: None,
        }
    }

    pub fn set_callback_user<F>(&mut self, callback: F)
    where
        F: CallbackFn + 'static,
    {
        self.callback_user = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        cb_ctx: *const c_void,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback_user = self.callback_user.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            // 忽略前面不需要的命令
            stm.readline().await?;
            stm.readline().await?;

            // user
            let user = stm.readline().await?.trim_end_matches("\r\n").to_string();
            if let Some(cb) = callback_user {
                cb.lock().unwrap()(user.clone(), cb_ctx);
            }

            // pass
            let pass = stm.readline().await?.trim_end_matches("\r\n").to_string();

            // mail from
            let line = stm.readline().await?.trim_end_matches("\r\n").to_string();
            if let Ok((_, (email, size))) = mail_from(&line) {
            } else {
                return Err(());
            }

            // rcpt to
            let line = stm.readline().await?.trim_end_matches("\r\n").to_string();
            if let Ok((_, mail)) = rcpt_to(&line) {
            } else {
                return Err(());
            }

            // DATA
            stm.readline().await?;

            // mail head
            let (_content_type, _bdry) = mail_head(stm).await;

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

    fn c2s_parser(&self, stream: *const PktStrm<T>, cb_ctx: *const c_void) -> Option<ParserFuture> {
        Some(
            self.pool()
                .alloc_future(self.c2s_parser_inner(stream, cb_ctx)),
        )
    }
}

#[derive(Debug)]
enum ContentType {
    Unknown,
    Alt,
}

// MAIL FROM: <user12345@example123.com> SIZE=10557
fn mail_from(input: &str) -> IResult<&str, (&str, usize)> {
    let (input, _) = tag("MAIL FROM: <")(input)?;
    let (input, mail) = take_while(|c| c != '>')(input)?;
    let (input, _) = tag("> SIZE=")(input)?;
    let (input, size) = map_res(digit1, |s: &str| s.parse::<usize>())(input)?;
    Ok((input, (mail, size)))
}

// RCPT TO: <user12345@example123.com>
fn rcpt_to(input: &str) -> IResult<&str, &str> {
    let (input, _) = tag("RCPT TO: <")(input)?;
    let (input, mail) = take_while(|c| c != '>')(input)?;
    Ok((input, (mail)))
}

async fn mail_head<T: Packet + Ord + 'static>(stm: &mut PktStrm<T>) -> (ContentType, String) {
    let mut cont_type_ok = false;
    let mut cont_type = ContentType::Unknown;
    let mut boundary = String::new();

    loop {
        let line = match stm.readline().await {
            Ok(line) => line,
            Err(_) => break,
        };
        if line == "\r\n" {
            break;
        }

        // subject
        match subject(&line) {
            Ok((_, subject)) => {}
            Err(_err) => {}
        }

        // content type
        match content_type(&line) {
            Ok((_, contenttype)) => {
                cont_type_ok = true;
                cont_type = contenttype;
            }
            Err(_err) => {}
        }

        // content type ext
        match content_type_ext(&line, cont_type_ok) {
            Ok((_, bdry)) => {
                boundary = bdry.to_string();
            }
            Err(_err) => {}
        }
    }
    (cont_type, boundary)
}

// Subject: biaoti
fn subject(input: &str) -> IResult<&str, &str> {
    let (input, _) = tag("Subject: ")(input)?;
    let (input, subject) = take_till(|c| c == '\r')(input)?;
    Ok((input, (subject)))
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
    use std::ptr;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_smtp_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/res/smtp.pcap");
        let mut cap = Capture::init(file_path).unwrap();
        let dir = PktDirection::Client2Server;

        let captured_user = Arc::new(Mutex::new(String::new()));
        let captured_user_clone = captured_user.clone();
        let callback = move |user: String, _cb_ctx: *const c_void| {
            let mut guard = captured_user_clone.lock().unwrap();
            *guard = user;
            dbg!("in callback user", &guard);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<SmtpParser<CapPacket>>();
        parser.set_callback_user(callback);
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
            *captured_user.lock().unwrap(),
            "dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t"
        );
    }

    #[test]
    fn test_smtp_future_sizes() {
        let pool = Rc::new(Pool::new(4096, vec![4]));
        let mut parser = SmtpParser::<CapPacket>::new();
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
}
