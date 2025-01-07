#![allow(unused)]

use crate::pool::Pool;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use futures_util::SinkExt;
use nom::{
    bytes::complete::{tag, take_till, take_while},
    character::complete::digit1,
    combinator::map_res,
    IResult,
};
use std::fmt;
use std::marker::PhantomData;
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

type UserCallback = Arc<Mutex<dyn FnMut(String) + Send + Sync>>;

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
        F: FnMut(String) + Send + Sync + 'static,
    {
        self.callback_user = Some(Arc::new(Mutex::new(callback)));
    }
}

impl<T: Packet + Ord + 'static> Default for SmtpParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for SmtpParser<T> {
    type PacketType = T;

    fn new() -> Self {
        Self::new()
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        mut meta_tx: mpsc::Sender<Meta>,
    ) -> ParserFuture {
        let callback_user = self.callback_user.clone();

        self.pool().alloc_future(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
            }

            // 忽略前面不需要的命令
            stm.readline().await?;
            stm.readline().await?;

            // user
            let user = stm.readline().await?.trim_end_matches("\r\n").to_string();
            if let Some(cb) = callback_user {
                cb.lock().unwrap()(user.clone());
            }
            let meta = Meta::Smtp(MetaSmtp::User(user));
            let _ = meta_tx.send(meta).await;

            // pass
            let pass = stm.readline().await?.trim_end_matches("\r\n").to_string();
            let meta = Meta::Smtp(MetaSmtp::Pass(pass));
            let _ = meta_tx.send(meta).await;

            // mail from
            let line = stm.readline().await?.trim_end_matches("\r\n").to_string();
            if let Ok((_, (email, size))) = mail_from(&line) {
                let meta = Meta::Smtp(MetaSmtp::MailFrom(email.to_string(), size));
                let _ = meta_tx.send(meta).await;
            } else {
                return Err(());
            }

            // rcpt to
            let line = stm.readline().await?.trim_end_matches("\r\n").to_string();
            if let Ok((_, mail)) = rcpt_to(&line) {
                let meta = Meta::Smtp(MetaSmtp::RcptTo(mail.to_string()));
                let _ = meta_tx.send(meta).await;
            } else {
                return Err(());
            }

            // DATA
            stm.readline().await?;

            // mail head
            let (_content_type, _bdry) = mail_head(stm, &mut meta_tx).await;

            Ok(())
        })
    }

    fn pool(&self) -> &Rc<Pool> {
        self.pool.as_ref().expect("Pool not set")
    }

    fn set_pool(&mut self, pool: Rc<Pool>) {
        self.pool = Some(pool);
    }
}

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

async fn mail_head<T: Packet + Ord + 'static>(
    stm: &mut PktStrm<T>,
    meta_tx: &mut mpsc::Sender<Meta>,
) -> (ContentType, String) {
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
            Ok((_, subject)) => {
                let meta = Meta::Smtp(MetaSmtp::Subject(subject.to_string()));
                let _ = meta_tx.send(meta).await;
            }
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
        let callback = move |user: String| {
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
                protolens.run_task(&mut task, pkt, dir.clone());
                meta_recver(&mut task);
            }
        }

        assert_eq!(
            *captured_user.lock().unwrap(),
            "dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t"
        );
    }

    fn meta_recver<T: Packet + Ord + std::fmt::Debug + 'static>(task: &mut Task<T>) {
        while let Some(meta) = task.get_meta() {
            match meta {
                Meta::Smtp(smtp) => meta_smtp_recver(smtp),
                Meta::Http(_) => {}
            }
        }
    }

    fn meta_smtp_recver(smtp: MetaSmtp) {
        println!("recv meta_smtp: {:?}", smtp);
        match smtp {
            MetaSmtp::User(user) => assert_eq!("dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t", user),
            MetaSmtp::Pass(pass) => assert_eq!("MTIzNDU2Nzg=", pass),
            MetaSmtp::MailFrom(mail, mail_size) => {
                assert_eq!("user12345@example123.com", mail);
                assert_eq!(10557, mail_size);
            }
            MetaSmtp::RcptTo(mail) => {
                assert_eq!("user12345@example123.com", mail);
            }
            MetaSmtp::Subject(subject) => {
                assert_eq!("biaoti", subject);
            }
        }
    }
}
