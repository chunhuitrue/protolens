use crate::Parser;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures::Future;
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
use std::pin::Pin;
use std::sync::Arc;

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

type UserCallback = Arc<dyn Fn(&str) + Send + Sync>;

pub struct SmtpParser<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_user: Option<UserCallback>,
}

impl<T: Packet + Ord + 'static> SmtpParser<T> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_user: None,
        }
    }

    pub fn set_callback_user<F>(&mut self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.callback_user = Some(Arc::new(callback));
    }
}

impl<T: Packet + Ord + 'static> Default for SmtpParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Packet + Ord + 'static> Parser for SmtpParser<T> {
    type PacketType = T;

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        mut meta_tx: mpsc::Sender<Meta>,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        let callback_user = self.callback_user.clone();

        Box::pin(async move {
            let stm: &mut PktStrm<Self::PacketType>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<Self::PacketType>);
            }

            // 忽略前面不需要的命令
            let _ = stm.readline().await;
            let _ = stm.readline().await;

            // user
            let user = stm
                .readline()
                .await
                .unwrap()
                .trim_end_matches("\r\n")
                .to_string();
            if let Some(cb) = callback_user {
                cb(&user);
            }
            let meta = Meta::Smtp(MetaSmtp::User(user));
            let _ = meta_tx.send(meta).await;

            // pass
            let pass = stm
                .readline()
                .await
                .unwrap()
                .trim_end_matches("\r\n")
                .to_string();
            let meta = Meta::Smtp(MetaSmtp::Pass(pass));
            let _ = meta_tx.send(meta).await;

            // mail from
            let line = stm
                .readline()
                .await
                .unwrap()
                .trim_end_matches("\r\n")
                .to_string();
            match mail_from(&line) {
                Ok((_, (email, size))) => {
                    let meta = Meta::Smtp(MetaSmtp::MailFrom(email.to_string(), size));
                    let _ = meta_tx.send(meta).await;
                }
                Err(_err) => {}
            }

            // rcpt to
            let line = stm
                .readline()
                .await
                .unwrap()
                .trim_end_matches("\r\n")
                .to_string();
            match rcpt_to(&line) {
                Ok((_, mail)) => {
                    let meta = Meta::Smtp(MetaSmtp::RcptTo(mail.to_string()));
                    let _ = meta_tx.send(meta).await;
                }
                Err(_err) => {}
            }

            // DATA
            let _ = stm
                .readline()
                .await
                .unwrap()
                .trim_end_matches("\r\n")
                .to_string();

            // mail head
            let (_content_type, _bdry) = mail_head(stm, &mut meta_tx).await;
        })
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
        let line = stm.readline().await.unwrap();
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
    (cont_type, boundary.to_string())
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

// 	boundary="----=_001_NextPart572182624333_=----"
fn content_type_ext(input: &str, cont_rady: bool) -> IResult<&str, &str> {
    if !cont_rady {
        return Ok((input, ""));
    }

    let (input, _) = tag("\tboundary=\"")(input)?;
    let (input, bdry) = take_till(|c| c == '"')(input)?;
    Ok((input, bdry))
}
