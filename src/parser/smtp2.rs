#![allow(unused)]

use crate::pool::Pool;
use crate::smtp::ContentType;
use crate::smtp::MetaSmtp;
use crate::Parser;
use crate::ParserFuture;
use crate::PktStrm;
use crate::{Meta, Packet};
use futures_channel::mpsc;
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

use super::smtp;

type UserCallback = Arc<Mutex<dyn FnMut(&[u8]) + Send + Sync>>;

pub struct SmtpParser2<T: Packet + Ord + 'static> {
    _phantom: PhantomData<T>,
    callback_user: Option<UserCallback>,
    pool: Option<Rc<Pool>>,
}

impl<T: Packet + Ord + 'static> SmtpParser2<T> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
            callback_user: None,
            pool: None,
        }
    }

    pub fn set_callback_user<F>(&mut self, callback: F)
    where
        F: FnMut(&[u8]) + Send + Sync + 'static,
    {
        self.callback_user = Some(Arc::new(Mutex::new(callback)));
    }

    fn c2s_parser_inner(
        &self,
        stream: *const PktStrm<T>,
        _meta_tx: mpsc::Sender<Meta>,
    ) -> impl Future<Output = Result<(), ()>> {
        let callback_user = self.callback_user.clone();

        async move {
            let stm: &mut PktStrm<T>;
            unsafe {
                stm = &mut *(stream as *mut PktStrm<T>);
            }

            // 忽略前面不需要的命令
            let _ = stm.readline2().await?;
            let _ = stm.readline2().await?;

            // user
            let user = stm.read_clean_line().await?;
            if let Some(cb) = callback_user {
                cb.lock().unwrap()(user);
            }

            // pass
            let pass = stm.read_clean_line().await?;
            dbg!(std::str::from_utf8(pass).expect("no"));

            // mail from
            let from = stm.read_clean_line_str().await?;
            dbg!(from);
            if let Ok((_, (email, size))) = smtp::mail_from(from) {
                dbg!("from", email);
            } else {
                dbg!("from return err");
                return Err(());
            }

            dbg!("rcpt");
            // rcpt to
            let rcpt = stm.read_clean_line_str().await?;
            if let Ok((_, mail)) = smtp::rcpt_to(rcpt) {
                dbg!("rcpt", mail);
            } else {
                dbg!("rcpt return err");
                return Err(());
            }

            // DATA
            let data = stm.readline2().await?;
            dbg!(std::str::from_utf8(data).expect("no"));

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
        let (tx, _rx) = mpsc::channel(1);
        let stream_ptr = std::ptr::null();

        let future = self.c2s_parser_inner(stream_ptr, tx);
        std::mem::size_of_val(&future)
    }

    fn c2s_parser(
        &self,
        stream: *const PktStrm<Self::PacketType>,
        meta_tx: mpsc::Sender<Meta>,
    ) -> Option<ParserFuture> {
        Some(
            self.pool()
                .alloc_future(self.c2s_parser_inner(stream, meta_tx)),
        )
    }
}

async fn mail_head<T: Packet + Ord + 'static>(
    stm: &mut PktStrm<T>,
) -> Result<(ContentType, String), ()> {
    let mut cont_type_ok = false;
    let mut cont_type = ContentType::Unknown;
    let mut boundary = String::new();

    loop {
        let line = match stm.readline2().await {
            Ok(line) => line,
            Err(_) => break,
        };
        // 头结束
        if line == b"\r\n" {
            break;
        }

        let line = std::str::from_utf8(line).map_err(|_| ())?;

        // subject
        match smtp::subject(line) {
            Ok((_, subject)) => {
                // todo
            }
            Err(_err) => {}
        }

        // content type
        match smtp::content_type(line) {
            Ok((_, contenttype)) => {
                cont_type_ok = true;
                cont_type = contenttype;
            }
            Err(_err) => {}
        }

        // content type ext
        match smtp::content_type_ext(line, cont_type_ok) {
            Ok((_, bdry)) => {
                boundary = bdry.to_string();
            }
            Err(_err) => {}
        }
    }
    Ok((cont_type, boundary))
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
            "Size of mpsc::Sender: {} bytes",
            std::mem::size_of::<mpsc::Sender<Meta>>()
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
            + std::mem::size_of::<mpsc::Sender<Meta>>()
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
        let captured_user_clone = captured_user.clone();
        let callback = move |user: &[u8]| {
            let mut guard = captured_user_clone.lock().unwrap();
            *guard = user.to_vec();
            dbg!("in callback user", std::str::from_utf8(user).unwrap());
        };

        let mut protolens = Prolens::<CapPacket>::default();
        let mut parser = protolens.new_parser::<SmtpParser2<CapPacket>>();
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
            }
        }

        assert_eq!(
            captured_user.lock().unwrap().as_slice(),
            b"dXNlcjEyMzQ1QGV4YW1wbGUxMjMuY29t"
        );
    }
}
