use crate::{
    Callbacks, CbBody, CbBodyEvt, CbClt, CbHeader, CbMailFrom, CbPass, CbRcpt, CbSrv, CbUser,
    DirConfirmFn, Direction, Parser, ParserFactory, ParserFuture, PktStrm, Prolens, SMTP_PORT,
    body, header, multi_body, packet::*,
};
use nom::{
    IResult, Offset,
    bytes::complete::{tag, take_till, take_while},
};
use std::ffi::c_void;
use std::marker::PhantomData;

#[derive(Clone)]
pub(crate) struct SmtpCallbacks {
    user: Option<CbUser>,
    pass: Option<CbPass>,
    mailfrom: Option<CbMailFrom>,
    rcpt: Option<CbRcpt>,
}

pub struct SmtpParser<T>
where
    T: Packet,
{
    cb_user: Option<CbUser>,
    cb_pass: Option<CbPass>,
    cb_mailfrom: Option<CbMailFrom>,
    cb_rcpt: Option<CbRcpt>,
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_clt: Option<CbClt>,
    cb_srv: Option<CbSrv>,
    _phantom_t: PhantomData<T>,
}

impl<T> SmtpParser<T>
where
    T: Packet,
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
            cb_clt: None,
            cb_srv: None,
            _phantom_t: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        strm: *mut PktStrm<T>,
        cb: Callbacks,
        cb_smtp: SmtpCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

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
            if let Some(cb) = cb_smtp.user {
                cb.borrow_mut()(user, seq, cb_ctx);
            }

            // pass
            let (pass, seq) = stm.read_clean_line().await?;
            if let Some(cb) = cb_smtp.pass {
                cb.borrow_mut()(pass, seq, cb_ctx);
            }

            // mail from。暂且不管有没有扩展参数
            let (from, seq) = stm.read_clean_line_str().await?;

            if let Ok((_, (mail, offset))) = mail_from(from) {
                let mailfrom_seq = seq + offset as u32;
                if let Some(cb) = cb_smtp.mailfrom {
                    cb.borrow_mut()(mail.as_bytes(), mailfrom_seq, cb_ctx);
                }
            }
        } else if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            // 没有auth，直接到mail from的情况
            if let Ok((_, (mail, offset))) = mail_from(line) {
                let mailfrom_seq = seq + offset as u32;
                if let Some(cb) = cb_smtp.mailfrom {
                    cb.borrow_mut()(mail.as_bytes(), mailfrom_seq, cb_ctx);
                }
            }
        } else {
            // 其他auth情况。AUTH PLAIN，AUTH CRAM-MD5
            // 清空mail from之前或有或无的命令
            read_to_from(stm, cb_smtp.mailfrom, cb_ctx).await?;
        }

        multi_rcpt_to(stm, cb_smtp.rcpt, cb_ctx).await?;

        let (boundary, te) = header(stm, cb.header.as_ref(), cb_ctx, Direction::C2s).await?;
        if let Some(bdry) = boundary {
            multi_body(stm, &bdry, &bdry, &cb, cb_ctx).await?;
        } else {
            body(
                stm,
                te,
                cb.body_start.as_ref(),
                cb.body.as_ref(),
                cb.body_stop.as_ref(),
                cb_ctx,
                cb.dir,
            )
            .await?;
        }

        Ok(())
    }

    async fn s2c_parser_inner(
        strm: *mut PktStrm<T>,
        cb_srv: Option<CbSrv>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        loop {
            let (line, seq) = stm.read_clean_line_str().await?;

            if let Some(ref cb) = cb_srv {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            if line.starts_with("221") {
                break;
            }
        }
        Ok(())
    }
}

impl<T> Parser for SmtpParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn dir_confirm(&self) -> DirConfirmFn<Self::T> {
        |c2s_strm, s2c_strm, c2s_port, s2c_port| {
            let stm_c2s = unsafe { &mut *c2s_strm };
            let stm_s2c = unsafe { &mut *s2c_strm };

            if s2c_port == SMTP_PORT {
                return Some(true);
            } else if c2s_port == SMTP_PORT {
                return Some(false);
            }

            let payload_c2s = stm_c2s.peek_payload();
            let payload_s2c = stm_s2c.peek_payload();

            if payload_c2s.is_err() && payload_s2c.is_err() {
                return None;
            }

            if let Ok(payload) = payload_s2c {
                if payload.len() >= 4
                    && (payload.starts_with(b"220 ")
                        || payload.starts_with(b"220-")
                        || payload.starts_with(b"421 ")
                        || payload.starts_with(b"421-"))
                {
                    return Some(true);
                }

                if payload.len() >= 4
                    && (payload.starts_with(b"HELO ") || payload.starts_with(b"EHLO "))
                {
                    return Some(false);
                }
            }

            if let Ok(payload) = payload_c2s
                && payload.len() >= 4
                    && (payload.starts_with(b"220 ")
                        || payload.starts_with(b"220-")
                        || payload.starts_with(b"421 ")
                        || payload.starts_with(b"421-"))
                {
                    return Some(false);
                }

            Some(true)
        }
    }

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb_smtp = SmtpCallbacks {
            user: self.cb_user.clone(),
            pass: self.cb_pass.clone(),
            mailfrom: self.cb_mailfrom.clone(),
            rcpt: self.cb_rcpt.clone(),
        };
        let cb = Callbacks {
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
            clt: self.cb_clt.clone(),
            srv: None,
            dir: Direction::C2s,
        };

        Some(Box::pin(Self::c2s_parser_inner(strm, cb, cb_smtp, cb_ctx)))
    }

    fn s2c_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::s2c_parser_inner(
            strm,
            self.cb_srv.clone(),
            cb_ctx,
        )))
    }
}

pub(crate) struct SmtpFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for SmtpFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(SmtpParser::new());
        parser.cb_user = prolens.cb_smtp_user.clone();
        parser.cb_pass = prolens.cb_smtp_pass.clone();
        parser.cb_mailfrom = prolens.cb_smtp_mailfrom.clone();
        parser.cb_rcpt = prolens.cb_smtp_rcpt.clone();
        parser.cb_header = prolens.cb_smtp_header.clone();
        parser.cb_body_start = prolens.cb_smtp_body_start.clone();
        parser.cb_body = prolens.cb_smtp_body.clone();
        parser.cb_body_stop = prolens.cb_smtp_body_stop.clone();
        parser.cb_srv = prolens.cb_smtp_srv.clone();
        parser
    }
}

async fn read_to_from<T>(
    stm: &mut PktStrm<T>,
    cb_mailfrom: Option<CbMailFrom>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: Packet,
{
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        if line.to_ascii_uppercase().starts_with("MAIL FROM:") {
            if let Ok((_, (mail, offset))) = mail_from(line) {
                let mailfrom_seq = seq + offset as u32;
                if let Some(cb) = cb_mailfrom {
                    cb.borrow_mut()(mail.as_bytes(), mailfrom_seq, cb_ctx);
                }
            }

            return Ok(());
        }
    }
}

async fn multi_rcpt_to<T>(
    stm: &mut PktStrm<T>,
    cb_rcpt: Option<CbRcpt>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: Packet,
{
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        if line.eq_ignore_ascii_case("DATA") {
            break;
        }

        if let Ok((_, (mail, offset))) = rcpt_to(line) {
            let mail_seq = seq + offset as u32;
            if let Some(ref cb) = cb_rcpt {
                cb.borrow_mut()(mail.as_bytes(), mail_seq, cb_ctx);
            }
        } else {
            return Err(());
        }
    }
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
    use crate::MAX_PKT_BUFF;
    use crate::SMTP_PORT;
    use crate::TransferEncoding;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::env;
    use std::rc::Rc;
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
        let pkt1 = build_pkt_payload2(seq1, &wrong_command, 4000, SMTP_PORT, false);
        let _ = pkt1.decode();

        let mut protolens = Prolens::<CapPacket>::default();
        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let result = protolens.run_task(&mut task, pkt1);
        assert_eq!(result, None, "none is ok");

        let seq2 = 1;
        let correct_commands = *b"EHLO tes\r\n";
        let pkt2 = build_pkt_payload2(seq2, &correct_commands, 4000, SMTP_PORT, false);
        let _ = pkt2.decode();

        let mut protolens = Prolens::<CapPacket>::default();
        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let result = protolens.run_task(&mut task, pkt2);
        assert_eq!(result, None, "none is ok");
    }

    #[test]
    fn test_smtp_not_smtp_port() {
        let lines = [
            "EHLO client.example.com\r\n",
            "AUTH LOGIN\r\n",
            "c2VuZGVyQGV4YW1wbGUuY29t\r\n", // user
            "cGFzc3dvcmQxMjM=\r\n",         // pass
        ];

        let captured_user = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_pass = Rc::new(RefCell::new(Vec::<u8>::new()));

        let user_callback = {
            let user_clone = captured_user.clone();
            move |user: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut user_guard = user_clone.borrow_mut();
                *user_guard = user.to_vec();
            }
        };

        let pass_callback = {
            let pass_clone = captured_pass.clone();
            move |pass: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut pass_guard = pass_clone.borrow_mut();
                *pass_guard = pass.to_vec();
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload2(seq, line_bytes, 4000, 2500, false);
            let _ = pkt.decode();

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
    }

    #[test]
    fn test_smtp_only_server() {
        let lines = [
            "220 smtp.qq.com Esmtp QQ QMail Server\r\n",
            "250-smtp.qq.com\r\n",
            "250-PIPELINING\r\n",
        ];

        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_srv(srv_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload2(seq, line_bytes, 2500, 5000, false);
            let _ = pkt.decode();

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        let srv_guard = captured_srv.borrow();
        assert_eq!(srv_guard.len(), lines.len());
        for (idx, expected) in lines.iter().enumerate() {
            assert_eq!(
                std::str::from_utf8(&srv_guard[idx]).unwrap(),
                expected.trim_end()
            );
        }
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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                if header.is_empty() {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_callback = {
            let body_clone = captured_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  _te: Option<TransferEncoding>| {
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

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_task_c2s(raw_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload2(seq, line_bytes, 4000, SMTP_PORT, false);
            let _ = pkt.decode();

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
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let body_guard = captured_body.borrow();
        assert_eq!(body_guard.len(), body.len());
        for (idx, expected) in body.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&body_guard[idx]).unwrap(), *expected);
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

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

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

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

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
            "\r\n",                                         // 只有head,跟close bdry
            "------=_001_NextPart572182624333_=------\r\n", // 最后的\r\n属于epilogue
            "This is the epilogue 1.\r\n",
            "This is the epilogue 2.\r\n",
            ".\r\n",
            "QUIT\r\n",
            "\r\n",
        ];

        let captured_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                dbg!(std::str::from_utf8(header).unwrap_or(""));
                if header == b"\r\n" {
                    dbg!("header cb. header end");
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_header(header_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        let expected_headers = [
            // 主题header
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            // 第二个 part 的 header
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                dbg!(std::str::from_utf8(header).unwrap_or("err"));
                if header == b"\r\n" {
                    dbg!("header cb. header end");
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                println!("Body start callback triggered");
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  _te: Option<TransferEncoding>| {
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
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

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);
        protolens.set_cb_task_c2s(raw_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

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
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Email Subject\r\n",
            "Date: Mon, 01 Jan 2023 12:00:00 +0000\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            // 第一个 part 的 header,空
            "\r\n",
            // 第二个 part 的 header
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            // 第三个 part 的 header
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
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
        assert_eq!(raw_guard.len(), lines_bytes_len - 8); // epilogue 读到.为止

        let raw_str = std::str::from_utf8(&raw_guard).unwrap();
        assert!(raw_str.contains("EHLO client.example.com\r\n"));
        assert!(raw_str.contains("Content-Type: text/html;\r\n"));
        assert!(raw_str.contains("<html> line 1\r\n"));
        assert!(raw_str.contains("This is the epilogue 2.\r\n"));
        assert!(!raw_str.contains("QUIT\r\n")); // epilogue 读到.为止
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
            "\r\n",                                            // 这个\r\n属于第二层的preamble
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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                if header == b"\r\n" {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                println!("Body start callback triggered");
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  _te: Option<TransferEncoding>| {
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);
                println!("Body callback: {} bytes", body.len());
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
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

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();

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
            "From: \"sender\" <sender@example.in>\r\n",
            "To: <recipient1@example.com>\r\n",
            "Subject: SMTP\r\n",
            "Date: Mon, 5 Oct 2009 11:36:07 +0530\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed;\r\n",
            "\tboundary=\"----=_NextPart_000_0004_01CA45B0.095693F0\"\r\n",
            "\r\n",
            // 第一个嵌套部分的头
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_NextPart_001_0005_01CA45B0.095693F0\"\r\n",
            "\r\n",
            // 第二个嵌套部分的头
            "Content-Type: text/plain;\r\n",
            "Content-Transfer-Encoding: 7bit\r\n",
            "\r\n",
            // 第三个嵌套部分的头
            "Content-Type: text/html;\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            // 最后一个部分的头
            "Content-Type: text/plain;\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 3);

        // 第一个是嵌套内层第一个
        let body0 = &bodies_guard[0];
        dbg!(body0.len(), std::str::from_utf8(body0).unwrap());
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert!(body0_str.contains("I send u smtp pcap file"));
        assert!(body0_str.contains("Find the attachment"));

        // 第二个是内层第二个。内层结束
        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains("<html"));
        assert!(body1_str.contains("</html>\r\n"));

        let bodyr2 = &bodies_guard[2];
        let body2_str = std::str::from_utf8(bodyr2).unwrap();
        assert!(body2_str.contains("* Profiling support\r\n"));
        assert!(body2_str.contains("* Lots of bugfixes\r\n"));
    }

    #[test]
    fn test_smtp_parser() {
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
        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_te = Rc::new(RefCell::new(None));
        let captured_tes = Rc::new(RefCell::new(Vec::new()));

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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                if header == b"\r\n" {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            let current_te = current_te.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                *current_te.borrow_mut() = None;
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            let current_te = current_te.clone();
            let captured_tes = captured_tes.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  te: Option<TransferEncoding>| {
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);

                let mut current_te = current_te.borrow_mut();
                if current_te.is_none() {
                    *current_te = te.clone();
                    captured_tes.borrow_mut().push(te);
                } else {
                    assert_eq!(*current_te, te, "TransferEncoding changed within same body");
                }
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                println!(
                    "Body stop callback triggered, body size: {} bytes",
                    body_guard.len()
                );
            }
        };

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                dbg!("========== in srv callback");
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);
        protolens.set_cb_smtp_srv(srv_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

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

            protolens.run_task(&mut task, pkt);
        }
        dbg!(task);

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
            "Date: Mon, 27 Jun 2022 17:01:55 +0800\r\n",
            "From: \"user12345@example123.com\" <user12345@example123.com>\r\n",
            "To: =?GB2312?B?wO60urvU?= <user12345@example123.com>\r\n",
            "Subject: biaoti\r\n",
            "X-Priority: 3\r\n",
            "X-Has-Attach: no\r\n",
            "X-Mailer: Foxmail 7.2.19.158[cn]\r\n",
            "Mime-Version: 1.0\r\n",
            "Message-ID: <202206271701548584972@example123.com>\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            "Content-Type: text/plain;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 2);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert!(body0_str.contains(
            "aGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRk\r\n"
        ));
        assert!(body0_str.contains(
            "ZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRk\r\n"
        ));
        assert!(body0_str.contains("DQo=\r\n"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains(
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n"
        ));
        assert!(body1_str.contains(
            "nd-color: transparent;\">hello dddddddddddddddddd</span><span style=3D\"line=\r\n"
        ));
        assert!(body1_str.contains("y></html>")); // 最后的\r\n不属于body

        let expected_srv = [
            "220 smtp.qq.com Esmtp QQ QMail Server",
            "250-smtp.qq.com",
            "250-PIPELINING",
            "250-SIZE 73400320",
            "250-STARTTLS",
            "250-AUTH LOGIN PLAIN",
            "250-AUTH=LOGIN",
            "250-MAILCOMPRESS",
            "250 8BITMIME",
            "334 VXNlcm5hbWU6",
            "334 UGFzc3dvcmQ6",
            "235 Authentication successful",
            "250 Ok",
            "250 Ok",
            "354 End data with <CR><LF>.<CR><LF>",
            "250 Ok: queued as ",
            "221 Bye",
        ];

        let srv_guard = captured_srv.borrow();
        assert_eq!(srv_guard.len(), expected_srv.len());
        for (idx, expected) in expected_srv.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&srv_guard[idx]).unwrap(), *expected);
        }

        let tes = captured_tes.borrow();
        assert_eq!(tes.len(), 2);
        assert_eq!(tes[0], Some(TransferEncoding::Base64));
        assert_eq!(tes[1], Some(TransferEncoding::QuotedPrintable));
    }

    // 数据包倒序run。验证bench中的倒序是否是走了错误路径才提高性能的？
    // 但parser会根据前几个包确认方向，所以需要保留在前
    #[test]
    fn test_smtp_parser_rev() {
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
        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let current_te = Rc::new(RefCell::new(None));
        let captured_tes = Rc::new(RefCell::new(Vec::new()));

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
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, _dir: Direction| {
                if header == b"\r\n" {
                    dbg!("header cb. header end", header);
                }
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header.to_vec());
            }
        };

        let body_start_callback = {
            let current_body_clone = current_body.clone();
            let current_te = current_te.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let mut body_guard = current_body_clone.borrow_mut();
                *body_guard = Vec::new();
                *current_te.borrow_mut() = None;
            }
        };

        let body_callback = {
            let current_body_clone = current_body.clone();
            let current_te = current_te.clone();
            let captured_tes = captured_tes.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  _dir: Direction,
                  te: Option<TransferEncoding>| {
                let mut body_guard = current_body_clone.borrow_mut();
                body_guard.extend_from_slice(body);

                let mut current_te = current_te.borrow_mut();
                if current_te.is_none() {
                    *current_te = te.clone();
                    captured_tes.borrow_mut().push(te);
                } else {
                    assert_eq!(*current_te, te, "TransferEncoding changed within same body");
                }
            }
        };

        let body_stop_callback = {
            let current_body_clone = current_body.clone();
            let bodies_clone = captured_bodies.clone();
            move |_cb_ctx: *mut c_void, _dir: Direction| {
                let body_guard = current_body_clone.borrow();
                let mut bodies_guard = bodies_clone.borrow_mut();
                bodies_guard.push(body_guard.clone());
                println!(
                    "Body stop callback triggered, body size: {} bytes",
                    body_guard.len()
                );
            }
        };

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smtp_user(user_callback);
        protolens.set_cb_smtp_pass(pass_callback);
        protolens.set_cb_smtp_mailfrom(mailfrom_callback);
        protolens.set_cb_smtp_rcpt(rcpt_callback);
        protolens.set_cb_smtp_header(header_callback);
        protolens.set_cb_smtp_body_start(body_start_callback);
        protolens.set_cb_smtp_body(body_callback);
        protolens.set_cb_smtp_body_stop(body_stop_callback);
        protolens.set_cb_smtp_srv(srv_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smtp);

        let mut packets = Vec::new();
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

            packets.push(pkt);
        }
        let _: () = assert!(MAX_PKT_BUFF >= packets.len());

        let mut packets_rev = Vec::new();

        if packets.len() >= 2 {
            packets_rev.push(packets[0].clone());
            packets_rev.push(packets[1].clone());
        }
        packets_rev.extend(packets[2..].iter().rev().cloned());

        for pkt in packets_rev {
            protolens.run_task(&mut task, pkt);
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
            "Date: Mon, 27 Jun 2022 17:01:55 +0800\r\n",
            "From: \"user12345@example123.com\" <user12345@example123.com>\r\n",
            "To: =?GB2312?B?wO60urvU?= <user12345@example123.com>\r\n",
            "Subject: biaoti\r\n",
            "X-Priority: 3\r\n",
            "X-Has-Attach: no\r\n",
            "X-Mailer: Foxmail 7.2.19.158[cn]\r\n",
            "Mime-Version: 1.0\r\n",
            "Message-ID: <202206271701548584972@example123.com>\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"----=_001_NextPart572182624333_=----\"\r\n",
            "\r\n",
            "Content-Type: text/plain;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "Content-Type: text/html;\r\n",
            "\tcharset=\"GB2312\"\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
        ];

        let headers_guard = captured_headers.borrow();
        assert_eq!(headers_guard.len(), expected_headers.len());
        for (idx, expected) in expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = captured_bodies.borrow();
        assert_eq!(bodies_guard.len(), 2);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert!(body0_str.contains(
            "aGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRk\r\n"
        ));
        assert!(body0_str.contains(
            "ZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRkaGVsbG8gZGRkZGRkZGRkZGRkZGRkZGRk\r\n"
        ));
        assert!(body0_str.contains("DQo=\r\n"));

        let body1 = &bodies_guard[1];
        let body1_str = std::str::from_utf8(body1).unwrap();
        assert!(body1_str.contains(
            "<html><head><meta http-equiv=3D\"content-type\" content=3D\"text/html; charse=\r\n"
        ));
        assert!(body1_str.contains(
            "nd-color: transparent;\">hello dddddddddddddddddd</span><span style=3D\"line=\r\n"
        ));
        assert!(body1_str.contains("y></html>")); // 最后的\r\n不属于body

        let expected_srv = [
            "220 smtp.qq.com Esmtp QQ QMail Server",
            "250-smtp.qq.com",
            "250-PIPELINING",
            "250-SIZE 73400320",
            "250-STARTTLS",
            "250-AUTH LOGIN PLAIN",
            "250-AUTH=LOGIN",
            "250-MAILCOMPRESS",
            "250 8BITMIME",
            "334 VXNlcm5hbWU6",
            "334 UGFzc3dvcmQ6",
            "235 Authentication successful",
            "250 Ok",
            "250 Ok",
            "354 End data with <CR><LF>.<CR><LF>",
            "250 Ok: queued as ",
            "221 Bye",
        ];

        let srv_guard = captured_srv.borrow();
        assert_eq!(srv_guard.len(), expected_srv.len());
        for (idx, expected) in expected_srv.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&srv_guard[idx]).unwrap(), *expected);
        }

        let tes = captured_tes.borrow();
        assert_eq!(tes.len(), 2);
        assert_eq!(tes[0], Some(TransferEncoding::Base64));
        assert_eq!(tes[1], Some(TransferEncoding::QuotedPrintable));
    }
}
