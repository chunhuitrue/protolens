use crate::CbClt;
use crate::CbFtpLink;
use crate::CbSrv;
use crate::FTP_PORT;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::packet::*;
use nom::{
    IResult,
    bytes::complete::{tag, take_until, take_while},
    character::complete::{char, digit1},
    combinator::map_res,
    sequence::{preceded, tuple},
};
use phf::phf_set;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct FtpCmdParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    cb_clt: Option<CbClt>,
    cb_srv: Option<CbSrv>,
    cb_link: Option<CbFtpLink>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> FtpCmdParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_clt: None,
            cb_srv: None,
            cb_link: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        strm: *const PktStrm<T, P>,
        cb_clt: Option<CbClt>,
        cb_link: Option<CbFtpLink>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(strm as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.readline_str().await?;

            if let Some(ref cb) = cb_clt {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            if let Some((ip, port)) = port_cmd(line) {
                if let Some(ref cb) = cb_link {
                    cb.borrow_mut()(Some(IpAddr::V4(ip)), port, cb_ctx, Direction::C2s);
                }
                continue;
            }

            if let Some((ip, port)) = eprt_cmd(line) {
                if let Some(ref cb) = cb_link {
                    cb.borrow_mut()(Some(ip), port, cb_ctx, Direction::C2s);
                }
                continue;
            }
        }
    }

    async fn s2c_parser_inner(
        strm: *const PktStrm<T, P>,
        cb_srv: Option<CbSrv>,
        cb_link: Option<CbFtpLink>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(strm as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.readline_str().await?;

            if let Some(ref cb) = cb_srv {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
            }

            if let Some((ip, port)) = pasv_rsp(line) {
                if let Some(ref cb) = cb_link {
                    cb.borrow_mut()(Some(IpAddr::V4(ip)), port, cb_ctx, Direction::S2c);
                }
                continue;
            }

            if let Some(port) = epsv_rsp(line) {
                if let Some(ref cb) = cb_link {
                    cb.borrow_mut()(None, port, cb_ctx, Direction::S2c);
                }
                continue;
            }
        }
    }
}

impl<T, P> Parser for FtpCmdParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn dir_confirm(
        &self,
        c2s_strm: *const PktStrm<T, P>,
        s2c_strm: *const PktStrm<T, P>,
        c2s_port: u16,
        s2c_port: u16,
    ) -> bool {
        let stm_c2s;
        let stm_s2c;
        unsafe {
            stm_c2s = &mut *(c2s_strm as *mut PktStrm<T, P>);
            stm_s2c = &mut *(s2c_strm as *mut PktStrm<T, P>);
        }

        if s2c_port == FTP_PORT {
            return true;
        } else if c2s_port == FTP_PORT {
            return false;
        }

        if let Ok(payload) = stm_s2c.peek_payload() {
            if payload.len() >= 4 && srv_cmd(unsafe { std::str::from_utf8_unchecked(payload) }) {
                return true;
            }

            if payload.len() >= 4 && clt_cmd(unsafe { std::str::from_utf8_unchecked(payload) }) {
                return false;
            }
        }

        if let Ok(payload) = stm_c2s.peek_payload() {
            if payload.len() >= 4 && srv_cmd(unsafe { std::str::from_utf8_unchecked(payload) }) {
                return false;
            }
        }

        true
    }

    fn c2s_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            strm,
            self.cb_clt.clone(),
            self.cb_link.clone(),
            cb_ctx,
        )))
    }

    fn s2c_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::s2c_parser_inner(
            strm,
            self.cb_srv.clone(),
            self.cb_link.clone(),
            cb_ctx,
        )))
    }
}

pub(crate) struct FtpCmdFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for FtpCmdFactory<T, P>
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
        let mut parser = Box::new(FtpCmdParser::new());
        parser.cb_clt = prolens.cb_ftp_clt.clone();
        parser.cb_srv = prolens.cb_ftp_srv.clone();
        parser.cb_link = prolens.cb_ftp_link.clone();
        parser
    }
}

fn pasv_rsp(input: &str) -> Option<(Ipv4Addr, u16)> {
    fn pasv_parser(input: &str) -> IResult<&str, (Ipv4Addr, u16)> {
        let (input, _) = preceded(
            tuple((tag("227"), take_while(|c| c != '('), char('('))),
            |i| Ok((i, ())),
        )(input)?;

        let (input, (a, _, b, _, c, _, d, _, p1, _, p2)) = tuple((
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
        ))(input)?;

        let ip = Ipv4Addr::new(a, b, c, d);
        let port = (p1 as u16) * 256 + (p2 as u16);

        Ok((input, (ip, port)))
    }

    match pasv_parser(input) {
        Ok((_, result)) => Some(result),
        Err(_) => None,
    }
}

fn epsv_rsp(input: &str) -> Option<u16> {
    fn epsv_parser(input: &str) -> IResult<&str, u16> {
        let (input, _) = tuple((tag("229"), take_while(|c| c != '('), tag("(|||")))(input)?;

        let (input, port_str) = take_until("|")(input)?;
        let port = match u16::from_str(port_str) {
            Ok(port) => port,
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        };

        let (input, _) = char('|')(input)?;
        Ok((input, port))
    }

    match epsv_parser(input) {
        Ok((_, result)) => Some(result),
        Err(_) => None,
    }
}

fn port_cmd(input: &str) -> Option<(Ipv4Addr, u16)> {
    fn port_parser(input: &str) -> IResult<&str, (Ipv4Addr, u16)> {
        let (input, _) = tuple((tag("PORT"), take_while(|c| c == ' ')))(input)?;

        let (input, (a, _, b, _, c, _, d, _, p1, _, p2)) = tuple((
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
            char(','),
            map_res(digit1, u8::from_str),
        ))(input)?;

        let ip = Ipv4Addr::new(a, b, c, d);
        let port = (p1 as u16) * 256 + (p2 as u16);

        Ok((input, (ip, port)))
    }

    match port_parser(input) {
        Ok((_, result)) => Some(result),
        Err(_) => None,
    }
}

fn eprt_cmd(input: &str) -> Option<(IpAddr, u16)> {
    fn eprt_parser(input: &str) -> IResult<&str, (IpAddr, u16)> {
        let (input, _) = tuple((tag("EPRT"), take_while(|c| c == ' ')))(input)?;

        let (input, _delimiter) = char('|')(input)?;

        let (input, addr_family) = take_until("|")(input)?;
        let (input, _) = char('|')(input)?;

        let (input, ip_str) = take_until("|")(input)?;
        let (input, _) = char('|')(input)?;

        let (input, port_str) = take_until("|")(input)?;
        let (input, _) = char('|')(input)?;

        let port = match u16::from_str(port_str) {
            Ok(port) => port,
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        };

        let ip = match addr_family {
            "1" => match Ipv4Addr::from_str(ip_str) {
                Ok(ip) => IpAddr::V4(ip),
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            },
            "2" => match Ipv6Addr::from_str(ip_str) {
                Ok(ip) => IpAddr::V6(ip),
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            },
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        };

        Ok((input, (ip, port)))
    }

    match eprt_parser(input) {
        Ok((_, result)) => Some(result),
        Err(_) => None,
    }
}

fn srv_cmd(input: &str) -> bool {
    if input.len() < 4 {
        return false;
    }

    let code = &input[..3];

    if !input[3..].starts_with(' ') && !input[3..].starts_with('-') {
        return false;
    }

    if let Ok(num) = code.parse::<u16>() {
        (200..=500).contains(&num)
    } else {
        false
    }
}

static FTP_COMMANDS: phf::Set<&'static str> = phf_set! {
    "ABOR", "ACCT", "ALLO", "APPE", "CDUP", "CWD", "DELE", "EPRT", "EPSV", "FEAT",
    "HELP", "LANG", "LIST", "MAIL", "MDTM", "MKD", "MLFL", "MLSD", "MLST", "MODE",
    "MRCP", "MRSQ", "MSAM", "MSND", "MSOM", "NLST", "NOOP", "OPTS", "PASS", "PASV",
    "PORT", "PWD", "QUIT", "REIN", "REST", "RETR", "RMD", "RNFR", "RNTO", "SITE",
    "SIZE", "SMNT", "STAT", "STOR", "STOU", "STRU", "SYST", "TYPE", "USER", "XCUP",
    "XMKD", "XPWD", "XRMD"
};

fn clt_cmd(input: &str) -> bool {
    if input.len() < 3 {
        return false;
    }

    let search_range = &input[..input.len().min(10)];
    let cmd = match search_range.split_once(|c| [' ', '\r', '\n'].contains(&c)) {
        Some((cmd, _)) => cmd,
        None => search_range,
    };

    FTP_COMMANDS.contains(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::env;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_clt_cmd() {
        assert!(clt_cmd("USER anonymous"));
        assert!(clt_cmd("PASS password"));
        assert!(clt_cmd("CWD /home"));
        assert!(clt_cmd("RETR file.txt"));
        assert!(clt_cmd("PWD"));
        assert!(clt_cmd("MKD "));
        assert!(clt_cmd("XPWD"));
        assert!(clt_cmd("XMKD\r\n"));

        assert!(!clt_cmd(""));
        assert!(!clt_cmd("ABC"));
        assert!(!clt_cmd("220 Welcome"));
        assert!(!clt_cmd("500 Error"));
    }

    #[test]
    fn test_srv_cmd() {
        assert!(srv_cmd("220 (vsFTPd 2.2.0)"));
        assert!(srv_cmd("230 Login successful"));
        assert!(srv_cmd("331-Please specify the password"));
        assert!(srv_cmd("500 Unknown command"));

        assert!(!srv_cmd("USER anonymous"));
        assert!(!srv_cmd("PASS password"));
        assert!(!srv_cmd("150"));
        assert!(!srv_cmd("600 Invalid code"));
        assert!(!srv_cmd("abc Invalid format"));
        assert!(!srv_cmd("2xx Invalid format"));
    }

    #[test]
    fn test_pasv_rsp() {
        let input = "227 Entering Passive Mode (192,168,1,1,10,21).\r\n";
        let result = pasv_rsp(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(port, 10 * 256 + 21);

        let input = "227  Entering Passive  Mode (127,0,0,1,4,1).\r\n";
        let result = pasv_rsp(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 4 * 256 + 1);

        let input = "227 Command okay ().\r\n";
        let result = pasv_rsp(input);
        assert!(result.is_none());

        let input = "200 Command okay.\r\n";
        let result = pasv_rsp(input);
        assert!(result.is_none());

        let input = "227 Entering Passive Mode (192,168,1,1,10).\r\n";
        let result = pasv_rsp(input);
        assert!(result.is_none());
    }

    #[test]
    fn test_epsv_rsp() {
        let input = "229 Entering Extended Passive Mode (|||5000|)\r\n";
        let result = epsv_rsp(input);
        assert!(result.is_some());
        let port = result.unwrap();
        assert_eq!(port, 5000);

        let input = "229  Entering  Extended  Passive  Mode  (|||2121|)\r\n";
        let result = epsv_rsp(input);
        assert!(result.is_some());
        let port = result.unwrap();
        assert_eq!(port, 2121);

        let input = "229 Ready for data transfer (|||8080|)\r\n";
        let result = epsv_rsp(input);
        assert!(result.is_some());
        let port = result.unwrap();
        assert_eq!(port, 8080);

        let input = "229 Entering Extended Passive Mode (||5000|)\r\n";
        let result = epsv_rsp(input);
        assert!(result.is_none());

        let input = "229 Entering Extended Passive Mode (|||port|)\r\n";
        let result = epsv_rsp(input);
        assert!(result.is_none());

        let input = "200 Command okay.\r\n";
        let result = epsv_rsp(input);
        assert!(result.is_none());
    }

    #[test]
    fn test_port_cmd() {
        let input = "PORT 192,168,1,1,10,21\r\n";
        let result = port_cmd(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(port, 10 * 256 + 21);

        let input = "PORT  127,0,0,1,4,1\r\n";
        let result = port_cmd(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 4 * 256 + 1);

        let input = "PORT\r\n";
        let result = port_cmd(input);
        assert!(result.is_none());

        let input = "PORT 192,168,1,1,10\r\n";
        let result = port_cmd(input);
        assert!(result.is_none());
    }

    #[test]
    fn test_eprt_cmd() {
        let input = "EPRT |1|192.168.1.100|2023|\r\n";
        let result = eprt_cmd(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(port, 2023);

        let input = "EPRT |2|2001:db8::1|2121|\r\n";
        let result = eprt_cmd(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap()));
        assert_eq!(port, 2121);

        let input = "EPRT  |1|127.0.0.1|8080|\r\n";
        let result = eprt_cmd(input);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 8080);

        let input = "EPRT |3|192.168.1.1|2121|\r\n";
        let result = eprt_cmd(input);
        assert!(result.is_none());

        let input = "EPRT |1|192.168.1.100|\r\n";
        let result = eprt_cmd(input);
        assert!(result.is_none());

        let input = "EPRT \r\n";
        let result = eprt_cmd(input);
        assert!(result.is_none());

        let input = "PORT 192,168,1,1,10,21\r\n";
        let result = eprt_cmd(input);
        assert!(result.is_none());
    }

    #[test]
    fn test_ftp_only_srv() {
        let lines = [
            "220 (vsFTPd 2.2.0)\r\n",
            "331 Please specify the password.\r\n",
            "227 Entering Passive Mode (5,5,5,149,88,50).\r\n",
        ];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let mut task = protolens.new_task();

        protolens.set_cb_ftp_srv(srv_callback);

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload2(seq, line_bytes, 2500, 5000, false);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::FtpCmd);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        let srv_guard = captured_srv.borrow();
        assert_eq!(srv_guard.len(), lines.len());
        for (idx, expected) in lines.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&srv_guard[idx]).unwrap(), *expected);
        }
    }

    #[test]
    fn test_ftp_only_clt() {
        let lines = ["USER root\r\n", "PASS net123\r\n", "OPTS UTF8 ON\r\n"];

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

        let captured_clt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));

        let clt_callback = {
            let clt_clone = captured_clt.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let mut task = protolens.new_task();

        protolens.set_cb_ftp_clt(clt_callback);

        let mut seq = 1000;
        for line in lines {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload2(seq, line_bytes, 2500, 5000, false);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::FtpCmd);

            protolens.run_task(&mut task, pkt);
            seq += line_bytes.len() as u32;
        }

        let clt_guard = captured_clt.borrow();
        assert_eq!(clt_guard.len(), lines.len());
        for (idx, expected) in lines.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&clt_guard[idx]).unwrap(), *expected);
        }
    }

    #[test]
    fn test_ftp_cmd() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/ftp_pasv.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_clt = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_srv = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let captured_links = Rc::new(RefCell::new(Vec::<(Option<IpAddr>, u16, Direction)>::new()));

        let clt_callback = {
            let clt_clone = captured_clt.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut clt_guard = clt_clone.borrow_mut();
                clt_guard.push(line.to_vec());
            }
        };

        let srv_callback = {
            let srv_clone = captured_srv.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut srv_guard = srv_clone.borrow_mut();
                srv_guard.push(line.to_vec());
            }
        };

        let link_callback = {
            let links_clone = captured_links.clone();
            move |ip: Option<IpAddr>, port: u16, _cb_ctx: *mut c_void, direction: Direction| {
                let mut links_guard = links_clone.borrow_mut();
                links_guard.push((ip, port, direction));
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        protolens.set_cb_ftp_clt(clt_callback);
        protolens.set_cb_ftp_srv(srv_callback);
        protolens.set_cb_ftp_link(link_callback);

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

            if pkt.header.borrow().as_ref().unwrap().dport() == 21
                || pkt.header.borrow().as_ref().unwrap().sport() == 21
            {
                pkt.set_l7_proto(L7Proto::FtpCmd);
                protolens.run_task(&mut task, pkt);
            }
        }

        let expected_clt = [
            "USER root\r\n",
            "PASS net123\r\n",
            "FEAT\r\n",
            "OPTS UTF8 ON\r\n",
            "TYPE A\r\n",
            "PASV\r\n",
            "LIST\r\n",
            "XPWD\r\n",
            "TYPE A\r\n",
            "PASV\r\n",
            "LIST\r\n",
            "CWD ccc\r\n",
            "XPWD\r\n",
            "TYPE A\r\n",
            "PASV\r\n",
            "LIST\r\n",
            "TYPE I\r\n",
            "PASV\r\n",
            "RETR /root/ccc/eeeee.exe\r\n",
        ];

        let clt_guard = captured_clt.borrow();
        assert_eq!(clt_guard.len(), expected_clt.len());
        for (idx, expected) in expected_clt.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&clt_guard[idx]).unwrap(), *expected);
        }

        let expected_srv = [
            "220 (vsFTPd 2.2.0)\r\n",
            "331 Please specify the password.\r\n",
            "230 Login successful.\r\n",
            "211-Features:\r\n",
            " EPRT\r\n",
            " EPSV\r\n",
            " MDTM\r\n",
            " PASV\r\n",
            " REST STREAM\r\n",
            " SIZE\r\n",
            " TVFS\r\n",
            " UTF8\r\n",
            "211 End\r\n",
            "200 Always in UTF8 mode.\r\n",
            "200 Switching to ASCII mode.\r\n",
            "227 Entering Passive Mode (5,5,5,149,88,50).\r\n",
            "150 Here comes the directory listing.\r\n",
            "226 Directory send OK.\r\n",
            "257 \"/root\"\r\n",
            "200 Switching to ASCII mode.\r\n",
            "227 Entering Passive Mode (5,5,5,149,47,180).\r\n",
            "150 Here comes the directory listing.\r\n",
            "226 Directory send OK.\r\n",
            "250 Directory successfully changed.\r\n",
            "257 \"/root/ccc\"\r\n",
            "200 Switching to ASCII mode.\r\n",
            "227 Entering Passive Mode (5,5,5,149,127,223).\r\n",
            "150 Here comes the directory listing.\r\n",
            "226 Directory send OK.\r\n",
            "200 Switching to Binary mode.\r\n",
            "227 Entering Passive Mode (5,5,5,149,33,230).\r\n",
            "150 Opening BINARY mode data connection for /root/ccc/eeeee.exe (68 bytes).\r\n",
            "226 File send OK.\r\n",
            "500 OOPS: vsf_sysutil_recv_peek: no data\r\n",
        ];

        let srv_guard = captured_srv.borrow();
        assert_eq!(srv_guard.len(), expected_srv.len());
        for (idx, expected) in expected_srv.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&srv_guard[idx]).unwrap(), *expected);
        }

        let links_guard = captured_links.borrow();
        assert_eq!(links_guard.len(), 4);

        for (idx, (ip, port, direction)) in links_guard.iter().enumerate() {
            if let Some(ip_addr) = ip {
                if let IpAddr::V4(ipv4) = ip_addr {
                    assert_eq!(*ipv4, Ipv4Addr::new(5, 5, 5, 149));
                } else {
                    panic!("Expected IPv4 address");
                }
            } else {
                panic!("Expected Some(IP), got None");
            }

            assert_eq!(*direction, Direction::S2c);
            match idx {
                0 => assert_eq!(*port, 88 * 256 + 50),
                1 => assert_eq!(*port, 47 * 256 + 180),
                2 => assert_eq!(*port, 127 * 256 + 223),
                3 => assert_eq!(*port, 33 * 256 + 230),
                _ => panic!("Unexpected index"),
            }
        }
    }
}
