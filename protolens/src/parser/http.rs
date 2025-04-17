use crate::CbBodyEvt;
use crate::CbHeader;
use crate::CbHttpBody;
use crate::CbStartLine;
use crate::Direction;
use crate::Encoding;
use crate::HTTP_PORT;
use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::ReadRet;
use crate::content_type;
use crate::content_type_ext;
use crate::packet::*;
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while, take_while1},
    combinator::{map_res, value},
    sequence::terminated,
};
use phf::phf_set;
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct HttpParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    cb_start_line: Option<CbStartLine>,
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbHttpBody>,
    cb_body_stop: Option<CbBodyEvt>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> HttpParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_start_line: None,
            cb_header: None,
            cb_body_start: None,
            cb_body: None,
            cb_body_stop: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn parser_inner(
        strm: *const PktStrm<T, P>,
        cb_http: HttpCallbacks,
        cb_ctx: *mut c_void,
        start_line_parser: fn(&[u8]) -> HttpVersion,
    ) -> Result<(), ()> {
        let stm;
        unsafe {
            stm = &mut *(strm as *mut PktStrm<T, P>);
        }

        loop {
            let (line, seq) = stm.readline_str().await?;

            match start_line_parser(line.as_bytes()) {
                HttpVersion::Http20 | HttpVersion::Unknown => {
                    return Ok(());
                }
                _ => {}
            }
            if let Some(ref cb) = cb_http.start_line {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx, cb_http.dir);
            }

            let header_ret =
                Self::header(stm, cb_http.header.as_ref(), cb_ctx, cb_http.dir).await?;

            if header_ret.boundary.is_some() {
                let bdry = header_ret.boundary.unwrap();
                Self::multi_body(stm, &bdry, &bdry, &cb_http, cb_ctx).await?;
            } else if header_ret.is_chunked() {
                Self::chunk_body(stm, &cb_http, cb_ctx, &header_ret.ce, &header_ret.te).await?;
            } else if header_ret.content_len.is_some() {
                let params = HttpBodyParams {
                    bdry: "",
                    cb_body_start: cb_http.body_start.as_ref(),
                    cb_body: cb_http.body.as_ref(),
                    cb_body_stop: cb_http.body_stop.as_ref(),
                    cb_ctx,
                    dir: cb_http.dir,
                    ce: &header_ret.ce,
                    te: &header_ret.te,
                };
                Self::size_body(stm, header_ret.content_len.unwrap(), params).await?;
            }
        }
    }

    async fn header(
        stm: &mut PktStrm<T, P>,
        cb_header: Option<&CbHeader>,
        cb_ctx: *mut c_void,
        dir: Direction,
    ) -> Result<HeaderRet, ()> {
        let mut content_len = None;
        let mut boundary = None;
        let mut te = None;
        let mut ce = None;
        let mut cont_type = false;

        loop {
            let (line, seq) = stm.readline_str().await?;

            if let Some(cb) = cb_header {
                cb.borrow_mut()(line.as_bytes(), seq, cb_ctx, dir);
            }

            if line == "\r\n" {
                let ret = HeaderRet {
                    content_len,
                    boundary,
                    ce,
                    te,
                };
                return Ok(ret);
            }

            if ce.is_none() {
                ce = content_encoding(line);
            }

            if te.is_none() {
                te = transfer_encoding(line);
            }

            if content_len.is_none() {
                content_len = content_length(line);
            }

            // content-type ext
            // 放在content-type前面是因为。只有content-type结束之后才能作这个判断。
            // 放在前面，cont_type 肯定为false
            if cont_type && boundary.is_none() {
                match content_type_ext(line) {
                    Ok((_, bdry)) => {
                        boundary = Some(bdry.to_string());
                        cont_type = false;
                    }
                    Err(_err) => {}
                }
            }
            // content-type
            if boundary.is_none() {
                match content_type(line) {
                    Ok((_input, Some(bdry))) => {
                        cont_type = true;
                        boundary = Some(bdry.to_string());
                    }
                    Ok((_input, None)) => {
                        cont_type = true;
                    }
                    Err(_err) => {}
                }
            }
        }
    }

    async fn multi_body(
        stm: &mut PktStrm<T, P>,
        out_bdry: &str,
        bdry: &str,
        cb_http: &HttpCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let _ = stm.readline_str().await?;
        loop {
            let header_ret =
                Self::header(stm, cb_http.header.as_ref(), cb_ctx, cb_http.dir).await?;
            if header_ret.boundary.is_some() {
                let bdry = header_ret.boundary.unwrap();
                Box::pin(Self::multi_body(stm, out_bdry, &bdry, cb_http, cb_ctx)).await?;
                continue;
            } else {
                let params = HttpBodyParams {
                    bdry,
                    cb_body_start: cb_http.body_start.as_ref(),
                    cb_body: cb_http.body.as_ref(),
                    cb_body_stop: cb_http.body_stop.as_ref(),
                    cb_ctx,
                    dir: cb_http.dir,
                    ce: &None,
                    te: &None,
                };
                Self::mime_body(stm, params, &header_ret.ce, &header_ret.te).await?;
            }

            let (byte, _seq) = stm.readn(2).await?;
            if byte == b"--" {
                break;
            } else if byte == b"\r\n" {
                continue;
            } else {
                return Err(());
            }
        }
        let _ = stm.readline_str().await?;
        Ok(())
    }

    async fn mime_body(
        stm: &mut PktStrm<T, P>,
        params: HttpBodyParams<'_>,
        ce: &Option<Vec<Encoding>>,
        te: &Option<Vec<Encoding>>,
    ) -> Result<(), ()> {
        if let Some(cb) = params.cb_body_start {
            cb.borrow_mut()(params.cb_ctx, params.dir);
        }
        loop {
            let (ret, content, seq) = stm.read_mime_octet(params.bdry).await?;

            if let Some(cb) = params.cb_body {
                cb.borrow_mut()(content, seq, params.cb_ctx, params.dir, ce, te);
            }

            if ret == ReadRet::DashBdry {
                break;
            }
        }
        if let Some(cb) = params.cb_body_stop {
            cb.borrow_mut()(params.cb_ctx, params.dir);
        }
        Ok(())
    }

    async fn size_body(
        stm: &mut PktStrm<T, P>,
        size: usize,
        params: HttpBodyParams<'_>,
    ) -> Result<(), ()> {
        let mut remain_size = size;

        if let Some(cb) = params.cb_body_start {
            cb.borrow_mut()(params.cb_ctx, params.dir);
        }
        while remain_size > 0 {
            let (bytes, seq) = stm.read(remain_size).await?;
            remain_size -= bytes.len();

            if let Some(cb) = params.cb_body {
                cb.borrow_mut()(bytes, seq, params.cb_ctx, params.dir, params.ce, params.te);
            }
        }
        if let Some(cb) = params.cb_body_stop {
            cb.borrow_mut()(params.cb_ctx, params.dir);
        }
        Ok(())
    }

    async fn chunk_body(
        stm: &mut PktStrm<T, P>,
        cb_http: &HttpCallbacks,
        cb_ctx: *mut c_void,
        ce: &Option<Vec<Encoding>>,
        te: &Option<Vec<Encoding>>,
    ) -> Result<(), ()> {
        if let Some(cb) = &cb_http.body_start {
            cb.borrow_mut()(cb_ctx, cb_http.dir);
        }
        loop {
            let (line, _seq) = stm.readline_str().await?;
            let chunk_size = chunk_size(line)?;

            if chunk_size == 0 {
                break;
            }

            let params = HttpBodyParams {
                bdry: "",
                cb_body_start: None,
                cb_body: cb_http.body.as_ref(),
                cb_body_stop: None,
                cb_ctx,
                dir: cb_http.dir,
                ce,
                te,
            };
            Self::size_body(stm, chunk_size, params).await?;

            let (bytes, _seq) = stm.readn(2).await?;
            if bytes != b"\r\n" {
                return Err(());
            }
        }
        if let Some(cb) = &cb_http.body_stop {
            cb.borrow_mut()(cb_ctx, cb_http.dir);
        }

        Self::tailer(stm).await?;
        Ok(())
    }

    async fn tailer(stm: &mut PktStrm<T, P>) -> Result<(), ()> {
        loop {
            let (line, _seq) = stm.readline_str().await?;
            if line == "\r\n" {
                return Ok(());
            }
        }
    }
}

impl<T, P> Parser for HttpParser<T, P>
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

        if s2c_port == HTTP_PORT {
            return true;
        } else if c2s_port == HTTP_PORT {
            return false;
        }

        if let Ok(payload) = stm_c2s.peek_payload() {
            if payload.len() >= 4 && req(unsafe { std::str::from_utf8_unchecked(payload) }) {
                return true;
            }

            if payload.len() >= 7 && rsp(unsafe { std::str::from_utf8_unchecked(payload) }) {
                return false;
            }
        }

        if let Ok(payload) = stm_s2c.peek_payload() {
            if payload.len() >= 4 && req(unsafe { std::str::from_utf8_unchecked(payload) }) {
                return false;
            }
        }

        true
    }

    fn c2s_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb_http = HttpCallbacks {
            start_line: self.cb_start_line.clone(),
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
            dir: Direction::C2s,
        };
        Some(Box::pin(Self::parser_inner(
            strm,
            cb_http,
            cb_ctx,
            req_version,
        )))
    }

    fn s2c_parser(&self, strm: *const PktStrm<T, P>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb_http = HttpCallbacks {
            start_line: self.cb_start_line.clone(),
            header: self.cb_header.clone(),
            body_start: self.cb_body_start.clone(),
            body: self.cb_body.clone(),
            body_stop: self.cb_body_stop.clone(),
            dir: Direction::S2c,
        };
        Some(Box::pin(Self::parser_inner(
            strm,
            cb_http,
            cb_ctx,
            rsp_version,
        )))
    }
}

pub(crate) struct HttpFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for HttpFactory<T, P>
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
        let mut parser = Box::new(HttpParser::new());
        parser.cb_start_line = prolens.cb_http_start_line.clone();
        parser.cb_header = prolens.cb_http_header.clone();
        parser.cb_body_start = prolens.cb_http_body_start.clone();
        parser.cb_body = prolens.cb_http_body.clone();
        parser.cb_body_stop = prolens.cb_http_body_stop.clone();
        parser
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct HeaderRet {
    content_len: Option<usize>,
    boundary: Option<String>,
    ce: Option<Vec<Encoding>>,
    te: Option<Vec<Encoding>>,
}

impl HeaderRet {
    fn is_chunked(&self) -> bool {
        if let Some(encodings) = &self.te {
            encodings.iter().rev().any(|enc| *enc == Encoding::Chunked)
        } else {
            false
        }
    }
}

struct HttpBodyParams<'a> {
    bdry: &'a str,
    cb_body_start: Option<&'a CbBodyEvt>,
    cb_body: Option<&'a CbHttpBody>,
    cb_body_stop: Option<&'a CbBodyEvt>,
    cb_ctx: *mut c_void,
    dir: Direction,
    ce: &'a Option<Vec<Encoding>>,
    te: &'a Option<Vec<Encoding>>,
}

#[derive(Clone)]
struct HttpCallbacks {
    pub(crate) start_line: Option<CbStartLine>,
    pub(crate) header: Option<CbHeader>,
    pub(crate) body_start: Option<CbBodyEvt>,
    pub(crate) body: Option<CbHttpBody>,
    pub(crate) body_stop: Option<CbBodyEvt>,
    pub(crate) dir: Direction,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum HttpVersion {
    Http10,
    Http11,
    Http20,
    Unknown,
}

fn req_version(line: &[u8]) -> HttpVersion {
    fn parse_req_version(input: &[u8]) -> IResult<&[u8], HttpVersion> {
        let (input, _) = nom::bytes::complete::take_until(" ")(input)?;
        let (input, _) = tag(b" ")(input)?;

        let (input, _) = nom::bytes::complete::take_until(" ")(input)?;
        let (input, _) = tag(b" ")(input)?;

        let (input, _) = tag_no_case(b"HTTP/")(input)?;

        let (input, version) = take_while1(|c: u8| c.is_ascii_digit() || c == b'.')(input)?;

        let version = match version {
            b"1.0" => HttpVersion::Http10,
            b"1.1" => HttpVersion::Http11,
            b"2.0" => HttpVersion::Http20,
            _ => HttpVersion::Unknown,
        };

        Ok((input, version))
    }

    match parse_req_version(line) {
        Ok((_, version)) => version,
        Err(_) => HttpVersion::Unknown,
    }
}

fn rsp_version(line: &[u8]) -> HttpVersion {
    fn parse_rsp_version(input: &[u8]) -> IResult<&[u8], HttpVersion> {
        let (input, _) = tag_no_case(b"HTTP/")(input)?;

        let (input, version) = take_while1(|c: u8| c.is_ascii_digit() || c == b'.')(input)?;

        let version = match version {
            b"1.0" => HttpVersion::Http10,
            b"1.1" => HttpVersion::Http11,
            b"2.0" => HttpVersion::Http20,
            _ => HttpVersion::Unknown,
        };

        Ok((input, version))
    }

    match parse_rsp_version(line) {
        Ok((_, version)) => version,
        Err(_) => HttpVersion::Unknown,
    }
}

fn content_length(line: &str) -> Option<usize> {
    fn parse_content_length(input: &str) -> IResult<&str, usize> {
        let (input, _) = tag_no_case("content-length:")(input)?;

        let (input, _) = nom::character::complete::space0(input)?;

        let (input, length) = map_res(nom::character::complete::digit1, |s: &str| {
            s.parse::<usize>()
        })(input)?;

        Ok((input, length))
    }

    match parse_content_length(line) {
        Ok((_, length)) => Some(length),
        Err(_) => None,
    }
}

fn transfer_encoding(line: &str) -> Option<Vec<Encoding>> {
    fn parse_transfer_encoding(input: &str) -> IResult<&str, Vec<Encoding>> {
        let (input, _) = tag_no_case("Transfer-Encoding:")(input)?;
        let (input, _) = take_while(|c| c == ' ')(input)?;

        let mut encodings = Vec::new();
        let mut remaining = input;

        loop {
            let (input, encoding) = terminated(
                alt((
                    value(Encoding::Compress, tag_no_case("compress")),
                    value(Encoding::Deflate, tag_no_case("deflate")),
                    value(Encoding::Gzip, tag_no_case("gzip")),
                    value(Encoding::Lzma, tag_no_case("lzma")),
                    value(Encoding::Br, tag_no_case("br")),
                    value(Encoding::Chunked, tag_no_case("chunked")),
                )),
                take_while(|c| c == ' ' || c == ','),
            )(remaining)?;

            encodings.push(encoding);
            remaining = input;

            if remaining.starts_with("\r\n") {
                let (input, _) = tag("\r\n")(remaining)?;
                return Ok((input, encodings));
            }
        }
    }

    match parse_transfer_encoding(line) {
        Ok((_, encodings)) => Some(encodings),
        Err(_) => None,
    }
}

fn content_encoding(line: &str) -> Option<Vec<Encoding>> {
    fn parse_content_encoding(input: &str) -> IResult<&str, Vec<Encoding>> {
        let (input, _) = tag_no_case("Content-Encoding:")(input)?;
        let (input, _) = take_while(|c| c == ' ')(input)?;

        let mut encodings = Vec::new();
        let mut remaining = input;

        loop {
            let (input, encoding) = terminated(
                alt((
                    value(Encoding::Compress, tag_no_case("compress")),
                    value(Encoding::Deflate, tag_no_case("deflate")),
                    value(Encoding::Gzip, tag_no_case("gzip")),
                    value(Encoding::Lzma, tag_no_case("lzma")),
                    value(Encoding::Br, tag_no_case("br")),
                    value(Encoding::Identity, tag_no_case("identity")),
                )),
                take_while(|c| c == ' ' || c == ','),
            )(remaining)?;

            encodings.push(encoding);
            remaining = input;

            if remaining.starts_with("\r\n") {
                let (input, _) = tag("\r\n")(remaining)?;
                return Ok((input, encodings));
            }
        }
    }

    match parse_content_encoding(line) {
        Ok((_, encodings)) => Some(encodings),
        Err(_) => None,
    }
}

fn chunk_size(line: &str) -> Result<usize, ()> {
    fn parse_chunk_size(input: &str) -> IResult<&str, usize> {
        let (input, size) = map_res(take_while1(|c: char| c.is_ascii_hexdigit()), |s: &str| {
            usize::from_str_radix(s, 16)
        })(input)?;

        Ok((input, size))
    }

    match parse_chunk_size(line.trim()) {
        Ok((_, size)) => Ok(size),
        Err(_) => Err(()),
    }
}

static HTTP_METHODS: phf::Set<&'static str> = phf_set! {
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    "COPY", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND", "VIEW",
    "MOVE", "MKCOL", "PROPPATCH", "REPORT", "CHECKOUT", "CHECKIN", "VERSION-CONTROL",
    "MERGE", "MKWORKSPACE", "MKACTIVITY", "BASELINE-CONTROL", "SEARCH"
};

fn req(input: &str) -> bool {
    if input.len() < 3 {
        return false;
    }

    let search_range = &input[..input.len().min(10)];
    let method = match search_range.split_once(|c| [' ', '\r', '\n'].contains(&c)) {
        Some((method, _)) => method,
        None => search_range,
    };

    HTTP_METHODS.contains(method)
}

fn rsp(input: &str) -> bool {
    if input.len() < 7 {
        return false;
    }

    if input.starts_with("HTTP/1.") || input.starts_with("http/1.") {
        return true;
    }
    false
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
    fn test_req() {
        assert!(req("GET /index.html HTTP/1.1\r\n"));
        assert!(req("POST /api/data HTTP/1.1\r\n"));
        assert!(req("HEAD / HTTP/1.1\r\n"));
        assert!(req("OPTIONS * HTTP/1.1\r\n"));
        assert!(req("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(req("PROPFIND /path HTTP/1.1\r\n"));
        assert!(req("MKCOL /new-collection HTTP/1.1\r\n"));

        assert!(!req(""));
        assert!(!req("ABC"));
        assert!(!req("HTTP/1.1 200 OK\r\n"));
        assert!(!req("INVALID /path HTTP/1.1\r\n"));
        assert!(!req("   GET /path HTTP/1.1\r\n"));
    }
    #[test]
    fn test_rsp() {
        assert!(rsp("HTTP/1.1 200 OK\r\n"));
        assert!(rsp("HTTP/1.0 404 Not Found\r\n"));
        assert!(rsp("http/1.1 200 OK\r\n"));

        assert!(!rsp("HTTP/2.0 200 OK\r\n"));
        assert!(!rsp(""));
        assert!(!rsp("GET /index.html HTTP/1.1\r\n"));
        assert!(!rsp("HTTP/3.0 200 OK\r\n"));
        assert!(!rsp("HTTPS/1.1 200 OK\r\n"));
        assert!(!rsp("HTT"));
        assert!(!rsp("     HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn test_http_req_version() {
        assert_eq!(
            req_version(b"GET /path/http/xxx HTTP/1.1\r\n"),
            HttpVersion::Http11
        );
        assert_eq!(req_version(b"GET /path HTTP/1.1\r\n"), HttpVersion::Http11);
        assert_eq!(
            req_version(b"POST /api/data HTTP/2.0\r\n"),
            HttpVersion::Http20
        );
        assert_eq!(
            req_version(b"GET /index.html HTTP/1.0\r\n"),
            HttpVersion::Http10
        );
        assert_eq!(
            req_version(b"GET /110/20403/stodownload?m=a52fbd700e5f5daa6c1ced987931a842&hy=SH&ef=3&bizid=1022 HTTP/1.1\r\n"),
            HttpVersion::Http11
        );
        assert_eq!(req_version(b"Invalid request"), HttpVersion::Unknown);
    }

    #[test]
    fn test_rsp_version() {
        assert_eq!(rsp_version(b"HTTP/1.1 200 OK\r\n"), HttpVersion::Http11);
        assert_eq!(
            rsp_version(b"HTTP/1.0 404 Not Found\r\n"),
            HttpVersion::Http10
        );
        assert_eq!(
            rsp_version(b"HTTP/2.0 500 Internal Server Error\r\n"),
            HttpVersion::Http20
        );
        assert_eq!(
            rsp_version(b"HTTP/1.1 301 Moved Permanently\r\n"),
            HttpVersion::Http11
        );
        assert_eq!(
            rsp_version(b"HTTP/1.1 204 No Content\r\n"),
            HttpVersion::Http11
        );
        assert_eq!(rsp_version(b"Invalid response"), HttpVersion::Unknown);
        assert_eq!(rsp_version(b"GET /path HTTP/1.1\r\n"), HttpVersion::Unknown);
    }

    #[test]
    fn test_http_content_length() {
        assert_eq!(content_length("Content-Length: 2864\r\n"), Some(2864));
        assert_eq!(content_length("CONTENT-LENGTH: 1024\r\n"), Some(1024));
        assert_eq!(content_length("Content-length: 500\r\n"), Some(500));
        assert_eq!(content_length("Content-Length:42\r\n"), Some(42));
        assert_eq!(content_length("Content-Length:  123\r\n"), Some(123));
        assert_eq!(content_length("Content-Type: text/html\r\n"), None);
        assert_eq!(content_length("Content-Length: abc\r\n"), None);
        assert_eq!(content_length(""), None);
    }

    #[test]
    fn test_http_transfer_encoding() {
        assert_eq!(
            transfer_encoding("Transfer-Encoding: chunked\r\n"),
            Some(vec![Encoding::Chunked])
        );
        assert_eq!(
            transfer_encoding("Transfer-Encoding: gzip, deflate, chunked\r\n"),
            Some(vec![Encoding::Gzip, Encoding::Deflate, Encoding::Chunked])
        );
        assert_eq!(
            transfer_encoding("Transfer-Encoding: GZIP, Deflate\r\n"),
            Some(vec![Encoding::Gzip, Encoding::Deflate])
        );
        assert_eq!(
            transfer_encoding("Transfer-Encoding:    chunked   ,   gzip   \r\n"),
            Some(vec![Encoding::Chunked, Encoding::Gzip])
        );
        assert_eq!(transfer_encoding("Transfer-Encoding: invalid\r\n"), None);
        assert_eq!(transfer_encoding("Content-Type: text/plain\r\n"), None);
    }

    #[test]
    fn test_http_content_encoding() {
        assert_eq!(
            content_encoding("Content-Encoding: gzip\r\n"),
            Some(vec![Encoding::Gzip])
        );
        assert_eq!(
            content_encoding("Content-Encoding: gzip, deflate, br\r\n"),
            Some(vec![Encoding::Gzip, Encoding::Deflate, Encoding::Br])
        );
        assert_eq!(
            content_encoding("Content-Encoding: GZIP, Deflate\r\n"),
            Some(vec![Encoding::Gzip, Encoding::Deflate])
        );
        assert_eq!(
            content_encoding("Content-Encoding:    gzip   ,   deflate   \r\n"),
            Some(vec![Encoding::Gzip, Encoding::Deflate])
        );
        assert_eq!(
            content_encoding("Content-Encoding: identity\r\n"),
            Some(vec![Encoding::Identity])
        );
        assert_eq!(content_encoding("Content-Encoding: invalid\r\n"), None);
        assert_eq!(content_encoding("Transfer-Encoding: gzip\r\n"), None);
    }

    #[test]
    fn test_chunk_size() {
        assert_eq!(chunk_size("3F"), Ok(63));
        assert_eq!(chunk_size("A5\r\n"), Ok(165));
        assert_eq!(chunk_size("fF"), Ok(255));

        assert_eq!(chunk_size("3F;part=1"), Ok(63));
        assert_eq!(chunk_size("A5;type=text\r\n"), Ok(165));
        assert_eq!(chunk_size("64;desc=\"test data\""), Ok(100));
        assert_eq!(chunk_size("  3F  "), Ok(63));
        assert_eq!(chunk_size(" A5\t;ext"), Ok(165));

        assert_eq!(chunk_size("0"), Ok(0));
        assert_eq!(chunk_size("0000"), Ok(0));
        assert_eq!(chunk_size("0;end"), Ok(0));

        assert!(chunk_size("").is_err());
        assert!(chunk_size("xyz").is_err());
    }

    #[test]
    fn test_http_content() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/http_content.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let c2s_start_line = Rc::new(RefCell::new(Vec::<u8>::new()));
        let c2s_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_start_line = Rc::new(RefCell::new(Vec::<u8>::new()));
        let sc2_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let start_line_callback = {
            let c2s_start_line_clone = c2s_start_line.clone();
            let s2c_start_line_clone = s2c_start_line.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(line).unwrap());
                if dir == Direction::S2c {
                    let mut s2c_start_line_guard = s2c_start_line_clone.borrow_mut();
                    *s2c_start_line_guard = line.to_vec();
                } else {
                    let mut c2s_start_line_guard = c2s_start_line_clone.borrow_mut();
                    *c2s_start_line_guard = line.to_vec();
                }
            }
        };

        let header_callback = {
            let c2s_headers_clone = c2s_headers.clone();
            let s2c_headers_clone = sc2_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(header).unwrap());
                if dir == Direction::S2c {
                    if header == b"\r\n" {
                        dbg!("header cb. header end");
                    }
                    let mut s2c_headers_guard = s2c_headers_clone.borrow_mut();
                    s2c_headers_guard.push(header.to_vec());
                } else {
                    let mut c2s_headers_guard = c2s_headers_clone.borrow_mut();
                    c2s_headers_guard.push(header.to_vec());
                }
            }
        };

        let body_start_callback = {
            let current_body_clone = s2c_body.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut body_guard = current_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                }
            }
        };

        let body_callback = {
            let current_body_clone = s2c_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  dir: Direction,
                  ce: &Option<Vec<Encoding>>,
                  te: &Option<Vec<Encoding>>| {
                if dir == Direction::S2c {
                    let mut body_guard = current_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);

                    assert_eq!(ce.as_deref(), None);
                    assert_eq!(te.as_deref(), None);
                }
            }
        };

        let body_stop_callback = {
            let current_body_clone = s2c_body.clone();
            let bodies_clone = s2c_bodies.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let body_guard = current_body_clone.borrow();
                    let mut bodies_guard = bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                }
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        protolens.set_cb_http_start_line(start_line_callback);
        protolens.set_cb_http_header(header_callback);
        protolens.set_cb_http_body_start(body_start_callback);
        protolens.set_cb_http_body(body_callback);
        protolens.set_cb_http_body_stop(body_stop_callback);

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
            pkt.set_l7_proto(L7Proto::Http);

            protolens.run_task(&mut task, pkt);
        }

        assert_eq!(c2s_start_line.borrow().as_slice(), b"GET /110/20403/stodownload?m=a52fbd700e5f5daa6c1ced987931a842&filekey=3043020101042f302d02016e040253480420613532666264373030653566356461613663316365643938373933316138343202020b30040d00000004627466730000000132&hy=SH&storeid=26292f43200015e1c8e4ffdb00000006e03004fb3534816cd2a00b663b0d81&ef=3&bizid=1022 HTTP/1.1\r\n");

        let c2s_expected_headers = ["Host: vvvvxxxx.tc.pp.com\r\n", "Accept: */*\r\n", "\r\n"];

        let headers_guard = c2s_headers.borrow();
        assert_eq!(headers_guard.len(), c2s_expected_headers.len());
        for (idx, expected) in c2s_expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        assert_eq!(s2c_start_line.borrow().as_slice(), b"HTTP/1.1 200 OK\r\n");

        let s2c_expected_headers = [
            "Accept-Ranges: bytes\r\n",
            "Access-Control-Allow-Headers: Origin; No-Cache; X-Requested-With; If-Modified-Since; Pragma; Last-Modified; Cache-Control; Expires; Content-Type; Content-Language; Cache-Control; X-E4M-With\r\n",
            "Access-Control-Allow-Origin: *\r\n",
            "C-Seq: \r\n",
            "CONTENT-LENGTH: 2864\r\n",
            "CONTENT-RANGE: bytes 0-2863/2864\r\n",
            "Cache-Control: max-age=2592000\r\n",
            "Content-Type: application/octet-stream\r\n",
            "X-Verify-Code: 9c2ad489537898a28c25aaca03f0190d\r\n",
            "X-encflag: 0\r\n",
            "X-enclen: 0\r\n",
            "X-snsvideoflag: xV0\r\n",
            "serverip: 11.111.66.1\r\n",
            "x-ClientIp: 111.222.222.111\r\n",
            "x-videoerrno: 0\r\n",
            "\r\n",
        ];

        let headers_guard = sc2_headers.borrow();
        assert_eq!(headers_guard.len(), s2c_expected_headers.len());
        for (idx, expected) in s2c_expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = s2c_bodies.borrow();
        assert_eq!(bodies_guard.len(), 1);

        let body0 = &bodies_guard[0];
        assert_eq!(body0.len(), 2864);
        assert_eq!(&body0[0..4], &[0x12, 0x7b, 0x38, 0xac]);
        eprintln!("last bytes: {:02x?}", &body0[body0.len() - 16..]);
        assert_eq!(&body0[body0.len() - 4..], &[0x13, 0xef, 0xeb, 0xb2]);
    }

    #[test]
    fn test_http_mime() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/http_mime.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let c2s_start_line = Rc::new(RefCell::new(Vec::<u8>::new()));
        let c2s_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let c2s_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let c2s_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let s2c_start_line = Rc::new(RefCell::new(Vec::<u8>::new()));
        let s2c_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let start_line_callback = {
            let c2s_start_line_clone = c2s_start_line.clone();
            let s2c_start_line_clone = s2c_start_line.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(line).unwrap());
                if dir == Direction::S2c {
                    let mut s2c_start_line_guard = s2c_start_line_clone.borrow_mut();
                    *s2c_start_line_guard = line.to_vec();
                } else {
                    let mut c2s_start_line_guard = c2s_start_line_clone.borrow_mut();
                    *c2s_start_line_guard = line.to_vec();
                }
            }
        };

        let header_callback = {
            let c2s_headers_clone = c2s_headers.clone();
            let s2c_headers_clone = s2c_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(header).unwrap());
                if dir == Direction::S2c {
                    if header == b"\r\n" {
                        dbg!("header cb. header end");
                    }
                    let mut s2c_headers_guard = s2c_headers_clone.borrow_mut();
                    s2c_headers_guard.push(header.to_vec());
                } else {
                    let mut c2s_headers_guard = c2s_headers_clone.borrow_mut();
                    c2s_headers_guard.push(header.to_vec());
                }
            }
        };

        let body_start_callback = {
            let current_s2c_body_clone = s2c_body.clone();
            let current_c2s_body_clone = c2s_body.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut body_guard = current_s2c_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                } else {
                    let mut body_guard = current_c2s_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                }
            }
        };

        let body_callback = {
            let current_s2c_body_clone = s2c_body.clone();
            let current_c2s_body_clone = c2s_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  dir: Direction,
                  ce: &Option<Vec<Encoding>>,
                  te: &Option<Vec<Encoding>>| {
                if dir == Direction::S2c {
                    let mut body_guard = current_s2c_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);

                    assert_eq!(ce.as_deref(), Some(&[Encoding::Gzip][..]));
                    assert_eq!(te.as_deref(), None);
                } else {
                    let mut body_guard = current_c2s_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);
                }
            }
        };

        let body_stop_callback = {
            let current_s2c_body_clone = s2c_body.clone();
            let s2c_bodies_clone = s2c_bodies.clone();
            let current_c2s_body_clone = c2s_body.clone();
            let c2s_bodies_clone = c2s_bodies.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let body_guard = current_s2c_body_clone.borrow();
                    let mut bodies_guard = s2c_bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                } else {
                    let body_guard = current_c2s_body_clone.borrow();
                    let mut bodies_guard = c2s_bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                }
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        protolens.set_cb_http_start_line(start_line_callback);
        protolens.set_cb_http_header(header_callback);
        protolens.set_cb_http_body_start(body_start_callback);
        protolens.set_cb_http_body(body_callback);
        protolens.set_cb_http_body_stop(body_stop_callback);

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
            pkt.set_l7_proto(L7Proto::Http);

            protolens.run_task(&mut task, pkt);
        }

        assert_eq!(
            c2s_start_line.borrow().as_slice(),
            b"POST /vul/unsafeupload/clientcheck.php HTTP/1.1\r\n"
        );

        let c2s_expected_headers = [
            "Host: 192.168.111.3:9002\r\n",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0\r\n",
            "Accept-Encoding: gzip, deflate\r\n",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
            "Connection: keep-alive\r\n",
            "Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\n",
            "Referer: http://127.0.0.1:9002/vul/unsafeupload/clientcheck.php\r\n",
            "Upgrade-Insecure-Requests: 1\r\n",
            "Content-Type: multipart/form-data; boundary=---------------------------43616034321\r\n",
            "Content-Length: 360\r\n",
            "\r\n",
            "Content-Disposition: form-data; name=\"uploadfile\"; filename=\"7bv9DW2RCm981d7B.php\"\r\n",
            "Content-Type: application/octet-stream\r\n",
            "\r\n",
            "Content-Disposition: form-data; name=\"submit\"\r\n",
            "\r\n",
        ];

        let headers_guard = c2s_headers.borrow();
        assert_eq!(headers_guard.len(), c2s_expected_headers.len());
        for (idx, expected) in c2s_expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = c2s_bodies.borrow();
        assert_eq!(bodies_guard.len(), 2);

        let body0 = &bodies_guard[0];
        let body0_str = std::str::from_utf8(body0).unwrap();
        assert_eq!(body0_str, "<?php eval($_POST['ant']); ?>");

        let body1 = &bodies_guard[1];
        assert_eq!(&body1[0..4], &[0xc3, 0xa5, 0xc2, 0xbc]);
        assert_eq!(&body1[body1.len() - 4..], &[0xc2, 0xbc, 0xc2, 0xa0]);

        assert_eq!(s2c_start_line.borrow().as_slice(), b"HTTP/1.1 200 OK\r\n");

        let s2c_expected_headers = [
            "Date: Mon, 07 Mar 2022 08:06:49 GMT\r\n",
            "Server: Apache/2.4.29 (Ubuntu)\r\n",
            "Vary: Accept-Encoding\r\n",
            "Content-Encoding: gzip\r\n",
            "Content-Length: 4379\r\n",
            "Keep-Alive: timeout=5, max=100\r\n",
            "Connection: Keep-Alive\r\n",
            "Content-Type: text/html; charset=UTF-8\r\n",
            "\r\n",
        ];

        let headers_guard = s2c_headers.borrow();
        assert_eq!(headers_guard.len(), s2c_expected_headers.len());
        for (idx, expected) in s2c_expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = s2c_bodies.borrow();
        assert_eq!(bodies_guard.len(), 1);

        let body0 = &bodies_guard[0];
        assert_eq!(&body0[0..4], &[0x1f, 0x8b, 0x08, 0x00]);
        assert_eq!(&body0[body0.len() - 4..], &[0xf0, 0x86, 0x00, 0x00]);
    }

    #[test]
    fn test_http_chunk() {
        let lines = [
            "HTTP/1.1 200 OK\r\n",
            "Date: Thu, 11 May 2023 06:46:57 GMT\r\n",
            "Content-Encoding: gzip\r\n",
            "Vary: Accept-Encoding\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "8\r\n",
            "12345678\r\n",
            "a\r\n",
            "123456789a\r\n",
            "b\r\n",
            "123456789ab\r\n",
            "0\r\n",
            "X-Powered-By: PHP/7.2.24\r\n",
            "X-ob_mode: 1\r\n",
            "X-Frame-Options: DENY\r\n",
            "\r\n",
        ];

        let s2c_start_line = Rc::new(RefCell::new(Vec::<u8>::new()));
        let s2c_headers = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_bodies = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let s2c_body = Rc::new(RefCell::new(Vec::<u8>::new()));

        let start_line_callback = {
            let s2c_start_line_clone = s2c_start_line.clone();
            move |line: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(line).unwrap());
                if dir == Direction::S2c {
                    let mut s2c_start_line_guard = s2c_start_line_clone.borrow_mut();
                    *s2c_start_line_guard = line.to_vec();
                }
            }
        };

        let header_callback = {
            let s2c_headers_clone = s2c_headers.clone();
            move |header: &[u8], _seq: u32, _cb_ctx: *mut c_void, dir: Direction| {
                dbg!(std::str::from_utf8(header).unwrap());
                if dir == Direction::S2c {
                    if header == b"\r\n" {
                        dbg!("header cb. header end");
                    }
                    let mut s2c_headers_guard = s2c_headers_clone.borrow_mut();
                    s2c_headers_guard.push(header.to_vec());
                }
            }
        };

        let body_start_callback = {
            let current_s2c_body_clone = s2c_body.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let mut body_guard = current_s2c_body_clone.borrow_mut();
                    *body_guard = Vec::new();
                }
            }
        };

        let body_callback = {
            let current_s2c_body_clone = s2c_body.clone();
            move |body: &[u8],
                  _seq: u32,
                  _cb_ctx: *mut c_void,
                  dir: Direction,
                  ce: &Option<Vec<Encoding>>,
                  te: &Option<Vec<Encoding>>| {
                if dir == Direction::S2c {
                    let mut body_guard = current_s2c_body_clone.borrow_mut();
                    body_guard.extend_from_slice(body);

                    assert_eq!(ce.as_deref(), Some(&[Encoding::Gzip][..]));
                    assert_eq!(te.as_deref(), Some(&[Encoding::Chunked][..]));
                }
            }
        };

        let body_stop_callback = {
            let current_s2c_body_clone = s2c_body.clone();
            let s2c_bodies_clone = s2c_bodies.clone();
            move |_cb_ctx: *mut c_void, dir: Direction| {
                if dir == Direction::S2c {
                    let body_guard = current_s2c_body_clone.borrow();
                    let mut bodies_guard = s2c_bodies_clone.borrow_mut();
                    bodies_guard.push(body_guard.clone());
                }
            }
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        let mut task = protolens.new_task();

        protolens.set_cb_http_start_line(start_line_callback);
        protolens.set_cb_http_header(header_callback);
        protolens.set_cb_http_body_start(body_start_callback);
        protolens.set_cb_http_body(body_callback);
        protolens.set_cb_http_body_stop(body_stop_callback);

        let mut seq = 1000;
        for line in lines.iter() {
            let line_bytes = line.as_bytes();
            let pkt = build_pkt_payload(seq, line_bytes);
            let _ = pkt.decode();
            pkt.set_l7_proto(L7Proto::Http);

            protolens.run_task(&mut task, pkt);

            seq += line_bytes.len() as u32;
        }

        assert_eq!(s2c_start_line.borrow().as_slice(), b"HTTP/1.1 200 OK\r\n");

        let s2c_expected_headers = [
            "Date: Thu, 11 May 2023 06:46:57 GMT\r\n",
            "Content-Encoding: gzip\r\n",
            "Vary: Accept-Encoding\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
        ];

        let headers_guard = s2c_headers.borrow();
        assert_eq!(headers_guard.len(), s2c_expected_headers.len());
        for (idx, expected) in s2c_expected_headers.iter().enumerate() {
            assert_eq!(std::str::from_utf8(&headers_guard[idx]).unwrap(), *expected);
        }

        let bodies_guard = s2c_bodies.borrow();
        assert_eq!(bodies_guard.len(), 1);

        let body0 = &bodies_guard[0];
        assert_eq!(*body0, b"12345678123456789a123456789ab");
    }
}
