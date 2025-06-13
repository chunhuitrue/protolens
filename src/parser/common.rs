use crate::dnsudp::Qclass;
use crate::{Direction, Header, OptRR, Packet, PktStrm, Qtype, RR, ReadRet};
use memchr::memmem::Finder;
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_till, take_while},
    combinator::{map_res, value},
    sequence::{preceded, terminated},
};
use std::cell::RefCell;
use std::ffi::c_void;
use std::net::IpAddr;
use std::rc::Rc;

pub trait OrdPktCbFn<T>: FnMut(T, *mut c_void, Direction) {}
impl<F, T> OrdPktCbFn<T> for F where F: FnMut(T, *mut c_void, Direction) {}

pub trait DataCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> DataCbFn for F {}

pub trait DataCbDirFn: FnMut(&[u8], u32, *mut c_void, Direction) {}
impl<F: FnMut(&[u8], u32, *mut c_void, Direction)> DataCbDirFn for F {}

pub trait EvtCbFn: FnMut(*mut c_void, Direction) {}
impl<F: FnMut(*mut c_void, Direction)> EvtCbFn for F {}

pub trait BodyCbFn: FnMut(&[u8], u32, *mut c_void, Direction, Option<TransferEncoding>) {}
impl<F: FnMut(&[u8], u32, *mut c_void, Direction, Option<TransferEncoding>)> BodyCbFn for F {}

pub trait HttpBodyCbFn:
    FnMut(
    &[u8],
    u32,
    *mut c_void,
    Direction,
    &Option<Vec<Encoding>>,      // ce
    &Option<Vec<Encoding>>,      // te
)
{
}
impl<
    F: FnMut(
        &[u8],
        u32,
        *mut c_void,
        Direction,
        &Option<Vec<Encoding>>, // ce
        &Option<Vec<Encoding>>, // te
    ),
> HttpBodyCbFn for F
{
}

pub trait FtpLinkCbFn: FnMut(Option<IpAddr>, u16, *mut c_void, Direction) {}
impl<F: FnMut(Option<IpAddr>, u16, *mut c_void, Direction)> FtpLinkCbFn for F {}

pub trait SipBodyCbFn: FnMut(&[u8], u32, *mut c_void, Direction) {}
impl<F: FnMut(&[u8], u32, *mut c_void, Direction)> SipBodyCbFn for F {}

pub trait DnsHeaderCbFn: FnMut(Header, usize, *mut c_void) {}
impl<F: FnMut(Header, usize, *mut c_void)> DnsHeaderCbFn for F {}

pub trait DnsQueryCbFn: FnMut(&[u8], Qtype, Qclass, bool, usize, *mut c_void) {}
impl<F: FnMut(&[u8], Qtype, Qclass, bool, usize, *mut c_void)> DnsQueryCbFn for F {}

pub trait DnsRrCbFn: FnMut(RR, usize, *mut c_void) {}
impl<F: FnMut(RR, usize, *mut c_void)> DnsRrCbFn for F {}

pub trait DnsOptRrCbFn: FnMut(OptRR, usize, *mut c_void) {}
impl<F: FnMut(OptRR, usize, *mut c_void)> DnsOptRrCbFn for F {}

pub trait DnsEndCbFn: FnMut(*mut c_void) {}
impl<F: FnMut(*mut c_void)> DnsEndCbFn for F {}

pub(crate) type CbOrdPkt<T> = Rc<RefCell<dyn OrdPktCbFn<T> + 'static>>;
pub(crate) type CbUser = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbPass = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbMailFrom = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbRcpt = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbSrv = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbClt = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbHeader = Rc<RefCell<dyn DataCbDirFn + 'static>>;
pub(crate) type CbBodyEvt = Rc<RefCell<dyn EvtCbFn + 'static>>;
pub(crate) type CbBody = Rc<RefCell<dyn BodyCbFn + 'static>>;
pub(crate) type CbStartLine = Rc<RefCell<dyn DataCbDirFn + 'static>>;
pub(crate) type CbHttpBody = Rc<RefCell<dyn HttpBodyCbFn + 'static>>;
pub(crate) type CbFtpLink = Rc<RefCell<dyn FtpLinkCbFn + 'static>>;
pub(crate) type CbFtpBody = Rc<RefCell<dyn DataCbDirFn + 'static>>;
pub(crate) type CbSipBody = Rc<RefCell<dyn SipBodyCbFn + 'static>>;
pub(crate) type CbDnsHeader = Rc<RefCell<dyn DnsHeaderCbFn + 'static>>;
pub(crate) type CbDnsQuery = Rc<RefCell<dyn DnsQueryCbFn + 'static>>;
pub(crate) type CbDnsAnswer = Rc<RefCell<dyn DnsRrCbFn + 'static>>;
pub(crate) type CbDnsAuth = Rc<RefCell<dyn DnsRrCbFn + 'static>>;
pub(crate) type CbDnsAdd = Rc<RefCell<dyn DnsRrCbFn + 'static>>;
pub(crate) type CbDnsOptAdd = Rc<RefCell<dyn DnsOptRrCbFn + 'static>>;
pub(crate) type CbDnsEnd = Rc<RefCell<dyn DnsEndCbFn + 'static>>;

#[derive(Clone)]
pub(crate) struct Callbacks {
    pub(crate) header: Option<CbHeader>,
    pub(crate) body_start: Option<CbBodyEvt>,
    pub(crate) body: Option<CbBody>,
    pub(crate) body_stop: Option<CbBodyEvt>,
    pub(crate) clt: Option<CbClt>,
    pub(crate) srv: Option<CbSrv>,
    pub(crate) dir: Direction,
}

pub(crate) async fn header<T>(
    stm: &mut PktStrm<T>,
    cb_header: Option<&CbHeader>,
    cb_ctx: *mut c_void,
    dir: Direction,
) -> Result<(Option<String>, Option<TransferEncoding>), ()>
where
    T: Packet,
{
    let mut cont_type = false;
    let mut boundary = None;
    let mut te = None;

    loop {
        let (line, seq) = stm.readline_str().await?;

        if let Some(cb) = cb_header {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx, dir);
        }

        if line == "\r\n" {
            return Ok((boundary, te));
        }

        if te.is_none() {
            te = transfer_encoding(line.as_bytes());
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

pub(crate) async fn body<T>(
    stm: &mut PktStrm<T>,
    te: Option<TransferEncoding>,
    cb_body_start: Option<&CbBodyEvt>,
    cb_body: Option<&CbBody>,
    cb_body_stop: Option<&CbBodyEvt>,
    cb_ctx: *mut c_void,
    dir: Direction,
) -> Result<bool, ()>
where
    T: Packet,
{
    if let Some(cb) = cb_body_start {
        cb.borrow_mut()(cb_ctx, dir);
    }
    loop {
        let (line, seq) = stm.readline_str().await?;

        if line == ".\r\n" {
            break;
        }

        if let Some(cb) = &cb_body {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx, dir, te.clone());
        }
    }
    if let Some(cb) = cb_body_stop {
        cb.borrow_mut()(cb_ctx, dir);
    }
    Ok(true)
}

pub(crate) async fn multi_body<T>(
    stm: &mut PktStrm<T>,
    out_bdry: &str,
    bdry: &str,
    cb: &Callbacks,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: Packet,
{
    let bdry_finder = Finder::new(bdry);

    preamble(stm, bdry).await?;
    loop {
        let (boundary, te) = header(stm, cb.header.as_ref(), cb_ctx, cb.dir).await?;

        if let Some(new_bdry) = boundary {
            Box::pin(multi_body(stm, out_bdry, &new_bdry, cb, cb_ctx)).await?;
            continue;
        } else {
            let params = MimeBodyParams {
                te,
                bdry,
                bdry_finder: Some(&bdry_finder),
                cb_body_start: cb.body_start.as_ref(),
                cb_body: cb.body.as_ref(),
                cb_body_stop: cb.body_stop.as_ref(),
                cb_ctx,
                dir: cb.dir,
            };
            mime_body(stm, params).await?;
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
    epilogue(stm, out_bdry).await?;
    Ok(())
}

pub(crate) async fn preamble<T>(stm: &mut PktStrm<T>, bdry: &str) -> Result<(), ()>
where
    T: Packet,
{
    let bdry_finder = Finder::new(bdry);
    let params = MimeBodyParams {
        te: None,
        bdry,
        bdry_finder: Some(&bdry_finder),
        cb_body_start: None,
        cb_body: None,
        cb_body_stop: None,
        cb_ctx: std::ptr::null_mut(),
        dir: Direction::Unknown,
    };
    mime_body(stm, params).await?;

    let (byte, _seq) = stm.readn(2).await?;
    if byte == b"\r\n" { Ok(()) } else { Err(()) }
}

pub(crate) struct MimeBodyParams<'a> {
    pub(crate) te: Option<TransferEncoding>,
    pub(crate) bdry: &'a str,
    pub(crate) bdry_finder: Option<&'a Finder<'a>>,
    pub(crate) cb_body_start: Option<&'a CbBodyEvt>,
    pub(crate) cb_body: Option<&'a CbBody>,
    pub(crate) cb_body_stop: Option<&'a CbBodyEvt>,
    pub(crate) cb_ctx: *mut c_void,
    pub(crate) dir: Direction,
}

pub(crate) async fn mime_body<T>(stm: &mut PktStrm<T>, params: MimeBodyParams<'_>) -> Result<(), ()>
where
    T: Packet,
{
    if params.bdry_finder.is_none() {
        return Err(());
    }

    if let Some(cb) = params.cb_body_start {
        cb.borrow_mut()(params.cb_ctx, params.dir);
    }
    loop {
        let (ret, content, seq) = stm
            .read_mime_octet2(params.bdry_finder.unwrap(), params.bdry)
            .await?;

        if let Some(cb) = params.cb_body {
            cb.borrow_mut()(content, seq, params.cb_ctx, params.dir, params.te.clone());
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

pub(crate) async fn epilogue<T>(stm: &mut PktStrm<T>, bdry: &str) -> Result<(), ()>
where
    T: Packet,
{
    loop {
        let (line, _seq) = stm.readline_str().await?;

        if line == ".\r\n" || dash_bdry(line, bdry) {
            break;
        }
    }
    Ok(())
}

pub(crate) fn dash_bdry(line: &str, bdry: &str) -> bool {
    if line.starts_with("--") && line[2..].starts_with(bdry) && line[line.len() - 2..] == *"\r\n" {
        return true;
    }
    false
}

// 如果是content type 且带boundary: Content-Type: multipart/mixed; boundary="abc123"
// 返回: (input, some(bdry))
// 如果是content type 不带bdry: Content-Type: multipart/mixed;
// 返回: (input, None)
// 如果不是content type 返回err
pub(crate) fn content_type(input: &str) -> IResult<&str, Option<&str>> {
    let (input, _) = tag("Content-Type: ")(input)?;

    if let Some(start) = input.find("boundary=\"") {
        let input = &input[start..];

        let (input, _) = tag("boundary=\"")(input)?;
        let (input, bdry) = take_till(|c| c == '"')(input)?;
        let (input, _) = tag("\"")(input)?;

        Ok((input, Some(bdry)))
    } else if let Some(start) = input.find("boundary=") {
        let input = &input[start..];

        let (input, _) = tag("boundary=")(input)?;
        let (input, bdry) = take_till(|c| c == ';' || c == ' ' || c == '\r')(input)?;

        Ok((input, Some(bdry)))
    } else {
        Ok((input, None))
    }
}

// \tboundary="----=_001_NextPart572182624333_=----" 或 \tboundary=----=_001_NextPart572182624333_=----
pub(crate) fn content_type_ext(input: &str) -> IResult<&str, &str> {
    if input.starts_with("\tboundary=\"") {
        let (input, _) = tag("\tboundary=\"")(input)?;
        let (input, bdry) = take_till(|c| c == '"')(input)?;
        let (input, _) = tag("\"")(input)?;
        Ok((input, bdry))
    } else {
        let (input, _) = tag("\tboundary=")(input)?;
        let (input, bdry) = take_till(|c| c == ';' || c == ' ' || c == '\r')(input)?;
        Ok((input, bdry))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TransferEncoding {
    Bit7,
    Bit8,
    Binary,
    QuotedPrintable,
    Base64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Encoding {
    Compress,
    Deflate,
    Gzip,
    Lzma,
    Br,
    Identity,
    Chunked,
}

fn transfer_encoding(input: &[u8]) -> Option<TransferEncoding> {
    let mut parser = preceded::<_, _, _, nom::error::Error<&[u8]>, _, _>(
        tag_no_case("Content-Transfer-Encoding:"),
        preceded(
            take_while(|c| c == b' '),
            terminated(
                alt((
                    value(TransferEncoding::Bit7, tag_no_case("7bit")),
                    value(TransferEncoding::Bit8, tag_no_case("8bit")),
                    value(TransferEncoding::Binary, tag_no_case("binary")),
                    value(
                        TransferEncoding::QuotedPrintable,
                        tag_no_case("quoted-printable"),
                    ),
                    value(TransferEncoding::Base64, tag_no_case("base64")),
                )),
                tag("\r\n"),
            ),
        ),
    );

    match parser(input) {
        Ok((_, encoding)) => Some(encoding),
        Err(_) => None,
    }
}

pub(crate) fn content_length(line: &str) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type() {
        // 不带引号,带\r\n
        let input = "Content-Type: multipart/form-data; boundary=---------------------------43616034321\r\n";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("---------------------------43616034321"));
        assert_eq!(rest, "\r\n");

        //  包含 boundary 的正常情况
        let input = "Content-Type: multipart/mixed; charset=utf-8; boundary=\"abc123\"";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("abc123"));
        assert!(rest.is_empty());

        //  包含 boundary 且后面还有其他参数
        let input = "Content-Type: multipart/mixed; boundary=\"xyz789\"; other=value";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("xyz789"));
        assert_eq!(rest, "; other=value");

        // 不包含 boundary 的情况
        let input = "Content-Type: text/plain; charset=utf-8";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, None);
        assert_eq!(rest, "text/plain; charset=utf-8");

        //  特殊字符的 boundary
        let input = "Content-Type: multipart/mixed; boundary=\"----=_NextPart_000_0000_01D123456.789ABCDE\"";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("----=_NextPart_000_0000_01D123456.789ABCDE"));
        assert!(rest.is_empty());

        // 不是以 Content-Type: 开头
        let input = "Wrong-Type: multipart/mixed; boundary=\"abc123\"";
        let result = content_type(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_content_type_ext() {
        // 带引号的情况
        let input = "\tboundary=\"----=_001_NextPart572182624333_=----\"";
        let result = content_type_ext(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, "----=_001_NextPart572182624333_=----");
        assert!(rest.is_empty());

        // 不带引号的情况
        let input = "\tboundary=----=_001_NextPart572182624333_=----";
        let result = content_type_ext(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, "----=_001_NextPart572182624333_=----");
        assert!(rest.is_empty());

        // 不带引号且后面有分号的情况
        let input = "\tboundary=----=_001_NextPart572182624333_=----;";
        let result = content_type_ext(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, "----=_001_NextPart572182624333_=----");
        assert_eq!(rest, ";");

        // 不带引号且后面有空格的情况
        let input = "\tboundary=----=_001_NextPart572182624333_=---- ";
        let result = content_type_ext(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, "----=_001_NextPart572182624333_=----");
        assert_eq!(rest, " ");

        // 不带引号且后面有回车的情况
        let input = "\tboundary=----=_001_NextPart572182624333_=----\r\n";
        let result = content_type_ext(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, "----=_001_NextPart572182624333_=----");
        assert_eq!(rest, "\r\n");

        // 格式错误的情况
        let input = "\twrong=----=_001_NextPart572182624333_=----";
        let result = content_type_ext(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_transfer_encoding() {
        assert_eq!(
            transfer_encoding(b"Content-Transfer-Encoding: base64\r\n"),
            Some(TransferEncoding::Base64)
        );
        assert_eq!(
            transfer_encoding(b"Content-Transfer-Encoding: 7BIT\r\n"),
            Some(TransferEncoding::Bit7)
        );
        assert_eq!(
            transfer_encoding(b"Content-Transfer-Encoding:quoted-printable\r\n"),
            Some(TransferEncoding::QuotedPrintable)
        );
        assert_eq!(
            transfer_encoding(b"Content-Transfer-Encoding: invalid\r\n"),
            None
        );
    }
}
