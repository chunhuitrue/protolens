pub mod ftpcmd;
pub mod ftpdata;
pub mod http;
pub mod imap;
pub mod ordpacket;
pub mod pop3;
pub mod smtp;

#[cfg(test)]
pub mod byte;
#[cfg(test)]
pub mod octet;
#[cfg(test)]
pub mod rawpacket;
#[cfg(test)]
pub mod read;
#[cfg(test)]
pub mod readline;
#[cfg(test)]
pub mod readn;

use crate::Direction;
use crate::PacketBind;
use crate::PktStrm;
use crate::Prolens;
use crate::PtrNew;
use crate::PtrWrapper;
use crate::ReadRet;
use futures::Future;
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_till, take_while},
    combinator::value,
    sequence::{preceded, terminated},
};
use std::cell::RefCell;
use std::ffi::c_void;
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;

pub(crate) type ParserFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;

pub(crate) trait Parser {
    type PacketType: PacketBind;
    type PtrType: PtrWrapper<Self::PacketType> + PtrNew<Self::PacketType>;

    fn dir_confirm(
        &self,
        _c2s_strm: *const PktStrm<Self::PacketType, Self::PtrType>,
        _s2c_strm: *const PktStrm<Self::PacketType, Self::PtrType>,
        _c2s_port: u16,
        _s2c_port: u16,
    ) -> bool {
        true // 默认先到的包就是c2s
    }

    fn c2s_parser(
        &self,
        _strm: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn s2c_parser(
        &self,
        _strm: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn bdir_parser(
        &self,
        _c2s_strm: *const PktStrm<Self::PacketType, Self::PtrType>,
        _s2c_strm: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }
}

pub(crate) trait ParserFactory<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn new() -> Self
    where
        Self: Sized;
    fn create(&self, prolens: &Prolens<T, P>) -> Box<dyn Parser<PacketType = T, PtrType = P>>;
}

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

pub(crate) async fn header<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_header: Option<&CbHeader>,
    cb_ctx: *mut c_void,
    dir: Direction,
) -> Result<(Option<String>, Option<TransferEncoding>), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
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

pub(crate) async fn body<T, P>(
    stm: &mut PktStrm<T, P>,
    te: Option<TransferEncoding>,
    cb_body_start: Option<&CbBodyEvt>,
    cb_body: Option<&CbBody>,
    cb_body_stop: Option<&CbBodyEvt>,
    cb_ctx: *mut c_void,
    dir: Direction,
) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
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

pub(crate) async fn multi_body<T, P>(
    stm: &mut PktStrm<T, P>,
    out_bdry: &str,
    bdry: &str,
    cb: &Callbacks,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
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

pub(crate) async fn preamble<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let params = MimeBodyParams {
        te: None,
        bdry,
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
    te: Option<TransferEncoding>,
    bdry: &'a str,
    cb_body_start: Option<&'a CbBodyEvt>,
    cb_body: Option<&'a CbBody>,
    cb_body_stop: Option<&'a CbBodyEvt>,
    cb_ctx: *mut c_void,
    dir: Direction,
}

pub(crate) async fn mime_body<T, P>(
    stm: &mut PktStrm<T, P>,
    params: MimeBodyParams<'_>,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    if let Some(cb) = params.cb_body_start {
        cb.borrow_mut()(params.cb_ctx, params.dir);
    }
    loop {
        let (ret, content, seq) = stm.read_mime_octet(params.bdry).await?;

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

pub(crate) async fn epilogue<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
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
