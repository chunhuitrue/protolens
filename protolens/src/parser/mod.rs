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

use crate::PacketBind;
use crate::PktStrm;
use crate::Prolens;
use crate::PtrNew;
use crate::PtrWrapper;
use crate::ReadRet;
use futures::Future;
use nom::{
    IResult,
    bytes::complete::{tag, take_till},
};
use std::cell::RefCell;
use std::ffi::c_void;
use std::pin::Pin;
use std::rc::Rc;

pub(crate) type ParserFuture = Pin<Box<dyn Future<Output = Result<(), ()>>>>;

pub(crate) trait Parser {
    type PacketType: PacketBind;
    type PtrType: PtrWrapper<Self::PacketType> + PtrNew<Self::PacketType>;

    fn c2s_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn s2c_parser(
        &self,
        _stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        None
    }

    fn bdir_parser(
        &self,
        _c2s_stream: *const PktStrm<Self::PacketType, Self::PtrType>,
        _s2c_stream: *const PktStrm<Self::PacketType, Self::PtrType>,
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

pub trait DataCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> DataCbFn for F {}

pub trait EvtCbFn: FnMut(*mut c_void) {}
impl<F: FnMut(*mut c_void)> EvtCbFn for F {}

pub(crate) type CbUser = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbPass = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbMailFrom = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbRcpt = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbHeader = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbBodyEvt = Rc<RefCell<dyn EvtCbFn + 'static>>;
pub(crate) type CbBody = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbSrv = Rc<RefCell<dyn DataCbFn + 'static>>;
pub(crate) type CbClt = Rc<RefCell<dyn DataCbFn + 'static>>;

pub(crate) async fn header<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_header: Option<CbHeader>,
    cb_ctx: *mut c_void,
) -> Result<Option<String>, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    let mut cont_type = false;
    let mut boundary = String::new();

    dbg!("header. start");
    loop {
        let (line, seq) = stm.read_clean_line_str().await?;

        // 空行也回调。调用者知道header结束
        if let Some(cb) = cb_header.clone() {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
        }
        dbg!(line);

        if line.is_empty() {
            let ret_bdry = if boundary.is_empty() {
                None
            } else {
                Some(boundary)
            };
            dbg!("header. end");
            return Ok(ret_bdry);
        }

        // content-type ext
        // 放在content-type前面是因为。只有content-type结束之后才能作这个判断。
        // 放在前面，cont_type 肯定为false
        if cont_type && boundary.is_empty() {
            match content_type_ext(line) {
                Ok((_, bdry)) => {
                    boundary = bdry.to_string();
                }
                Err(_err) => {}
            }
        }
        // content-type
        match content_type(line) {
            Ok((_input, Some(bdry))) => {
                cont_type = true;
                boundary = bdry.to_string();
            }
            Ok((_input, None)) => {
                cont_type = true;
            }
            Err(_err) => {}
        }
    }
}

pub(crate) async fn body<T, P>(
    stm: &mut PktStrm<T, P>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_ctx: *mut c_void,
) -> Result<bool, ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("body start");
    if let Some(cb) = cb_body_start.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    loop {
        let (line, seq) = stm.readline_str().await?;

        if line == (".\r\n") {
            break;
        }

        dbg!(line);
        if let Some(cb) = cb_body.clone() {
            cb.borrow_mut()(line.as_bytes(), seq, cb_ctx);
        }
    }
    if let Some(cb) = cb_body_stop.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    dbg!("body end");
    Ok(true)
}

pub(crate) async fn multi_body<T, P>(
    stm: &mut PktStrm<T, P>,
    bdry: &str,
    cb_header: Option<CbHeader>,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    preamble(stm, bdry).await?;
    loop {
        if let Some(new_bdry) = header(stm, cb_header.clone(), cb_ctx).await? {
            Box::pin(multi_body(
                stm,
                &new_bdry,
                cb_header.clone(),
                cb_body_start.clone(),
                cb_body.clone(),
                cb_body_stop.clone(),
                cb_ctx,
            ))
            .await?;
        }

        mime_body2(
            stm,
            bdry,
            cb_body_start.clone(),
            cb_body.clone(),
            cb_body_stop.clone(),
            cb_ctx,
        )
        .await?;

        let (byte, _seq) = stm.readn(2).await?;
        if byte.starts_with(b"--") {
            dbg!("muti_body end");
            break;
        } else if byte.starts_with(b"\r\n") {
            continue;
        } else {
            return Err(());
        }
    }
    Ok(())
}

async fn preamble<T, P>(stm: &mut PktStrm<T, P>, bdry: &str) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("preamble start");
    mime_body2(stm, bdry, None, None, None, std::ptr::null_mut()).await?;

    let (byte, _seq) = stm.readn(2).await?;
    if byte == b"\r\n" { Ok(()) } else { Err(()) }
}

async fn mime_body2<T, P>(
    stm: &mut PktStrm<T, P>,
    bdry: &str,
    cb_body_start: Option<CbBodyEvt>,
    cb_body: Option<CbBody>,
    cb_body_stop: Option<CbBodyEvt>,
    cb_ctx: *mut c_void,
) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("mime body start");
    if let Some(cb) = cb_body_start.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    loop {
        let (ret, content, seq) = stm.read_mime_octet(bdry).await?;
        dbg!(std::str::from_utf8(content).unwrap_or(""));
        if let Some(cb) = cb_body.clone() {
            cb.borrow_mut()(content, seq, cb_ctx);
        }

        if ret == ReadRet::DashBdry {
            break;
        }
    }
    if let Some(cb) = cb_body_stop.clone() {
        cb.borrow_mut()(cb_ctx);
    }
    dbg!("mime body end");
    Ok(())
}

async fn epilogue<T, P>(stm: &mut PktStrm<T, P>) -> Result<(), ()>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    dbg!("--------- epilogue start");
    let _ = body(stm, None, None, None, std::ptr::null_mut()).await?;
    dbg!("--------- epilogue end");
    Ok(())
}

// 如果是content type 且带boundary: Content-Type: multipart/mixed; boundary="abc123"
// 返回: (input, some(bdry))
// 如果是content type 不带bdry: Content-Type: multipart/mixed;
// 返回: (input, None)
// 如果不是content type 返回err
fn content_type(input: &str) -> IResult<&str, Option<&str>> {
    let (input, _) = tag("Content-Type: ")(input)?;

    if let Some(start) = input.find("boundary=\"") {
        let input = &input[start..];

        let (input, _) = tag("boundary=\"")(input)?;
        let (input, bdry) = take_till(|c| c == '"')(input)?;
        let (input, _) = tag("\"")(input)?;

        Ok((input, Some(bdry)))
    } else {
        Ok((input, None))
    }
}

// \tboundary="----=_001_NextPart572182624333_=----"
fn content_type_ext(input: &str) -> IResult<&str, &str> {
    let (input, _) = tag("\tboundary=\"")(input)?;
    let (input, bdry) = take_till(|c| c == '"')(input)?;
    Ok((input, bdry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type() {
        // 测试用例1: 包含 boundary 的正常情况
        let input = "Content-Type: multipart/mixed; charset=utf-8; boundary=\"abc123\"";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("abc123"));
        assert!(rest.is_empty());

        // 测试用例2: 包含 boundary 且后面还有其他参数
        let input = "Content-Type: multipart/mixed; boundary=\"xyz789\"; other=value";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("xyz789"));
        assert_eq!(rest, "; other=value");

        // 测试用例3: 不包含 boundary 的情况
        let input = "Content-Type: text/plain; charset=utf-8";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, None);
        assert_eq!(rest, "text/plain; charset=utf-8");

        // 测试用例4: 特殊字符的 boundary
        let input = "Content-Type: multipart/mixed; boundary=\"----=_NextPart_000_0000_01D123456.789ABCDE\"";
        let result = content_type(input);
        assert!(result.is_ok());
        let (rest, boundary) = result.unwrap();
        assert_eq!(boundary, Some("----=_NextPart_000_0000_01D123456.789ABCDE"));
        assert!(rest.is_empty());

        // 测试用例5: 错误格式 - 不是以 Content-Type: 开头
        let input = "Wrong-Type: multipart/mixed; boundary=\"abc123\"";
        let result = content_type(input);
        assert!(result.is_err());
    }
}
