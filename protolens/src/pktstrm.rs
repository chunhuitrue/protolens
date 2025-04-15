use crate::Heap;
use crate::packet::*;
use futures::Future;
use futures::future::poll_fn;
use futures_util::stream::{Stream, StreamExt};
use std::cell::RefCell;
use std::ffi::c_void;
use std::fmt;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Context;
use std::task::Poll;

#[derive(Debug, PartialEq)]
pub(crate) enum ReadError {
    Eof,    // 连接已结束
    NoData, // 没有足够的数据
}

enum FillRet {
    OK,    // 填充正常,
    Final, // buff满(尝试太多next而没真正读取), 或者fin。无法填充
    NoPkt, // 当前没有数据包到来，无法填充
}

#[derive(PartialEq, Debug)]
pub(crate) enum ReadRet {
    Data,     // 正常读到了一部分数据
    DashBdry, // 读到了 "\r\n--"+boundary，同时也携带数据
}

pub trait StmCbFn: FnMut(&[u8], u32, *const c_void) {}
impl<F> StmCbFn for F where F: FnMut(&[u8], u32, *const c_void) {}
pub type CbStrm = Rc<RefCell<dyn StmCbFn + 'static>>;

pub(crate) struct PktStrm<T, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    heap: Heap<PacketWrapper<T, P>>,

    max_buff: usize,
    buff: Vec<u8>,
    buff_start: usize, // 开始的index(绝对值)
    buff_len: usize,
    buff_next: usize, // pool next的待读取的index（绝对值）
    read_size: usize, // 已经读取的总字节数

    next_seq: u32, // 待读取的seq
    fin: bool,

    // 只有成功返回的才会被callback，比如hello\nxxx。对readline来说，hello\n成功读取，然后调用callback。
    // 后续的xxx不会调用callback
    cb_strm: Option<CbStrm>,
    cb_ctx: *const c_void, // 只在c语言api中使用
}

impl<T, P> PktStrm<T, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    pub(crate) fn new(max_pkt_buff: usize, max_read_buff: usize, cb_ctx: *const c_void) -> Self {
        PktStrm {
            heap: Heap::new(max_pkt_buff),

            max_buff: max_read_buff,
            buff: vec![0; max_read_buff],
            buff_start: 0,
            buff_len: 0,
            buff_next: 0,
            read_size: 0,

            next_seq: 0,
            fin: false,

            cb_strm: None,
            cb_ctx,
        }
    }

    pub(crate) fn set_cb<F>(&mut self, callback: F)
    where
        F: StmCbFn + 'static,
    {
        self.cb_strm = Some(Rc::new(RefCell::new(callback)));
    }

    pub(crate) fn push(&mut self, packet: PacketWrapper<T, P>) {
        if self.fin {
            return;
        }

        if packet.ptr.trans_proto() != TransProto::Tcp {
            return;
        }
        if self.heap.len() >= self.heap.capacity() {
            return;
        }

        self.heap.push(packet);
    }

    // 无论是否严格seq连续，peek一个当前最有序的包
    // 不更新next_seq
    pub(crate) fn peek(&self) -> Option<&T> {
        if self.fin {
            return None;
        }
        self.heap.peek().map(|p| &*p.ptr)
    }

    // 无论是否严格seq连续，都pop一个当前包。
    // 注意：next_seq由调用者负责
    pub(crate) fn pop(&mut self) -> Option<PacketWrapper<T, P>> {
        if let Some(wrapper) = self.heap.pop() {
            if wrapper.ptr.fin() {
                self.fin = true;
            }
            return Some(wrapper);
        }
        None
    }

    // top位置和当前next_seq对比并去重
    fn top_dedup(&mut self) {
        while let Some(pkt) = self.peek() {
            if (pkt.fin() && pkt.payload_len() == 0) || (pkt.syn() && pkt.payload_len() == 0) {
                return;
            }

            if pkt.seq() + pkt.payload_len() as u32 <= self.next_seq {
                self.pop();
                continue;
            }
            return;
        }
    }

    pub(crate) fn peek_ord(&mut self) -> Option<&T> {
        if let Some((pkt, _next_seq)) = self.peek_ord_with_seq() {
            Some(pkt)
        } else {
            None
        }
    }

    // 严格有序。peek一个seq严格有序的包，可能包含payload为0的。如果当前top有序，就peek，否则就none。
    pub(crate) fn peek_ord_with_seq(&mut self) -> Option<(&T, u32)> {
        if self.fin {
            return None;
        }

        if self.next_seq == 0 {
            if let Some(pkt) = self.peek() {
                self.next_seq = pkt.seq();
            }
            if let Some(pkt) = self.peek() {
                return Some((pkt, self.next_seq));
            } else {
                return None;
            }
        }

        self.top_dedup();
        if let Some(pkt) = self.peek() {
            if pkt.seq() <= self.next_seq {
                return Some((pkt, self.next_seq));
            }
        }
        None
    }

    // 严格有序。弹出一个严格有序的包，可能包含载荷为0的。否则为none
    // 并不需要关心fin标记，这不是pkt这一层关心的问题
    pub(crate) fn pop_ord(&mut self) -> Option<PacketWrapper<T, P>> {
        if self.fin {
            return None;
        }

        if let Some(pkt) = self.peek_ord() {
            let seq = pkt.seq();
            let payload_len = pkt.payload_len() as u32;
            if pkt.syn() && payload_len == 0 {
                self.next_seq += 1;
            } else if self.next_seq == seq {
                self.next_seq += payload_len;
            } else if self.next_seq > seq {
                self.next_seq += payload_len - (self.next_seq - seq);
            }
            return self.pop();
        }
        None
    }

    // 严格有序。peek出一个带数据的严格有序的包。否则为none
    #[allow(dead_code)]
    pub(crate) fn peek_ord_data(&mut self) -> Option<&T> {
        if let Some((pkt, _nex_seq)) = self.peek_ord_data_with_seq() {
            Some(pkt)
        } else {
            None
        }
    }

    // 严格有序。peek出一个带数据的严格有序的包。同时返回next_seq
    pub(crate) fn peek_ord_data_with_seq(&mut self) -> Option<(&T, u32)> {
        if self.fin {
            return None;
        }

        while let Some(pkt) = self.peek_ord() {
            if pkt.payload_len() == 0 {
                self.pop_ord();
                continue;
            }

            break;
        }
        self.peek_ord_with_seq()
    }

    // 严格有序。pop一个带数据的严格有序的包。否则为none
    #[allow(dead_code)]
    pub(crate) fn pop_ord_data(&mut self) -> Option<PacketWrapper<T, P>> {
        if self.fin {
            return None;
        }

        if let Some(pkt) = self.peek_ord_data() {
            let seq = pkt.seq();
            let payload_len = pkt.payload_len() as u32;
            match self.next_seq.cmp(&seq) {
                std::cmp::Ordering::Equal => self.next_seq += payload_len,
                std::cmp::Ordering::Greater => self.next_seq += payload_len - (self.next_seq - seq),
                std::cmp::Ordering::Less => {}
            }
            return self.pop();
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.heap.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn fin(&self) -> bool {
        self.fin
    }

    // 严格读到n个字节返回。但最大不超过max_buff
    pub(crate) async fn readn_err(&mut self, n: usize) -> Result<(&[u8], u32), ReadError> {
        if n > self.max_buff {
            return Err(ReadError::NoData);
        }

        for _ in 0..n {
            match self.next().await {
                Some(_byte) => {}
                None => {
                    if self.fin {
                        return Err(ReadError::Eof);
                    }
                    return Err(ReadError::NoData);
                }
            }
        }
        self.get_buff_data(0)
    }

    pub(crate) async fn readn(&mut self, n: usize) -> Result<(&[u8], u32), ()> {
        match self.readn_err(n).await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    // n可以大于MAX_BUFF，但最大返回MAX_BUFF
    // 比如读1M读数据。循环传入剩余总量，但每次返回最大MAX_BUFF
    pub(crate) async fn read_err(&mut self, n: usize) -> Result<(&[u8], u32), ReadError> {
        let num = std::cmp::min(n, self.max_buff);
        self.readn_err(num).await
    }

    pub(crate) async fn read(&mut self, n: usize) -> Result<(&[u8], u32), ()> {
        match self.read_err(n).await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    pub(crate) async fn read2eof(&mut self) -> Result<(&[u8], u32), ReadError> {
        if self.fin {
            return Err(ReadError::Eof);
        }

        let mut get_byte = false;
        for _ in 0..self.max_buff {
            match self.next().await {
                Some(_byte) => get_byte = true,
                None => break,
            }
        }

        if get_byte {
            self.get_buff_data(0)
        } else {
            Err(ReadError::NoData)
        }
    }

    async fn readline_inner(&mut self, ignore: usize) -> Result<(&[u8], u32), ReadError> {
        // 0: 正常读取
        // 1: 读到\r
        let mut state = 0;

        // 一行最多不能超过buff大小
        for _ in 0..self.max_buff {
            match self.next().await {
                Some(byte) => {
                    match state {
                        0 => {
                            // 正常状态
                            if byte == b'\r' {
                                state = 1;
                            }
                        }
                        1 => {
                            // 已读到\r
                            if byte == b'\n' {
                                return self.get_buff_data(ignore);
                            } else if byte == b'\r' {
                                state = 1;
                            } else {
                                state = 0;
                            }
                        }
                        _ => {
                            return Err(ReadError::NoData);
                        }
                    }
                }
                None => {
                    if self.fin {
                        return Err(ReadError::Eof);
                    }
                    return Err(ReadError::NoData);
                }
            }
        }
        Err(ReadError::NoData)
    }

    // 包含\r\n
    pub(crate) async fn readline_err(&mut self) -> Result<(&[u8], u32), ReadError> {
        self.readline_inner(0).await
    }

    pub(crate) async fn readline(&mut self) -> Result<(&[u8], u32), ()> {
        match self.readline_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    pub(crate) async fn readline_str_err(&mut self) -> Result<(&str, u32), ReadError> {
        let (line, seq) = self.readline_err().await?;
        Ok((unsafe { std::str::from_utf8_unchecked(line) }, seq))
    }

    pub(crate) async fn readline_str(&mut self) -> Result<(&str, u32), ()> {
        match self.readline_str_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    // 不带\r\n
    pub(crate) async fn read_clean_line_err(&mut self) -> Result<(&[u8], u32), ReadError> {
        self.readline_inner(2).await
    }

    pub(crate) async fn read_clean_line(&mut self) -> Result<(&[u8], u32), ()> {
        match self.read_clean_line_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    // 在read_clean_line基础上，返回str而不是u8
    pub(crate) async fn read_clean_line_str_err(&mut self) -> Result<(&str, u32), ReadError> {
        let (line, seq) = self.read_clean_line_err().await?;
        Ok((unsafe { std::str::from_utf8_unchecked(line) }, seq))
    }

    pub(crate) async fn read_clean_line_str(&mut self) -> Result<(&str, u32), ()> {
        match self.read_clean_line_str_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    pub(crate) async fn peekline_str_err(&mut self) -> Result<&str, ReadError> {
        // 0: 正常读取
        // 1: 读到\r
        let mut state = 0;

        for i in 0..self.max_buff {
            match self.next().await {
                Some(byte) => {
                    match state {
                        0 => {
                            // 正常状态
                            if byte == b'\r' {
                                state = 1;
                            }
                        }
                        1 => {
                            // 已读到\r
                            if byte == b'\n' {
                                let data_len = i + 1;
                                let data =
                                    &self.buff[self.buff_start..(self.buff_start + data_len)];
                                let result = Ok(unsafe { std::str::from_utf8_unchecked(data) });
                                self.buff_next -= data_len;
                                return result;
                            } else if byte == b'\r' {
                                state = 1;
                            } else {
                                state = 0;
                            }
                        }
                        _ => {
                            return Err(ReadError::NoData);
                        }
                    }
                }
                None => {
                    if self.fin {
                        return Err(ReadError::Eof);
                    }
                    return Err(ReadError::NoData);
                }
            }
        }
        Err(ReadError::NoData)
    }

    pub(crate) async fn peekline_str(&mut self) -> Result<&str, ()> {
        match self.peekline_str_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    // 有或者没有octect
    // 有则读到\r\n--bdry
    // 没有则读到 --bdry
    // 但不包括bdry结束的\r\n
    pub(crate) async fn read_mime_octet_err(
        &mut self,
        bdry: &str,
    ) -> Result<(ReadRet, &[u8], u32), ReadError> {
        // 0: 正常读取
        // 1: 读到\r
        // 2: 读到\n
        // 3: 读到-
        // 4: 读到第二个-
        let mut state = 0;
        let bdry_bytes = bdry.as_bytes();
        let mut bdry_index = 0;
        let mut match_len = 0;

        for _ in 0..self.max_buff {
            match self.next().await {
                Some(byte) => {
                    match state {
                        0 => {
                            // 正常状态
                            if byte == b'\r' {
                                state = 1;
                                match_len = 1;
                            } else if byte == b'-' {
                                state = 3;
                                match_len = 1;
                            }
                        }
                        1 => {
                            // 已读到\r
                            if byte == b'\n' {
                                state = 2;
                                match_len += 1;
                            } else if byte == b'\r' {
                                state = 1;
                                match_len = 1;
                            } else if byte == b'-' {
                                state = 3;
                                match_len = 1;
                            } else {
                                state = 0;
                                match_len = 0;
                            }
                        }
                        2 => {
                            // 已读到\r\n
                            if byte == b'-' {
                                state = 3;
                                match_len += 1;
                            } else if byte == b'\r' {
                                state = 1;
                                match_len = 1;
                            } else {
                                state = 0;
                                match_len = 0;
                            }
                        }
                        3 => {
                            // 已读到\r\n- 或者 -
                            if byte == b'-' {
                                state = 4;
                                bdry_index = 0;
                                match_len += 1;
                            } else if byte == b'\r' {
                                state = 1;
                                match_len = 1;
                            } else {
                                state = 0;
                                match_len = 0;
                            }
                        }
                        4 => {
                            // 已读到\r\n--或--，开始匹配boundary
                            if bdry_index < bdry_bytes.len() && byte == bdry_bytes[bdry_index] {
                                bdry_index += 1;
                                match_len += 1;
                                if bdry_index == bdry_bytes.len() {
                                    // dash bdry匹配了，返回
                                    let (data, seq) = self.get_buff_data(match_len)?;
                                    return Ok((ReadRet::DashBdry, data, seq));
                                }
                            } else if byte == b'\r' {
                                state = 1;
                                match_len = 1;
                            } else if byte == b'-' {
                                state = 3;
                                match_len = 1;
                            } else {
                                state = 0;
                                match_len = 0;
                            }
                        }
                        _ => {
                            return Err(ReadError::NoData);
                        }
                    }
                }
                None => {
                    // for 循环buff长度过程中如果返回None，不会是到达buff边界，只能是fin
                    // 如果读到fin都没读到dash bdry。说明有错。
                    // 虽然此时buff中仍然有读到的数据。但直接出错，不返回数据
                    if self.fin {
                        return Err(ReadError::Eof);
                    }
                    return Err(ReadError::NoData);
                }
            }
        }

        // 处理可能的情况[++++++\r\n--boun]dary
        if match_len > 0 {
            self.buff_next -= match_len; // 把match到的部分bdry留在buff中，下次继续match
        }
        let (data, seq) = self.get_buff_data(0)?;
        Ok((ReadRet::Data, data, seq))
    }

    pub(crate) async fn read_mime_octet(
        &mut self,
        bdry: &str,
    ) -> Result<(ReadRet, &[u8], u32), ()> {
        match self.read_mime_octet_err(bdry).await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    pub(crate) fn get_read_size(&self) -> usize {
        self.read_size
    }

    // 异步方式获取下一个严格有序的包。包含载荷为0的
    pub(crate) fn next_ord_pkt(
        &mut self,
    ) -> impl Future<Output = Option<PacketWrapper<T, P>>> + '_ {
        poll_fn(|_cx| {
            if self.fin {
                return Poll::Ready(None);
            }
            if let Some(pkt) = self.pop_ord() {
                return Poll::Ready(Some(pkt));
            }
            Poll::Pending
        })
    }

    // 这个接口没必要提供
    // 异步方式获取下一个原始顺序的包。包含载荷为0的。如果cache中每到来一个包，就调用，那就是原始到来的包顺序
    #[cfg(test)]
    pub(crate) fn next_raw_pkt(
        &mut self,
    ) -> impl Future<Output = Option<PacketWrapper<T, P>>> + '_ {
        poll_fn(|_cx| {
            if let Some(_pkt) = self.peek() {
                return Poll::Ready(self.pop());
            }
            Poll::Pending
        })
    }

    // 返回试读过的数据, start到next - 1
    // ignore: 忽略尾部的数据长度。比如boundary \r\n
    fn get_buff_data(&mut self, ignore: usize) -> Result<(&[u8], u32), ReadError> {
        let seq = self.next_seq - self.buff_len as u32;
        let data_len = self.buff_next - self.buff_start;
        let data = &self.buff[self.buff_start..(self.buff_start + data_len - ignore)];

        if let Some(ref mut cb) = self.cb_strm {
            let raw_data = &self.buff[self.buff_start..(self.buff_start + data_len)];
            cb.borrow_mut()(raw_data, seq, self.cb_ctx);
        }

        let result = Ok((data, seq));
        self.buff_start += data_len;
        self.buff_len -= data_len;
        self.read_size += data_len;

        // 如果数据读空，buff start移到开始位置。可以减少将来move数据的机会
        if self.buff_len == 0 {
            self.buff_start = 0;
            self.buff_next = 0;
        }

        result
    }

    fn fill_bottom(&mut self) -> FillRet {
        if self.fin {
            return FillRet::Final;
        }

        let mut filled = false;
        let buff_start = self.buff_start;
        let mut buff_len = self.buff_len;
        let max_buff = self.max_buff;

        while let Some((pkt, next_seq)) = self.peek_ord_data_with_seq() {
            let seq = pkt.seq();
            let payload = pkt.payload();
            let payload_len = payload.len();
            let payload_off = (next_seq - seq) as usize;

            let space = max_buff - (buff_start + buff_len);
            if space == 0 {
                break;
            }

            let copy_len = std::cmp::min(payload_len - payload_off, space);
            if copy_len == 0 {
                break;
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    payload[payload_off..].as_ptr(),
                    self.buff.as_mut_ptr().add(buff_start + buff_len),
                    copy_len,
                );
            }
            buff_len += copy_len;
            self.next_seq += copy_len as u32;
            filled = true;
        }

        if filled {
            self.buff_len = buff_len;
            FillRet::OK
        } else {
            FillRet::NoPkt
        }
    }

    fn fill_buff(&mut self) -> FillRet {
        // case 1: 后面没有空间，前面也没有空间，填满状态。 [++++++++++++]如果满，直接返回。
        // case 2: 后续有空间，无论前面是否有空，只填充后面的空间。 [******++++++-----]
        // case 3: 后面没有空间，前面有空间，需要移动，并填充后面的空间。移动后就是case 2。

        // case 1
        if self.buff_len >= self.max_buff {
            return FillRet::Final;
        }

        // 尽量避免移动，如果后面有空间，只填充后面即可
        // case 2
        if self.buff_start + self.buff_len < self.max_buff {
            return self.fill_bottom();
        }

        // case 3
        if self.buff_start + self.buff_len >= self.max_buff && self.buff_start > 0 {
            unsafe {
                std::ptr::copy(
                    self.buff.as_ptr().add(self.buff_start),
                    self.buff.as_mut_ptr(),
                    self.buff_len,
                );
            }
            self.buff_next -= self.buff_start;
            self.buff_start = 0;
            return self.fill_bottom();
        }

        FillRet::Final // 不应该到达这里，相当于出错
    }
}

impl<T, P> Drop for PktStrm<T, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn drop(&mut self) {
        self.heap.clear();
    }
}

impl<T, P> Unpin for PktStrm<T, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
}

impl<T, P> Stream for PktStrm<T, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    type Item = u8;

    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.buff_next >= self.buff_start + self.buff_len {
            match self.fill_buff() {
                FillRet::OK => {}
                FillRet::Final => {
                    return Poll::Ready(None);
                }
                FillRet::NoPkt => {
                    return Poll::Pending;
                }
            }
        }

        let byte = self.buff[self.buff_next];
        self.buff_next += 1;
        Poll::Ready(Some(byte))
    }
}

impl<T, P> fmt::Debug for PktStrm<T, P>
where
    T: Packet,
    P: PtrWrapper<T> + PtrNew<T>,
    PacketWrapper<T, P>: PartialEq + Eq + PartialOrd + Ord,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PktStrm")
            .field("pkt_buff_len", &self.heap.len())
            .field("read_buff_len", &self.buff_len)
            .field("next_seq", &self.next_seq)
            .field("fin", &self.fin)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::test_utils::*;
    use std::marker::PhantomData;
    use std::ptr;

    #[test]
    fn test_pkt() {
        let pkt1 = make_pkt_data(123);
        let _ = pkt1.decode();
        assert_eq!(72, pkt1.data_len);
        assert_eq!(62, pkt1.header.borrow().as_ref().unwrap().payload_offset);
        assert_eq!(10, pkt1.header.borrow().as_ref().unwrap().payload_len);
        assert_eq!(25, pkt1.header.borrow().as_ref().unwrap().sport());
    }

    #[test]
    fn test_pktstrm_push() {
        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let pkt1 = make_pkt_data(123);
        let _ = pkt1.decode();
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1),
            _phantom: PhantomData,
        });
        assert_eq!(1, stm.len());

        let pkt2 = make_pkt_data(123);
        let _ = pkt2.decode();
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2),
            _phantom: PhantomData,
        });
        assert_eq!(2, stm.len());
    }

    #[test]
    fn test_pktstrm_peek() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });

        if let Some(pkt) = pkt_strm.peek() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected a packet wrapper");
        }
    }

    #[test]
    fn test_pktstrm_peek_push_clone() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = Rc::new(MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        });

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: packet2.clone(),
            _phantom: PhantomData,
        });

        if let Some(pkt) = pkt_strm.peek() {
            assert_eq!(*pkt, *packet2);
        } else {
            panic!("Expected a packet wrapper");
        }
    }

    #[test]
    fn test_pktstrm_peek2() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let pkt1 = MyPacket::new(L7Proto::Unknown, 1, false);
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1),
            _phantom: PhantomData,
        });

        let pkt2 = MyPacket::new(L7Proto::Unknown, 30, false);
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2),
            _phantom: PhantomData,
        });

        let pkt3 = MyPacket::new(L7Proto::Unknown, 80, false);
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3),
            _phantom: PhantomData,
        });

        assert_eq!(1, stm.peek().unwrap().seq());
        stm.pop();
        assert_eq!(30, stm.peek().unwrap().seq());
        stm.pop();
        assert_eq!(80, stm.peek().unwrap().seq());
        stm.pop();
        assert!(stm.is_empty());
    }

    #[test]
    fn test_pktstrm_pop() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1001,
            syn_flag: true,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet3.clone()),
            _phantom: PhantomData,
        });

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(
                popped_packet,
                PacketWrapper {
                    ptr: Rc::new(packet2),
                    _phantom: PhantomData,
                }
            );
        } else {
            panic!("Expected to pop a packet");
        }

        assert!(pkt_strm.fin);

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(
                popped_packet,
                PacketWrapper {
                    ptr: Rc::new(packet1),
                    _phantom: PhantomData,
                }
            );
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(
                popped_packet,
                PacketWrapper {
                    ptr: Rc::new(packet3),
                    _phantom: PhantomData,
                }
            );
        } else {
            panic!("Expected to pop a packet");
        }

        assert_eq!(pkt_strm.pop(), None);
    }

    #[test]
    fn test_pktstrm_peek_ord() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet3.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet4.clone()),
            _phantom: PhantomData,
        });

        if let Some(pkt) = pkt_strm.peek_ord() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1000;
        if let Some(pkt) = pkt_strm.peek_ord() {
            assert_eq!(*pkt, packet4);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1004;
        if let Some(pkt) = pkt_strm.peek_ord() {
            assert_eq!(*pkt, packet3);
        } else {
            panic!("Expected to peek a packet");
        }
    }

    #[test]
    fn test_pktstrm_peek_ord2() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(L7Proto::Unknown, seq1, false);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(L7Proto::Unknown, seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(L7Proto::Unknown, seq3, false);

        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        assert_eq!(seq1, stm.peek_ord().unwrap().seq());
        assert_eq!(seq1, stm.pop_ord().unwrap().ptr.seq());
        assert_eq!(seq2, stm.peek_ord().unwrap().seq());
        assert_eq!(seq2, stm.pop_ord().unwrap().ptr.seq());
        assert_eq!(seq3, stm.peek_ord().unwrap().seq());
        assert_eq!(seq3, stm.pop_ord().unwrap().ptr.seq());
        assert!(stm.is_empty());
    }

    // 插入的包有完整重传
    #[test]
    fn test_pktstrm_peek_ord_retrans() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(L7Proto::Unknown, seq1, false);
        // 11- 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(L7Proto::Unknown, seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(L7Proto::Unknown, seq3, false);

        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });

        assert_eq!(4, stm.len());
        assert_eq!(0, stm.next_seq);

        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 按有序方式，看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt1, 通过pop_ord_pkt更新next_seq
        assert_eq!(seq2, stm.next_seq);

        assert_eq!(3, stm.len()); // 此时重复的pkt1，仍在里面，top上
        assert_eq!(seq1, stm.peek().unwrap().seq());
        assert_eq!(seq2, stm.next_seq);

        dbg!(stm.next_seq);
        assert_eq!(seq2, stm.peek_ord().unwrap().seq()); // 看到pkt2
        assert_eq!(2, stm.len()); // peek_ord清理了重复的pkt1
        assert_eq!(seq2, stm.next_seq); //  peek_ord不会更新next_seq

        assert_eq!(seq2, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt2, 通过pop_ord更新next_seq
        assert_eq!(1, stm.len());
        assert_eq!(seq3, stm.next_seq); //  peek_ord不会更新next_seq

        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(seq3, stm.peek_ord().unwrap().seq()); // 看到pkt3
        assert_eq!(seq3, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt3, 通过pop_ord更新next_seq
        assert_eq!(seq3 + pkt3.payload_len() as u32, stm.next_seq);

        assert!(stm.is_empty());
    }

    // 插入的包有覆盖重传
    #[test]
    fn test_pktstrm_peek_ord_cover() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(L7Proto::Unknown, seq1, false);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(L7Proto::Unknown, seq2, false);
        // 15 - 24
        let seq3 = 15;
        let pkt3 = MyPacket::new(L7Proto::Unknown, seq3, false);
        // 25 - 34
        let seq4 = 25;
        let pkt4 = MyPacket::new(L7Proto::Unknown, seq4, false);

        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt4.clone()),
            _phantom: PhantomData,
        });

        assert_eq!(4, stm.len());
        assert_eq!(0, stm.next_seq);

        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt1, 通过pop_ord更新next_seq
        assert_eq!(pkt1.seq() + pkt1.payload_len() as u32, stm.next_seq);

        assert_eq!(3, stm.len());
        assert_eq!(seq2, stm.peek().unwrap().seq()); // 此时pkt2在top
        assert_eq!(seq2, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt2, 通过pop_ord更新next_seq

        assert_eq!(2, stm.len());
        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(seq3, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt3, 通过pop_ord更新next_seq

        assert_eq!(seq3 + pkt3.payload_len() as u32, stm.next_seq);
        assert_eq!(1, stm.len());
        assert_eq!(seq4, stm.peek().unwrap().seq()); // 此时pkt4在top
        assert_eq!(seq4, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt4, 通过pop_ord更新next_seq

        assert_eq!(seq4 + pkt4.payload_len() as u32, stm.next_seq);
        assert!(stm.is_empty());
    }

    // 有中间丢包
    #[test]
    fn test_pktstrm_peek_drop() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(L7Proto::Unknown, seq1, false);
        // 11- 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(L7Proto::Unknown, seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(L7Proto::Unknown, seq3, false);

        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });

        assert_eq!(2, stm.len());
        assert_eq!(0, stm.next_seq);
        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().ptr.seq()); // 弹出pkt1, 通过pop_ord更新next_seq
        assert_eq!(pkt1.seq() + pkt1.payload_len() as u32, stm.next_seq);

        assert_eq!(1, stm.len());
        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(None, stm.peek_ord()); // 但是通peek_ord_pkt 看不到pkt3
        assert_eq!(None, stm.pop_ord());
    }

    // 带数据，带fin。是否可以set fin标记？
    #[test]
    fn test_pkt_fin() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(L7Proto::Unknown, seq1, true);

        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        let ret_pkt1 = stm.pop_ord_data();
        assert_eq!(seq1, ret_pkt1.unwrap().ptr.seq());
        assert!(stm.fin);
    }

    // 插入的包严格有序 1-10 11-20 21-30, 最后一个有数据而且带fin
    // 用pop_ord_data，才会设置fin
    #[test]
    fn test_3pkt_fin() {
        let mut stm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(L7Proto::Unknown, seq1, false);
        println!("pkt1. seq1: {}, pkt1 seq: {}", seq1, pkt1.seq());
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(L7Proto::Unknown, seq2, false);
        println!("pkt2. seq2: {}, pkt2 seq: {}", seq2, pkt2.seq());
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(L7Proto::Unknown, seq3, true);
        println!("pkt3. seq3: {}, pkt3 seq: {}", seq3, pkt3.seq());

        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        assert_eq!(seq1, stm.pop_ord_data().unwrap().ptr.seq());
        assert!(!stm.fin);
        assert_eq!(seq2, stm.pop_ord_data().unwrap().ptr.seq());
        assert!(!stm.fin);
        assert_eq!(seq3, stm.pop_ord_data().unwrap().ptr.seq());
        assert!(stm.fin);
        assert!(stm.is_empty());
    }

    #[test]
    fn test_pktstrm_pop_ord() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 100,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 103,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 106,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 102,
            syn_flag: false,
            fin_flag: false,
            data: vec![5],
        };

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet4.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet3.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1.clone()),
            _phantom: PhantomData,
        });

        if let Some(popped_packet) = pkt_strm.pop_ord() {
            assert_eq!(
                popped_packet,
                PacketWrapper {
                    ptr: Rc::new(packet1),
                    _phantom: PhantomData,
                }
            );
            assert_eq!(pkt_strm.next_seq, 103);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop_ord() {
            assert_eq!(
                popped_packet,
                PacketWrapper {
                    ptr: Rc::new(packet2),
                    _phantom: PhantomData,
                }
            );
            assert_eq!(pkt_strm.next_seq, 106);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop_ord() {
            assert_eq!(
                popped_packet,
                PacketWrapper {
                    ptr: Rc::new(packet3),
                    _phantom: PhantomData,
                }
            );
            assert_eq!(pkt_strm.next_seq, 109);
        } else {
            panic!("Expected to pop a packet");
        }

        assert_eq!(pkt_strm.pop_ord(), None);
        assert_eq!(pkt_strm.pop_ord(), None);
    }

    #[test]
    fn test_pktstrm_peek_ord_data() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![],
        };

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet3.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet4.clone()),
            _phantom: PhantomData,
        });

        if let Some(pkt) = pkt_strm.peek_ord_data() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1000;
        let res = pkt_strm.peek_ord_data();
        assert_eq!(res, None);
    }

    #[test]
    fn test_pktstrm_pop_ord_data() {
        let mut pkt_strm =
            PktStrm::<MyPacket, Rc<MyPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            l7_proto: L7Proto::Unknown,
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![],
        };

        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet1.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet2.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet3.clone()),
            _phantom: PhantomData,
        });
        pkt_strm.push(PacketWrapper {
            ptr: Rc::new(packet4.clone()),
            _phantom: PhantomData,
        });

        if let Some(pkt) = pkt_strm.pop_ord_data() {
            assert_eq!(
                pkt,
                PacketWrapper {
                    ptr: Rc::new(packet2),
                    _phantom: PhantomData,
                }
            );
        } else {
            panic!("Expected to peek a packet");
        }

        pkt_strm.next_seq = 1000;
        let res = pkt_strm.pop_ord_data();
        assert_eq!(res, None);
    }

    // pop_ord. 一个syn，一个正常包。
    #[test]
    fn test_pktstrm_pop_ord_syn() {
        // syn 包seq占一个
        let syn_pkt_seq = 1;
        let syn_pkt = build_pkt_syn(syn_pkt_seq);
        let _ = syn_pkt.decode();
        // 2 - 11
        let seq1 = syn_pkt_seq + 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(syn_pkt.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        let ret_syn_pkt = stm.pop_ord();
        assert_eq!(1, ret_syn_pkt.unwrap().ptr.seq());
        let ret_pkt1 = stm.pop_ord();
        assert_eq!(2, ret_pkt1.unwrap().ptr.seq());
    }

    // pop_ord. syn包从0开始
    #[test]
    fn test_pktstrm_pop_ord_syn_seq0() {
        // syn 包seq占一个
        let syn_pkt_seq = 0;
        let syn_pkt = build_pkt_syn(syn_pkt_seq);
        let _ = syn_pkt.decode();
        // 1 - 10
        let seq1 = syn_pkt_seq + 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(syn_pkt.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        let ret_syn_pkt = stm.pop_ord();
        assert_eq!(0, ret_syn_pkt.unwrap().ptr.seq());
        let ret_pkt1 = stm.pop_ord();
        assert_eq!(1, ret_pkt1.unwrap().ptr.seq());
    }

    // 可以多次peek。有一个独立的syn包
    #[test]
    fn test_pktstrm_peek_pkt_syn() {
        // syn 包seq占一个
        let syn_pkt_seq = 1;
        let syn_pkt = build_pkt_syn(syn_pkt_seq);
        let _ = syn_pkt.decode();
        // 2 - 11
        let seq1 = syn_pkt_seq + 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(syn_pkt.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        let ret_syn_pkt = stm.peek();
        assert_eq!(syn_pkt_seq, ret_syn_pkt.unwrap().seq());
        let ret_syn_pkt2 = stm.peek();
        assert_eq!(syn_pkt_seq, ret_syn_pkt2.unwrap().seq());
        let ret_syn_pkt3 = stm.peek();
        assert_eq!(syn_pkt_seq, ret_syn_pkt3.unwrap().seq());
    }

    // 可以多次peek_ord。有一个独立的syn包
    #[test]
    fn test_pktstrm_peek_ord_pkt_syn() {
        // syn 包seq占一个
        let syn_pkt_seq = 1;
        let syn_pkt = build_pkt_syn(syn_pkt_seq);
        let _ = syn_pkt.decode();
        // 2 - 11
        let seq1 = syn_pkt_seq + 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(syn_pkt.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });

        let ret_syn_pkt = stm.peek_ord();
        assert_eq!(syn_pkt_seq, ret_syn_pkt.unwrap().seq());
        let ret_syn_pkt2 = stm.peek_ord();
        assert_eq!(syn_pkt_seq, ret_syn_pkt2.unwrap().seq());
        let ret_syn_pkt3 = stm.peek_ord();
        assert_eq!(syn_pkt_seq, ret_syn_pkt3.unwrap().seq());
    }

    // pop_ord_data. syn包，3个数据，一个纯fin包
    #[test]
    fn test_pktstrm_pop_data_syn() {
        // syn 包seq占一个
        let syn_pkt_seq = 1;
        let syn_pkt = build_pkt_syn(syn_pkt_seq);
        let _ = syn_pkt.decode();
        // 2 - 11
        let seq1 = syn_pkt_seq + 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();
        // 12 - 21
        let seq2 = seq1 + pkt1.payload_len();
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();
        // 22 - 31
        let seq3 = seq2 + pkt2.payload_len();
        let pkt3 = build_pkt(seq3, false);
        let _ = pkt3.decode();
        // 32 无数据，fin
        let seq4 = seq3 + pkt3.payload_len();
        let pkt4 = build_pkt_fin(seq4);
        let _ = pkt4.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(syn_pkt.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt4.clone()),
            _phantom: PhantomData,
        });

        let ret_syn_pkt = stm.peek_ord(); // peek ord pkt 可以看到syn包
        assert_eq!(syn_pkt_seq, ret_syn_pkt.unwrap().seq());
        let ret_syn_pkt2 = stm.peek_ord(); // 可以再次peek到syn包
        assert_eq!(syn_pkt_seq, ret_syn_pkt2.unwrap().seq());

        let ret_pkt1 = stm.peek_ord_data(); // peek ord data 可以看到pkt1
        assert_eq!(seq1, ret_pkt1.unwrap().seq());

        let ret_pkt1 = stm.pop_ord_data(); // pop ord data 可以弹出pkt1
        assert_eq!(seq1, ret_pkt1.unwrap().ptr.seq());
    }

    // pop_ord. 独立的fin包
    #[test]
    fn test_pktstrm_pop_ord_fin() {
        // 1 - 10
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len();
        let pkt2 = build_pkt_fin(seq2);
        let _ = pkt2.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });

        let ret_pkt1 = stm.pop_ord();
        assert_eq!(1, ret_pkt1.unwrap().ptr.seq());
        let ret_pkt2 = stm.pop_ord();
        assert_eq!(11, ret_pkt2.unwrap().ptr.seq());
    }

    // pop_ord. 独立的fin包。4个包乱序
    #[test]
    fn test_pktstrm_pop_ord_fin_4pkt() {
        // syn pkt
        let syn_seq = 0;
        let syn_pkt = build_pkt_syn(syn_seq);
        let _ = syn_pkt.decode();
        // 1 - 10
        let seq1 = syn_seq + 1;
        let pkt1 = build_pkt(seq1, false);
        let _ = pkt1.decode();
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len();
        let pkt2 = build_pkt(seq2, false);
        let _ = pkt2.decode();
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len();
        let pkt3 = build_pkt(seq3, false);
        let _ = pkt3.decode();
        // 31 - 40
        let seq4 = seq3 + pkt3.payload_len();
        let pkt4 = build_pkt(seq4, false);
        let _ = pkt4.decode();
        // 41
        let fin_seq = seq4 + pkt3.payload_len();
        let fin_pkt = build_pkt_fin(fin_seq);
        let _ = fin_pkt.decode();

        let mut stm =
            PktStrm::<CapPacket, Rc<CapPacket>>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        stm.push(PacketWrapper {
            ptr: Rc::new(syn_pkt.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt1.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt4.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt3.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(pkt2.clone()),
            _phantom: PhantomData,
        });
        stm.push(PacketWrapper {
            ptr: Rc::new(fin_pkt.clone()),
            _phantom: PhantomData,
        });

        let ret_syn_pkt = stm.pop_ord();
        assert_eq!(syn_seq, ret_syn_pkt.as_ref().unwrap().ptr.seq());
        assert_eq!(0, ret_syn_pkt.as_ref().unwrap().ptr.payload_len());
        let ret_pkt1 = stm.pop_ord();
        assert_eq!(seq1, ret_pkt1.unwrap().ptr.seq());
        let ret_pkt2 = stm.pop_ord();
        assert_eq!(seq2, ret_pkt2.unwrap().ptr.seq());
        let ret_pkt3 = stm.pop_ord();
        assert_eq!(seq3, ret_pkt3.unwrap().ptr.seq());
        let ret_pkt4 = stm.pop_ord();
        assert_eq!(seq4, ret_pkt4.unwrap().ptr.seq());
        let ret_fin = stm.pop_ord();
        assert_eq!(fin_seq, ret_fin.as_ref().unwrap().ptr.seq());
        assert_eq!(0, ret_fin.as_ref().unwrap().ptr.payload_len());
    }
}
