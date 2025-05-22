use crate::Heap;
use crate::packet::*;
use futures::Future;
use futures::future::poll_fn;
use memchr::memchr;
use memchr::memmem::Finder;
use std::cell::RefCell;
use std::cmp::min;
use std::ffi::c_void;
use std::fmt;
use std::ptr::copy;
use std::ptr::copy_nonoverlapping;
use std::rc::Rc;
use std::str::from_utf8_unchecked;
use std::task::Poll;

#[derive(Debug, PartialEq)]
pub(crate) enum ReadError {
    Eof,    // 连接已结束
    NoData, // 没有足够的数据
}

#[derive(PartialEq, Debug)]
pub(crate) enum ReadRet {
    Data,     // 正常读到了一部分数据
    DashBdry, // 读到了 "\r\n--"+bdry或--bdry ，同时也携带数据
}

pub trait StmCbFn: FnMut(&[u8], u32, *const c_void) {}
impl<F> StmCbFn for F where F: FnMut(&[u8], u32, *const c_void) {}
pub type CbStrm = Rc<RefCell<dyn StmCbFn + 'static>>;

pub(crate) struct PktStrm<T>
where
    T: Packet,
{
    heap: Heap<SeqPacket<T>>,

    buff: Vec<u8>,
    max_buff: usize,
    buff_start: usize, // 开始的index(绝对值)
    buff_len: usize,
    buff_cur: usize,      // pool next的待读取的index（绝对值）
    tot_read_size: usize, // 已经读取的总字节数

    next_seq: u32, // 待读取的seq
    fin: bool,

    // 只有成功返回的才会被callback，比如hello\nxxx。对readline来说，hello\n成功读取，然后调用callback。
    // 后续的xxx不会调用callback
    cb_strm: Option<CbStrm>,
    cb_ctx: *const c_void, // 只在ffi中使用

    move_size: usize,
}

impl<T> PktStrm<T>
where
    T: Packet,
{
    pub(crate) fn new(max_pkt_buff: usize, max_read_buff: usize, cb_ctx: *const c_void) -> Self {
        PktStrm {
            heap: Heap::new(max_pkt_buff),

            buff: vec![0; max_read_buff],
            max_buff: max_read_buff,
            buff_start: 0,
            buff_len: 0,
            buff_cur: 0,
            tot_read_size: 0,

            next_seq: 0,
            fin: false,

            cb_strm: None,
            cb_ctx,

            move_size: 0,
        }
    }

    pub(crate) fn set_cb(&mut self, callback: CbStrm) {
        self.cb_strm = Some(callback);
    }

    pub(crate) fn push(&mut self, pkt: T) {
        if self.fin {
            return;
        }

        if pkt.trans_proto() != TransProto::Tcp {
            return;
        }
        if self.heap.len() >= self.heap.capacity() {
            return;
        }

        self.heap.push(SeqPacket::new(pkt));
    }

    // 无论是否严格seq连续，peek一个当前最有序的包
    // 不更新next_seq
    pub(crate) fn peek(&self) -> Option<&T> {
        if self.fin {
            return None;
        }
        self.heap.peek().map(|p| p.inner())
    }

    // 无论是否严格seq连续，都pop一个当前包。
    // 注意：next_seq由调用者负责
    pub(crate) fn pop(&mut self) -> Option<T> {
        if let Some(wrapper) = self.heap.pop() {
            if wrapper.inner().fin() {
                self.fin = true;
            }
            return Some(wrapper.into_inner());
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
    pub(crate) fn pop_ord(&mut self) -> Option<T> {
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
    pub(crate) fn peek_ord_data(&mut self) -> Option<&T> {
        if let Some((pkt, _nex_seq)) = self.peek_ord_data_with_next_seq() {
            Some(pkt)
        } else {
            None
        }
    }

    // 严格有序。peek出一个带数据的严格有序的包。同时返回next_seq
    pub(crate) fn peek_ord_data_with_next_seq(&mut self) -> Option<(&T, u32)> {
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
    #[allow(unused)]
    pub(crate) fn pop_ord_data(&mut self) -> Option<T> {
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

    // peek第一个有序数据包的payload
    pub(crate) fn peek_payload(&mut self) -> Result<&[u8], ()> {
        if let Some(pkt) = self.peek_ord_data() {
            Ok(pkt.payload())
        } else {
            Err(())
        }
    }

    // 异步方式获取下一个严格有序的包。包含载荷为0的
    pub(crate) fn next_ord_pkt(&mut self) -> impl Future<Output = Option<T>> + '_ {
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

    // 异步方式获取下一个原始顺序的包。包含载荷为0的。如果cache中每到来一个包，就调用，那就是原始到来的包顺序
    #[cfg(test)]
    pub(crate) fn next_raw_pkt(&mut self) -> impl Future<Output = Option<T>> + '_ {
        poll_fn(|_cx| {
            if let Some(_pkt) = self.peek() {
                return Poll::Ready(self.pop());
            }
            Poll::Pending
        })
    }

    async fn buff_fill_end(&mut self) -> Result<(), ReadError> {
        poll_fn(|_ctx| {
            if self.fin {
                return Poll::Ready(Err(ReadError::Eof));
            }

            let mut filled = false;
            let buff_start = self.buff_start;
            let mut buff_len = self.buff_len;
            let max_buff = self.max_buff;

            while let Some((pkt, next_seq)) = self.peek_ord_data_with_next_seq() {
                let seq = pkt.seq();
                let payload = pkt.payload();
                let payload_len = payload.len();
                let payload_off = (next_seq - seq) as usize;

                let space = max_buff - (buff_start + buff_len);
                if space == 0 {
                    break;
                }

                let copy_len = min(payload_len - payload_off, space);
                if copy_len == 0 {
                    break;
                }

                unsafe {
                    copy_nonoverlapping(
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
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending::<Result<(), ReadError>>
            }
        })
        .await
    }

    fn buff_move_start(&mut self) {
        if self.buff_start == 0 {
            return;
        }

        unsafe {
            copy(
                self.buff.as_ptr().add(self.buff_start),
                self.buff.as_mut_ptr(),
                self.buff_len,
            );
            self.move_size += self.buff_len;
        }
        self.buff_cur -= self.buff_start;
        self.buff_start = 0;
    }

    async fn buff_fill(&mut self) -> Result<(), ReadError> {
        self.buff_move_start();
        self.buff_fill_end().await
    }

    // 返回试读过的数据, start到next - 1
    // ignore: 忽略尾部的数据长度。比如boundary \r\n
    fn get_buff_data(&mut self, ignore: usize) -> Result<(&[u8], u32), ReadError> {
        let seq = self.next_seq - self.buff_len as u32;
        let data_len = self.buff_cur - self.buff_start;
        let data = &self.buff[self.buff_start..(self.buff_start + data_len - ignore)];

        if let Some(ref mut cb) = self.cb_strm {
            let raw_data = &self.buff[self.buff_start..(self.buff_start + data_len)];
            cb.borrow_mut()(raw_data, seq, self.cb_ctx);
        }

        let result = Ok((data, seq));
        self.buff_start += data_len;
        self.buff_len -= data_len;
        self.tot_read_size += data_len;

        // 如果数据读空，buff start移到开始位置。可以减少将来move数据的机会
        if self.buff_len == 0 {
            self.buff_start = 0;
            self.buff_cur = 0;
        }

        result
    }

    // peek之后buff_cur会会退
    fn peek_buff_data(&mut self, ignore: usize) -> Result<&[u8], ReadError> {
        let data_len = self.buff_cur - self.buff_start;
        let data = &self.buff[self.buff_start..(self.buff_start + data_len - ignore)];

        let result = Ok(data);
        self.buff_cur -= data_len;

        result
    }

    fn find_line(&mut self) -> bool {
        if self.buff_len == 0 {
            return false;
        }

        let buff = &self.buff[self.buff_cur..(self.buff_start + self.buff_len)];
        if let Some(pos) = memchr(b'\n', buff) {
            self.buff_cur += pos + 1;
            return true;
        }
        self.buff_cur += buff.len();
        false
    }

    async fn readline_inner(&mut self, ignore: usize) -> Result<(&[u8], u32), ReadError> {
        loop {
            if self.find_line() {
                return self.get_buff_data(ignore);
            }
            self.buff_fill().await?;
        }
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
        Ok((unsafe { from_utf8_unchecked(line) }, seq))
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

    pub(crate) async fn read_clean_line_str_err(&mut self) -> Result<(&str, u32), ReadError> {
        let (line, seq) = self.read_clean_line_err().await?;
        Ok((unsafe { from_utf8_unchecked(line) }, seq))
    }

    pub(crate) async fn read_clean_line_str(&mut self) -> Result<(&str, u32), ()> {
        match self.read_clean_line_str_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    // 带\r\n
    pub(crate) async fn peekline_str_err(&mut self) -> Result<&str, ReadError> {
        loop {
            if self.find_line() {
                let data = self.peek_buff_data(0)?;
                return Ok(unsafe { from_utf8_unchecked(data) });
            }
            self.buff_fill().await?;
        }
    }

    pub(crate) async fn peekline_str(&mut self) -> Result<&str, ()> {
        match self.peekline_str_err().await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    fn tail_match(&mut self, bdry: &str) -> usize {
        // 0: 正常读取
        // 1: 读到\r
        // 2: 读到\n
        // 3: 读到-
        // 4: 读到第二个-
        let mut state = 0;
        let bdry_bytes = bdry.as_bytes();
        let mut bdry_index = 0;
        let mut match_len = 0;

        let nedle_len = bdry.len() + 3;
        let start = if self.buff_len >= nedle_len {
            self.buff_start + self.buff_len - nedle_len
        } else {
            self.buff_start
        };
        let buff = &self.buff[start..(self.buff_start + self.buff_len)];
        for &byte in buff.iter() {
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
                    break;
                }
            }
        }
        match_len
    }

    // 有或者没有dash bdry
    // 读到\r\n--bdry
    // 或者读到--bdry
    // 但不包括bdry后面的\r\n
    pub(crate) async fn read_mime_octet_err2(
        &mut self,
        finder: &Finder<'_>,
        bdry: &str,
    ) -> Result<(ReadRet, &[u8], u32), ReadError> {
        loop {
            if self.buff_len == 0 {
                self.buff_fill().await?;
            }

            let buff = &self.buff[self.buff_cur..(self.buff_start + self.buff_len)];

            // case 1: buff中有完整的dash bdry
            let mut search_start = 0;
            while let Some(pos) = finder.find(&buff[search_start..]) {
                let abs_pos = search_start + pos;
                if abs_pos >= 4 && &buff[abs_pos - 4..abs_pos] == b"\r\n--" {
                    self.buff_cur += abs_pos + bdry.len();
                    let (data, seq) = self.get_buff_data(bdry.len() + 4)?;
                    return Ok((ReadRet::DashBdry, data, seq));
                }
                if abs_pos >= 2 && &buff[abs_pos - 2..abs_pos] == b"--" {
                    self.buff_cur += abs_pos + bdry.len();
                    let (data, seq) = self.get_buff_data(bdry.len() + 2)?;
                    return Ok((ReadRet::DashBdry, data, seq));
                }

                search_start = abs_pos + 1;
                if search_start > buff.len() - bdry.len() {
                    break;
                }
            }

            let match_len = self.tail_match(bdry);
            self.buff_cur = self.buff_start + self.buff_len - match_len;

            // case 2: buff中全是数据
            if match_len == 0 {
                let (data, seq) = self.get_buff_data(0)?;
                return Ok((ReadRet::Data, data, seq));
            }

            // case 3: buff中包含部分数据，部分bdry
            // [++++++\r\n--boun]dary 把match到的部分bdry留在buff中，下次继续match
            if self.buff_cur - self.buff_start > 0 {
                let (data, seq) = self.get_buff_data(0)?;
                return Ok((ReadRet::Data, data, seq));
            }

            // case 4: [\r\n--boun]只有部分bdry。说明是上次取走数据后留下的。
            self.buff_fill().await?;
        }
    }

    pub(crate) async fn read_mime_octet2(
        &mut self,
        finder: &Finder<'_>,
        bdry: &str,
    ) -> Result<(ReadRet, &[u8], u32), ()> {
        match self.read_mime_octet_err2(finder, bdry).await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    // 严格读到n个字节返回。但最大不超过max_buff
    pub(crate) async fn readn_err(&mut self, n: usize) -> Result<(&[u8], u32), ReadError> {
        if n > self.max_buff {
            return Err(ReadError::NoData);
        }

        loop {
            if self.buff_len >= n {
                self.buff_cur = self.buff_start + n;
                return self.get_buff_data(0);
            }
            self.buff_fill().await?;
        }
    }

    pub(crate) async fn readn(&mut self, n: usize) -> Result<(&[u8], u32), ()> {
        match self.readn_err(n).await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    pub(crate) async fn read_err(&mut self, n: usize) -> Result<(&[u8], u32), ReadError> {
        if self.buff_len == 0 {
            self.buff_fill().await?;
        }

        let len = min(n, self.buff_len);
        self.buff_cur = self.buff_start + len;
        self.get_buff_data(0)
    }

    pub(crate) async fn read(&mut self, n: usize) -> Result<(&[u8], u32), ()> {
        match self.read_err(n).await {
            Ok(result) => Ok(result),
            Err(_) => Err(()),
        }
    }

    pub(crate) async fn read2eof(&mut self) -> Result<(&[u8], u32), ReadError> {
        if self.buff_len == 0 {
            self.buff_fill().await?;
        }

        self.buff_cur = self.buff_start + self.buff_len;
        self.get_buff_data(0)
    }

    #[cfg(test)]
    pub(crate) async fn next_byte(&mut self) -> Result<(u8, u32), ReadError> {
        match self.readn_err(1).await {
            Ok((bytes, seq)) => Ok((bytes[0], seq)),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn get_read_size(&self) -> usize {
        self.tot_read_size
    }
}

impl<T> Unpin for PktStrm<T> where T: Packet {}

impl<T> fmt::Debug for PktStrm<T>
where
    T: Packet,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PktStrm")
            .field("pkt_buff_len", &self.heap.len())
            .field("read_buff_len", &self.buff.len())
            .field("next_seq", &self.next_seq)
            .field("fin", &self.fin)
            .field("buff move size:", &self.move_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::test_utils::*;
    use std::ptr;

    #[test]
    fn test_pkt() {
        let pkt1 = make_pkt_data(123);
        let _ = pkt1.decode();
        assert_eq!(72, pkt1.data_len);
        assert_eq!(62, pkt1.header.borrow().as_ref().unwrap().payload_offset);
        assert_eq!(10, pkt1.header.borrow().as_ref().unwrap().payload_len);
        assert_eq!(
            TEST_UTILS_SPORT,
            pkt1.header.borrow().as_ref().unwrap().sport()
        );
    }

    #[test]
    fn test_pktstrm_push() {
        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let pkt1 = make_pkt_data(123);
        let _ = pkt1.decode();
        stm.push(pkt1);
        assert_eq!(1, stm.len());

        let pkt2 = make_pkt_data(123);
        let _ = pkt2.decode();
        stm.push(pkt2);
        assert_eq!(2, stm.len());
    }

    #[test]
    fn test_pktstrm_peek() {
        let mut pkt_strm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        pkt_strm.push(packet1);
        pkt_strm.push(packet2.clone());

        if let Some(pkt) = pkt_strm.peek() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected a packet wrapper");
        }
    }

    #[test]
    fn test_pktstrm_peek_push_clone() {
        let mut pkt_strm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = Rc::new(MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        });

        pkt_strm.push(packet1);
        pkt_strm.push((*packet2).clone());

        if let Some(pkt) = pkt_strm.peek() {
            assert_eq!(*pkt, *packet2);
        } else {
            panic!("Expected a packet wrapper");
        }
    }

    #[test]
    fn test_pktstrm_peek2() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let pkt1 = MyPacket::new(1, false);
        stm.push(pkt1);

        let pkt2 = MyPacket::new(30, false);
        stm.push(pkt2);

        let pkt3 = MyPacket::new(80, false);
        stm.push(pkt3);

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
        let mut pkt_strm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: true,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 999,
            syn_flag: false,
            fin_flag: true,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1001,
            syn_flag: true,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet3.clone());

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(popped_packet, packet2);
        } else {
            panic!("Expected to pop a packet");
        }

        assert!(pkt_strm.fin);

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(popped_packet, packet1);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = pkt_strm.pop() {
            assert_eq!(popped_packet, packet3);
        } else {
            panic!("Expected to pop a packet");
        }

        assert_eq!(pkt_strm.pop(), None);
    }

    #[test]
    fn test_pktstrm_peek_ord() {
        let mut pkt_strm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        pkt_strm.push(packet1.clone());
        pkt_strm.push(packet2.clone());
        pkt_strm.push(packet3.clone());
        pkt_strm.push(packet4.clone());

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
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, false);

        stm.push(pkt2.clone());
        stm.push(pkt3.clone());
        stm.push(pkt1.clone());

        assert_eq!(seq1, stm.peek_ord().unwrap().seq());
        assert_eq!(seq1, stm.pop_ord().unwrap().seq());
        assert_eq!(seq2, stm.peek_ord().unwrap().seq());
        assert_eq!(seq2, stm.pop_ord().unwrap().seq());
        assert_eq!(seq3, stm.peek_ord().unwrap().seq());
        assert_eq!(seq3, stm.pop_ord().unwrap().seq());
        assert!(stm.is_empty());
    }

    // 插入的包有完整重传
    #[test]
    fn test_pktstrm_peek_ord_retrans() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11- 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, false);

        stm.push(pkt1.clone());
        stm.push(pkt2.clone());
        stm.push(pkt1.clone());
        stm.push(pkt3.clone());

        assert_eq!(4, stm.len());
        assert_eq!(0, stm.next_seq);

        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 按有序方式，看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().seq()); // 弹出pkt1, 通过pop_ord_pkt更新next_seq
        assert_eq!(seq2, stm.next_seq);

        assert_eq!(3, stm.len()); // 此时重复的pkt1，仍在里面，top上
        assert_eq!(seq1, stm.peek().unwrap().seq());
        assert_eq!(seq2, stm.next_seq);

        dbg!(stm.next_seq);
        assert_eq!(seq2, stm.peek_ord().unwrap().seq()); // 看到pkt2
        assert_eq!(2, stm.len()); // peek_ord清理了重复的pkt1
        assert_eq!(seq2, stm.next_seq); //  peek_ord不会更新next_seq

        assert_eq!(seq2, stm.pop_ord().unwrap().seq()); // 弹出pkt2, 通过pop_ord更新next_seq
        assert_eq!(1, stm.len());
        assert_eq!(seq3, stm.next_seq); //  peek_ord不会更新next_seq

        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(seq3, stm.peek_ord().unwrap().seq()); // 看到pkt3
        assert_eq!(seq3, stm.pop_ord().unwrap().seq()); // 弹出pkt3, 通过pop_ord更新next_seq
        assert_eq!(seq3 + pkt3.payload_len() as u32, stm.next_seq);

        assert!(stm.is_empty());
    }

    // 插入的包有覆盖重传
    #[test]
    fn test_pktstrm_peek_ord_cover() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 15 - 24
        let seq3 = 15;
        let pkt3 = MyPacket::new(seq3, false);
        // 25 - 34
        let seq4 = 25;
        let pkt4 = MyPacket::new(seq4, false);

        stm.push(pkt1.clone());
        stm.push(pkt2.clone());
        stm.push(pkt3.clone());
        stm.push(pkt4.clone());

        assert_eq!(4, stm.len());
        assert_eq!(0, stm.next_seq);

        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().seq()); // 弹出pkt1, 通过pop_ord更新next_seq
        assert_eq!(pkt1.seq() + pkt1.payload_len() as u32, stm.next_seq);

        assert_eq!(3, stm.len());
        assert_eq!(seq2, stm.peek().unwrap().seq()); // 此时pkt2在top
        assert_eq!(seq2, stm.pop_ord().unwrap().seq()); // 弹出pkt2, 通过pop_ord更新next_seq

        assert_eq!(2, stm.len());
        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(seq3, stm.pop_ord().unwrap().seq()); // 弹出pkt3, 通过pop_ord更新next_seq

        assert_eq!(seq3 + pkt3.payload_len() as u32, stm.next_seq);
        assert_eq!(1, stm.len());
        assert_eq!(seq4, stm.peek().unwrap().seq()); // 此时pkt4在top
        assert_eq!(seq4, stm.pop_ord().unwrap().seq()); // 弹出pkt4, 通过pop_ord更新next_seq

        assert_eq!(seq4 + pkt4.payload_len() as u32, stm.next_seq);
        assert!(stm.is_empty());
    }

    // 有中间丢包
    #[test]
    fn test_pktstrm_peek_drop() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        // 11- 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, false);

        stm.push(pkt1.clone());
        stm.push(pkt3.clone());

        assert_eq!(2, stm.len());
        assert_eq!(0, stm.next_seq);
        assert_eq!(seq1, stm.peek().unwrap().seq()); // 此时pkt1在top
        assert_eq!(seq1, stm.peek_ord().unwrap().seq()); // 看到pkt1
        assert_eq!(seq1, stm.pop_ord().unwrap().seq()); // 弹出pkt1, 通过pop_ord更新next_seq
        assert_eq!(pkt1.seq() + pkt1.payload_len() as u32, stm.next_seq);

        assert_eq!(1, stm.len());
        assert_eq!(seq3, stm.peek().unwrap().seq()); // 此时pkt3在top
        assert_eq!(None, stm.peek_ord()); // 但是通peek_ord_pkt 看不到pkt3
        assert_eq!(None, stm.pop_ord());
    }

    // 带数据，带fin。是否可以set fin标记？
    #[test]
    fn test_pkt_fin() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, true);

        stm.push(pkt1.clone());

        let ret_pkt1 = stm.pop_ord_data();
        assert_eq!(seq1, ret_pkt1.unwrap().seq());
        assert!(stm.fin);
    }

    // 插入的包严格有序 1-10 11-20 21-30, 最后一个有数据而且带fin
    // 用pop_ord_data，才会设置fin
    #[test]
    fn test_3pkt_fin() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());
        // 1 - 10
        let seq1 = 1;
        let pkt1 = MyPacket::new(seq1, false);
        println!("pkt1. seq1: {}, pkt1 seq: {}", seq1, pkt1.seq());
        // 11 - 20
        let seq2 = seq1 + pkt1.payload_len() as u32;
        let pkt2 = MyPacket::new(seq2, false);
        println!("pkt2. seq2: {}, pkt2 seq: {}", seq2, pkt2.seq());
        // 21 - 30
        let seq3 = seq2 + pkt2.payload_len() as u32;
        let pkt3 = MyPacket::new(seq3, true);
        println!("pkt3. seq3: {}, pkt3 seq: {}", seq3, pkt3.seq());

        stm.push(pkt2.clone());
        stm.push(pkt3.clone());
        stm.push(pkt1.clone());

        assert_eq!(seq1, stm.pop_ord_data().unwrap().seq());
        assert!(!stm.fin);
        assert_eq!(seq2, stm.pop_ord_data().unwrap().seq());
        assert!(!stm.fin);
        assert_eq!(seq3, stm.pop_ord_data().unwrap().seq());
        assert!(stm.fin);
        assert!(stm.is_empty());
    }

    #[test]
    fn test_pktstrm_pop_ord() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 100,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 103,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 106,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 102,
            syn_flag: false,
            fin_flag: false,
            data: vec![5],
        };

        stm.push(packet4.clone());
        stm.push(packet3.clone());
        stm.push(packet2.clone());
        stm.push(packet1.clone());

        if let Some(popped_packet) = stm.pop_ord() {
            assert_eq!(popped_packet, packet1);
            assert_eq!(stm.next_seq, 103);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = stm.pop_ord() {
            assert_eq!(popped_packet, packet2);
            assert_eq!(stm.next_seq, 106);
        } else {
            panic!("Expected to pop a packet");
        }

        if let Some(popped_packet) = stm.pop_ord() {
            assert_eq!(popped_packet, packet3);
            assert_eq!(stm.next_seq, 109);
        } else {
            panic!("Expected to pop a packet");
        }

        assert_eq!(stm.pop_ord(), None);
        assert_eq!(stm.pop_ord(), None);
    }

    #[test]
    fn test_pktstrm_peek_ord_data() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![],
        };

        stm.push(packet1.clone());
        stm.push(packet2.clone());
        stm.push(packet3.clone());
        stm.push(packet4.clone());

        if let Some(pkt) = stm.peek_ord_data() {
            assert_eq!(*pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        stm.next_seq = 1000;
        let res = stm.peek_ord_data();
        assert_eq!(res, None);
    }

    #[test]
    fn test_pktstrm_pop_ord_data() {
        let mut stm = PktStrm::<MyPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        let packet1 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 300,
            syn_flag: false,
            fin_flag: false,
            data: vec![1, 2, 3],
        };

        let packet2 = MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: 200,
            syn_flag: false,
            fin_flag: false,
            data: vec![4, 5, 6],
        };

        let packet3 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1004,
            syn_flag: false,
            fin_flag: false,
            data: vec![7, 8, 9],
        };

        let packet4 = MyPacket {
            sport: 12345,
            dport: 80,
            sequence: 1000,
            syn_flag: false,
            fin_flag: false,
            data: vec![],
        };

        stm.push(packet1.clone());
        stm.push(packet2.clone());
        stm.push(packet3.clone());
        stm.push(packet4.clone());

        if let Some(pkt) = stm.pop_ord_data() {
            assert_eq!(pkt, packet2);
        } else {
            panic!("Expected to peek a packet");
        }

        stm.next_seq = 1000;
        let res = stm.pop_ord_data();
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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(syn_pkt.clone());
        stm.push(pkt1.clone());

        let ret_syn_pkt = stm.pop_ord();
        assert_eq!(1, ret_syn_pkt.unwrap().seq());
        let ret_pkt1 = stm.pop_ord();
        assert_eq!(2, ret_pkt1.unwrap().seq());
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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(syn_pkt.clone());
        stm.push(pkt1.clone());

        let ret_syn_pkt = stm.pop_ord();
        assert_eq!(0, ret_syn_pkt.unwrap().seq());
        let ret_pkt1 = stm.pop_ord();
        assert_eq!(1, ret_pkt1.unwrap().seq());
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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(syn_pkt.clone());
        stm.push(pkt1.clone());

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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(syn_pkt.clone());
        stm.push(pkt1.clone());

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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(syn_pkt.clone());
        stm.push(pkt2.clone());
        stm.push(pkt3.clone());
        stm.push(pkt1.clone());
        stm.push(pkt4.clone());

        let ret_syn_pkt = stm.peek_ord(); // peek ord pkt 可以看到syn包
        assert_eq!(syn_pkt_seq, ret_syn_pkt.unwrap().seq());
        let ret_syn_pkt2 = stm.peek_ord(); // 可以再次peek到syn包
        assert_eq!(syn_pkt_seq, ret_syn_pkt2.unwrap().seq());

        let ret_pkt1 = stm.peek_ord_data(); // peek ord data 可以看到pkt1
        assert_eq!(seq1, ret_pkt1.unwrap().seq());

        let ret_pkt1 = stm.pop_ord_data(); // pop ord data 可以弹出pkt1
        assert_eq!(seq1, ret_pkt1.unwrap().seq());
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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(pkt1.clone());
        stm.push(pkt2.clone());

        let ret_pkt1 = stm.pop_ord();
        assert_eq!(1, ret_pkt1.unwrap().seq());
        let ret_pkt2 = stm.pop_ord();
        assert_eq!(11, ret_pkt2.unwrap().seq());
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

        let mut stm = PktStrm::<CapPacket>::new(MAX_PKT_BUFF, MAX_READ_BUFF, ptr::null_mut());

        stm.push(syn_pkt.clone());
        stm.push(pkt1.clone());
        stm.push(pkt4.clone());
        stm.push(pkt3.clone());
        stm.push(pkt2.clone());
        stm.push(fin_pkt.clone());

        let ret_syn_pkt = stm.pop_ord();
        assert_eq!(syn_seq, ret_syn_pkt.as_ref().unwrap().seq());
        assert_eq!(0, ret_syn_pkt.as_ref().unwrap().payload_len());
        let ret_pkt1 = stm.pop_ord();
        assert_eq!(seq1, ret_pkt1.unwrap().seq());
        let ret_pkt2 = stm.pop_ord();
        assert_eq!(seq2, ret_pkt2.unwrap().seq());
        let ret_pkt3 = stm.pop_ord();
        assert_eq!(seq3, ret_pkt3.unwrap().seq());
        let ret_pkt4 = stm.pop_ord();
        assert_eq!(seq4, ret_pkt4.unwrap().seq());
        let ret_fin = stm.pop_ord();
        assert_eq!(fin_seq, ret_fin.as_ref().unwrap().seq());
        assert_eq!(0, ret_fin.as_ref().unwrap().payload_len());
    }
}
