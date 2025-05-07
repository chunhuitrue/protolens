use crate::Parser;
use crate::ParserFactory;
use crate::ParserFuture;
use crate::PktStrm;
use crate::Prolens;
use crate::packet::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;

const MAX_READN: usize = 10;

pub trait ReadnCbFn: FnMut(&[u8], u32, *mut c_void) {}
impl<F: FnMut(&[u8], u32, *mut c_void)> ReadnCbFn for F {}
pub(crate) type CbReadn = Rc<RefCell<dyn ReadnCbFn + 'static>>;

pub struct ReadnParser<T>
where
    T: Packet,
{
    pub(crate) cb_readn: Option<CbReadn>,
    _phantom_t: PhantomData<T>,
}

impl<T> ReadnParser<T>
where
    T: Packet,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_readn: None,
            _phantom_t: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_readn: Option<CbReadn>,
        read_size: usize,
        strm: *mut PktStrm<T>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        while !stm.fin() {
            match stm.readn_err(read_size).await {
                Ok((bytes, seq)) => {
                    if let Some(ref cb) = cb_readn {
                        cb.borrow_mut()(bytes, seq, cb_ctx);
                    }
                }
                Err(_) => break,
            }
        }
        Ok(())
    }
}

impl<T> Default for ReadnParser<T>
where
    T: Packet,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Parser for ReadnParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_readn.clone(),
            MAX_READN,
            strm,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadnFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for ReadnFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(ReadnParser::new());
        parser.cb_readn = prolens.cb_readn.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_READ_BUFF;
    use crate::test_utils::*;

    #[test]
    fn test_readn_single_packet() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_value = Rc::new(RefCell::new(0u32));
        let seq_clone = Rc::clone(&seq_value);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            *seq_clone.borrow_mut() = seq;
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readn(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Readn);

        protolens.run_task(&mut task, pkt1);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(*vec.borrow(), expected);
        assert_eq!(*seq_value.borrow(), seq1);
    }

    #[test]
    fn test_readn_multiple_packets() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, false);
        let seq2 = 11;
        let pkt2 = build_pkt(seq2, true);
        let _ = pkt1.decode();
        let _ = pkt2.decode();

        let vec = Rc::new(RefCell::new(Vec::new()));
        let vec_clone = Rc::clone(&vec);
        let seq_values = Rc::new(RefCell::new(Vec::new()));
        let seq_clone = Rc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            vec_clone.borrow_mut().extend_from_slice(bytes);
            seq_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readn(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Readn);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        let expected: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let expected_seqs = vec![seq1, seq2];
        assert_eq!(*vec.borrow(), expected);
        assert_eq!(*seq_values.borrow(), expected_seqs);
    }

    // 多个包才够一次读取的情况
    #[test]
    fn test_readn_across_packets() {
        // 第一个包，包含5个字节
        let seq1 = 1;
        let payload1 = vec![1, 2, 3, 4, 5];
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        // 第二个包，包含3个字节
        let seq2 = seq1 + payload1.len() as u32;
        let payload2 = vec![6, 7, 8];
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        // 第三个包，包含4个字节（凑够10个字节后还有2个剩余）
        let seq3 = seq2 + payload2.len() as u32;
        let payload3 = vec![9, 10, 11, 12];
        let pkt3 = build_pkt_payload(seq3, &payload3);
        let _ = pkt3.decode();

        let data_chunks = Rc::new(RefCell::new(Vec::new()));
        let data_chunks_clone = Rc::clone(&data_chunks);
        let seq_values = Rc::new(RefCell::new(Vec::new()));
        let seq_values_clone = Rc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_chunks_clone.borrow_mut().push(bytes.to_vec());
            seq_values_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readn(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Readn);

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt3);

        let chunks_result = data_chunks.borrow();
        let seqs_result = seq_values.borrow();

        // 应该只有一个数据块，包含10个字节
        assert_eq!(chunks_result.len(), 1);
        assert_eq!(chunks_result[0], vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // 序列号应该是第一个包的序列号
        assert_eq!(seqs_result.len(), 1);
        assert_eq!(seqs_result[0], seq1);
    }

    #[test]
    fn test_readn_buff_move() {
        // 如果整除，不可能遗留部分。无法触发move
        if MAX_READ_BUFF / MAX_READN == 0 {
            return;
        }

        // 创建第一个包，填满整个缓冲区
        let seq1 = 1;
        let mut payload1 = Vec::with_capacity(MAX_READ_BUFF);
        for i in 0..MAX_READ_BUFF {
            payload1.push((i % 256) as u8);
        }
        let pkt1 = build_pkt_payload(seq1, &payload1);
        let _ = pkt1.decode();

        // 创建第二个包，包含额外数据
        let pkt2_payload_len = MAX_READN - MAX_READ_BUFF % MAX_READN;
        let seq2 = seq1 + payload1.len() as u32;
        let mut payload2 = Vec::with_capacity(pkt2_payload_len);
        for i in 0..pkt2_payload_len {
            payload2.push((i + 100) as u8);
        }
        let pkt2 = build_pkt_payload(seq2, &payload2);
        let _ = pkt2.decode();

        // 使用两个不同的变量来收集结果
        let data_chunks1 = Rc::new(RefCell::new(Vec::new()));
        let seq_values1 = Rc::new(RefCell::new(Vec::new()));
        let data_chunks2 = Rc::new(RefCell::new(Vec::new()));
        let seq_values2 = Rc::new(RefCell::new(Vec::new()));
        // 使用一个标志来区分处理第一个包还是第二个包
        let is_first_packet = Rc::new(RefCell::new(true));

        let data_chunks1_clone = Rc::clone(&data_chunks1);
        let seq_values1_clone = Rc::clone(&seq_values1);
        let data_chunks2_clone = Rc::clone(&data_chunks2);
        let seq_values2_clone = Rc::clone(&seq_values2);
        let is_first_packet_clone = Rc::clone(&is_first_packet);

        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            if *is_first_packet_clone.borrow() {
                data_chunks1_clone.borrow_mut().push(bytes.to_vec());
                seq_values1_clone.borrow_mut().push(seq);
            } else {
                data_chunks2_clone.borrow_mut().push(bytes.to_vec());
                seq_values2_clone.borrow_mut().push(seq);
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readn(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Readn);

        protolens.run_task(&mut task, pkt1);

        let chunks_result = data_chunks1.borrow();
        let seqs_result = seq_values1.borrow();

        // 应该读取到多个10字节的数据块
        let expected_chunks_count = MAX_READ_BUFF / MAX_READN;
        assert_eq!(chunks_result.len(), expected_chunks_count);

        // 验证每个数据块的内容
        for i in 0..expected_chunks_count {
            let start = i * 10;
            let expected: Vec<u8> = (start..(start + MAX_READN))
                .map(|j| (j % 256) as u8)
                .collect();
            assert_eq!(chunks_result[i], expected);
            assert_eq!(seqs_result[i], seq1 + start as u32);
        }

        // 切换标志，准备处理第二个包
        *is_first_packet.borrow_mut() = false;
        protolens.run_task(&mut task, pkt2);

        // 验证第二个包的结果
        let chunks_result = data_chunks2.borrow();
        let seqs_result = seq_values2.borrow();

        assert_eq!(chunks_result.len(), 1);

        // 前两个字节是第一个包的最后两个字节 (MAX_READ_BUFF - 2) 和 (MAX_READ_BUFF - 1)
        // 后8个字节是第二个包的8个字节
        let mut expected1 = Vec::with_capacity(MAX_READN);
        // 添加第一个包的最后两个字节
        for i in (1..=MAX_READ_BUFF % MAX_READN).rev() {
            expected1.push(((MAX_READ_BUFF - i) % 256) as u8);
        }
        // 添加第二个包的8个字节
        for i in 0..(MAX_READN - MAX_READ_BUFF % MAX_READN) {
            expected1.push((i + 100) as u8);
        }

        assert_eq!(chunks_result[0], expected1);
        assert_eq!(
            seqs_result[0],
            seq1 + (MAX_READ_BUFF - MAX_READ_BUFF % MAX_READN) as u32
        );
    }

    // 不够一次读取的情况，应该读不到内容
    #[test]
    fn test_readn_insufficient_data() {
        let seq1 = 1;
        let size = MAX_READN - 1; // 比需要的少1个字节
        let mut payload = Vec::with_capacity(size);
        for i in 0..size {
            payload.push((i + 1) as u8);
        }
        let pkt = build_pkt_payload(seq1, &payload);
        let _ = pkt.decode();

        let data_chunks = Rc::new(RefCell::new(Vec::new()));
        let data_chunks_clone = Rc::clone(&data_chunks);
        let seq_values = Rc::new(RefCell::new(Vec::new()));
        let seq_values_clone = Rc::clone(&seq_values);
        let callback = move |bytes: &[u8], seq: u32, _cb_ctx: *mut c_void| {
            data_chunks_clone.borrow_mut().push(bytes.to_vec());
            seq_values_clone.borrow_mut().push(seq);
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_readn(callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Readn);

        protolens.run_task(&mut task, pkt);

        // 验证结果 - 应该没有读取到任何数据块
        let chunks_result = data_chunks.borrow();
        let seqs_result = seq_values.borrow();

        assert_eq!(
            chunks_result.len(),
            0,
            "不应该读取到任何数据块，因为数据不够一次完整读取"
        );
        assert_eq!(seqs_result.len(), 0, "不应该有任何序列号记录");
    }
}
