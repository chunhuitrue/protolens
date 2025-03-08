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

pub trait ReadLineCbFn: FnMut(String, *mut c_void) {}
impl<F: FnMut(String, *mut c_void)> ReadLineCbFn for F {}
pub(crate) type CbReadline = Rc<RefCell<dyn ReadLineCbFn + 'static>>;

pub struct ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub(crate) cb_readline: Option<CbReadline>,
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    pub fn new() -> Self {
        Self {
            cb_readline: None,
            _phantom_t: PhantomData,
            _phantom_p: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        cb_readline: Option<CbReadline>,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm: &mut PktStrm<T, P>;
        unsafe {
            stm = &mut *(stream as *mut PktStrm<T, P>);
        }

        while !stm.fin() {
            match stm.readline().await {
                Ok(line) => {
                    if line.is_empty() {
                        break;
                    }
                    if let Some(ref cb) = cb_readline {
                        cb.borrow_mut()(line, cb_ctx);
                    }
                }
                Err(_) => break,
            }
        }
        Ok(())
    }
}

impl<T, P> Default for ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, P> Parser for ReadlineParser<T, P>
where
    T: PacketBind,
    P: PtrWrapper<T> + PtrNew<T> + 'static,
{
    type PacketType = T;
    type PtrType = P;

    fn c2s_parser(
        &self,
        stream: *const PktStrm<T, P>,
        cb_ctx: *mut c_void,
    ) -> Option<ParserFuture> {
        Some(Box::pin(Self::c2s_parser_inner(
            self.cb_readline.clone(),
            stream,
            cb_ctx,
        )))
    }
}

pub(crate) struct ReadlineFactory<T, P> {
    _phantom_t: PhantomData<T>,
    _phantom_p: PhantomData<P>,
}

impl<T, P> ParserFactory<T, P> for ReadlineFactory<T, P>
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
        let mut parser = Box::new(ReadlineParser::new());
        parser.cb_readline = prolens.cb_readline.clone();
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_stream_readline_single_line() {
        // 创建一个包含一行数据的包
        let seq1 = 1;
        let payload = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b'l'];
        let pkt1 = build_pkt_payload(seq1, &payload);
        let _ = pkt1.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let callback = move |line: String, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let expected = vec!["Hello\n".to_string()];
        assert_eq!(*lines.borrow(), expected);
    }

    #[test]
    fn test_stream_readline_multiple_packets() {
        // 第一个包包含 "Hello\nWor"
        let seq1 = 1;
        let payload1 = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b' '];
        let pkt1 = build_pkt_payload(seq1, &payload1);

        // 第二个包包含 "ld!\nBye\n"
        let seq2 = 11;
        let payload2 = [b'l', b'd', b'!', b'\n', b'B', b'y', b'e', b'\n', b'x', b'x'];
        let pkt2 = build_pkt_payload(seq2, &payload2);

        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt1.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let callback = move |line: String, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        protolens.run_task(&mut task, pkt1);
        protolens.run_task(&mut task, pkt2);

        // 验证收到的行是否正确
        let expected = vec![
            "Hello\n".to_string(),
            "Wor ld!\n".to_string(),
            "Bye\n".to_string(),
        ];
        assert_eq!(*lines.borrow(), expected);
    }

    #[test]
    fn test_stream_readline_with_syn() {
        // 创建SYN包
        let seq1 = 1;
        let pkt_syn = build_pkt_syn(seq1);

        // 创建数据包
        let seq2 = 2; // SYN占一个序列号
        let payload1 = [b'H', b'e', b'l', b'l', b'o', b'\n', b'W', b'o', b'r', b'l'];
        let pkt1 = build_pkt_payload(seq2, &payload1);

        let seq3 = 12;
        let payload2 = [b'd', b'!', b'\n', b'B', b'y', b'e', b'\n', b'x', b'x', b'x'];
        let pkt2 = build_pkt_payload(seq3, &payload2);

        let _ = pkt_syn.decode();
        let _ = pkt1.decode();
        let _ = pkt2.decode();
        pkt_syn.set_l7_proto(L7Proto::Readline);

        let lines = Rc::new(RefCell::new(Vec::new()));
        let lines_clone = Rc::clone(&lines);
        let callback = move |line: String, _cb_ctx: *mut c_void| {
            lines_clone.borrow_mut().push(line);
        };

        let mut protolens = Prolens::<CapPacket, Rc<CapPacket>>::default();
        protolens.set_cb_readline(callback);
        let mut task = protolens.new_task();

        // 乱序发送包
        protolens.run_task(&mut task, pkt_syn);
        protolens.run_task(&mut task, pkt2);
        protolens.run_task(&mut task, pkt1);

        // 验证收到的行是否正确
        let expected = vec![
            "Hello\n".to_string(),
            "World!\n".to_string(),
            "Bye\n".to_string(),
        ];
        assert_eq!(*lines.borrow(), expected);
    }
}
