use crate::{
    CbTlsCert, CbTlsCertStart, CbTlsCertStop, CbTlsKey, CbTlsRandom, Parser, ParserFactory,
    ParserFuture, PktStrm, Prolens, SharedStateManager, packet::*,
};
use byteorder::{BigEndian, ByteOrder};
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct TlsParser<T>
where
    T: Packet,
{
    cb_clt_random: Option<CbTlsRandom>,
    cb_clt_key: Option<CbTlsKey>,
    cb_srv_random: Option<CbTlsRandom>,
    cb_srv_key: Option<CbTlsKey>,
    cb_cert_start: Option<CbTlsCertStart>,
    cb_cert: Option<CbTlsCert>,
    cb_cert_stop: Option<CbTlsCertStop>,
    version: Version,
    _phantom_t: PhantomData<T>,
}

impl<T> TlsParser<T>
where
    T: Packet,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_clt_random: None,
            cb_clt_key: None,
            cb_srv_random: None,
            cb_srv_key: None,
            cb_cert_start: None,
            cb_cert: None,
            cb_cert_stop: None,
            version: Version::new(),
            _phantom_t: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        strm: *mut PktStrm<T>,
        cb_tls: TlsCallbacks,
        cb_ctx: *mut c_void,
        version: Version,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        Self::cli_hello(stm, &cb_tls, cb_ctx).await?;

        let ver = version.wait_for().await;
        match ver {
            0x0303 => {
                // tls 1.2
                Self::cli_key_exchange(stm, &cb_tls, cb_ctx).await?;
                // Self::change_cipher_spec(stm).await?;
                Ok(())
            }
            0x0304 => {
                // tls 1.3
                // Self::change_cipher_spec(stm).await?;
                Ok(())
            }
            _ => Err(()),
        }
    }

    async fn s2c_parser_inner(
        strm: *mut PktStrm<T>,
        cb_tls: TlsCallbacks,
        cb_ctx: *mut c_void,
        version: Version,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        let ver = Self::srv_hello(stm, &cb_tls, cb_ctx).await?;
        version.set(ver).map_err(|_| ())?;

        match ver {
            0x0303 => {
                // tls 1.2
                Self::srv_cert(stm, &cb_tls, cb_ctx).await?;
                Self::srv_key_exchange(stm, &cb_tls, cb_ctx).await?;
                // Self::srv_hello_done(stm).await?;
                // Self::change_cipher_spec(stm).await?;
                Ok(())
            }
            0x0304 => {
                // tls 1.3
                // Self::change_cipher_spec(stm).await?;
                // Self::srv_wrapped_encry_data(stm).await?;
                Ok(())
            }
            _ => Err(()),
        }
    }

    async fn header(stm: &mut PktStrm<T>) -> Result<Header, ()> {
        let (bytes, _seq) = stm.readn(9).await?;

        if bytes[0] != 0x16 {
            return Err(());
        }
        if bytes[1] != 0x03 {
            return Err(());
        }
        if !(bytes[2] == 0x01 || bytes[2] == 0x03 || bytes[2] == 0x04) {
            return Err(());
        }

        let header = Header {
            mtype: bytes[5],
            len: BigEndian::read_u24(&bytes[6..9]),
        };
        Ok(header)
    }

    async fn cli_hello(
        stm: &mut PktStrm<T>,
        cb_tls: &TlsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let header = Self::header(stm).await?;
        if header.mtype != 0x01 {
            return Err(());
        }

        // version
        let (_bytes, _seq) = stm.readn(2).await?;

        // random
        let (bytes, seq) = stm.readn(32).await?;
        let random = bytes;
        if let Some(ref cb) = cb_tls.clt_random {
            cb.borrow_mut()(random, seq, cb_ctx);
        }

        // session id
        let (bytes, _seq) = stm.readn(1).await?;
        let id_len: u8 = bytes[0];
        if id_len > 0 {
            let (_bytes, _seq) = stm.readn(id_len as usize).await?;
        }

        // cipher suite
        let (bytes, _seq) = stm.readn(2).await?;
        let cs_len: u16 = BigEndian::read_u16(bytes);
        let (_bytes, _seq) = stm.readn(cs_len as usize).await?;

        // compression method
        let (bytes, _seq) = stm.readn(1).await?;
        let cp_len: u8 = bytes[0];
        let (_bytes, _seq) = stm.readn(cp_len as usize).await?;

        // extensions len
        let (bytes, _seq) = stm.readn(2).await?;
        let mut exts_len: u16 = BigEndian::read_u16(bytes);

        while exts_len > 0 {
            let (bytes, _seq) = stm.readn(4).await?;
            let etype = BigEndian::read_u16(&bytes[0..2]);
            let len = BigEndian::read_u16(&bytes[2..4]);

            // extern: key share. tls 1.3
            if etype == 0x0033 {
                let (bytes, _seq) = stm.readn(6).await?;
                let key_len = BigEndian::read_u16(&bytes[4..6]);

                let (key, seq) = stm.readn(key_len as usize).await?;

                if let Some(ref cb) = cb_tls.clt_key {
                    cb.borrow_mut()(key, seq, cb_ctx);
                }
            } else {
                let (_bytes, _seq) = stm.readn(len as usize).await?;
            }

            exts_len -= 4 + len;
        }
        Ok(())
    }

    async fn cli_key_exchange(
        stm: &mut PktStrm<T>,
        cb_tls: &TlsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let header = Self::header(stm).await?;
        if header.mtype != 0x10 {
            return Err(());
        }

        let (bytes, _seq) = stm.readn(1).await?;
        let len = bytes[0];

        let (key, seq) = stm.readn(len.into()).await?;
        if let Some(ref cb) = cb_tls.clt_key {
            cb.borrow_mut()(key, seq, cb_ctx);
        }

        Ok(())
    }

    #[allow(unused)]
    async fn change_cipher_spec(stm: &mut PktStrm<T>) -> Result<(), ()> {
        let (bytes, _seq) = stm.readn(5).await?;
        let len: u16 = BigEndian::read_u16(&bytes[3..5]);

        Self::consume(stm, len.into()).await
    }

    async fn srv_hello(
        stm: &mut PktStrm<T>,
        cb_tls: &TlsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<u16, ()> {
        let header = Self::header(stm).await?;
        if header.mtype != 0x02 {
            return Err(());
        }

        // version
        let (bytes, _seq) = stm.readn(2).await?;
        let mut ver: u16 = BigEndian::read_u16(bytes);

        // random
        let (bytes, seq) = stm.readn(32).await?;
        let random = bytes;
        if let Some(ref cb) = cb_tls.srv_random {
            cb.borrow_mut()(random, seq, cb_ctx);
        }

        // session id
        let (bytes, _seq) = stm.readn(1).await?;
        let id_len: u8 = bytes[0];
        if id_len > 0 {
            let (_bytes, _seq) = stm.readn(id_len as usize).await?;
        }

        // cipher suite, compression method, extensions len
        let (bytes, _seq) = stm.readn(5).await?;
        let mut exts_len: u16 = BigEndian::read_u16(&bytes[3..5]);

        while exts_len > 0 {
            let (bytes, _seq) = stm.readn(4).await?;
            let etype = BigEndian::read_u16(&bytes[0..2]);
            let len = BigEndian::read_u16(&bytes[2..4]);

            // extern: supported versions
            if etype == 0x002b && len == 2 {
                let (bytes, _seq) = stm.readn(2).await?;
                ver = BigEndian::read_u16(bytes);
            } else if etype == 0x0033 {
                // tls 1.3 key share
                let (bytes, _seq) = stm.readn(4).await?;
                let key_len = BigEndian::read_u16(&bytes[2..4]);
                let (bytes, seq) = stm.readn(key_len as usize).await?;

                if let Some(ref cb) = cb_tls.srv_key {
                    cb.borrow_mut()(bytes, seq, cb_ctx);
                }
            } else {
                let (_bytes, _seq) = stm.readn(len as usize).await?;
            }

            exts_len -= 4 + len;
        }
        Ok(ver)
    }

    async fn srv_cert(
        stm: &mut PktStrm<T>,
        cb_tls: &TlsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let header = Self::header(stm).await?;
        if header.mtype != 0x0b {
            return Err(());
        }

        let (bytes, _seq) = stm.readn(3).await?;
        let mut certs_len: u32 = BigEndian::read_u24(bytes);

        while certs_len > 0 {
            let (bytes, _seq) = stm.readn(3).await?;
            let len: u32 = BigEndian::read_u24(bytes);
            Self::cert(stm, len as usize, cb_tls, cb_ctx).await?;

            certs_len -= 3 + len;
        }
        Ok(())
    }

    async fn srv_key_exchange(
        stm: &mut PktStrm<T>,
        cb_tls: &TlsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let header = Self::header(stm).await?;
        if header.mtype != 0x0c {
            return Err(());
        }

        let (bytes, _seq) = stm.readn(4).await?;
        let len = bytes[3];

        let (key, seq) = stm.readn(len.into()).await?;
        if let Some(ref cb) = cb_tls.srv_key {
            cb.borrow_mut()(key, seq, cb_ctx);
        }

        Self::consume(stm, (header.len - 4 - len as u32) as usize).await
    }

    #[allow(unused)]
    async fn srv_hello_done(stm: &mut PktStrm<T>) -> Result<(), ()> {
        let header = Self::header(stm).await?;
        if header.mtype != 0x0e {
            return Err(());
        }

        Self::consume(stm, header.len as usize).await
    }

    async fn cert(
        stm: &mut PktStrm<T>,
        size: usize,
        cb_tls: &TlsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        if let Some(ref cb) = cb_tls.cert_start {
            cb.borrow_mut()(cb_ctx);
        }
        let mut remain_size = size;
        while remain_size > 0 {
            let (bytes, seq) = stm.read(remain_size).await?;
            if let Some(ref cb) = cb_tls.cert {
                cb.borrow_mut()(bytes, seq, cb_ctx);
            }

            remain_size -= bytes.len();
        }
        if let Some(ref cb) = cb_tls.cert_stop {
            cb.borrow_mut()(cb_ctx);
        }
        Ok(())
    }

    #[allow(unused)]
    async fn srv_wrapped_encry_data(stm: &mut PktStrm<T>) -> Result<(), ()> {
        Self::change_cipher_spec(stm).await
    }

    async fn consume(stm: &mut PktStrm<T>, size: usize) -> Result<(), ()> {
        let mut remain_size = size;
        while remain_size > 0 {
            let (bytes, _seq) = stm.read(remain_size).await?;
            remain_size -= bytes.len();
        }
        Ok(())
    }
}

impl<T> Parser for TlsParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb = TlsCallbacks {
            clt_random: self.cb_clt_random.clone(),
            clt_key: self.cb_clt_key.clone(),
            srv_random: self.cb_srv_random.clone(),
            srv_key: self.cb_srv_key.clone(),
            cert_start: self.cb_cert_start.clone(),
            cert: self.cb_cert.clone(),
            cert_stop: self.cb_cert_stop.clone(),
        };
        let ver = self.version.clone();

        Some(Box::pin(Self::c2s_parser_inner(strm, cb, cb_ctx, ver)))
    }

    fn s2c_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb = TlsCallbacks {
            clt_random: self.cb_clt_random.clone(),
            clt_key: self.cb_clt_key.clone(),
            srv_random: self.cb_srv_random.clone(),
            srv_key: self.cb_srv_key.clone(),
            cert_start: self.cb_cert_start.clone(),
            cert: self.cb_cert.clone(),
            cert_stop: self.cb_cert_stop.clone(),
        };
        let ver = self.version.clone();

        Some(Box::pin(Self::s2c_parser_inner(strm, cb, cb_ctx, ver)))
    }
}

pub(crate) struct TlsFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for TlsFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(TlsParser::new());
        parser.cb_clt_random = prolens.cb_tls_clt_random.clone();
        parser.cb_clt_key = prolens.cb_tls_clt_key.clone();
        parser.cb_srv_random = prolens.cb_tls_srv_random.clone();
        parser.cb_srv_key = prolens.cb_tls_srv_key.clone();
        parser.cb_cert_start = prolens.cb_tls_cert_start.clone();
        parser.cb_cert = prolens.cb_tls_cert.clone();
        parser.cb_cert_stop = prolens.cb_tls_cert_stop.clone();
        parser
    }
}

#[derive(Clone)]
pub(crate) struct TlsCallbacks {
    clt_random: Option<CbTlsRandom>,
    clt_key: Option<CbTlsKey>,
    srv_random: Option<CbTlsRandom>,
    srv_key: Option<CbTlsKey>,
    cert_start: Option<CbTlsCertStart>,
    cert: Option<CbTlsCert>,
    cert_stop: Option<CbTlsCertStop>,
}

#[derive(Clone, Debug)]
pub(crate) struct Header {
    mtype: u8,
    len: u32,
}

type Version = SharedStateManager<u16>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::env;
    use std::ffi::c_void;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_tlsv1_2_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/tlsv1_2.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_clt_random = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_clt_key = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_srv_random = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_srv_key = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_cert = Rc::new(RefCell::new(Vec::<u8>::new()));
        let cert_started = Rc::new(RefCell::new(false));

        let clt_random_callback = {
            let data_clone = captured_clt_random.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS Client Random: {} bytes received", data.len());
            }
        };

        let clt_key_callback = {
            let data_clone = captured_clt_key.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS Client Key: {} bytes received", data.len());
            }
        };

        let srv_random_callback = {
            let data_clone = captured_srv_random.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS Server Random: {} bytes received", data.len());
            }
        };

        let srv_key_callback = {
            let data_clone = captured_srv_key.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS Server Key: {} bytes received", data.len());
            }
        };

        let cert_start_callback = {
            let started_clone = cert_started.clone();
            move |_cb_ctx: *mut c_void| {
                let mut started_guard = started_clone.borrow_mut();
                *started_guard = true;
                println!("TLS Certificate Start");
            }
        };

        let cert_callback = {
            let data_clone = captured_cert.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS Certificate: {} bytes received", data.len());
            }
        };

        let cert_stop_callback = {
            let started_clone = cert_started.clone();
            move |_cb_ctx: *mut c_void| {
                let mut started_guard = started_clone.borrow_mut();
                *started_guard = false;
                println!("TLS Certificate Stop");
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_tls_clt_random(clt_random_callback);
        protolens.set_cb_tls_clt_key(clt_key_callback);
        protolens.set_cb_tls_srv_random(srv_random_callback);
        protolens.set_cb_tls_srv_key(srv_key_callback);
        protolens.set_cb_tls_cert_start(cert_start_callback);
        protolens.set_cb_tls_cert(cert_callback);
        protolens.set_cb_tls_cert_stop(cert_stop_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Tls);

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

        let clt_random_guard = captured_clt_random.borrow();
        let clt_key_guard = captured_clt_key.borrow();
        let srv_random_guard = captured_srv_random.borrow();
        let srv_key_guard = captured_srv_key.borrow();
        let cert_guard = captured_cert.borrow();

        println!("Captured {} bytes of client random", clt_random_guard.len());
        println!("Captured {} bytes of client key", clt_key_guard.len());
        println!("Captured {} bytes of server random", srv_random_guard.len());
        println!("Captured {} bytes of server key", srv_key_guard.len());
        println!("Captured {} bytes of certificate", cert_guard.len());

        let expected_clt_random = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let expected_clt_key = vec![
            0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
            0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2,
            0xcd, 0x16, 0x62, 0x54,
        ];

        let expected_srv_random = vec![
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,
            0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
            0x8c, 0x8d, 0x8e, 0x8f,
        ];

        let expected_srv_key = vec![
            0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a,
            0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98,
            0x28, 0x80, 0xb6, 0x15,
        ];

        let expected_cert = vec![
            0x30, 0x82, 0x03, 0x21, 0x30, 0x82, 0x02, 0x09, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
            0x08, 0x15, 0x5a, 0x92, 0xad, 0xc2, 0x04, 0x8f, 0x90, 0x30, 0x0d, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x22, 0x31, 0x0b,
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30,
            0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x30, 0x30, 0x35,
            0x30, 0x31, 0x33, 0x38, 0x31, 0x37, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x30,
            0x35, 0x30, 0x31, 0x33, 0x38, 0x31, 0x37, 0x5a, 0x30, 0x2b, 0x31, 0x0b, 0x30, 0x09,
            0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1c, 0x30, 0x1a, 0x06,
            0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74, 0x30, 0x82, 0x01,
            0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,
            0x01, 0x00, 0xc4, 0x80, 0x36, 0x06, 0xba, 0xe7, 0x47, 0x6b, 0x08, 0x94, 0x04, 0xec,
            0xa7, 0xb6, 0x91, 0x04, 0x3f, 0xf7, 0x92, 0xbc, 0x19, 0xee, 0xfb, 0x7d, 0x74, 0xd7,
            0xa8, 0x0d, 0x00, 0x1e, 0x7b, 0x4b, 0x3a, 0x4a, 0xe6, 0x0f, 0xe8, 0xc0, 0x71, 0xfc,
            0x73, 0xe7, 0x02, 0x4c, 0x0d, 0xbc, 0xf4, 0xbd, 0xd1, 0x1d, 0x39, 0x6b, 0xba, 0x70,
            0x46, 0x4a, 0x13, 0xe9, 0x4a, 0xf8, 0x3d, 0xf3, 0xe1, 0x09, 0x59, 0x54, 0x7b, 0xc9,
            0x55, 0xfb, 0x41, 0x2d, 0xa3, 0x76, 0x52, 0x11, 0xe1, 0xf3, 0xdc, 0x77, 0x6c, 0xaa,
            0x53, 0x37, 0x6e, 0xca, 0x3a, 0xec, 0xbe, 0xc3, 0xaa, 0xb7, 0x3b, 0x31, 0xd5, 0x6c,
            0xb6, 0x52, 0x9c, 0x80, 0x98, 0xbc, 0xc9, 0xe0, 0x28, 0x18, 0xe2, 0x0b, 0xf7, 0xf8,
            0xa0, 0x3a, 0xfd, 0x17, 0x04, 0x50, 0x9e, 0xce, 0x79, 0xbd, 0x9f, 0x39, 0xf1, 0xea,
            0x69, 0xec, 0x47, 0x97, 0x2e, 0x83, 0x0f, 0xb5, 0xca, 0x95, 0xde, 0x95, 0xa1, 0xe6,
            0x04, 0x22, 0xd5, 0xee, 0xbe, 0x52, 0x79, 0x54, 0xa1, 0xe7, 0xbf, 0x8a, 0x86, 0xf6,
            0x46, 0x6d, 0x0d, 0x9f, 0x16, 0x95, 0x1a, 0x4c, 0xf7, 0xa0, 0x46, 0x92, 0x59, 0x5c,
            0x13, 0x52, 0xf2, 0x54, 0x9e, 0x5a, 0xfb, 0x4e, 0xbf, 0xd7, 0x7a, 0x37, 0x95, 0x01,
            0x44, 0xe4, 0xc0, 0x26, 0x87, 0x4c, 0x65, 0x3e, 0x40, 0x7d, 0x7d, 0x23, 0x07, 0x44,
            0x01, 0xf4, 0x84, 0xff, 0xd0, 0x8f, 0x7a, 0x1f, 0xa0, 0x52, 0x10, 0xd1, 0xf4, 0xf0,
            0xd5, 0xce, 0x79, 0x70, 0x29, 0x32, 0xe2, 0xca, 0xbe, 0x70, 0x1f, 0xdf, 0xad, 0x6b,
            0x4b, 0xb7, 0x11, 0x01, 0xf4, 0x4b, 0xad, 0x66, 0x6a, 0x11, 0x13, 0x0f, 0xe2, 0xee,
            0x82, 0x9e, 0x4d, 0x02, 0x9d, 0xc9, 0x1c, 0xdd, 0x67, 0x16, 0xdb, 0xb9, 0x06, 0x18,
            0x86, 0xed, 0xc1, 0xba, 0x94, 0x21, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x52, 0x30,
            0x50, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
            0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06,
            0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
            0x18, 0x30, 0x16, 0x80, 0x14, 0x89, 0x4f, 0xde, 0x5b, 0xcc, 0x69, 0xe2, 0x52, 0xcf,
            0x3e, 0xa3, 0x00, 0xdf, 0xb1, 0x97, 0xb8, 0x1d, 0xe1, 0xc1, 0x46, 0x30, 0x0d, 0x06,
            0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
            0x01, 0x01, 0x00, 0x59, 0x16, 0x45, 0xa6, 0x9a, 0x2e, 0x37, 0x79, 0xe4, 0xf6, 0xdd,
            0x27, 0x1a, 0xba, 0x1c, 0x0b, 0xfd, 0x6c, 0xd7, 0x55, 0x99, 0xb5, 0xe7, 0xc3, 0x6e,
            0x53, 0x3e, 0xff, 0x36, 0x59, 0x08, 0x43, 0x24, 0xc9, 0xe7, 0xa5, 0x04, 0x07, 0x9d,
            0x39, 0xe0, 0xd4, 0x29, 0x87, 0xff, 0xe3, 0xeb, 0xdd, 0x09, 0xc1, 0xcf, 0x1d, 0x91,
            0x44, 0x55, 0x87, 0x0b, 0x57, 0x1d, 0xd1, 0x9b, 0xdf, 0x1d, 0x24, 0xf8, 0xbb, 0x9a,
            0x11, 0xfe, 0x80, 0xfd, 0x59, 0x2b, 0xa0, 0x39, 0x8c, 0xde, 0x11, 0xe2, 0x65, 0x1e,
            0x61, 0x8c, 0xe5, 0x98, 0xfa, 0x96, 0xe5, 0x37, 0x2e, 0xef, 0x3d, 0x24, 0x8a, 0xfd,
            0xe1, 0x74, 0x63, 0xeb, 0xbf, 0xab, 0xb8, 0xe4, 0xd1, 0xab, 0x50, 0x2a, 0x54, 0xec,
            0x00, 0x64, 0xe9, 0x2f, 0x78, 0x19, 0x66, 0x0d, 0x3f, 0x27, 0xcf, 0x20, 0x9e, 0x66,
            0x7f, 0xce, 0x5a, 0xe2, 0xe4, 0xac, 0x99, 0xc7, 0xc9, 0x38, 0x18, 0xf8, 0xb2, 0x51,
            0x07, 0x22, 0xdf, 0xed, 0x97, 0xf3, 0x2e, 0x3e, 0x93, 0x49, 0xd4, 0xc6, 0x6c, 0x9e,
            0xa6, 0x39, 0x6d, 0x74, 0x44, 0x62, 0xa0, 0x6b, 0x42, 0xc6, 0xd5, 0xba, 0x68, 0x8e,
            0xac, 0x3a, 0x01, 0x7b, 0xdd, 0xfc, 0x8e, 0x2c, 0xfc, 0xad, 0x27, 0xcb, 0x69, 0xd3,
            0xcc, 0xdc, 0xa2, 0x80, 0x41, 0x44, 0x65, 0xd3, 0xae, 0x34, 0x8c, 0xe0, 0xf3, 0x4a,
            0xb2, 0xfb, 0x9c, 0x61, 0x83, 0x71, 0x31, 0x2b, 0x19, 0x10, 0x41, 0x64, 0x1c, 0x23,
            0x7f, 0x11, 0xa5, 0xd6, 0x5c, 0x84, 0x4f, 0x04, 0x04, 0x84, 0x99, 0x38, 0x71, 0x2b,
            0x95, 0x9e, 0xd6, 0x85, 0xbc, 0x5c, 0x5d, 0xd6, 0x45, 0xed, 0x19, 0x90, 0x94, 0x73,
            0x40, 0x29, 0x26, 0xdc, 0xb4, 0x0e, 0x34, 0x69, 0xa1, 0x59, 0x41, 0xe8, 0xe2, 0xcc,
            0xa8, 0x4b, 0xb6, 0x08, 0x46, 0x36, 0xa0,
        ];

        assert_eq!(
            *clt_random_guard, expected_clt_random,
            "Client random should match expected value"
        );
        println!("✓ Client random verification passed");

        assert_eq!(
            *clt_key_guard, expected_clt_key,
            "Client key should match expected value"
        );
        println!("✓ Client key verification passed");

        assert_eq!(
            *srv_random_guard, expected_srv_random,
            "Server random should match expected value"
        );
        println!("✓ Server random verification passed");

        assert_eq!(
            *srv_key_guard, expected_srv_key,
            "Server key should match expected value"
        );
        println!("✓ Server key verification passed");

        assert_eq!(
            *cert_guard, expected_cert,
            "Certificate should match expected value"
        );
        println!("✓ Certificate verification passed");
    }

    #[test]
    fn test_tlsv1_3_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/tlsv1_3.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_clt_random = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_clt_key = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_srv_random = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_srv_key = Rc::new(RefCell::new(Vec::<u8>::new()));
        let captured_cert = Rc::new(RefCell::new(Vec::<u8>::new()));
        let cert_started = Rc::new(RefCell::new(false));

        let clt_random_callback = {
            let data_clone = captured_clt_random.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS 1.3 Client Random: {} bytes received", data.len());
            }
        };

        let clt_key_callback = {
            let data_clone = captured_clt_key.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS 1.3 Client Key: {} bytes received", data.len());
            }
        };

        let srv_random_callback = {
            let data_clone = captured_srv_random.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS 1.3 Server Random: {} bytes received", data.len());
            }
        };

        let srv_key_callback = {
            let data_clone = captured_srv_key.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!("TLS 1.3 Server Key: {} bytes received", data.len());
            }
        };

        let cert_start_callback = {
            let started_clone = cert_started.clone();
            move |_cb_ctx: *mut c_void| {
                let mut started_guard = started_clone.borrow_mut();
                *started_guard = true;
                println!("TLS 1.3 Certificate Start (unexpected)");
            }
        };

        let cert_callback = {
            let data_clone = captured_cert.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let mut data_guard = data_clone.borrow_mut();
                data_guard.extend_from_slice(data);
                println!(
                    "TLS 1.3 Certificate: {} bytes received (unexpected)",
                    data.len()
                );
            }
        };

        let cert_stop_callback = {
            let started_clone = cert_started.clone();
            move |_cb_ctx: *mut c_void| {
                let mut started_guard = started_clone.borrow_mut();
                *started_guard = false;
                println!("TLS 1.3 Certificate Stop (unexpected)");
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_tls_clt_random(clt_random_callback);
        protolens.set_cb_tls_clt_key(clt_key_callback);
        protolens.set_cb_tls_srv_random(srv_random_callback);
        protolens.set_cb_tls_srv_key(srv_key_callback);
        protolens.set_cb_tls_cert_start(cert_start_callback);
        protolens.set_cb_tls_cert(cert_callback);
        protolens.set_cb_tls_cert_stop(cert_stop_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Tls);

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

        let clt_random_guard = captured_clt_random.borrow();
        let clt_key_guard = captured_clt_key.borrow();
        let srv_random_guard = captured_srv_random.borrow();
        let srv_key_guard = captured_srv_key.borrow();
        let cert_guard = captured_cert.borrow();

        println!("Captured {} bytes of client random", clt_random_guard.len());
        println!("Captured {} bytes of client key", clt_key_guard.len());
        println!("Captured {} bytes of server random", srv_random_guard.len());
        println!("Captured {} bytes of server key", srv_key_guard.len());
        println!(
            "Captured {} bytes of certificate (should be 0)",
            cert_guard.len()
        );

        let expected_clt_random = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let expected_clt_key = vec![
            0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
            0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2,
            0xcd, 0x16, 0x62, 0x54,
        ];

        let expected_srv_random = vec![
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,
            0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
            0x8c, 0x8d, 0x8e, 0x8f,
        ];

        let expected_srv_key = vec![
            0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a,
            0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98,
            0x28, 0x80, 0xb6, 0x15,
        ];

        assert_eq!(
            *clt_random_guard, expected_clt_random,
            "TLS 1.3 Client random should match expected value"
        );
        println!("✓ TLS 1.3 Client random verification passed");

        assert_eq!(
            *clt_key_guard, expected_clt_key,
            "TLS 1.3 Client key should match expected value"
        );
        println!("✓ TLS 1.3 Client key verification passed");

        assert_eq!(
            *srv_random_guard, expected_srv_random,
            "TLS 1.3 Server random should match expected value"
        );
        println!("✓ TLS 1.3 Server random verification passed");

        assert_eq!(
            *srv_key_guard, expected_srv_key,
            "TLS 1.3 Server key should match expected value"
        );
        println!("✓ TLS 1.3 Server key verification passed");

        assert_eq!(
            cert_guard.len(),
            0,
            "TLS 1.3 Certificate data should be empty (encrypted)"
        );
        println!("✓ TLS 1.3 Certificate verification passed (empty as expected)");

        let cert_started_guard = cert_started.borrow();
        assert!(
            !(*cert_started_guard),
            "TLS 1.3 Certificate start should not be triggered (encrypted)"
        );
        println!("✓ TLS 1.3 Certificate start verification passed (not triggered as expected)");
    }
}
