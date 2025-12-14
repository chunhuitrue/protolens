use crate::{
    CbSmbFile, CbSmbFileStart, CbSmbFileStop, DirConfirmFn, Parser, ParserFactory, ParserFuture,
    PktStrm, Prolens, SMB_PORT, SharedStateManager, packet::*,
};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct SmbParser<T>
where
    T: Packet,
{
    version: ValidVer,
    encrypt: EncryptMng,
    cb_file_start: Option<CbSmbFileStart>,
    cb_file: Option<CbSmbFile>,
    cb_file_stop: Option<CbSmbFileStop>,
    _phantom_t: PhantomData<T>,
}

impl<T> SmbParser<T>
where
    T: Packet,
{
    pub(crate) fn new() -> Self {
        Self {
            version: ValidVer::new(),
            encrypt: EncryptMng::new(),
            cb_file_start: None,
            cb_file: None,
            cb_file_stop: None,
            _phantom_t: PhantomData,
        }
    }

    async fn c2s_parser_inner(
        strm: *mut PktStrm<T>,
        cb_smb: SmbCallbacks,
        cb_ctx: *mut c_void,
        valid_ver: ValidVer,
        encrypt: EncryptMng,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        if !valid_ver.wait_for().await {
            return Err(());
        }

        if encrypt.wait_for().await {
            return Err(());
        }

        loop {
            let (byte, _seq) = stm.readn(4).await?;
            let netbios_len = BigEndian::read_u24(&byte[1..4]) as usize;
            let start_size = stm.get_read_size();
            loop {
                let header = Self::header(stm).await?;
                match header.command {
                    command::READ => Self::read_req(stm, header, &cb_smb, cb_ctx).await?,
                    command::WRITE => Self::write_req(stm, header, &cb_smb, cb_ctx).await?,
                    _ => Self::consume(stm, netbios_len - HEADER_SIZE as usize).await?,
                }

                let cmd_size = stm.get_read_size().saturating_sub(start_size);
                if cmd_size == netbios_len {
                    break;
                }
            }
        }
    }

    async fn s2c_parser_inner(
        strm: *mut PktStrm<T>,
        cb_smb: SmbCallbacks,
        cb_ctx: *mut c_void,
        valid_ver: ValidVer,
        encrypt: EncryptMng,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        loop {
            let (byte, _seq) = stm.readn(4).await?;
            let netbios_len = BigEndian::read_u24(&byte[1..4]) as usize;
            let start_size = stm.get_read_size();
            loop {
                let header = Self::header(stm).await?;
                match header.command {
                    command::NEGOTIATE => {
                        let ver_valiad = Self::peek_negotiate_rsp(stm).await?;
                        if !ver_valiad {
                            valid_ver.set(false).map_err(|_| ())?;
                            return Err(());
                        }
                        valid_ver.set(true).map_err(|_| ())?;

                        Self::consume(stm, netbios_len - HEADER_SIZE as usize).await?
                    }
                    command::SESSION_SETUP => {
                        let ecypt = Self::session_setup_rsp(stm).await?;
                        if ecypt {
                            encrypt.set(true).map_err(|_| ())?;
                            return Err(());
                        }
                        encrypt.set(false).map_err(|_| ())?;
                    }
                    command::READ => Self::read_rsp(stm, header, &cb_smb, cb_ctx).await?,
                    _ => Self::consume(stm, netbios_len - HEADER_SIZE as usize).await?,
                }

                let cmd_size = stm.get_read_size().saturating_sub(start_size);
                if cmd_size == netbios_len {
                    break;
                }
            }
        }
    }

    async fn header(stm: &mut PktStrm<T>) -> Result<SmbHeader, ()> {
        let (byte, _seq) = stm.readn(HEADER_SIZE as usize).await?;

        let protocol_id = LittleEndian::read_u32(&byte[0..4]);
        let structure_size = LittleEndian::read_u16(&byte[4..6]);
        let credit_charge = LittleEndian::read_u16(&byte[6..8]);
        let status = LittleEndian::read_u32(&byte[8..12]);
        let command = LittleEndian::read_u16(&byte[12..14]);
        let credit = LittleEndian::read_u16(&byte[14..16]);
        let flags = LittleEndian::read_u32(&byte[16..20]);
        let next_command = LittleEndian::read_u32(&byte[20..24]);
        let message_id = LittleEndian::read_u64(&byte[24..32]);
        let reserved = LittleEndian::read_u32(&byte[32..36]);
        let tree_id = LittleEndian::read_u32(&byte[36..40]);
        let session_id = LittleEndian::read_u64(&byte[40..48]);
        let signature = LittleEndian::read_u128(&byte[48..64]);

        Ok(SmbHeader {
            protocol_id,
            structure_size,
            credit_charge,
            status,
            command,
            credit,
            flags,
            next_command,
            message_id,
            reserved,
            tree_id,
            session_id,
            signature,
        })
    }

    async fn read_req(
        stm: &mut PktStrm<T>,
        header: SmbHeader,
        cb_smb: &SmbCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let (bytes, _seq) = stm.readn(48).await?;

        let len: u32 = LittleEndian::read_u32(&bytes[4..8]);
        let off: u64 = LittleEndian::read_u64(&bytes[8..16]);
        let fid: u128 = LittleEndian::read_u128(&bytes[16..32]);

        if let Some(ref cb) = cb_smb.file_start {
            cb.borrow_mut()(&header, len, off, fid, cb_ctx);
        }

        let channel_len: u16 = LittleEndian::read_u16(&bytes[46..48]);
        if channel_len == 0 {
            let (_bytes, _seq) = stm.readn(1).await?;
        } else {
            Self::consume(stm, channel_len.into()).await?;
        }
        Ok(())
    }

    async fn write_req(
        stm: &mut PktStrm<T>,
        header: SmbHeader,
        cb_smb: &SmbCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let (bytes, _seq) = stm.readn(48).await?;

        let len: u32 = LittleEndian::read_u32(&bytes[4..8]);
        let off: u64 = LittleEndian::read_u64(&bytes[8..16]);
        let fid: u128 = LittleEndian::read_u128(&bytes[16..32]);

        if let Some(ref cb) = cb_smb.file_start {
            cb.borrow_mut()(&header, len, off, fid, cb_ctx);
        }

        if len == 0 {
            let (_bytes, _seq) = stm.readn(1).await?;
        } else {
            let mut remain_size = len as usize;
            while remain_size > 0 {
                let (bytes, seq) = stm.read(remain_size).await?;

                if let Some(ref cb) = cb_smb.file {
                    cb.borrow_mut()(bytes, seq, cb_ctx);
                }

                remain_size -= bytes.len();
            }
            if let Some(ref cb) = cb_smb.file_stop {
                cb.borrow_mut()(&header, cb_ctx);
            }
        }
        Ok(())
    }

    async fn peek_negotiate_rsp(stm: &mut PktStrm<T>) -> Result<bool, ()> {
        let bytes = stm.peekn(6).await?;

        let ver: u16 = LittleEndian::read_u16(&bytes[4..6]);
        let is_valid = matches!(ver, 0x0202 | 0x0210 | 0x0300 | 0x0302 | 0x0311);
        Ok(is_valid)
    }

    async fn session_setup_rsp(stm: &mut PktStrm<T>) -> Result<bool, ()> {
        let (bytes, _seq) = stm.readn(8).await?;

        let flags: u16 = LittleEndian::read_u16(&bytes[2..4]);
        let buff_len: u16 = LittleEndian::read_u16(&bytes[6..8]);

        Self::consume(stm, buff_len.into()).await?;

        let ret = (flags & SESSION_FLAG_ENCRYPT_DATA) == SESSION_FLAG_ENCRYPT_DATA;
        Ok(ret)
    }

    async fn read_rsp(
        stm: &mut PktStrm<T>,
        header: SmbHeader,
        cb_smb: &SmbCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let (bytes, _seq) = stm.readn(16).await?;

        let data_len: u32 = LittleEndian::read_u32(&bytes[4..8]);

        if data_len == 0 {
            let (_bytes, _seq) = stm.readn(1).await?;
        } else {
            let mut remain_size = data_len as usize;
            while remain_size > 0 {
                let (bytes, seq) = stm.read(remain_size).await?;

                if let Some(ref cb) = cb_smb.file {
                    cb.borrow_mut()(bytes, seq, cb_ctx);
                }

                remain_size -= bytes.len();
            }
            if let Some(ref cb) = cb_smb.file_stop {
                cb.borrow_mut()(&header, cb_ctx);
            }
        }
        Ok(())
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

impl<T> Parser for SmbParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn dir_confirm(&self) -> DirConfirmFn<Self::T> {
        |c2s_strm, s2c_strm, c2s_port, s2c_port| {
            let stm_c2s = unsafe { &mut *c2s_strm };
            let stm_s2c = unsafe { &mut *s2c_strm };

            if s2c_port == SMB_PORT {
                return Some(true);
            } else if c2s_port == SMB_PORT {
                return Some(false);
            }

            let payload_c2s = stm_c2s.peek_payload();
            let payload_s2c = stm_s2c.peek_payload();

            if payload_c2s.is_err() && payload_s2c.is_err() {
                return None;
            }

            if let Ok(payload) = payload_c2s
                && payload.len() >= 32 {
                    let flags = LittleEndian::read_u32(&payload[28..32]);
                    if (flags & HEADER_FLAGS_SERVER_TO_REDIR) == 0 {
                        return Some(true);
                    } else {
                        return Some(false);
                    }
                }

            if let Ok(payload) = payload_s2c
                && payload.len() >= 32 {
                    let flags = LittleEndian::read_u32(&payload[28..32]);
                    if (flags & HEADER_FLAGS_SERVER_TO_REDIR) == 1 {
                        return Some(true);
                    } else {
                        return Some(false);
                    }
                }

            Some(true)
        }
    }

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb = SmbCallbacks {
            file_start: self.cb_file_start.clone(),
            file: self.cb_file.clone(),
            file_stop: self.cb_file_stop.clone(),
        };
        let valid_ver = self.version.clone();
        let encrypt = self.encrypt.clone();

        Some(Box::pin(Self::c2s_parser_inner(
            strm, cb, cb_ctx, valid_ver, encrypt,
        )))
    }

    fn s2c_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let cb = SmbCallbacks {
            file_start: self.cb_file_start.clone(),
            file: self.cb_file.clone(),
            file_stop: self.cb_file_stop.clone(),
        };
        let valid_ver = self.version.clone();
        let encrypt = self.encrypt.clone();

        Some(Box::pin(Self::s2c_parser_inner(
            strm, cb, cb_ctx, valid_ver, encrypt,
        )))
    }
}

pub(crate) struct SmbFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for SmbFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(SmbParser::new());
        parser.cb_file_start = prolens.cb_smb_file_start.clone();
        parser.cb_file = prolens.cb_smb_file.clone();
        parser.cb_file_stop = prolens.cb_smb_file_stop.clone();
        parser
    }
}

#[derive(Clone)]
pub(crate) struct SmbCallbacks {
    file_start: Option<CbSmbFileStart>,
    file: Option<CbSmbFile>,
    file_stop: Option<CbSmbFileStop>,
}

pub(crate) type ValidVer = SharedStateManager<bool>;
pub(crate) type EncryptMng = SharedStateManager<bool>;

const HEADER_FLAGS_SERVER_TO_REDIR: u32 = 0x00000001;
const HEADER_SIZE: u16 = 64;
const SESSION_FLAG_ENCRYPT_DATA: u16 = 0x0004;

#[rustfmt::skip]
mod command {
    pub(crate) const NEGOTIATE:     u16 = 0x0000;
    pub(crate) const SESSION_SETUP: u16 = 0x0001;
    pub(crate) const READ:          u16 = 0x0008;
    pub(crate) const WRITE:         u16 = 0x0009;
}

#[derive(Debug, Clone)]
pub struct SmbHeader {
    pub protocol_id: u32,
    pub structure_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credit: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::env;
    use std::ffi::c_void;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_smb_parser() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/smb3.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let expected_content_path = project_root.join("tests/pcap/smb_read.txt");
        let expected_content =
            std::fs::read_to_string(expected_content_path).expect("Failed to read smb_read.txt");

        let captured_file_starts = Rc::new(RefCell::new(Vec::<(SmbHeader, u32, u64, u128)>::new()));
        let captured_file_data = Rc::new(RefCell::new(HashMap::<u128, Vec<u8>>::new()));
        let captured_file_stops = Rc::new(RefCell::new(Vec::<SmbHeader>::new()));
        let current_fid = Rc::new(RefCell::new(None::<u128>));

        let file_start_callback = {
            let starts_clone = captured_file_starts.clone();
            let fid_clone = current_fid.clone();
            let data_clone = captured_file_data.clone();
            move |header: &SmbHeader, len: u32, offset: u64, fid: u128, _cb_ctx: *mut c_void| {
                let mut starts_guard = starts_clone.borrow_mut();
                starts_guard.push((header.clone(), len, offset, fid));

                // Set current FID for data collection
                let mut fid_guard = fid_clone.borrow_mut();
                *fid_guard = Some(fid);

                // Initialize data storage for this FID if not exists
                let mut data_guard = data_clone.borrow_mut();
                data_guard.entry(fid).or_default();

                println!(
                    "SMB File Start: command=0x{:04x}, len={}, offset={}, fid=0x{:032x}",
                    header.command, len, offset, fid
                );
            }
        };

        let file_data_callback = {
            let data_clone = captured_file_data.clone();
            let fid_clone = current_fid.clone();
            move |data: &[u8], _seq: u32, _cb_ctx: *mut c_void| {
                let fid_guard = fid_clone.borrow();
                if let Some(fid) = *fid_guard {
                    let mut data_guard = data_clone.borrow_mut();
                    if let Some(file_data) = data_guard.get_mut(&fid) {
                        file_data.extend_from_slice(data);
                    }
                }
                println!("SMB File Data: {} bytes received", data.len());
            }
        };

        let file_stop_callback = {
            let stops_clone = captured_file_stops.clone();
            let fid_clone = current_fid.clone();
            move |header: &SmbHeader, _cb_ctx: *mut c_void| {
                let mut stops_guard = stops_clone.borrow_mut();
                stops_guard.push(header.clone());

                // Clear current FID
                let mut fid_guard = fid_clone.borrow_mut();
                *fid_guard = None;

                println!("SMB File Stop: command=0x{:04x}\n", header.command);
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_smb_file_start(file_start_callback);
        protolens.set_cb_smb_file(file_data_callback);
        protolens.set_cb_smb_file_stop(file_stop_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::Smb);

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

        let starts_guard = captured_file_starts.borrow();
        let data_guard = captured_file_data.borrow();
        let stops_guard = captured_file_stops.borrow();

        // Verify basic statistics
        println!("Captured {} file start events", starts_guard.len());
        let total_data_bytes: usize = data_guard.values().map(|v| v.len()).sum();
        println!(
            "Captured {} bytes of file data across {} files",
            total_data_bytes,
            data_guard.len()
        );
        println!("Captured {} file stop events", stops_guard.len());

        assert_eq!(5, starts_guard.len());
        assert_eq!(3975, total_data_bytes);
        assert_eq!(5, stops_guard.len());

        // Verify READ operations
        let read_operations: Vec<_> = starts_guard
            .iter()
            .filter(|(header, _, _, _)| header.command == command::READ)
            .collect();

        assert!(
            !read_operations.is_empty(),
            "Should have at least one READ operation"
        );
        println!("Found {} READ operations", read_operations.len());

        // Find the specific large file read operation (len=3519, fid=0x000000006843c46e0000000076045775)
        let target_fid = 0x000000006843c46e0000000076045775u128;
        let large_read_op = starts_guard.iter().find(|(header, len, offset, fid)| {
            header.command == command::READ && *len == 3519 && *offset == 0 && *fid == target_fid
        });

        assert!(
            large_read_op.is_some(),
            "Should find the large READ operation with len=3519 and target FID"
        );
        println!(
            "Found target large READ operation: len=3519, fid=0x{:032x}",
            target_fid
        );

        // Verify the content of the large file read
        if let Some(large_file_data) = data_guard.get(&target_fid) {
            let received_content = String::from_utf8_lossy(large_file_data);
            println!("Large file content length: {}", received_content.len());
            println!("Expected file content length: {}", expected_content.len());

            // Verify that the read content matches expected content from smb_read.txt
            assert_eq!(
                received_content.trim(),
                expected_content.trim(),
                "Large file read content should match expected content from smb_read.txt"
            );

            println!("✓ Large file content verification passed");
        } else {
            panic!("No data found for the target large file read operation");
        }

        // Verify file operations are properly paired
        assert_eq!(
            starts_guard.len(),
            stops_guard.len(),
            "File start and stop events should be paired"
        );

        // Print summary of all file operations
        println!("\nFile operations summary:");
        for (i, (header, len, offset, fid)) in starts_guard.iter().enumerate() {
            let data_len = data_guard.get(fid).map(|v| v.len()).unwrap_or(0);
            println!(
                "  {}: command=0x{:04x}, len={}, offset={}, fid=0x{:032x}, actual_data={} bytes",
                i + 1,
                header.command,
                len,
                offset,
                fid,
                data_len
            );
        }
    }
}
