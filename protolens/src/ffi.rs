extern crate libc;
use crate::Encoding;
use crate::L7Proto;
use crate::Prolens;
use crate::Task;
use crate::TransferEncoding;
use crate::packet::Direction;
use crate::packet::TransProto;
use std::cell::RefCell;
use std::ffi::c_void;
use std::net::IpAddr;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CIpAddr {
    pub ip_type: u8, // 0: Invalid, 1: IPv4, 2: IPv6
    pub octets: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketVTable {
    pub trans_proto: extern "C" fn(*mut std::ffi::c_void) -> TransProto,
    pub sip: extern "C" fn(*mut std::ffi::c_void) -> CIpAddr,
    pub dip: extern "C" fn(*mut std::ffi::c_void) -> CIpAddr,
    pub tu_sport: extern "C" fn(*mut std::ffi::c_void) -> u16,
    pub tu_dport: extern "C" fn(*mut std::ffi::c_void) -> u16,
    pub seq: extern "C" fn(*mut std::ffi::c_void) -> u32,
    pub syn: extern "C" fn(*mut std::ffi::c_void) -> bool,
    pub fin: extern "C" fn(*mut std::ffi::c_void) -> bool,
    pub payload_len: extern "C" fn(*mut std::ffi::c_void) -> usize,
    pub payload: extern "C" fn(*mut std::ffi::c_void) -> *const u8,
    pub free: extern "C" fn(*mut std::ffi::c_void),
}

extern "C" fn missing_trans_proto(_: *mut std::ffi::c_void) -> TransProto {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_ip(_: *mut std::ffi::c_void) -> CIpAddr {
    CIpAddr {
        ip_type: 0,
        octets: [0; 16],
    }
}

extern "C" fn missing_u16(_: *mut std::ffi::c_void) -> u16 {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_u32(_: *mut std::ffi::c_void) -> u32 {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_bool(_: *mut std::ffi::c_void) -> bool {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_usize(_: *mut std::ffi::c_void) -> usize {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_ptr(_: *mut std::ffi::c_void) -> *const u8 {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_free(_: *mut std::ffi::c_void) {
    panic!("VTABLE not initialized")
}

thread_local! {
    static VTABLE: RefCell<PacketVTable> = RefCell::new(PacketVTable {
        trans_proto: missing_trans_proto,
        sip: missing_ip,
        dip: missing_ip,
        tu_sport: missing_u16,
        tu_dport: missing_u16,
        seq: missing_u32,
        syn: missing_bool,
        fin: missing_bool,
        payload_len: missing_usize,
        payload: missing_ptr,
        free: missing_free,
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_init_vtable(vtable: PacketVTable) {
    VTABLE.with(|v| {
        *v.borrow_mut() = vtable;
    });
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Clone)]
pub struct FfiPacket {
    packet_ptr: *mut std::ffi::c_void,
}

impl crate::Packet for FfiPacket {
    fn trans_proto(&self) -> TransProto {
        VTABLE.with(|vtable| (vtable.borrow().trans_proto)(self.packet_ptr))
    }

    fn sip(&self) -> IpAddr {
        let c_ip = VTABLE.with(|vtable| (vtable.borrow().sip)(self.packet_ptr));
        match c_ip.ip_type {
            1 => IpAddr::V4(std::net::Ipv4Addr::from([
                c_ip.octets[0],
                c_ip.octets[1],
                c_ip.octets[2],
                c_ip.octets[3],
            ])),
            2 => IpAddr::V6(std::net::Ipv6Addr::from(c_ip.octets)),
            _ => IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        }
    }

    fn dip(&self) -> IpAddr {
        let c_ip = VTABLE.with(|vtable| (vtable.borrow().dip)(self.packet_ptr));
        match c_ip.ip_type {
            1 => IpAddr::V4(std::net::Ipv4Addr::from([
                c_ip.octets[0],
                c_ip.octets[1],
                c_ip.octets[2],
                c_ip.octets[3],
            ])),
            2 => IpAddr::V6(std::net::Ipv6Addr::from(c_ip.octets)),
            _ => IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        }
    }

    fn tu_sport(&self) -> u16 {
        VTABLE.with(|vtable| (vtable.borrow().tu_sport)(self.packet_ptr))
    }

    fn tu_dport(&self) -> u16 {
        VTABLE.with(|vtable| (vtable.borrow().tu_dport)(self.packet_ptr))
    }

    fn seq(&self) -> u32 {
        VTABLE.with(|vtable| (vtable.borrow().seq)(self.packet_ptr))
    }

    fn syn(&self) -> bool {
        VTABLE.with(|vtable| (vtable.borrow().syn)(self.packet_ptr))
    }

    fn fin(&self) -> bool {
        VTABLE.with(|vtable| (vtable.borrow().fin)(self.packet_ptr))
    }

    fn payload_len(&self) -> usize {
        VTABLE.with(|vtable| (vtable.borrow().payload_len)(self.packet_ptr))
    }

    fn payload(&self) -> &[u8] {
        VTABLE.with(|vtable| unsafe {
            let ptr = (vtable.borrow().payload)(self.packet_ptr);
            let len = self.payload_len();
            std::slice::from_raw_parts(ptr, len)
        })
    }
}

impl Drop for FfiPacket {
    fn drop(&mut self) {
        VTABLE.with(|vtable| (vtable.borrow().free)(self.packet_ptr))
    }
}

#[allow(dead_code)]
pub struct FfiProlens(Prolens<FfiPacket>);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_new() -> *mut FfiProlens {
    let prolens = Box::new(FfiProlens(Prolens::<FfiPacket>::default()));
    Box::into_raw(prolens)
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_free(prolens: *mut FfiProlens) {
    if !prolens.is_null() {
        unsafe {
            let _ = Box::from_raw(prolens);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_new(
    prolens: *mut FfiProlens,
    l4_proto: TransProto,
    cb_ctx: *mut c_void,
) -> *mut Task<FfiPacket> {
    if prolens.is_null() {
        return std::ptr::null_mut();
    }

    let prolens = unsafe { &mut *prolens };
    let task = prolens.0.new_task_ffi(l4_proto, cb_ctx);
    Box::into_raw(task)
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_free(prolens: *mut FfiProlens, task: *mut Task<FfiPacket>) {
    if task.is_null() || prolens.is_null() {
        return;
    }

    unsafe {
        let _ = Box::from_raw(task);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_dbinfo(prolens: *mut FfiProlens, task: *mut Task<FfiPacket>) {
    if task.is_null() || prolens.is_null() {
        return;
    }

    let task = unsafe { &mut *task };
    task.debug_info();
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CL7Proto {
    OrdPacket = 0,
    Smtp,
    Pop3,
    Imap,
    Http,
    FtpCmd,
    FtpData,
    Unknown,
}

impl From<CL7Proto> for L7Proto {
    fn from(proto: CL7Proto) -> Self {
        match proto {
            CL7Proto::OrdPacket => L7Proto::OrdPacket,
            CL7Proto::Smtp => L7Proto::Smtp,
            CL7Proto::Pop3 => L7Proto::Pop3,
            CL7Proto::Imap => L7Proto::Imap,
            CL7Proto::Http => L7Proto::Http,
            CL7Proto::FtpCmd => L7Proto::FtpCmd,
            CL7Proto::FtpData => L7Proto::FtpData,
            CL7Proto::Unknown => L7Proto::Unknown,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_task_parser(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket>,
    l7_proto: CL7Proto,
) {
    if prolens.is_null() || task.is_null() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let task = unsafe { &mut *task };
    prolens.0.set_task_parser(task, l7_proto.into());
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TaskResult {
    Pending,
    Done,
    Error,
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_run(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket>,
    pkt_ptr: *mut c_void,
) -> TaskResult {
    if prolens.is_null() || task.is_null() || pkt_ptr.is_null() {
        return TaskResult::Error;
    }

    let prolens = unsafe { &mut *prolens };
    let task = unsafe { &mut *task };

    let pkt = FfiPacket {
        packet_ptr: pkt_ptr,
    };

    match prolens.0.run_task(task, pkt) {
        None => TaskResult::Pending,
        Some(Ok(())) => TaskResult::Done,
        Some(Err(())) => TaskResult::Error,
    }
}

pub type CbStm = extern "C" fn(data: *const u8, data_len: usize, seq: u32, *const c_void);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_task_c2s(prolens: *mut FfiProlens, callback: Option<CbStm>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };

    let wrapper = move |data: &[u8], seq: u32, ctx: *const c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_task_c2s(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_task_s2c(prolens: *mut FfiProlens, callback: Option<CbStm>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };

    let wrapper = move |data: &[u8], seq: u32, ctx: *const c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_task_c2s(wrapper);
}

type CbOrdPkt = extern "C" fn(pkt_ptr: *mut c_void, ctx: *const c_void, dir: Direction);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ord_pkt(prolens: *mut FfiProlens, callback: Option<CbOrdPkt>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |pkt: FfiPacket, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(pkt.packet_ptr, ctx, dir);
    };
    prolens.0.set_cb_ord_pkt(wrapper);
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CTransferEncoding {
    None,
    Bit7,
    Bit8,
    Binary,
    QuotedPrintable,
    Base64,
}

impl From<Option<TransferEncoding>> for CTransferEncoding {
    fn from(te: Option<TransferEncoding>) -> Self {
        match te {
            Some(TransferEncoding::Bit7) => CTransferEncoding::Bit7,
            Some(TransferEncoding::Bit8) => CTransferEncoding::Bit8,
            Some(TransferEncoding::Binary) => CTransferEncoding::Binary,
            Some(TransferEncoding::QuotedPrintable) => CTransferEncoding::QuotedPrintable,
            Some(TransferEncoding::Base64) => CTransferEncoding::Base64,
            None => CTransferEncoding::None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CEncoding {
    None,
    Compress,
    Deflate,
    Gzip,
    Lzma,
    Br,
    Identity,
    Chunked,
}

impl From<Option<Encoding>> for CEncoding {
    fn from(ce: Option<Encoding>) -> Self {
        match ce {
            Some(Encoding::Compress) => CEncoding::Compress,
            Some(Encoding::Deflate) => CEncoding::Deflate,
            Some(Encoding::Gzip) => CEncoding::Gzip,
            Some(Encoding::Lzma) => CEncoding::Lzma,
            Some(Encoding::Br) => CEncoding::Br,
            Some(Encoding::Identity) => CEncoding::Identity,
            Some(Encoding::Chunked) => CEncoding::Chunked,
            None => CEncoding::None,
        }
    }
}

type CbData = extern "C" fn(data: *const u8, len: usize, seq: u32, ctx: *const c_void);
type CbDirData =
    extern "C" fn(data: *const u8, len: usize, seq: u32, ctx: *const c_void, dir: Direction);
type CbDirEvt = extern "C" fn(ctx: *const c_void, dir: Direction);
type CbBody = extern "C" fn(
    data: *const u8,
    len: usize,
    seq: u32,
    ctx: *const c_void,
    dir: Direction,
    te: CTransferEncoding,
);
type CbFtpLink = extern "C" fn(
    ip_ptr: *const u8,
    ip_len: usize,
    ip_type: u8, // 0表示无IP，1表示IPv4，2表示IPv6
    port: u16,
    ctx: *const c_void,
    dir: Direction,
);

const MAX_ENCODING: usize = 8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CEncodingArray {
    ptr: *const CEncoding,
    len: usize,
    buffer: [CEncoding; MAX_ENCODING],
}

impl From<Option<Vec<Encoding>>> for CEncodingArray {
    fn from(encodings: Option<Vec<Encoding>>) -> Self {
        match encodings {
            None => CEncodingArray {
                ptr: std::ptr::null(),
                len: 0,
                buffer: [CEncoding::None; MAX_ENCODING],
            },
            Some(vec) => {
                let mut array = CEncodingArray {
                    ptr: std::ptr::null(),
                    len: 0,
                    buffer: [CEncoding::None; MAX_ENCODING],
                };
                array.len = vec.len().min(MAX_ENCODING);
                for (i, e) in vec.iter().take(MAX_ENCODING).enumerate() {
                    array.buffer[i] = CEncoding::from(Some(*e));
                }
                array.ptr = array.buffer.as_ptr();
                array
            }
        }
    }
}

type CbHttpBody = extern "C" fn(
    data: *const u8,
    len: usize,
    seq: u32,
    ctx: *const c_void,
    dir: Direction,
    ce: CEncodingArray,
    te: CEncodingArray,
);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_user(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_user(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_pass(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_pass(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_mailfrom(
    prolens: *mut FfiProlens,
    callback: Option<CbData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_mailfrom(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_rcpt(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_rcpt(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_header(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir);
    };
    prolens.0.set_cb_smtp_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_smtp_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_body(prolens: *mut FfiProlens, callback: Option<CbBody>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8],
                        seq: u32,
                        ctx: *mut c_void,
                        dir: Direction,
                        te: Option<TransferEncoding>| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir, te.into());
    };
    prolens.0.set_cb_smtp_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_body_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_smtp_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smtp_srv(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_srv(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_pop3_header(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir);
    };
    prolens.0.set_cb_pop3_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_pop3_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_pop3_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_pop3_body(prolens: *mut FfiProlens, callback: Option<CbBody>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8],
                        seq: u32,
                        ctx: *mut c_void,
                        dir: Direction,
                        te: Option<TransferEncoding>| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir, te.into());
    };
    prolens.0.set_cb_pop3_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_pop3_body_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_pop3_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_pop3_clt(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_pop3_clt(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_pop3_srv(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_pop3_srv(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_imap_header(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir);
    };
    prolens.0.set_cb_imap_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_imap_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_imap_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_imap_body(prolens: *mut FfiProlens, callback: Option<CbBody>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8],
                        seq: u32,
                        ctx: *mut c_void,
                        dir: Direction,
                        te: Option<TransferEncoding>| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir, te.into());
    };
    prolens.0.set_cb_imap_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_imap_body_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_imap_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_imap_clt(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_imap_clt(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_imap_srv(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_imap_srv(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_http_start_line(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir);
    };
    prolens.0.set_cb_http_start_line(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_http_header(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir);
    };
    prolens.0.set_cb_http_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_http_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_http_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_http_body(
    prolens: *mut FfiProlens,
    callback: Option<CbHttpBody>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8],
                        seq: u32,
                        ctx: *mut c_void,
                        dir: Direction,
                        ce: &Option<Vec<Encoding>>,
                        te: &Option<Vec<Encoding>>| {
        callback.unwrap()(
            data.as_ptr(),
            data.len(),
            seq,
            ctx,
            dir,
            CEncodingArray::from(ce.clone()),
            CEncodingArray::from(te.clone()),
        );
    };
    prolens.0.set_cb_http_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_http_body_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_http_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ftp_clt(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_ftp_clt(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ftp_srv(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_ftp_srv(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ftp_link(prolens: *mut FfiProlens, callback: Option<CbFtpLink>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ip: Option<IpAddr>, port: u16, ctx: *mut c_void, dir: Direction| {
        let mut ip_bytes: [u8; 16] = [0; 16];
        let mut ip_len: usize = 0;
        let mut ip_type: u8 = 0;

        if let Some(addr) = ip {
            match addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    ip_bytes[..4].copy_from_slice(&octets);
                    ip_len = 4;
                    ip_type = 1;
                }
                IpAddr::V6(ipv6) => {
                    let octets = ipv6.octets();
                    ip_bytes.copy_from_slice(&octets);
                    ip_len = 16;
                    ip_type = 2;
                }
            }
        }

        callback.unwrap()(ip_bytes.as_ptr(), ip_len, ip_type, port, ctx, dir);
    };
    prolens.0.set_cb_ftp_link(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ftp_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_ftp_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ftp_body(prolens: *mut FfiProlens, callback: Option<CbDirData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx, dir);
    };
    prolens.0.set_cb_ftp_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_ftp_body_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_ftp_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_sip_start_line(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], offset: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), offset, ctx, dir);
    };
    prolens.0.set_cb_sip_start_line(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_sip_header(
    prolens: *mut FfiProlens,
    callback: Option<CbDirData>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], offset: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), offset, ctx, dir);
    };
    prolens.0.set_cb_sip_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_sip_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_sip_body_start(wrapper);
}

type CbSipBody =
    extern "C" fn(data: *const u8, len: usize, offset: u32, ctx: *const c_void, dir: Direction);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_sip_body(prolens: *mut FfiProlens, callback: Option<CbSipBody>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], offset: u32, ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(data.as_ptr(), data.len(), offset, ctx, dir);
    };
    prolens.0.set_cb_sip_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_sip_body_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbDirEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void, dir: Direction| {
        callback.unwrap()(ctx, dir);
    };
    prolens.0.set_cb_sip_body_stop(wrapper);
}
