extern crate libc;
use crate::Encoding;
use crate::L7Proto;
use crate::Prolens;
use crate::Task;
use crate::TransferEncoding;
use crate::packet::Direction;
use crate::packet::TransProto;
use crate::parser::dnsudp::{
    Class, DnsHeader, Opcode, OptRR, Qclass, Qtype, RR, Rcode, Rdata, Type,
};
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
    Sip,
    DnsUdp,
    DnsTcp,
    Smb,
    Tls,

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
            CL7Proto::Sip => L7Proto::Sip,
            CL7Proto::DnsUdp => L7Proto::DnsUdp,
            CL7Proto::DnsTcp => L7Proto::DnsTcp,
            CL7Proto::Smb => L7Proto::Smb,
            CL7Proto::Tls => L7Proto::Tls,
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

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum COpcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Reserved = 255,
}

impl From<Opcode> for COpcode {
    fn from(opcode: Opcode) -> Self {
        match opcode {
            Opcode::Query => COpcode::Query,
            Opcode::IQuery => COpcode::IQuery,
            Opcode::Status => COpcode::Status,
            Opcode::Reserved(_) => COpcode::Reserved,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CRcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Reserved = 255,
}

impl From<Rcode> for CRcode {
    fn from(rcode: Rcode) -> Self {
        match rcode {
            Rcode::NoError => CRcode::NoError,
            Rcode::FormatError => CRcode::FormatError,
            Rcode::ServerFailure => CRcode::ServerFailure,
            Rcode::NameError => CRcode::NameError,
            Rcode::NotImplemented => CRcode::NotImplemented,
            Rcode::Refused => CRcode::Refused,
            Rcode::Reserved(_) => CRcode::Reserved,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: COpcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: CRcode,
    pub qcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl From<DnsHeader> for CHeader {
    fn from(header: DnsHeader) -> Self {
        CHeader {
            id: header.id,
            qr: header.qr,
            opcode: header.opcode.into(),
            aa: header.aa,
            tc: header.tc,
            rd: header.rd,
            ra: header.ra,
            ad: header.ad,
            cd: header.cd,
            rcode: header.rcode.into(),
            qcount: header.qcount,
            ancount: header.ancount,
            nscount: header.nscount,
            arcount: header.arcount,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CQtype {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    Cname = 5,
    Soa = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    Null = 10,
    Wks = 11,
    Ptr = 12,
    Hinfo = 13,
    Minfo = 14,
    MX = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Axfr = 252,
    Mailb = 253,
    Maila = 254,
    All = 255,
}

impl From<Qtype> for CQtype {
    fn from(qtype: Qtype) -> Self {
        match qtype {
            Qtype::A => CQtype::A,
            Qtype::NS => CQtype::NS,
            Qtype::MD => CQtype::MD,
            Qtype::MF => CQtype::MF,
            Qtype::Cname => CQtype::Cname,
            Qtype::Soa => CQtype::Soa,
            Qtype::MB => CQtype::MB,
            Qtype::MG => CQtype::MG,
            Qtype::MR => CQtype::MR,
            Qtype::Null => CQtype::Null,
            Qtype::Wks => CQtype::Wks,
            Qtype::Ptr => CQtype::Ptr,
            Qtype::Hinfo => CQtype::Hinfo,
            Qtype::Minfo => CQtype::Minfo,
            Qtype::MX => CQtype::MX,
            Qtype::Txt => CQtype::Txt,
            Qtype::Aaaa => CQtype::Aaaa,
            Qtype::Srv => CQtype::Srv,
            Qtype::Axfr => CQtype::Axfr,
            Qtype::Mailb => CQtype::Mailb,
            Qtype::Maila => CQtype::Maila,
            Qtype::All => CQtype::All,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CQclass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    Any = 255,
}

impl From<Qclass> for CQclass {
    fn from(qclass: Qclass) -> Self {
        match qclass {
            Qclass::IN => CQclass::IN,
            Qclass::CS => CQclass::CS,
            Qclass::CH => CQclass::CH,
            Qclass::HS => CQclass::HS,
            Qclass::Any => CQclass::Any,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    Cname = 5,
    Soa = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    Null = 10,
    Wks = 11,
    Ptr = 12,
    Hinfo = 13,
    Minfo = 14,
    MX = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Opt = 41,
    Nsec = 47,
}

impl From<Type> for CType {
    fn from(rtype: Type) -> Self {
        match rtype {
            Type::A => CType::A,
            Type::NS => CType::NS,
            Type::MD => CType::MD,
            Type::MF => CType::MF,
            Type::Cname => CType::Cname,
            Type::Soa => CType::Soa,
            Type::MB => CType::MB,
            Type::MG => CType::MG,
            Type::MR => CType::MR,
            Type::Null => CType::Null,
            Type::Wks => CType::Wks,
            Type::Ptr => CType::Ptr,
            Type::Hinfo => CType::Hinfo,
            Type::Minfo => CType::Minfo,
            Type::MX => CType::MX,
            Type::Txt => CType::Txt,
            Type::Aaaa => CType::Aaaa,
            Type::Srv => CType::Srv,
            Type::Opt => CType::Opt,
            Type::Nsec => CType::Nsec,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl From<Class> for CClass {
    fn from(class: Class) -> Self {
        match class {
            Class::IN => CClass::IN,
            Class::CS => CClass::CS,
            Class::CH => CClass::CH,
            Class::HS => CClass::HS,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Crr {
    pub unicast: bool,
    pub name_ptr: *const u8,
    pub name_len: usize,
    pub rtype: CType,
    pub class: CClass,
    pub ttl: u32,
    pub rdata_ptr: *const u8,
    pub rdata_len: usize,
    pub soa_data: CRdSoa,
    pub srv_data: CRdSrv,
    pub mx_data: CRdMx,
    pub ipv4_addr: [u8; 4],
    pub ipv6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct COptRR {
    pub payload_size: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub rdata_ptr: *const u8,
    pub rdata_len: usize,
    pub ipv4_addr: [u8; 4],
    pub ipv6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRdSoa {
    pub primary_ns_ptr: *const u8,
    pub primary_ns_len: usize,
    pub mailbox_ptr: *const u8,
    pub mailbox_len: usize,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRdSrv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target_ptr: *const u8,
    pub target_len: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CRdMx {
    pub preference: u16,
    pub exchange_ptr: *const u8,
    pub exchange_len: usize,
}

type DnsHeaderCbFn = extern "C" fn(header: CHeader, offset: usize, ctx: *mut c_void);
type DnsQueryCbFn = extern "C" fn(
    name_ptr: *const u8,
    name_len: usize,
    qtype: CQtype,
    qclass: CQclass,
    unicast: bool,
    offset: usize,
    ctx: *mut c_void,
);
type DnsRrCbFn = extern "C" fn(rr: Crr, offset: usize, ctx: *mut c_void);
type DnsOptRrCbFn = extern "C" fn(opt_rr: COptRR, offset: usize, ctx: *mut c_void);
type DnsEndCbFn = extern "C" fn(ctx: *mut c_void);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_header(
    prolens: *mut FfiProlens,
    callback: Option<DnsHeaderCbFn>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |header: DnsHeader, offset: usize, ctx: *mut c_void| {
        callback.unwrap()(header.into(), offset, ctx);
    };
    prolens.0.set_cb_dns_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_query(
    prolens: *mut FfiProlens,
    callback: Option<DnsQueryCbFn>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |name: &[u8],
                        qtype: Qtype,
                        qclass: Qclass,
                        unicast: bool,
                        offset: usize,
                        ctx: *mut c_void| {
        callback.unwrap()(
            name.as_ptr(),
            name.len(),
            qtype.into(),
            qclass.into(),
            unicast,
            offset,
            ctx,
        );
    };
    prolens.0.set_cb_dns_query(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_answer(
    prolens: *mut FfiProlens,
    callback: Option<DnsRrCbFn>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |rr: RR, offset: usize, ctx: *mut c_void| {
        let mut c_rr = Crr {
            unicast: rr.unicast,
            name_ptr: rr.name.as_ptr(),
            name_len: rr.name.len(),
            rtype: rr.rtype.into(),
            class: rr.class.into(),
            ttl: rr.ttl,
            rdata_ptr: std::ptr::null(),
            rdata_len: 0,
            soa_data: CRdSoa {
                primary_ns_ptr: std::ptr::null(),
                primary_ns_len: 0,
                mailbox_ptr: std::ptr::null(),
                mailbox_len: 0,
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum_ttl: 0,
            },
            srv_data: CRdSrv {
                priority: 0,
                weight: 0,
                port: 0,
                target_ptr: std::ptr::null(),
                target_len: 0,
            },
            mx_data: CRdMx {
                preference: 0,
                exchange_ptr: std::ptr::null(),
                exchange_len: 0,
            },
            ipv4_addr: [0; 4],
            ipv6_addr: [0; 16],
        };

        match &rr.rdata {
            Rdata::A(addr) => {
                c_rr.ipv4_addr = addr.octets();
                c_rr.rdata_ptr = c_rr.ipv4_addr.as_ptr();
                c_rr.rdata_len = 4;
            }
            Rdata::Aaaa(addr) => {
                c_rr.ipv6_addr = addr.octets();
                c_rr.rdata_ptr = c_rr.ipv6_addr.as_ptr();
                c_rr.rdata_len = 16;
            }
            Rdata::Cname(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::MX(mx) => {
                c_rr.mx_data.preference = mx.preference;
                c_rr.mx_data.exchange_ptr = mx.exchange.as_ptr();
                c_rr.mx_data.exchange_len = mx.exchange.len();
                c_rr.rdata_ptr = mx.exchange.as_ptr();
                c_rr.rdata_len = mx.exchange.len();
            }
            Rdata::NS(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Ptr(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Soa(soa) => {
                c_rr.soa_data.primary_ns_ptr = soa.primary_ns.as_ptr();
                c_rr.soa_data.primary_ns_len = soa.primary_ns.len();
                c_rr.soa_data.mailbox_ptr = soa.mailbox.as_ptr();
                c_rr.soa_data.mailbox_len = soa.mailbox.len();
                c_rr.soa_data.serial = soa.serial;
                c_rr.soa_data.refresh = soa.refresh;
                c_rr.soa_data.retry = soa.retry;
                c_rr.soa_data.expire = soa.expire;
                c_rr.soa_data.minimum_ttl = soa.minimum_ttl;
                c_rr.rdata_ptr = soa.primary_ns.as_ptr();
                c_rr.rdata_len = soa.primary_ns.len();
            }
            Rdata::Srv(srv) => {
                c_rr.srv_data.priority = srv.priority;
                c_rr.srv_data.weight = srv.weight;
                c_rr.srv_data.port = srv.port;
                c_rr.srv_data.target_ptr = srv.target.as_ptr();
                c_rr.srv_data.target_len = srv.target.len();
                c_rr.rdata_ptr = srv.target.as_ptr();
                c_rr.rdata_len = srv.target.len();
            }
            Rdata::Txt(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Unknown(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
        };

        callback.unwrap()(c_rr, offset, ctx);
    };
    prolens.0.set_cb_dns_answer(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_auth(prolens: *mut FfiProlens, callback: Option<DnsRrCbFn>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |rr: RR, offset: usize, ctx: *mut c_void| {
        let mut c_rr = Crr {
            unicast: rr.unicast,
            name_ptr: rr.name.as_ptr(),
            name_len: rr.name.len(),
            rtype: rr.rtype.into(),
            class: rr.class.into(),
            ttl: rr.ttl,
            rdata_ptr: std::ptr::null(),
            rdata_len: 0,
            soa_data: CRdSoa {
                primary_ns_ptr: std::ptr::null(),
                primary_ns_len: 0,
                mailbox_ptr: std::ptr::null(),
                mailbox_len: 0,
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum_ttl: 0,
            },
            srv_data: CRdSrv {
                priority: 0,
                weight: 0,
                port: 0,
                target_ptr: std::ptr::null(),
                target_len: 0,
            },
            mx_data: CRdMx {
                preference: 0,
                exchange_ptr: std::ptr::null(),
                exchange_len: 0,
            },
            ipv4_addr: [0; 4],
            ipv6_addr: [0; 16],
        };

        match &rr.rdata {
            Rdata::A(addr) => {
                c_rr.ipv4_addr = addr.octets();
                c_rr.rdata_ptr = c_rr.ipv4_addr.as_ptr();
                c_rr.rdata_len = 4;
            }
            Rdata::Aaaa(addr) => {
                c_rr.ipv6_addr = addr.octets();
                c_rr.rdata_ptr = c_rr.ipv6_addr.as_ptr();
                c_rr.rdata_len = 16;
            }
            Rdata::Cname(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::MX(mx) => {
                c_rr.mx_data.preference = mx.preference;
                c_rr.mx_data.exchange_ptr = mx.exchange.as_ptr();
                c_rr.mx_data.exchange_len = mx.exchange.len();
                c_rr.rdata_ptr = mx.exchange.as_ptr();
                c_rr.rdata_len = mx.exchange.len();
            }
            Rdata::NS(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Ptr(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Soa(soa) => {
                c_rr.soa_data.primary_ns_ptr = soa.primary_ns.as_ptr();
                c_rr.soa_data.primary_ns_len = soa.primary_ns.len();
                c_rr.soa_data.mailbox_ptr = soa.mailbox.as_ptr();
                c_rr.soa_data.mailbox_len = soa.mailbox.len();
                c_rr.soa_data.serial = soa.serial;
                c_rr.soa_data.refresh = soa.refresh;
                c_rr.soa_data.retry = soa.retry;
                c_rr.soa_data.expire = soa.expire;
                c_rr.soa_data.minimum_ttl = soa.minimum_ttl;
                c_rr.rdata_ptr = soa.primary_ns.as_ptr();
                c_rr.rdata_len = soa.primary_ns.len();
            }
            Rdata::Srv(srv) => {
                c_rr.srv_data.priority = srv.priority;
                c_rr.srv_data.weight = srv.weight;
                c_rr.srv_data.port = srv.port;
                c_rr.srv_data.target_ptr = srv.target.as_ptr();
                c_rr.srv_data.target_len = srv.target.len();
                c_rr.rdata_ptr = srv.target.as_ptr();
                c_rr.rdata_len = srv.target.len();
            }
            Rdata::Txt(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Unknown(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
        };

        callback.unwrap()(c_rr, offset, ctx);
    };
    prolens.0.set_cb_dns_auth(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_add(prolens: *mut FfiProlens, callback: Option<DnsRrCbFn>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |rr: RR, offset: usize, ctx: *mut c_void| {
        // 使用与dns_answer相同的逻辑
        let mut c_rr = Crr {
            unicast: rr.unicast,
            name_ptr: rr.name.as_ptr(),
            name_len: rr.name.len(),
            rtype: rr.rtype.into(),
            class: rr.class.into(),
            ttl: rr.ttl,
            rdata_ptr: std::ptr::null(),
            rdata_len: 0,
            soa_data: CRdSoa {
                primary_ns_ptr: std::ptr::null(),
                primary_ns_len: 0,
                mailbox_ptr: std::ptr::null(),
                mailbox_len: 0,
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum_ttl: 0,
            },
            srv_data: CRdSrv {
                priority: 0,
                weight: 0,
                port: 0,
                target_ptr: std::ptr::null(),
                target_len: 0,
            },
            mx_data: CRdMx {
                preference: 0,
                exchange_ptr: std::ptr::null(),
                exchange_len: 0,
            },
            ipv4_addr: [0; 4],
            ipv6_addr: [0; 16],
        };

        match &rr.rdata {
            Rdata::A(addr) => {
                c_rr.ipv4_addr = addr.octets();
                c_rr.rdata_ptr = c_rr.ipv4_addr.as_ptr();
                c_rr.rdata_len = 4;
            }
            Rdata::Aaaa(addr) => {
                c_rr.ipv6_addr = addr.octets();
                c_rr.rdata_ptr = c_rr.ipv6_addr.as_ptr();
                c_rr.rdata_len = 16;
            }
            Rdata::Cname(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::MX(mx) => {
                c_rr.mx_data.preference = mx.preference;
                c_rr.mx_data.exchange_ptr = mx.exchange.as_ptr();
                c_rr.mx_data.exchange_len = mx.exchange.len();
                c_rr.rdata_ptr = mx.exchange.as_ptr();
                c_rr.rdata_len = mx.exchange.len();
            }
            Rdata::NS(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Ptr(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Soa(soa) => {
                c_rr.soa_data.primary_ns_ptr = soa.primary_ns.as_ptr();
                c_rr.soa_data.primary_ns_len = soa.primary_ns.len();
                c_rr.soa_data.mailbox_ptr = soa.mailbox.as_ptr();
                c_rr.soa_data.mailbox_len = soa.mailbox.len();
                c_rr.soa_data.serial = soa.serial;
                c_rr.soa_data.refresh = soa.refresh;
                c_rr.soa_data.retry = soa.retry;
                c_rr.soa_data.expire = soa.expire;
                c_rr.soa_data.minimum_ttl = soa.minimum_ttl;
                c_rr.rdata_ptr = soa.primary_ns.as_ptr();
                c_rr.rdata_len = soa.primary_ns.len();
            }
            Rdata::Srv(srv) => {
                c_rr.srv_data.priority = srv.priority;
                c_rr.srv_data.weight = srv.weight;
                c_rr.srv_data.port = srv.port;
                c_rr.srv_data.target_ptr = srv.target.as_ptr();
                c_rr.srv_data.target_len = srv.target.len();
                c_rr.rdata_ptr = srv.target.as_ptr();
                c_rr.rdata_len = srv.target.len();
            }
            Rdata::Txt(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
            Rdata::Unknown(data) => {
                c_rr.rdata_ptr = data.as_ptr();
                c_rr.rdata_len = data.len();
            }
        };

        callback.unwrap()(c_rr, offset, ctx);
    };
    prolens.0.set_cb_dns_add(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_opt_add(
    prolens: *mut FfiProlens,
    callback: Option<DnsOptRrCbFn>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |opt_rr: OptRR, offset: usize, ctx: *mut c_void| {
        let mut c_opt_rr = COptRR {
            payload_size: opt_rr.payload_size,
            extrcode: opt_rr.extrcode,
            version: opt_rr.version,
            flags: opt_rr.flags,
            rdata_ptr: std::ptr::null(),
            rdata_len: 0,
            ipv4_addr: [0; 4],
            ipv6_addr: [0; 16],
        };

        // 根据rdata类型设置相应的数据
        match &opt_rr.rdata {
            Rdata::A(addr) => {
                c_opt_rr.ipv4_addr = addr.octets();
                c_opt_rr.rdata_ptr = c_opt_rr.ipv4_addr.as_ptr();
                c_opt_rr.rdata_len = 4;
            }
            Rdata::Aaaa(addr) => {
                c_opt_rr.ipv6_addr = addr.octets();
                c_opt_rr.rdata_ptr = c_opt_rr.ipv6_addr.as_ptr();
                c_opt_rr.rdata_len = 16;
            }
            Rdata::Cname(data) => {
                c_opt_rr.rdata_ptr = data.as_ptr();
                c_opt_rr.rdata_len = data.len();
            }
            Rdata::MX(mx) => {
                c_opt_rr.rdata_ptr = mx.exchange.as_ptr();
                c_opt_rr.rdata_len = mx.exchange.len();
            }
            Rdata::NS(data) => {
                c_opt_rr.rdata_ptr = data.as_ptr();
                c_opt_rr.rdata_len = data.len();
            }
            Rdata::Ptr(data) => {
                c_opt_rr.rdata_ptr = data.as_ptr();
                c_opt_rr.rdata_len = data.len();
            }
            Rdata::Soa(soa) => {
                c_opt_rr.rdata_ptr = soa.primary_ns.as_ptr();
                c_opt_rr.rdata_len = soa.primary_ns.len();
            }
            Rdata::Srv(srv) => {
                c_opt_rr.rdata_ptr = srv.target.as_ptr();
                c_opt_rr.rdata_len = srv.target.len();
            }
            Rdata::Txt(data) => {
                c_opt_rr.rdata_ptr = data.as_ptr();
                c_opt_rr.rdata_len = data.len();
            }
            Rdata::Unknown(data) => {
                c_opt_rr.rdata_ptr = data.as_ptr();
                c_opt_rr.rdata_len = data.len();
            }
        };

        callback.unwrap()(c_opt_rr, offset, ctx);
    };
    prolens.0.set_cb_dns_opt_add(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_dns_end(prolens: *mut FfiProlens, callback: Option<DnsEndCbFn>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_dns_end(wrapper);
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CSmbHeader {
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
    pub signature: [u8; 16],
}

impl From<&crate::parser::smb::SmbHeader> for CSmbHeader {
    fn from(header: &crate::parser::smb::SmbHeader) -> Self {
        let signature_bytes = header.signature.to_le_bytes();
        CSmbHeader {
            protocol_id: header.protocol_id,
            structure_size: header.structure_size,
            credit_charge: header.credit_charge,
            status: header.status,
            command: header.command,
            credit: header.credit,
            flags: header.flags,
            next_command: header.next_command,
            message_id: header.message_id,
            reserved: header.reserved,
            tree_id: header.tree_id,
            session_id: header.session_id,
            signature: signature_bytes,
        }
    }
}

type CbSmbFileStart =
    extern "C" fn(header: CSmbHeader, len: u32, offset: u64, fid: [u8; 16], ctx: *const c_void);

type CbSmbFileStop = extern "C" fn(header: CSmbHeader, ctx: *const c_void);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smb_file_start(
    prolens: *mut FfiProlens,
    callback: Option<CbSmbFileStart>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |header: &crate::parser::smb::SmbHeader,
                        len: u32,
                        offset: u64,
                        fid: u128,
                        ctx: *mut c_void| {
        let c_header = CSmbHeader::from(header);
        let fid_bytes = fid.to_le_bytes();
        callback.unwrap()(c_header, len, offset, fid_bytes, ctx);
    };
    prolens.0.set_cb_smb_file_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smb_file(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smb_file(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_smb_file_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbSmbFileStop>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |header: &crate::parser::smb::SmbHeader, ctx: *mut c_void| {
        let c_header = CSmbHeader::from(header);
        callback.unwrap()(c_header, ctx);
    };
    prolens.0.set_cb_smb_file_stop(wrapper);
}

type CbTlsEvt = extern "C" fn(ctx: *const c_void);

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_clt_random(
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
    prolens.0.set_cb_tls_clt_random(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_clt_key(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_tls_clt_key(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_srv_random(
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
    prolens.0.set_cb_tls_srv_random(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_srv_key(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_tls_srv_key(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_cert_start(
    prolens: *mut FfiProlens,
    callback: Option<CbTlsEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_tls_cert_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_cert(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_tls_cert(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_set_cb_tls_cert_stop(
    prolens: *mut FfiProlens,
    callback: Option<CbTlsEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_tls_cert_stop(wrapper);
}
