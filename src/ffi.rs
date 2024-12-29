extern crate libc;
use crate::packet::TransProto;
use crate::{smtp::SmtpParser, Packet, PktDirection, Task};
use std::ptr;

#[repr(C)]
#[allow(dead_code)]
pub enum ParserType {
    Smtp,
    Http,
    Undef,
}

#[repr(C)]
pub struct PacketVTable {
    pub trans_proto: extern "C" fn(*mut std::ffi::c_void) -> TransProto,
    pub tu_sport: extern "C" fn(*mut std::ffi::c_void) -> u16,
    pub tu_dport: extern "C" fn(*mut std::ffi::c_void) -> u16,
    pub seq: extern "C" fn(*mut std::ffi::c_void) -> u32,
    pub syn: extern "C" fn(*mut std::ffi::c_void) -> bool,
    pub fin: extern "C" fn(*mut std::ffi::c_void) -> bool,
    pub payload_len: extern "C" fn(*mut std::ffi::c_void) -> usize,
    pub payload: extern "C" fn(*mut std::ffi::c_void) -> *const u8,
}

pub struct FfiPacket {
    packet_ptr: *mut std::ffi::c_void,
    vtable: *const PacketVTable,
}

impl Packet for FfiPacket {
    fn trans_proto(&self) -> TransProto {
        unsafe { (self.vtable.as_ref().unwrap().trans_proto)(self.packet_ptr) }
    }
    fn tu_sport(&self) -> u16 {
        unsafe { (self.vtable.as_ref().unwrap().tu_sport)(self.packet_ptr) }
    }
    fn tu_dport(&self) -> u16 {
        unsafe { (self.vtable.as_ref().unwrap().tu_dport)(self.packet_ptr) }
    }
    fn seq(&self) -> u32 {
        unsafe { (self.vtable.as_ref().unwrap().seq)(self.packet_ptr) }
    }
    fn syn(&self) -> bool {
        unsafe { (self.vtable.as_ref().unwrap().syn)(self.packet_ptr) }
    }
    fn fin(&self) -> bool {
        unsafe { (self.vtable.as_ref().unwrap().fin)(self.packet_ptr) }
    }
    fn payload_len(&self) -> usize {
        unsafe { (self.vtable.as_ref().unwrap().payload_len)(self.packet_ptr) }
    }
    fn payload(&self) -> &[u8] {
        unsafe {
            let ptr = (self.vtable.as_ref().unwrap().payload)(self.packet_ptr);
            std::slice::from_raw_parts(ptr, self.payload_len())
        }
    }
}

impl Ord for FfiPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq().cmp(&other.seq())
    }
}

impl PartialOrd for FfiPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for FfiPacket {
    fn eq(&self, other: &Self) -> bool {
        self.seq() == other.seq()
    }
}

impl Eq for FfiPacket {}

impl std::fmt::Debug for FfiPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiPacket")
            .field("seq", &self.seq())
            .field("payload_len", &self.payload_len())
            .finish()
    }
}

#[no_mangle]
pub extern "C" fn task_new() -> *mut Task<FfiPacket> {
    Box::into_raw(Box::new(Task::new()))
}

#[no_mangle]
pub extern "C" fn task_free(ptr: *mut Task<FfiPacket>) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn task_new_with_parser(parser_type: ParserType) -> *mut Task<FfiPacket> {
    match parser_type {
        ParserType::Smtp => Box::into_raw(Box::new(Task::new_with_parser(SmtpParser::new()))),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn task_init_parser(
    task_ptr: *mut Task<FfiPacket>,
    parser_type: ParserType,
) -> *mut Task<FfiPacket> {
    if task_ptr.is_null() {
        return task_ptr;
    }

    let task = unsafe { &mut *task_ptr };
    match parser_type {
        ParserType::Smtp => {
            task.init_parser(SmtpParser::new());
            task_ptr
        }
        _ => task_ptr,
    }
}

#[no_mangle]
pub extern "C" fn task_run(
    task_ptr: *mut Task<FfiPacket>,
    packet_ptr: *mut std::ffi::c_void,
    vtable_ptr: *const PacketVTable,
    pkt_dir: PktDirection,
    _ts: u64,
) {
    if task_ptr.is_null() || packet_ptr.is_null() || vtable_ptr.is_null() {
        return;
    }

    let task = unsafe { &mut *task_ptr };
    let packet = FfiPacket {
        packet_ptr,
        vtable: vtable_ptr,
    };
    task.run(packet, pkt_dir);
}
