extern crate libc;
use crate::packet::TransProto;
use crate::packet::PktDirection;
use crate::parser::ParserInner;
use crate::Prolens;
use crate::Task;
use crate::smtp2::SmtpParser2;
use std::os::raw::c_char;
use std::sync::Once;
use crate::Packet;
use std::ptr;

#[repr(C)]
pub enum ParserType {
    Smtp,
    Http,
    Undef,
}

static mut CALLBACKS: Callbacks = Callbacks {
    smtp_user: None,
};

static INIT: Once = Once::new();

struct Callbacks {
    smtp_user: Option<extern "C" fn(*const c_char)>,
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

impl crate::Packet for FfiPacket {
    fn direction(&self) -> PktDirection {
        PktDirection::Unknown
    }

    fn trans_proto(&self) -> TransProto {
        unsafe { ((*self.vtable).trans_proto)(self.packet_ptr) }
    }

    fn tu_sport(&self) -> u16 {
        unsafe { ((*self.vtable).tu_sport)(self.packet_ptr) }
    }

    fn tu_dport(&self) -> u16 {
        unsafe { ((*self.vtable).tu_dport)(self.packet_ptr) }
    }

    fn seq(&self) -> u32 {
        unsafe { ((*self.vtable).seq)(self.packet_ptr) }
    }

    fn syn(&self) -> bool {
        unsafe { ((*self.vtable).syn)(self.packet_ptr) }
    }

    fn fin(&self) -> bool {
        unsafe { ((*self.vtable).fin)(self.packet_ptr) }
    }

    fn payload_len(&self) -> usize {
        unsafe { ((*self.vtable).payload_len)(self.packet_ptr) }
    }

    fn payload(&self) -> &[u8] {
        unsafe {
            let ptr = ((*self.vtable).payload)(self.packet_ptr);
            let len = self.payload_len();
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

impl PartialEq for FfiPacket {
    fn eq(&self, other: &Self) -> bool {
        self.seq() == other.seq()
    }
}

impl Eq for FfiPacket {}

impl PartialOrd for FfiPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FfiPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq().cmp(&other.seq())
    }
}

impl std::fmt::Debug for FfiPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FfiPacket {{ seq: {} }}", self.seq())
    }
}

pub struct FfiProlens(Prolens<FfiPacket>);

#[no_mangle]
pub extern "C" fn prolens_new() -> *mut FfiProlens {
    let prolens = Box::new(FfiProlens(Prolens::<FfiPacket>::default()));
    Box::into_raw(prolens)
}

#[no_mangle]
pub extern "C" fn prolens_free(prolens: *mut FfiProlens) {
    if !prolens.is_null() {
        unsafe {
            drop(Box::from_raw(prolens));
        }
    }
}

#[no_mangle]
pub extern "C" fn task_new(prolens: *mut FfiProlens) -> *mut Task<FfiPacket> {
    if prolens.is_null() {
        return ptr::null_mut();
    }
    
    let prolens = unsafe { &mut *prolens };
    let mut task = prolens.0.new_task();
    &mut task as *mut _
}

#[no_mangle]
pub extern "C" fn task_free(task: *mut Task<FfiPacket>) {
    if !task.is_null() {
        let _ = task;
    }
}

#[repr(C)]
pub struct FfiParser(*mut dyn ParserInner<PacketType = FfiPacket>);

#[no_mangle]
pub extern "C" fn parser_new(
    prolens: *mut FfiProlens,
    parser_type: ParserType,
) -> *mut FfiParser {
    if prolens.is_null() {
        return ptr::null_mut();
    }
    
    let prolens = unsafe { &mut *prolens };
    match parser_type {
        ParserType::Smtp => {
            let parser = prolens.0.new_parser::<SmtpParser2<FfiPacket>>();
            let inner = parser.into_inner() as *mut dyn ParserInner<PacketType = FfiPacket>;
            unsafe {
                let ffi_parser = FfiParser(inner);
                std::mem::transmute(inner)
            }
        },
        ParserType::Http => ptr::null_mut(), // 暂时不支持
        ParserType::Undef => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn parser_free(parser: *mut FfiParser) {
    if !parser.is_null() {
        let _ = parser;
    }
}

#[no_mangle]
pub extern "C" fn task_set_parser(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket>,
    parser: *mut FfiParser,
) {
    if prolens.is_null() || task.is_null() || parser.is_null() {
        return;
    }
    
    let prolens = unsafe { &mut *prolens };
    let task = unsafe { &mut *task };
    let parser = unsafe { &mut *((*parser).0) };
    task.as_inner_mut().init_parser(parser);
}

#[no_mangle]
pub extern "C" fn task_new_with_parser(
    prolens: *mut FfiProlens,
    parser_type: ParserType
) -> *mut Task<FfiPacket> {
    if prolens.is_null() {
        return ptr::null_mut();
    }
    
    let prolens = unsafe { &mut *prolens };
    let parser = prolens.0.new_parser::<SmtpParser2<FfiPacket>>();
    let task = Box::new(prolens.0.new_task_with_parser(parser));
    Box::into_raw(task)
}



#[no_mangle]
pub extern "C" fn task_set_smtp_user_callback(callback: extern "C" fn(*const c_char)) {
    unsafe {
        CALLBACKS.smtp_user = Some(callback);
    }
}

#[no_mangle]
pub extern "C" fn task_run(
    prolens: *mut FfiProlens,
    task_ptr: *mut Task<FfiPacket>,
    packet_ptr: *mut std::ffi::c_void,
    vtable_ptr: *const PacketVTable,
    pkt_dir: PktDirection,
    _ts: u64,
) {
    if prolens.is_null() || task_ptr.is_null() || packet_ptr.is_null() || vtable_ptr.is_null() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let task = unsafe { &mut *task_ptr };
    let packet = FfiPacket {
        packet_ptr,
        vtable: vtable_ptr,
    };

    prolens.0.run_task(task, packet);
}


