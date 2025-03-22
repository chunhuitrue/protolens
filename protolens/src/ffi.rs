extern crate libc;
use crate::L7Proto;
use crate::Prolens;
use crate::Task;
use crate::packet::PktDirection;
use crate::packet::TransProto;
use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketVTable {
    pub direction: extern "C" fn(*mut std::ffi::c_void) -> PktDirection,
    pub l7_proto: extern "C" fn(*mut std::ffi::c_void) -> L7Proto,
    pub trans_proto: extern "C" fn(*mut std::ffi::c_void) -> TransProto,
    pub tu_sport: extern "C" fn(*mut std::ffi::c_void) -> u16,
    pub tu_dport: extern "C" fn(*mut std::ffi::c_void) -> u16,
    pub seq: extern "C" fn(*mut std::ffi::c_void) -> u32,
    pub syn: extern "C" fn(*mut std::ffi::c_void) -> bool,
    pub fin: extern "C" fn(*mut std::ffi::c_void) -> bool,
    pub payload_len: extern "C" fn(*mut std::ffi::c_void) -> usize,
    pub payload: extern "C" fn(*mut std::ffi::c_void) -> *const u8,
}

extern "C" fn missing_direction(_: *mut std::ffi::c_void) -> PktDirection {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_l7proto(_: *mut std::ffi::c_void) -> L7Proto {
    panic!("VTABLE not initialized")
}

extern "C" fn missing_trans_proto(_: *mut std::ffi::c_void) -> TransProto {
    panic!("VTABLE not initialized")
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

thread_local! {
    static VTABLE: RefCell<PacketVTable> = RefCell::new(PacketVTable {
        direction: missing_direction,
        l7_proto: missing_l7proto,
        trans_proto: missing_trans_proto,
        tu_sport: missing_u16,
        tu_dport: missing_u16,
        seq: missing_u32,
        syn: missing_bool,
        fin: missing_bool,
        payload_len: missing_usize,
        payload: missing_ptr,
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_init_vtable(vtable: PacketVTable) {
    VTABLE.with(|v| {
        *v.borrow_mut() = vtable;
    });
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Clone)]
pub struct FfiPacket {
    packet_ptr: *mut std::ffi::c_void,
}

impl crate::Packet for FfiPacket {
    fn direction(&self) -> PktDirection {
        VTABLE.with(|vtable| (vtable.borrow().direction)(self.packet_ptr))
    }

    fn l7_proto(&self) -> L7Proto {
        VTABLE.with(|vtable| (vtable.borrow().l7_proto)(self.packet_ptr))
    }

    fn trans_proto(&self) -> TransProto {
        VTABLE.with(|vtable| (vtable.borrow().trans_proto)(self.packet_ptr))
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

#[allow(dead_code)]
pub struct FfiProlens(Prolens<FfiPacket, Rc<FfiPacket>>);

#[unsafe(no_mangle)]
pub extern "C" fn prolens_new() -> *mut FfiProlens {
    let prolens = Box::new(FfiProlens(Prolens::<FfiPacket, Rc<FfiPacket>>::default()));
    Box::into_raw(prolens)
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_free(prolens: *mut FfiProlens) {
    if !prolens.is_null() {
        unsafe {
            let _ = Box::from_raw(prolens);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_new(
    prolens: *mut FfiProlens,
    cb_ctx: *mut c_void,
) -> *mut Task<FfiPacket, Rc<FfiPacket>> {
    if prolens.is_null() {
        return std::ptr::null_mut();
    }

    let prolens = unsafe { Box::from_raw(prolens) };
    let task = prolens.0.new_task_ffi(cb_ctx);
    std::mem::forget(prolens);
    Box::into_raw(task)
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_free(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket, Rc<FfiPacket>>,
) {
    if task.is_null() || prolens.is_null() {
        return;
    }

    unsafe {
        let prolens = Box::from_raw(prolens);
        let _ = Box::from_raw(task);
        std::mem::forget(prolens);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn protolens_task_dbinfo(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket, Rc<FfiPacket>>,
) {
    if task.is_null() || prolens.is_null() {
        return;
    }

    unsafe {
        let prolens = Box::from_raw(prolens);
        let task = Box::from_raw(task);
        task.debug_info();
        std::mem::forget(prolens);
        std::mem::forget(task);
    }
    eprintln!("protolens_task_dbinfo. end");
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
    task: *mut Task<FfiPacket, Rc<FfiPacket>>,
    pkt_ptr: *mut c_void,
) -> TaskResult {
    if prolens.is_null() || task.is_null() || pkt_ptr.is_null() {
        return TaskResult::Error;
    }

    let mut prolens = unsafe { Box::from_raw(prolens) };
    let mut task = unsafe { Box::from_raw(task) };

    let pkt = FfiPacket {
        packet_ptr: pkt_ptr,
    };

    let result = match prolens.0.run_task(&mut task, pkt) {
        None => TaskResult::Pending,
        Some(Ok(())) => TaskResult::Done,
        Some(Err(())) => TaskResult::Error,
    };
    std::mem::forget(prolens);
    std::mem::forget(task);
    result
}

pub type CbStm = extern "C" fn(data: *const u8, data_len: usize, seq: u32, *const c_void);

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_task_c2s(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket, Rc<FfiPacket>>,
    callback: Option<CbStm>,
) {
    if prolens.is_null() || task.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { Box::from_raw(prolens) };
    let mut task = unsafe { Box::from_raw(task) };

    let wrapper = move |data: &[u8], seq: u32, ctx: *const c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    task.set_cb_c2s(wrapper);
    std::mem::forget(prolens);
    std::mem::forget(task);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_task_s2c(
    prolens: *mut FfiProlens,
    task: *mut Task<FfiPacket, Rc<FfiPacket>>,
    callback: Option<CbStm>,
) {
    if prolens.is_null() || task.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { Box::from_raw(prolens) };
    let mut task = unsafe { Box::from_raw(task) };

    let wrapper = move |data: &[u8], seq: u32, ctx: *const c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    task.set_cb_s2c(wrapper);
    std::mem::forget(prolens);
    std::mem::forget(task);
}

type CbOrdPkt = extern "C" fn(pkt_ptr: *mut c_void, ctx: *const c_void);

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_ord_pkt(prolens: *mut FfiProlens, callback: Option<CbOrdPkt>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |pkt: FfiPacket, ctx: *mut c_void| {
        callback.unwrap()(pkt.packet_ptr, ctx);
    };
    prolens.0.set_cb_ord_pkt(wrapper);
}

type CbData = extern "C" fn(data: *const u8, len: usize, seq: u32, ctx: *const c_void);
type CbEvt = extern "C" fn(ctx: *const c_void);

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_smtp_user(prolens: *mut FfiProlens, callback: Option<CbData>) {
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
pub extern "C" fn prolens_set_cb_smtp_pass(prolens: *mut FfiProlens, callback: Option<CbData>) {
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
pub extern "C" fn prolens_set_cb_smtp_mailfrom(prolens: *mut FfiProlens, callback: Option<CbData>) {
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
pub extern "C" fn prolens_set_cb_smtp_rcpt(prolens: *mut FfiProlens, callback: Option<CbData>) {
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
pub extern "C" fn prolens_set_cb_smtp_header(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_smtp_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_smtp_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_smtp_body(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_smtp_body_stop(prolens: *mut FfiProlens, callback: Option<CbEvt>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_smtp_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_smtp_srv(prolens: *mut FfiProlens, callback: Option<CbData>) {
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
pub extern "C" fn prolens_set_cb_pop3_header(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_pop3_header(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_pop3_body_start(
    prolens: *mut FfiProlens,
    callback: Option<CbEvt>,
) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_pop3_body_start(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_pop3_body(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_pop3_body(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_pop3_body_stop(prolens: *mut FfiProlens, callback: Option<CbEvt>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |ctx: *mut c_void| {
        callback.unwrap()(ctx);
    };
    prolens.0.set_cb_pop3_body_stop(wrapper);
}

#[unsafe(no_mangle)]
pub extern "C" fn prolens_set_cb_pop3_clt(prolens: *mut FfiProlens, callback: Option<CbData>) {
    if prolens.is_null() || callback.is_none() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback.unwrap()(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_pop3_clt(wrapper);
}
