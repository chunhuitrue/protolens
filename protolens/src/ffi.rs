extern crate libc;
use crate::packet::PktDirection;
use crate::packet::TransProto;
use crate::L7Proto;
use crate::Prolens;
use crate::Task;
use std::ffi::c_void;

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

// 为不同返回类型添加对应的 panic 函数
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

static mut VTABLE: PacketVTable = PacketVTable {
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
};

#[no_mangle]
pub extern "C" fn prolens_init_vtable(vtable: PacketVTable) {
    unsafe {
        VTABLE = vtable;
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FfiPacket {
    packet_ptr: *mut std::ffi::c_void,
}

impl crate::Packet for FfiPacket {
    fn direction(&self) -> PktDirection {
        unsafe { (VTABLE.direction)(self.packet_ptr) }
    }

    fn l7_proto(&self) -> L7Proto {
        unsafe { (VTABLE.l7_proto)(self.packet_ptr) }
    }

    fn trans_proto(&self) -> TransProto {
        unsafe { (VTABLE.trans_proto)(self.packet_ptr) }
    }

    fn tu_sport(&self) -> u16 {
        unsafe { (VTABLE.tu_sport)(self.packet_ptr) }
    }

    fn tu_dport(&self) -> u16 {
        unsafe { (VTABLE.tu_dport)(self.packet_ptr) }
    }

    fn seq(&self) -> u32 {
        unsafe { (VTABLE.seq)(self.packet_ptr) }
    }

    fn syn(&self) -> bool {
        unsafe { (VTABLE.syn)(self.packet_ptr) }
    }

    fn fin(&self) -> bool {
        unsafe { (VTABLE.fin)(self.packet_ptr) }
    }

    fn payload_len(&self) -> usize {
        unsafe { (VTABLE.payload_len)(self.packet_ptr) }
    }

    fn payload(&self) -> &[u8] {
        unsafe {
            let ptr = (VTABLE.payload)(self.packet_ptr);
            let len = self.payload_len();
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

#[allow(dead_code)]
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

pub type CbStm = extern "C" fn(data: *const u8, data_len: usize, seq: u32, *const c_void);

#[no_mangle]
pub extern "C" fn prolens_set_cb_task_c2s(task: *mut Task<FfiPacket>, callback: CbStm) {
    if task.is_null() {
        return;
    }

    let task = unsafe { &mut *task };
    let wrapper = move |data: &[u8], seq: u32, ctx: *const c_void| {
        callback(data.as_ptr(), data.len(), seq, ctx);
    };
    (*task).as_inner_mut().set_cb_c2s(wrapper);
}

#[no_mangle]
pub extern "C" fn prolens_set_cb_task_s2c(task: *mut Task<FfiPacket>, callback: CbStm) {
    if task.is_null() {
        return;
    }

    let task = unsafe { &mut *task };
    let wrapper = move |data: &[u8], seq: u32, ctx: *const c_void| {
        callback(data.as_ptr(), data.len(), seq, ctx);
    };
    (*task).as_inner_mut().set_cb_s2c(wrapper);
}

type CbOrdPkt = extern "C" fn(pkt_ptr: *mut c_void, ctx: *const c_void);

#[no_mangle]
pub extern "C" fn prolens_set_cb_ord_pkt(prolens: *mut FfiProlens, callback: CbOrdPkt) {
    if prolens.is_null() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |pkt: FfiPacket, ctx: *mut c_void| {
        callback(pkt.packet_ptr, ctx);
    };
    prolens.0.set_cb_ord_pkt(wrapper);
}

// c 头文件
// typedef void (*cb_smtp)(const uint8_t* data, size_t len, void* ctx);
// void prolens_set_cb_smtp_user(struct FfiProlens* prolens, cb_smtp callback, void* ctx);
// void prolens_set_cb_smtp_pass(struct FfiProlens* prolens, cb_smtp callback, void* ctx);
// SMTP 回调函数类型定义
type CbSmtp = extern "C" fn(data: *const u8, len: usize, seq: u32, ctx: *const c_void);

#[no_mangle]
pub extern "C" fn prolens_set_cb_smtp_user(prolens: *mut FfiProlens, callback: CbSmtp) {
    if prolens.is_null() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_user(wrapper);
}

#[no_mangle]
pub extern "C" fn prolens_set_cb_smtp_pass(prolens: *mut FfiProlens, callback: CbSmtp) {
    if prolens.is_null() {
        return;
    }

    let prolens = unsafe { &mut *prolens };
    let wrapper = move |data: &[u8], seq: u32, ctx: *mut c_void| {
        callback(data.as_ptr(), data.len(), seq, ctx);
    };
    prolens.0.set_cb_smtp_pass(wrapper);
}

// c 头文件：Task* protolens_new_task(FfiProlens* prolens, void* cb_ctx);
// // 示例用法：
// void* my_ctx = ...; // 用户的回调上下文
// Task* task = protolens_new_task(prolens, my_ctx);
#[no_mangle]
pub extern "C" fn protolens_new_task(
    prolens: *mut FfiProlens,
    cb_ctx: *mut c_void,
) -> *mut Task<FfiPacket> {
    if prolens.is_null() {
        return std::ptr::null_mut();
    }

    let prolens = unsafe { &*prolens };
    // 创建新的 task，传入回调上下文
    let task = prolens.0.new_task_inner(cb_ctx);
    // 将 task 转换为原始指针
    task.into_raw()
}

// void protolens_free_task(Task* task, FfiProlens* prolens);
#[no_mangle]
pub extern "C" fn protolens_free_task(task: *mut Task<FfiPacket>, prolens: *mut FfiProlens) {
    if task.is_null() || prolens.is_null() {
        return;
    }

    unsafe {
        let prolens = &*prolens;
        Task::from_raw(task, prolens.0.pool.clone());
    }
}

// c 头文件：
// typedef enum {
//     TASK_PENDING = 0,  // None
//     TASK_DONE = 1,     // Some(Ok(()))
//     TASK_ERROR = 2     // Some(Err(()))
// } TaskResult;
// TaskResult protolens_run_task(FfiProlens* prolens, Task* task, void* pkt_ptr);
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TaskResult {
    Pending = 0,
    Done = 1,
    Error = 2,
}

#[no_mangle]
pub extern "C" fn protolens_run_task(
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

    // 调用 run_task 并转换返回值
    match prolens.0.run_task(task, pkt) {
        None => TaskResult::Pending,
        Some(Ok(())) => TaskResult::Done,
        Some(Err(())) => TaskResult::Error,
    }
}
