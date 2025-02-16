#![allow(unused)]

use crate::capture::CapPacket;
use crate::capture::PktHeader;
use crate::recognize::{recognize_pkt, Direction, ProtoID};
use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use protolens::Prolens;
use protolens::SmtpParser;
use protolens::Task;
use std::cmp::Ordering;
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::Mutex;
use std::{
    borrow::{Borrow, BorrowMut},
    cell::{Ref, RefCell, RefMut},
    net::IpAddr,
    ops::Deref,
    rc::Rc,
};
use tmohash::TmoHash;

const MAX_TABLE_CAPACITY: usize = 128;
const NODE_TIMEOUT: u128 = 10000;

pub struct Flow {
    table: RefCell<TmoHash<FlowKey, FlowNode>>,
}

impl Flow {
    pub fn new() -> Self {
        Flow {
            table: RefCell::new(TmoHash::new(MAX_TABLE_CAPACITY)),
        }
    }

    pub fn insert(&self, pkt: &CapPacket, now: u128) {
        if let Some(key) = make_key(pkt.header.borrow().as_ref().unwrap()) {
            let mut table = self.table.borrow_mut();
            if !table.contains_key(&key) {
                table.insert(key, FlowNode::new(&key, now));
            }
        }
    }

    pub fn get(&self, pkt: &CapPacket) -> Option<Ref<FlowNode>> {
        make_key(pkt.header.borrow().as_ref().unwrap())
            .map(|key| Ref::map(self.table.borrow(), |tbl| tbl.get(&key).unwrap()))
    }

    pub fn get_mut(&self, pkt: &CapPacket) -> Option<RefMut<FlowNode>> {
        make_key(pkt.header.borrow().as_ref().unwrap())
            .map(|key| RefMut::map(self.table.borrow_mut(), |tbl| tbl.get_mut(&key).unwrap()))
    }

    pub fn process_pkt(
        &self,
        pkt: &CapPacket,
        now: u128,
        prolens: &mut Prolens<CapPacket>,
    ) -> Option<RefMut<FlowNode>> {
        if let Some(mut node) = self.get_mut_node(pkt, now) {
            // [插入点] 数据包处理
            recognize_pkt(pkt, &mut node); // 协议识别
            node.parse(pkt.clone(), prolens);

            if node.both_fin(pkt.header.borrow().as_ref().unwrap()) {
                // [插入点] 流结束
                self.table.borrow_mut().remove(&node.key);
            }
            Some(node)
        } else {
            None
        }
    }

    pub fn timer(&self, now: u128) {
        // [插入点] 定时器
        // flow 本身的定时器
        self.timeout(now);
    }

    pub fn clear(&self) {}

    fn get_node(&self, pkt: &CapPacket, now: u128) -> Option<Ref<FlowNode>> {
        let key = make_key(pkt.header.borrow().as_ref().unwrap())?;
        if !self.table.borrow().contains_key(&key) {
            self.table
                .borrow_mut()
                .insert(key, FlowNode::new(&key, now));
        }
        self.get(pkt)
    }

    fn get_mut_node(&self, pkt: &CapPacket, now: u128) -> Option<RefMut<FlowNode>> {
        let key = make_key(pkt.header.borrow().as_ref().unwrap())?;
        if !self.table.borrow().contains_key(&key) {
            self.table
                .borrow_mut()
                .insert(key, FlowNode::new(&key, now));
        }
        self.get_mut(pkt)
    }

    // 流节点超时
    fn timeout(&self, now: u128) {
        self.table.borrow_mut().timeout(|_key, node| {
            if now - node.borrow().last_time >= NODE_TIMEOUT {
                // [插入点] 超时流结点处理
                // match node.pkt_dir {
                //     Direction::Client => node.stream.0.timeout(),
                //     Direction::Server => node.stream.1.timeout(),
                //     _ => ()
                // }
                true
            } else {
                false
            }
        })
    }
}

impl Drop for Flow {
    fn drop(&mut self) {}
}

fn make_key(header: &PktHeader) -> Option<FlowKey> {
    if let Some(key) = pkt_key(header) {
        match key.addr1.cmp(&key.addr2) {
            Ordering::Greater => Some(key),
            Ordering::Less => swap_key(key),
            Ordering::Equal => cmp_port(key),
        }
    } else {
        None
    }
}

fn swap_key(key: FlowKey) -> Option<FlowKey> {
    Some(FlowKey {
        addr1: key.addr2,
        port1: key.port2,
        addr2: key.addr1,
        port2: key.port1,
        ..key
    })
}

fn cmp_port(key: FlowKey) -> Option<FlowKey> {
    match key.port1.cmp(&key.port2) {
        Ordering::Greater | Ordering::Equal => Some(key),
        Ordering::Less => swap_key(key),
    }
}

fn pkt_key(header: &PktHeader) -> Option<FlowKey> {
    match &header.ip {
        Some(IpHeader::Version4(ipv4h, _)) => Some(FlowKey {
            addr1: Some(ipv4h.source.into()),
            port1: header.sport(),
            addr2: Some(ipv4h.destination.into()),
            port2: header.dport(),
            trans_proto: trans_proto(header),
        }),
        Some(IpHeader::Version6(ipv6h, _)) => Some(FlowKey {
            addr1: Some(ipv6h.source.into()),
            port1: header.sport(),
            addr2: Some(ipv6h.destination.into()),
            port2: header.dport(),
            trans_proto: trans_proto(header),
        }),
        None => None,
    }
}

fn trans_proto(header: &PktHeader) -> TransProto {
    match &header.transport {
        Some(TransportHeader::Udp(_)) => TransProto::Udp,
        Some(TransportHeader::Tcp(_)) => TransProto::Tcp,
        Some(TransportHeader::Icmpv4(_)) => TransProto::Icmp4,
        Some(TransportHeader::Icmpv6(_)) => TransProto::Icmp6,
        None => TransProto::Unknown,
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub struct FlowKey {
    pub addr1: Option<IpAddr>,
    pub port1: u16,
    pub addr2: Option<IpAddr>,
    pub port2: u16,
    trans_proto: TransProto,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
enum TransProto {
    Udp,
    Tcp,
    Icmp4,
    Icmp6,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyDir {
    Addr1Client,
    Addr2Client,
    Unknown,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
enum StreamState {
    Fin,
    Unknown,
}

#[derive(Debug)]
pub struct FlowNode {
    pub key: FlowKey,
    pub key_dir: KeyDir,
    pub last_time: u128,
    pub proto_id: ProtoID,
    pub pkt_dir: Direction,
    client_stat: StreamState,
    server_stat: StreamState,

    parser_task: Option<Task<CapPacket>>,
    // 解码出来的元数据
    user: Arc<Mutex<Vec<u8>>>,
    pass: Arc<Mutex<Vec<u8>>>,
}

impl FlowNode {
    fn new(node_key: &FlowKey, now: u128) -> Self {
        FlowNode {
            key: *node_key,
            key_dir: KeyDir::Unknown,
            last_time: now,
            proto_id: ProtoID::Unknown,
            pkt_dir: Direction::Unknown,
            client_stat: StreamState::Unknown,
            server_stat: StreamState::Unknown,

            parser_task: None,
            user: Arc::new(Mutex::new(Vec::<u8>::new())),
            pass: Arc::new(Mutex::new(Vec::<u8>::new())),
        }
    }

    fn client_ip(&self) -> Option<IpAddr> {
        match self.key_dir {
            KeyDir::Addr1Client => self.key.addr1,
            KeyDir::Addr2Client => self.key.addr2,
            KeyDir::Unknown => None,
        }
    }

    fn client_port(&self) -> u16 {
        match self.key_dir {
            KeyDir::Addr1Client => self.key.port1,
            KeyDir::Addr2Client => self.key.port2,
            KeyDir::Unknown => 0,
        }
    }

    fn server_ip(&self) -> Option<IpAddr> {
        match self.key_dir {
            KeyDir::Addr1Client => self.key.addr2,
            KeyDir::Addr2Client => self.key.addr1,
            KeyDir::Unknown => None,
        }
    }

    fn server_port(&self) -> u16 {
        match self.key_dir {
            KeyDir::Addr1Client => self.key.port2,
            KeyDir::Addr2Client => self.key.port2,
            KeyDir::Unknown => 0,
        }
    }

    fn both_fin(&mut self, header: &PktHeader) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &header.transport {
            if !tcph.fin && !tcph.rst {
                return false;
            }

            match &header.ip {
                Some(IpHeader::Version4(ipv4h, _)) => {
                    if self.client_ip().unwrap() == Into::<IpAddr>::into(ipv4h.source)
                        && self.client_port() == tcph.source_port
                    {
                        self.client_stat = StreamState::Fin;
                    } else {
                        self.server_stat = StreamState::Fin;
                    }
                }
                Some(IpHeader::Version6(ipv6h, _)) => {
                    if self.client_ip().unwrap() == Into::<IpAddr>::into(ipv6h.source)
                        && self.client_port() == tcph.source_port
                    {
                        self.client_stat = StreamState::Fin;
                    } else {
                        self.server_stat = StreamState::Fin;
                    }
                }
                None => {
                    return false;
                }
            }

            self.client_stat == StreamState::Fin && self.server_stat == StreamState::Fin
        } else {
            false
        }
    }

    fn parse(&mut self, pkt: CapPacket, prolens: &mut Prolens<CapPacket>) {
        self.init_parser_task(prolens);

        if let Some(ref mut task) = self.parser_task {
            prolens.run_task(task, pkt);
            // println!("run task");
        }
    }

    fn init_parser_task(&mut self, prolens: &mut Prolens<CapPacket>) {
        if self.parser_task.is_some() {
            return;
        }
        if self.proto_id != ProtoID::Smtp {
            return;
        }

        // let mut parser = prolens.new_parser::<SmtpParser<CapPacket>>();

        // 设置用户名回调
        let user_data = self.user.clone();
        let user_callback = move |user: &[u8], seq: u32, _cb_ctx: *const c_void| {
            if let Ok(mut user_guard) = user_data.lock() {
                *user_guard = user.to_vec();
                println!(
                    "get user: {}, seq: {}",
                    std::str::from_utf8(user).unwrap(),
                    seq
                );
            }
        };
        // parser.set_callback_user(user_callback);

        // 设置密码回调
        let pass_data = self.pass.clone();
        let pass_callback = move |pass: &[u8], seq: u32, _cb_ctx: *const c_void| {
            if let Ok(mut pass_guard) = pass_data.lock() {
                pass_guard.extend_from_slice(pass);
                println!(
                    "get pass: {}, seq: {}",
                    std::str::from_utf8(pass).unwrap(),
                    seq
                );
            }
        };
        // parser.set_callback_pass(pass_callback);

        prolens.set_cb_smtp_user(user_callback);
        prolens.set_cb_smtp_pass(pass_callback);

        let mut task = prolens.new_task();
        // let task = prolens.new_task_with_parser(parser);
        self.parser_task = Some(task);
    }
}
