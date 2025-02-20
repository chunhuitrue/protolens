use etherparse::{IpHeader, TransportHeader};
use protolens::L7Proto;
use protolens::PktDirection;
use std::net::IpAddr;

use crate::{
    capture::{CapPacket, PktHeader},
    flow::{FlowNode, KeyDir},
};

pub const SMTP_PORT_NET: u16 = 25;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtoID {
    Smtp,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Client,
    Server,
    Unknown,
}

impl From<Direction> for PktDirection {
    fn from(value: Direction) -> Self {
        match value {
            Direction::Client => PktDirection::Client2Server,
            Direction::Server => PktDirection::Server2Client,
            _ => PktDirection::Unknown,
        }
    }
}

pub fn recognize_pkt(pkt: &CapPacket, node: &mut FlowNode) {
    reg_smtp(pkt.header.borrow().as_ref().unwrap(), node);
    if node.proto_id == ProtoID::Smtp {
        pkt.set_l7_proto(L7Proto::Smtp);
    }
}

fn reg_smtp(header: &PktHeader, node: &mut FlowNode) {
    if let Some(TransportHeader::Tcp(tcph)) = &header.transport {
        if tcph.source_port == SMTP_PORT_NET || tcph.destination_port == SMTP_PORT_NET {
            node.proto_id = ProtoID::Smtp;
        } else {
            return;
        }

        if tcph.source_port == SMTP_PORT_NET {
            node.pkt_dir = Direction::Server;
            match &header.ip {
                Some(IpHeader::Version4(ipv4h, _)) => {
                    if node.key.addr1.unwrap() == Into::<IpAddr>::into(ipv4h.source)
                        && node.key.port1 == tcph.source_port
                        && node.key.addr2.unwrap() == Into::<IpAddr>::into(ipv4h.destination)
                        && node.key.port2 == tcph.destination_port
                    {
                        node.key_dir = KeyDir::Addr2Client;
                    } else {
                        node.key_dir = KeyDir::Addr1Client;
                    }
                }
                Some(IpHeader::Version6(ipv6h, _)) => {
                    if node.key.addr1.unwrap() == Into::<IpAddr>::into(ipv6h.source)
                        && node.key.port1 == tcph.source_port
                        && node.key.addr2.unwrap() == Into::<IpAddr>::into(ipv6h.destination)
                        && node.key.port2 == tcph.destination_port
                    {
                        node.key_dir = KeyDir::Addr2Client;
                    } else {
                        node.key_dir = KeyDir::Addr1Client;
                    }
                }
                None => {
                    node.key_dir = KeyDir::Unknown;
                }
            }
        } else {
            node.pkt_dir = Direction::Client;
            match &header.ip {
                Some(IpHeader::Version4(ipv4h, _)) => {
                    if node.key.addr1.unwrap() == Into::<IpAddr>::into(ipv4h.source)
                        && node.key.port1 == tcph.source_port
                        && node.key.addr2.unwrap() == Into::<IpAddr>::into(ipv4h.destination)
                        && node.key.port2 == tcph.destination_port
                    {
                        node.key_dir = KeyDir::Addr1Client;
                    } else {
                        node.key_dir = KeyDir::Addr2Client;
                    }
                }
                Some(IpHeader::Version6(ipv6h, _)) => {
                    if node.key.addr1.unwrap() == Into::<IpAddr>::into(ipv6h.source)
                        && node.key.port1 == tcph.source_port
                        && node.key.addr2.unwrap() == Into::<IpAddr>::into(ipv6h.destination)
                        && node.key.port2 == tcph.destination_port
                    {
                        node.key_dir = KeyDir::Addr1Client;
                    } else {
                        node.key_dir = KeyDir::Addr2Client;
                    }
                }
                None => {
                    node.key_dir = KeyDir::Unknown;
                }
            }
        }
    }
}
