use etherparse::*;
use pcap::Capture as PcapCap;
use pcap::Offline;
use protolens::{L7Proto, Packet, PktDirection, TransProto};
use std::cell::RefCell;
use std::fmt;
use std::ops::Deref;
use std::path::Path;

use crate::recognize::SMTP_PORT_NET;

pub const MAX_PACKET_LEN: usize = 2048;

pub enum PacketError {
    DecodeErr,
}

#[derive(Eq, PartialEq, Clone)]
pub struct PktHeader {
    pub link: Option<Ethernet2Header>,
    pub vlan: Option<VlanHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub l7_proto: L7Proto,
}

impl PktHeader {
    // 返回tcp或者udp的sport
    pub fn sport(&self) -> u16 {
        match &self.transport {
            Some(TransportHeader::Udp(udph)) => udph.source_port,
            Some(TransportHeader::Tcp(tcph)) => tcph.source_port,
            _ => 0,
        }
    }

    // 返回tcp或者udp的sport
    pub fn dport(&self) -> u16 {
        match &self.transport {
            Some(TransportHeader::Udp(udph)) => udph.destination_port,
            Some(TransportHeader::Tcp(tcph)) => tcph.destination_port,
            _ => 0,
        }
    }
}

#[derive(Clone)]
pub struct CapPacket {
    pub timestamp: u128,
    pub data: [u8; MAX_PACKET_LEN],
    pub data_len: usize,
    pub header: RefCell<Option<PktHeader>>,
}

impl Deref for CapPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl fmt::Debug for CapPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ip: {:?}, Packet: ts: {}, caplen: {}, data: {:?}",
            self.header.borrow().as_ref().unwrap().ip,
            self.timestamp,
            self.data_len,
            self.data
        )
    }
}

impl CapPacket {
    pub fn new(ts: u128, len: usize, data: &[u8]) -> CapPacket {
        let mut pkt = CapPacket {
            timestamp: ts,
            data_len: len,
            data: [0; MAX_PACKET_LEN],
            header: RefCell::new(None),
        };
        let s_data = &mut pkt.data[..len];
        s_data.copy_from_slice(&data[..len]);
        pkt
    }

    pub fn decode(&self) -> Result<(), PacketError> {
        match PacketHeaders::from_ethernet_slice(self) {
            Ok(headers) => {
                if headers.ip.is_none() || headers.transport.is_none() {
                    return Err(PacketError::DecodeErr);
                }

                self.header.replace(Some(PktHeader {
                    link: headers.link,
                    vlan: headers.vlan,
                    ip: headers.ip,
                    transport: headers.transport,
                    payload_offset: headers.payload.as_ptr() as usize - self.data.as_ptr() as usize,
                    payload_len: self.data_len
                        - (headers.payload.as_ptr() as usize - self.data.as_ptr() as usize),
                    l7_proto: L7Proto::Unknown,
                }));
                Ok(())
            }
            Err(_) => Err(PacketError::DecodeErr),
        }
    }

    pub fn set_l7_proto(&self, l7_proto: L7Proto) {
        if let Some(header) = self.header.borrow_mut().as_mut() {
            header.l7_proto = l7_proto;
        }
    }

    pub fn seq(&self) -> u32 {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.sequence_number
        } else {
            0
        }
    }

    pub fn syn(&self) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.syn
        } else {
            false
        }
    }

    pub fn fin(&self) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.fin
        } else {
            false
        }
    }

    pub fn payload_len(&self) -> u32 {
        self.header
            .borrow()
            .as_ref()
            .unwrap()
            .payload_len
            .try_into()
            .unwrap()
    }
}

impl Packet for CapPacket {
    fn direction(&self) -> PktDirection {
        if self.tu_dport() == SMTP_PORT_NET {
            PktDirection::Client2Server
        } else {
            PktDirection::Server2Client
        }
    }

    fn l7_proto(&self) -> L7Proto {
        self.header.borrow().as_ref().unwrap().l7_proto
    }

    fn trans_proto(&self) -> TransProto {
        if let Some(TransportHeader::Tcp(_tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            TransProto::Tcp
        } else {
            TransProto::Udp
        }
    }

    fn tu_sport(&self) -> u16 {
        self.header.borrow().as_ref().unwrap().sport()
    }

    fn tu_dport(&self) -> u16 {
        self.header.borrow().as_ref().unwrap().dport()
    }

    fn seq(&self) -> u32 {
        self.seq()
    }

    fn syn(&self) -> bool {
        self.syn()
    }

    fn fin(&self) -> bool {
        self.fin()
    }

    fn payload_len(&self) -> usize {
        self.payload_len() as usize
    }

    fn payload(&self) -> &[u8] {
        let header = self.header.borrow();
        let offset = header.as_ref().unwrap().payload_offset;
        let len = header.as_ref().unwrap().payload_len;
        &self.data[offset..offset + len]
    }
}

impl Ord for CapPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq().cmp(&other.seq())
    }
}

impl PartialOrd for CapPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for CapPacket {}

impl PartialEq for CapPacket {
    fn eq(&self, other: &Self) -> bool {
        self.seq() == other.seq()
    }
}

#[derive(Debug)]
pub enum CaptureError {}

pub struct Capture {
    cap: PcapCap<Offline>,
    pkt_num: u64,
}

impl Capture {
    pub fn init<P: AsRef<Path>>(path: P) -> Result<Capture, CaptureError> {
        let capture = Capture {
            cap: PcapCap::from_file(path).unwrap(),
            pkt_num: 0,
        };
        Ok(capture)
    }

    pub fn next_packet(&mut self, timestamp: u128) -> Option<CapPacket> {
        self.pkt_num += 1;
        match self.cap.next_packet() {
            Ok(pcap_pkt) => {
                if pcap_pkt.header.caplen > MAX_PACKET_LEN.try_into().unwrap() {
                    return None;
                }

                Some(CapPacket::new(
                    timestamp,
                    pcap_pkt.header.caplen.try_into().unwrap(),
                    pcap_pkt.data,
                ))
            }
            Err(_) => None,
        }
    }
}
