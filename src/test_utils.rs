#![allow(unused)]
use crate::Direction;
use crate::{L7Proto, Packet, TransProto};
use etherparse::*;
use pcap::Capture as PcapCap;
use pcap::Offline;
use std::cell::RefCell;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;

pub(crate) const TEST_UTILS_SPORT: u16 = 5000;
pub(crate) const TEST_UTILS_DPORT: u16 = 4000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MyPacket {
    pub sport: u16,
    pub dport: u16,
    pub sequence: u32,
    pub syn_flag: bool,
    pub fin_flag: bool,
    pub data: Vec<u8>,
}

impl MyPacket {
    pub(crate) fn new(seq: u32, fin: bool) -> Self {
        MyPacket {
            sport: 54321,
            dport: 8080,
            sequence: seq,
            syn_flag: false,
            fin_flag: fin,
            data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        }
    }
}

impl Packet for MyPacket {
    fn trans_proto(&self) -> TransProto {
        TransProto::Tcp
    }

    fn sip(&self) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))
    }

    fn dip(&self) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(2, 2, 2, 2))
    }

    fn tu_sport(&self) -> u16 {
        self.sport
    }

    fn tu_dport(&self) -> u16 {
        self.dport
    }

    fn seq(&self) -> u32 {
        self.sequence
    }

    fn syn(&self) -> bool {
        self.syn_flag
    }

    fn fin(&self) -> bool {
        self.fin_flag
    }

    fn payload_len(&self) -> usize {
        self.data.len()
    }

    fn payload(&self) -> &[u8] {
        &self.data
    }
}

impl Packet for Box<MyPacket> {
    fn trans_proto(&self) -> TransProto {
        (**self).trans_proto()
    }

    fn sip(&self) -> IpAddr {
        (**self).sip()
    }

    fn dip(&self) -> IpAddr {
        (**self).dip()
    }

    fn tu_sport(&self) -> u16 {
        (**self).tu_sport()
    }

    fn tu_dport(&self) -> u16 {
        (**self).tu_dport()
    }

    fn seq(&self) -> u32 {
        (**self).seq()
    }

    fn syn(&self) -> bool {
        (**self).syn()
    }

    fn fin(&self) -> bool {
        (**self).fin()
    }

    fn payload_len(&self) -> usize {
        (**self).payload_len()
    }

    fn payload(&self) -> &[u8] {
        (**self).payload()
    }
}

pub(crate) const MAX_PACKET_LEN: usize = 4096;

pub(crate) enum PacketError {
    DecodeErr,
}

#[derive(Eq, PartialEq, Clone)]
pub(crate) struct PktHeader {
    pub(crate) link: Option<Ethernet2Header>,
    pub(crate) vlan: Option<VlanHeader>,
    pub(crate) ip: Option<IpHeader>,
    pub(crate) transport: Option<TransportHeader>,
    pub(crate) payload_offset: usize,
    pub(crate) payload_len: usize,
    pub(crate) l7_proto: L7Proto,
    pub(crate) direction: Direction,
}

impl PktHeader {
    // 返回tcp或者udp的sport
    pub(crate) fn sport(&self) -> u16 {
        match &self.transport {
            Some(TransportHeader::Udp(udph)) => udph.source_port,
            Some(TransportHeader::Tcp(tcph)) => tcph.source_port,
            _ => 0,
        }
    }

    // 返回tcp或者udp的sport
    pub(crate) fn dport(&self) -> u16 {
        match &self.transport {
            Some(TransportHeader::Udp(udph)) => udph.destination_port,
            Some(TransportHeader::Tcp(tcph)) => tcph.destination_port,
            _ => 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CapPacket {
    pub(crate) timestamp: u128,
    pub(crate) data: [u8; MAX_PACKET_LEN],
    pub(crate) data_len: usize,
    pub(crate) header: RefCell<Option<PktHeader>>,
}

impl CapPacket {
    pub(crate) fn new(ts: u128, len: usize, data: &[u8]) -> CapPacket {
        let mut pkt_data = [0; MAX_PACKET_LEN];
        pkt_data[..len].copy_from_slice(&data[..len]);

        CapPacket {
            timestamp: ts,
            data: pkt_data,
            data_len: len,
            header: RefCell::new(None),
        }
    }

    pub(crate) fn decode(&self) -> Result<(), PacketError> {
        match PacketHeaders::from_ethernet_slice(self) {
            Ok(headers) => {
                if headers.ip.is_none() || headers.transport.is_none() {
                    return Err(PacketError::DecodeErr);
                }

                let payload_offset =
                    headers.payload.as_ptr() as usize - self.data.as_ptr() as usize;
                let mut payload_len = 0;

                match (&headers.ip, &headers.transport) {
                    (Some(IpHeader::Version4(ipv4, _)), Some(transport)) => {
                        let ip_total_len = ipv4.total_len() as usize;
                        let ip_header_len = ipv4.ihl() as usize * 4;

                        match transport {
                            TransportHeader::Tcp(tcp_header) => {
                                let tcp_header_len = tcp_header.header_len() as usize;
                                payload_len = ip_total_len - ip_header_len - tcp_header_len;
                            }
                            TransportHeader::Udp(_) => {
                                payload_len = ip_total_len - ip_header_len - 8;
                            }
                            _ => {}
                        }
                    }
                    (Some(IpHeader::Version6(ipv6, _)), Some(transport)) => {
                        let ip_payload_len = ipv6.payload_length as usize;

                        match transport {
                            TransportHeader::Tcp(tcp_header) => {
                                let tcp_header_len = tcp_header.header_len() as usize;
                                payload_len = ip_payload_len - tcp_header_len;
                            }
                            TransportHeader::Udp(_) => {
                                payload_len = ip_payload_len - 8;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }

                self.header.replace(Some(PktHeader {
                    link: headers.link,
                    vlan: headers.vlan,
                    ip: headers.ip,
                    transport: headers.transport,
                    payload_offset,
                    payload_len,
                    l7_proto: L7Proto::Unknown,
                    direction: Direction::C2s,
                }));
                Ok(())
            }
            Err(_) => Err(PacketError::DecodeErr),
        }
    }

    pub(crate) fn seq(&self) -> u32 {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.sequence_number
        } else {
            0
        }
    }

    pub(crate) fn syn(&self) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.syn
        } else {
            false
        }
    }

    pub(crate) fn fin(&self) -> bool {
        if let Some(TransportHeader::Tcp(tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            tcph.fin
        } else {
            false
        }
    }

    pub(crate) fn payload_len(&self) -> u32 {
        self.header
            .borrow()
            .as_ref()
            .unwrap()
            .payload_len
            .try_into()
            .unwrap()
    }
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

impl Packet for CapPacket {
    fn trans_proto(&self) -> TransProto {
        if let Some(TransportHeader::Tcp(_tcph)) = &self.header.borrow().as_ref().unwrap().transport
        {
            TransProto::Tcp
        } else {
            TransProto::Udp
        }
    }

    fn sip(&self) -> std::net::IpAddr {
        match &self.header.borrow().as_ref().unwrap().ip {
            Some(IpHeader::Version4(ipv4h, _)) => IpAddr::from(ipv4h.source),
            Some(IpHeader::Version6(ipv6h, _)) => IpAddr::from(ipv6h.source),
            None => IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        }
    }

    fn dip(&self) -> std::net::IpAddr {
        match &self.header.borrow().as_ref().unwrap().ip {
            Some(IpHeader::Version4(ipv4h, _)) => IpAddr::from(ipv4h.destination),
            Some(IpHeader::Version6(ipv6h, _)) => IpAddr::from(ipv6h.destination),
            None => IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
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

impl Packet for Box<CapPacket> {
    fn trans_proto(&self) -> TransProto {
        (**self).trans_proto()
    }

    fn sip(&self) -> IpAddr {
        (**self).sip()
    }

    fn dip(&self) -> IpAddr {
        (**self).dip()
    }

    fn tu_sport(&self) -> u16 {
        (**self).tu_sport()
    }

    fn tu_dport(&self) -> u16 {
        (**self).tu_dport()
    }

    fn seq(&self) -> u32 {
        (**self).seq()
    }

    fn syn(&self) -> bool {
        (**self).syn()
    }

    fn fin(&self) -> bool {
        (**self).fin()
    }

    fn payload_len(&self) -> usize {
        (**self).payload_len() as usize
    }

    fn payload(&self) -> &[u8] {
        (**self).payload()
    }
}

#[derive(Debug)]
pub(crate) enum CaptureError {}

pub(crate) struct Capture {
    cap: PcapCap<Offline>,
    pkt_num: u64,
}

impl Capture {
    pub(crate) fn init<P: AsRef<Path>>(path: P) -> Result<Capture, CaptureError> {
        let capture = Capture {
            cap: PcapCap::from_file(path).unwrap(),
            pkt_num: 0,
        };
        Ok(capture)
    }

    pub(crate) fn next_packet(&mut self, timestamp: u128) -> Option<CapPacket> {
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

pub(crate) fn build_pkt_nodata(seq: u32, fin: bool) -> CapPacket {
    //setup the packet headers
    let mut builder = PacketBuilder::ethernet2(
        [1, 2, 3, 4, 5, 6], //source mac
        [7, 8, 9, 10, 11, 12],
    ) //destionation mac
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //desitionation ip
        20,
    ) //time to life
    .tcp(
        TEST_UTILS_SPORT, //source port
        TEST_UTILS_DPORT, //desitnation port
        seq,              //sequence number
        1024,
    ) //window size
    //set additional tcp header fields
    .ns() //set the ns flag
    //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
    .ack(123) //ack flag + the ack number
    .urg(23) //urg flag + urgent pointer
    .options(&[
        TcpOptionElement::Noop,
        TcpOptionElement::MaximumSegmentSize(1234),
    ])
    .unwrap();
    if fin {
        builder = builder.fin();
    }

    //payload of the tcp packet
    let payload = [];
    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    //serialize
    //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    builder.write(&mut result, &payload).unwrap();
    // println!("result len:{}", result.len());

    CapPacket::new(1, result.len(), &result)
}

// 独立的ack包，没有载荷
pub(crate) fn build_pkt_ack(seq: u32, ack_seq: u32) -> CapPacket {
    //setup the packet headers
    let builder = PacketBuilder::ethernet2(
        [1, 2, 3, 4, 5, 6], //source mac
        [7, 8, 9, 10, 11, 12],
    ) //destionation mac
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //desitionation ip
        20,
    ) //time to life
    .tcp(
        TEST_UTILS_SPORT, //source port
        TEST_UTILS_DPORT, //desitnation port
        seq,              //sequence number
        1024,
    ) //window size
    //set additional tcp header fields
    .ns() //set the ns flag
    //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
    .ack(ack_seq) //ack flag + the ack number
    .urg(23) //urg flag + urgent pointer
    .options(&[
        TcpOptionElement::Noop,
        TcpOptionElement::MaximumSegmentSize(1234),
    ])
    .unwrap();

    //payload of the tcp packet
    let payload = [];
    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    //serialize
    //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    builder.write(&mut result, &payload).unwrap();
    // println!("result len:{}", result.len());

    CapPacket::new(1, result.len(), &result)
}

// 独立的syn包，没有载荷
pub(crate) fn build_pkt_syn(seq: u32) -> CapPacket {
    //setup the packet headers
    let builder = PacketBuilder::ethernet2(
        [1, 2, 3, 4, 5, 6], //source mac
        [7, 8, 9, 10, 11, 12],
    ) //destionation mac
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //desitionation ip
        20,
    ) //time to life
    .tcp(
        TEST_UTILS_SPORT, //source port
        TEST_UTILS_DPORT, //desitnation port
        seq,              //sequence number
        1024,
    ) //window size
    //set additional tcp header fields
    .ns() //set the ns flag
    //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
    .syn()
    .urg(23) //urg flag + urgent pointer
    .options(&[
        TcpOptionElement::Noop,
        TcpOptionElement::MaximumSegmentSize(1234),
    ])
    .unwrap();

    //payload of the tcp packet
    let payload = [];
    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    //serialize
    //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    builder.write(&mut result, &payload).unwrap();
    // println!("result len:{}", result.len());

    CapPacket::new(1, result.len(), &result)
}

// 带载荷，可以带fin
pub(crate) fn build_pkt(seq: u32, fin: bool) -> CapPacket {
    //setup the packet headers
    let mut builder = PacketBuilder::ethernet2(
        [1, 2, 3, 4, 5, 6], //source mac
        [7, 8, 9, 10, 11, 12],
    ) //destionation mac
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //desitionation ip
        20,
    ) //time to life
    .tcp(
        TEST_UTILS_SPORT, //source port
        TEST_UTILS_DPORT, //desitnation port
        seq,              //sequence number
        1024,
    ) //window size
    //set additional tcp header fields
    .ns() //set the ns flag
    //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
    .ack(123) //ack flag + the ack number
    .urg(23) //urg flag + urgent pointer
    .options(&[
        TcpOptionElement::Noop,
        TcpOptionElement::MaximumSegmentSize(1234),
    ])
    .unwrap();
    if fin {
        builder = builder.fin();
    }

    //payload of the tcp packet
    let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    //serialize
    //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    builder.write(&mut result, &payload).unwrap();
    // println!("result len:{}", result.len());

    CapPacket::new(1, result.len(), &result)
}

// 独立的fin包，没有载荷
pub(crate) fn build_pkt_fin(seq: u32) -> CapPacket {
    build_pkt_nodata(seq, true)
}

pub(crate) fn make_pkt_data(seq: u32) -> CapPacket {
    build_pkt(seq, false)
}

// 接受任意长度的payload数组
fn build_pkt_payload_inner(
    seq: u32,
    payload: &[u8],
    sport: u16,
    dport: u16,
    fin: bool,
) -> CapPacket {
    //setup the packet headers
    let mut builder = PacketBuilder::ethernet2(
        [1, 2, 3, 4, 5, 6],    //source mac
        [7, 8, 9, 10, 11, 12], //destionation mac
    )
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //desitionation ip
        20,               //time to life
    )
    .tcp(
        sport, //source port
        dport, //desitnation port
        seq,   //sequence number
        1024,  //window size
    )
    //set additional tcp header fields
    .ns() //set the ns flag
    //supported flags: ns(), fin(), syn(), rst(), psh(), ece(), cwr()
    .ack(123) //ack flag + the ack number
    .urg(23) //urg flag + urgent pointer
    .options(&[
        TcpOptionElement::Noop,
        TcpOptionElement::MaximumSegmentSize(1234),
    ])
    .unwrap();
    if fin {
        builder = builder.fin();
    }

    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    //serialize
    //this will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    builder.write(&mut result, payload).unwrap();

    CapPacket::new(1, result.len(), &result)
}

// 接受任意长度的payload数组
pub(crate) fn build_pkt_payload(seq: u32, payload: &[u8]) -> CapPacket {
    build_pkt_payload_inner(seq, payload, TEST_UTILS_SPORT, TEST_UTILS_DPORT, false)
}

pub(crate) fn build_pkt_payload_fin(seq: u32, payload: &[u8]) -> CapPacket {
    build_pkt_payload_inner(seq, payload, TEST_UTILS_SPORT, TEST_UTILS_DPORT, true)
}

pub(crate) fn build_pkt_payload2(
    seq: u32,
    payload: &[u8],
    sport: u16,
    dport: u16,
    fin: bool,
) -> CapPacket {
    build_pkt_payload_inner(seq, payload, sport, dport, fin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_pkt() {
        let seq1 = 1;
        let pkt1 = build_pkt(seq1, true);
        let _ = pkt1.decode();

        // 使用完全限定路径调用 trait 方法
        assert_eq!(1, crate::Packet::seq(&pkt1));
        // 验证 fin 标志 (通过 trait 方法)
        assert!(crate::Packet::fin(&pkt1));
        // 验证端口 (通过 trait 方法)
        assert_eq!(TEST_UTILS_SPORT, crate::Packet::tu_sport(&pkt1));
        assert_eq!(TEST_UTILS_DPORT, crate::Packet::tu_dport(&pkt1));

        // 验证 IP (通过 header 获取)
        if let Some(IpHeader::Version4(ipv4, _)) = &pkt1.header.borrow().as_ref().unwrap().ip {
            assert_eq!([192, 168, 1, 1], ipv4.source);
            assert_eq!([192, 168, 1, 2], ipv4.destination);
        }

        // 验证 payload (通过 trait 方法)
        let expected_payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(expected_payload.len(), crate::Packet::payload_len(&pkt1));
        assert_eq!(&expected_payload, crate::Packet::payload(&pkt1));
    }

    #[test]
    fn test_build_pkt_nodata() {
        let seq1 = 1;
        let pkt1 = build_pkt_nodata(seq1, true);
        let _ = pkt1.decode();

        // 验证序列号 (通过 trait 方法)
        assert_eq!(1, crate::Packet::seq(&pkt1));
        // 验证 fin 标志 (通过 trait 方法)
        assert!(crate::Packet::fin(&pkt1));
        // 验证端口 (通过 trait 方法)
        assert_eq!(TEST_UTILS_SPORT, crate::Packet::tu_sport(&pkt1));
        assert_eq!(TEST_UTILS_DPORT, crate::Packet::tu_dport(&pkt1));
        // 验证 IP (通过 header 获取)
        if let Some(IpHeader::Version4(ipv4, _)) = &pkt1.header.borrow().as_ref().unwrap().ip {
            assert_eq!([192, 168, 1, 1], ipv4.source);
            assert_eq!([192, 168, 1, 2], ipv4.destination);
        }
        // 验证 payload 为空 (通过 trait 方法)
        assert_eq!(0, crate::Packet::payload_len(&pkt1));
        assert!(crate::Packet::payload(&pkt1).is_empty());
    }

    #[test]
    fn test_build_pkt_ack() {
        let seq1 = 1;
        let ack_seq = 100;
        let pkt1 = build_pkt_ack(seq1, ack_seq);
        let _ = pkt1.decode();

        // 验证序列号 (通过 trait 方法)
        assert_eq!(1, crate::Packet::seq(&pkt1));
        // 验证端口 (通过 trait 方法)
        assert_eq!(TEST_UTILS_SPORT, crate::Packet::tu_sport(&pkt1));
        assert_eq!(TEST_UTILS_DPORT, crate::Packet::tu_dport(&pkt1));
        // 先获取 header 的引用
        let header = pkt1.header.borrow();
        let header_ref = header.as_ref().unwrap();
        // 验证 IP
        if let Some(IpHeader::Version4(ipv4, _)) = &header_ref.ip {
            assert_eq!([192, 168, 1, 1], ipv4.source);
            assert_eq!([192, 168, 1, 2], ipv4.destination);
        }
        // 验证 payload
        assert_eq!(0, crate::Packet::payload_len(&pkt1));
        assert!(crate::Packet::payload(&pkt1).is_empty());
        assert!(!crate::Packet::fin(&pkt1));
        // 验证 ack
        if let Some(TransportHeader::Tcp(tcp)) = &header_ref.transport {
            assert_eq!(ack_seq, tcp.acknowledgment_number);
            assert!(tcp.ack);
        }
    }

    #[test]
    fn test_build_pkt_syn() {
        let seq1 = 1;
        let pkt1 = build_pkt_syn(seq1);
        let _ = pkt1.decode();

        // 验证序列号 (通过 trait 方法)
        assert_eq!(1, crate::Packet::seq(&pkt1));
        // 验证端口 (通过 trait 方法)
        assert_eq!(TEST_UTILS_SPORT, crate::Packet::tu_sport(&pkt1));
        assert_eq!(TEST_UTILS_DPORT, crate::Packet::tu_dport(&pkt1));
        // 先获取 header 的引用
        let header = pkt1.header.borrow();
        let header_ref = header.as_ref().unwrap();
        // 验证 IP
        if let Some(IpHeader::Version4(ipv4, _)) = &header_ref.ip {
            assert_eq!([192, 168, 1, 1], ipv4.source);
            assert_eq!([192, 168, 1, 2], ipv4.destination);
        }
        // 验证 payload
        assert_eq!(0, crate::Packet::payload_len(&pkt1));
        assert!(crate::Packet::payload(&pkt1).is_empty());
        // 验证 SYN 标志
        assert!(crate::Packet::syn(&pkt1));
        assert!(!crate::Packet::fin(&pkt1));
        // 验证 TCP 标志
        if let Some(TransportHeader::Tcp(tcp)) = &header_ref.transport {
            assert!(tcp.syn);
            assert!(!tcp.ack);
        }
    }

    #[test]
    fn test_build_pkt_payload() {
        // 测试用例1：使用标准长度的payload
        let seq1 = 1;
        let custom_payload = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let pkt1 = build_pkt_payload(seq1, &custom_payload);
        let _ = pkt1.decode();

        // 验证序列号 (通过 trait 方法)
        assert_eq!(1, crate::Packet::seq(&pkt1));
        // 验证端口 (通过 trait 方法)
        assert_eq!(TEST_UTILS_SPORT, crate::Packet::tu_sport(&pkt1));
        assert_eq!(TEST_UTILS_DPORT, crate::Packet::tu_dport(&pkt1));
        // 先获取 header 的引用
        let header = pkt1.header.borrow();
        let header_ref = header.as_ref().unwrap();
        // 验证 IP
        if let Some(IpHeader::Version4(ipv4, _)) = &header_ref.ip {
            assert_eq!([192, 168, 1, 1], ipv4.source);
            assert_eq!([192, 168, 1, 2], ipv4.destination);
        }
        // 验证 payload
        assert_eq!(custom_payload.len(), crate::Packet::payload_len(&pkt1));
        assert_eq!(&custom_payload, crate::Packet::payload(&pkt1));
        // 验证标志位
        assert!(!crate::Packet::syn(&pkt1));
        assert!(!crate::Packet::fin(&pkt1));
        // 验证 TCP 标志
        if let Some(TransportHeader::Tcp(tcp)) = &header_ref.transport {
            assert!(!tcp.syn);
            assert!(tcp.ack); // 这个包应该有 ACK 标志
        }

        // 测试用例2：使用空payload
        let seq2 = 2;
        let empty_payload: Vec<u8> = vec![];
        let pkt2 = build_pkt_payload(seq2, &empty_payload);
        let _ = pkt2.decode();

        // 验证序列号
        assert_eq!(2, crate::Packet::seq(&pkt2));
        // 验证payload为空
        assert_eq!(0, crate::Packet::payload_len(&pkt2));
        assert!(crate::Packet::payload(&pkt2).is_empty());

        // 测试用例3：使用大型payload
        let seq3 = 3;
        let large_payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let pkt3 = build_pkt_payload(seq3, &large_payload);
        let _ = pkt3.decode();

        // 验证序列号
        assert_eq!(3, crate::Packet::seq(&pkt3));
        // 验证payload大小
        assert_eq!(1000, crate::Packet::payload_len(&pkt3));
        assert_eq!(&large_payload, crate::Packet::payload(&pkt3));

        // 测试用例4：使用不同的序列号
        let seq4 = 12345;
        let custom_payload4 = vec![1, 3, 5, 7, 9];
        let pkt4 = build_pkt_payload(seq4, &custom_payload4);
        let _ = pkt4.decode();

        // 验证序列号
        assert_eq!(12345, crate::Packet::seq(&pkt4));
        // 验证payload
        assert_eq!(custom_payload4.len(), crate::Packet::payload_len(&pkt4));
        assert_eq!(&custom_payload4, crate::Packet::payload(&pkt4));
    }

    #[test]
    fn test_build_pkt_line() {
        let seq1 = 1;
        let custom_payload = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let pkt1 = build_pkt_payload(seq1, &custom_payload);
        let _ = pkt1.decode();

        // 验证序列号 (通过 trait 方法)
        assert_eq!(1, crate::Packet::seq(&pkt1));
        // 验证端口 (通过 trait 方法)
        assert_eq!(TEST_UTILS_SPORT, crate::Packet::tu_sport(&pkt1));
        assert_eq!(TEST_UTILS_DPORT, crate::Packet::tu_dport(&pkt1));
        // 先获取 header 的引用
        let header = pkt1.header.borrow();
        let header_ref = header.as_ref().unwrap();
        // 验证 IP
        if let Some(IpHeader::Version4(ipv4, _)) = &header_ref.ip {
            assert_eq!([192, 168, 1, 1], ipv4.source);
            assert_eq!([192, 168, 1, 2], ipv4.destination);
        }
        // 验证 payload
        assert_eq!(custom_payload.len(), crate::Packet::payload_len(&pkt1));
        assert_eq!(&custom_payload, crate::Packet::payload(&pkt1));
        // 验证标志位
        assert!(!crate::Packet::syn(&pkt1));
        assert!(!crate::Packet::fin(&pkt1));
        // 验证 TCP 标志
        if let Some(TransportHeader::Tcp(tcp)) = &header_ref.transport {
            assert!(!tcp.syn);
            assert!(tcp.ack); // 这个包应该有 ACK 标志
        }
    }
}
