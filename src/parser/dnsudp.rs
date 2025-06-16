use crate::{
    CbDnsAdd, CbDnsAnswer, CbDnsAuth, CbDnsEnd, CbDnsHeader, CbDnsOptAdd, CbDnsQuery, Parser,
    ParserFactory, Prolens, UdpParser, UdpParserFn, packet::*,
};
use byteorder::{BigEndian, ByteOrder};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub struct DnsUdpParser<T>
where
    T: Packet,
{
    cb_dns_header: Option<CbDnsHeader>,
    cb_dns_query: Option<CbDnsQuery>,
    cb_dns_answer: Option<CbDnsAnswer>,
    cb_dns_auth: Option<CbDnsAuth>,
    cb_dns_add: Option<CbDnsAdd>,
    cb_dns_opt_add: Option<CbDnsOptAdd>,
    cb_dns_end: Option<CbDnsEnd>,
    _phantom_t: PhantomData<T>,
}

impl<T> DnsUdpParser<T>
where
    T: Packet,
{
    pub(crate) fn new() -> Self {
        Self {
            cb_dns_header: None,
            cb_dns_query: None,
            cb_dns_answer: None,
            cb_dns_auth: None,
            cb_dns_add: None,
            cb_dns_opt_add: None,
            cb_dns_end: None,
            _phantom_t: PhantomData,
        }
    }

    fn bdir_parser(pkt: T, callbacks: DnsCallbacks, cb_ctx: *mut c_void) -> Result<(), ()> {
        dns_parser(pkt.payload(), &callbacks, cb_ctx)
    }
}

impl<T> Parser for DnsUdpParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn pkt_bdir_parser(&self) -> Option<UdpParserFn<T>> {
        struct ParserImpl<T> {
            callbacks: DnsCallbacks,
            _phantom: PhantomData<T>,
        }

        impl<T> UdpParser for ParserImpl<T>
        where
            T: Packet,
        {
            type T = T;

            fn parse(&self, pkt: Self::T, cb_ctx: *mut c_void) -> Result<(), ()> {
                DnsUdpParser::<T>::bdir_parser(pkt, self.callbacks.clone(), cb_ctx)
            }
        }

        let callbacks = DnsCallbacks {
            header: self.cb_dns_header.clone(),
            query: self.cb_dns_query.clone(),
            answer: self.cb_dns_answer.clone(),
            auth: self.cb_dns_auth.clone(),
            add: self.cb_dns_add.clone(),
            opt_add: self.cb_dns_opt_add.clone(),
            end: self.cb_dns_end.clone(),
        };

        Some(Box::new(ParserImpl {
            callbacks,
            _phantom: PhantomData,
        }))
    }
}

pub(crate) struct DnsUdpFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for DnsUdpFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(DnsUdpParser::new());
        parser.cb_dns_header = prolens.cb_dns_header.clone();
        parser.cb_dns_query = prolens.cb_dns_query.clone();
        parser.cb_dns_answer = prolens.cb_dns_answer.clone();
        parser.cb_dns_auth = prolens.cb_dns_auth.clone();
        parser.cb_dns_add = prolens.cb_dns_add.clone();
        parser.cb_dns_opt_add = prolens.cb_dns_opt_add.clone();
        parser.cb_dns_end = prolens.cb_dns_end.clone();
        parser
    }
}

const MAX_NAME: usize = 1024;

pub(crate) fn dns_parser(data: &[u8], cb: &DnsCallbacks, cb_ctx: *mut c_void) -> Result<(), ()> {
    const OPT_RECORD: [u8; 3] = [0, 0, 41];
    const HEADER_SIZE: usize = 12;
    let mut offset = HEADER_SIZE;
    let mut name = [0u8; MAX_NAME];
    let mut rd_name = [0u8; MAX_NAME];
    let mut soa_name = [0u8; MAX_NAME];
    let pkt = data;

    let header = header_parser(data)?;
    if let Some(ref cb) = cb.header {
        cb.borrow_mut()(header, 0, cb_ctx);
    }

    for _ in 0..header.qcount {
        name.fill(0);
        let label_len = name_parser(&data[offset..], pkt, &mut name)?;

        offset += label_len;
        let qtype = qtype_parser(&data[offset..])?;
        offset += 2;

        let (unicast, qclass) = qclass_parser(&data[offset..])?;
        offset += 2;

        if let Some(ref cb) = cb.query {
            cb.borrow_mut()(
                &name,
                qtype,
                qclass,
                unicast,
                offset - 4 - label_len,
                cb_ctx,
            );
        }
    }

    for _ in 0..header.ancount {
        name.fill(0);
        rd_name.fill(0);
        soa_name.fill(0);
        let (record_len, record) =
            record_parser(&data[offset..], pkt, &mut name, &mut rd_name, &mut soa_name)?;
        offset += record_len;

        if let Some(ref cb) = cb.answer {
            cb.borrow_mut()(record, offset - record_len, cb_ctx);
        }
    }

    for _ in 0..header.nscount {
        name.fill(0);
        rd_name.fill(0);
        soa_name.fill(0);
        let (record_len, record) =
            record_parser(&data[offset..], pkt, &mut name, &mut rd_name, &mut soa_name)?;
        offset += record_len;

        if let Some(ref cb) = cb.auth {
            cb.borrow_mut()(record, offset - record_len, cb_ctx);
        }
    }

    for _ in 0..header.arcount {
        name.fill(0);
        rd_name.fill(0);
        soa_name.fill(0);
        if offset + 3 <= data.len() && data[offset..offset + 3] == OPT_RECORD {
            let (record_len, opt_record) =
                opt_record_parser(&data[offset..], pkt, &mut rd_name, &mut soa_name)?;
            offset += record_len;

            if let Some(ref cb) = cb.opt_add {
                cb.borrow_mut()(opt_record, offset - record_len, cb_ctx);
            }
        } else {
            let (record_len, record) =
                record_parser(&data[offset..], pkt, &mut name, &mut rd_name, &mut soa_name)?;
            offset += record_len;

            if let Some(ref cb) = cb.add {
                cb.borrow_mut()(record, offset - record_len, cb_ctx);
            }
        }
    }

    if let Some(ref cb) = cb.end {
        cb.borrow_mut()(cb_ctx);
    }

    Ok(())
}

fn header_parser(data: &[u8]) -> Result<DnsHeader, ()> {
    if data.len() < 12 {
        return Err(());
    }

    let flags = BigEndian::read_u16(&data[2..4]);
    if flags & mask::Z != 0 {
        return Err(());
    }

    let header = DnsHeader {
        id: BigEndian::read_u16(&data[..2]),
        qr: flags & mask::QR != 0,
        opcode: ((flags & mask::OPCODE) >> mask::OPCODE.trailing_zeros()).into(),
        aa: flags & mask::AA != 0,
        tc: flags & mask::TC != 0,
        rd: flags & mask::RD != 0,
        ra: flags & mask::RA != 0,
        ad: flags & mask::AD != 0,
        cd: flags & mask::CD != 0,
        rcode: From::from(flags & mask::RCODE),
        qcount: BigEndian::read_u16(&data[4..6]),
        ancount: BigEndian::read_u16(&data[6..8]),
        nscount: BigEndian::read_u16(&data[8..10]),
        arcount: BigEndian::read_u16(&data[10..12]),
    };
    Ok(header)
}

fn name_parser(data: &[u8], pkt: &[u8], name: &mut [u8]) -> Result<usize, ()> {
    name_parser_acc(data, pkt, name, 0)
}

const MAX_JUMPS: usize = 3;

fn name_parser_acc(data: &[u8], pkt: &[u8], name: &mut [u8], count: usize) -> Result<usize, ()> {
    let mut pos = 0;
    let mut name_pos = 0;

    if count > MAX_JUMPS {
        return Err(());
    }

    loop {
        if data.len() <= pos {
            return Err(());
        }

        let byte = data[pos];
        if byte & 0b1100_0000 == 0b1100_0000 {
            if data.len() < pos + 2 {
                return Err(());
            }

            let offset =
                (BigEndian::read_u16(&data[pos..pos + 2]) & !0b1100_0000_0000_0000) as usize;
            if offset >= pkt.len() {
                return Err(());
            }

            if name_pos >= name.len() {
                return Err(());
            }
            if name_pos > 0 {
                name[name_pos] = b'.';
                name_pos += 1;
            }

            if name_pos >= name.len() {
                return Err(());
            }

            name_parser_acc(&pkt[offset..], pkt, &mut name[name_pos..], count + 1)?;

            return Ok(pos + 2);
        } else if byte & 0b1100_0000 == 0 {
            if byte == 0 {
                return Ok(pos + 1);
            }

            let label_len = byte as usize;
            let end = pos + label_len + 1;

            if data.len() < end {
                return Err(());
            }

            let required_space = if name_pos > 0 {
                label_len + 1
            } else {
                label_len
            };
            if name_pos + required_space >= name.len() {
                return Err(());
            }

            if name_pos > 0 {
                name[name_pos] = b'.';
                name_pos += 1;
            }

            name[name_pos..name_pos + label_len].copy_from_slice(&data[pos + 1..end]);
            name_pos += label_len;
            pos = end;
            continue;
        }
        return Err(());
    }
}

fn type_parser(data: &[u8]) -> Result<Type, ()> {
    if data.len() < 2 {
        return Err(());
    }

    let val = BigEndian::read_u16(&data[..2]);
    match val {
        1 => Ok(Type::A),
        2 => Ok(Type::NS),
        3 => Ok(Type::MD),
        4 => Ok(Type::MF),
        5 => Ok(Type::Cname),
        6 => Ok(Type::Soa),
        7 => Ok(Type::MB),
        8 => Ok(Type::MG),
        9 => Ok(Type::MR),
        10 => Ok(Type::Null),
        11 => Ok(Type::Wks),
        12 => Ok(Type::Ptr),
        13 => Ok(Type::Hinfo),
        14 => Ok(Type::Minfo),
        15 => Ok(Type::MX),
        16 => Ok(Type::Txt),
        28 => Ok(Type::Aaaa),
        33 => Ok(Type::Srv),
        41 => Ok(Type::Opt),
        47 => Ok(Type::Nsec),
        _ => Err(()),
    }
}

fn qtype_parser(data: &[u8]) -> Result<Qtype, ()> {
    if data.len() < 2 {
        return Err(());
    }

    let val = BigEndian::read_u16(&data[..2]);
    match val {
        1 => Ok(Qtype::A),
        2 => Ok(Qtype::NS),
        3 => Ok(Qtype::MD),
        4 => Ok(Qtype::MF),
        5 => Ok(Qtype::Cname),
        6 => Ok(Qtype::Soa),
        7 => Ok(Qtype::MB),
        8 => Ok(Qtype::MG),
        9 => Ok(Qtype::MR),
        10 => Ok(Qtype::Null),
        11 => Ok(Qtype::Wks),
        12 => Ok(Qtype::Ptr),
        13 => Ok(Qtype::Hinfo),
        14 => Ok(Qtype::Minfo),
        15 => Ok(Qtype::MX),
        16 => Ok(Qtype::Txt),
        28 => Ok(Qtype::Aaaa),
        33 => Ok(Qtype::Srv),
        252 => Ok(Qtype::Axfr),
        253 => Ok(Qtype::Mailb),
        254 => Ok(Qtype::Maila),
        255 => Ok(Qtype::All),
        _ => Err(()),
    }
}

fn qclass_parser(data: &[u8]) -> Result<(bool, Qclass), ()> {
    if data.len() < 2 {
        return Err(());
    }

    let val = BigEndian::read_u16(&data[..2]);
    let unicast = val & 0x8000 == 0x8000;
    let code = val & 0x7FFF;

    let qclass = match code {
        1 => Qclass::IN,
        2 => Qclass::CS,
        3 => Qclass::CH,
        4 => Qclass::HS,
        255 => Qclass::Any,
        _ => return Err(()),
    };

    Ok((unicast, qclass))
}

fn class_parser(data: &[u8]) -> Result<(bool, Class), ()> {
    if data.len() < 2 {
        return Err(());
    }

    let val = BigEndian::read_u16(&data[..2]);
    let unicast = val & 0x8000 == 0x8000;
    let code = val & 0x7FFF;

    let class = match code {
        1 => Class::IN,
        2 => Class::CS,
        3 => Class::CH,
        4 => Class::HS,
        _x => return Err(()),
    };

    Ok((unicast, class))
}

fn record_parser<'a>(
    data: &'a [u8],
    pkt: &'a [u8],
    name: &'a mut [u8],
    rd_name: &'a mut [u8],
    soa_name: &'a mut [u8],
) -> Result<(usize, RR<'a>), ()> {
    let mut offset = 0;

    let name_len = name_parser(&data[offset..], pkt, name)?;
    offset += name_len;

    if offset + 10 > data.len() {
        return Err(());
    }

    let rtype = type_parser(&data[offset..])?;
    offset += 2;

    let (unicast, class) = class_parser(&data[offset..])?;
    offset += 2;

    let mut ttl = BigEndian::read_u32(&data[offset..offset + 4]);
    if ttl > i32::MAX as u32 {
        ttl = 0;
    }
    offset += 4;

    let rdata_len = BigEndian::read_u16(&data[offset..offset + 2]) as usize;
    offset += 2;

    if offset + rdata_len > data.len() {
        return Err(());
    }

    let rdata = rdata_parser(
        rtype,
        &data[offset..offset + rdata_len],
        pkt,
        rd_name,
        soa_name,
    )?;
    offset += rdata_len;

    let rr = RR {
        unicast,
        name,
        rtype,
        class,
        ttl,
        rdata,
    };
    Ok((offset, rr))
}

fn opt_record_parser<'a>(
    data: &'a [u8],
    pkt: &'a [u8],
    rd_name: &'a mut [u8],
    soa_name: &'a mut [u8],
) -> Result<(usize, OptRR<'a>), ()> {
    let mut offset = 0;

    // . 1, type 2, class 2, ttl 4, rdlen 2
    if data.len() < offset + 11 {
        return Err(());
    }

    // name
    if data[offset] != 0 {
        return Err(());
    }
    offset += 1;

    // type
    let rtype = type_parser(&data[offset..])?;
    offset += 2;

    // class (payload size)
    let payload_size = BigEndian::read_u16(&data[offset..offset + 2]);
    offset += 2;

    // ttl
    let extrcode = data[offset];
    offset += 1;
    let version = data[offset];
    offset += 1;
    let flags = BigEndian::read_u16(&data[offset..offset + 2]);
    offset += 2;

    // rdlen
    let rdlen = BigEndian::read_u16(&data[offset..offset + 2]) as usize;
    offset += 2;

    // rdata
    if data.len() < offset + rdlen {
        return Err(());
    }

    let rdata = rdata_parser(rtype, &data[offset..offset + rdlen], pkt, rd_name, soa_name)?;
    offset += rdlen;

    let rr = OptRR {
        payload_size,
        extrcode,
        version,
        flags,
        rdata,
    };
    Ok((offset, rr))
}

fn rdata_parser<'a>(
    typ: Type,
    data: &'a [u8],
    pkt: &'a [u8],
    rd_name: &'a mut [u8],
    soa_name: &'a mut [u8],
) -> Result<Rdata<'a>, ()> {
    match typ {
        Type::A => a_parser(data),
        Type::Aaaa => aaaa_parser(data),
        Type::Cname => cname_parser(data, pkt, rd_name),
        Type::NS => ns_parser(data, pkt, rd_name),
        Type::MX => mx_parser(data, pkt, rd_name),
        Type::Ptr => ptr_parser(data, pkt, rd_name),
        Type::Soa => soa_parser(data, pkt, rd_name, soa_name),
        Type::Srv => srv_parser(data, pkt, rd_name),
        Type::Txt => Ok(Rdata::Txt(data)),
        _ => Ok(Rdata::Unknown(data)),
    }
}

fn a_parser(rdata: &[u8]) -> Result<Rdata, ()> {
    if rdata.len() != 4 {
        return Err(());
    }

    let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
    Ok(Rdata::A(ip))
}

fn aaaa_parser(rdata: &[u8]) -> Result<Rdata, ()> {
    if rdata.len() != 16 {
        return Err(());
    }

    let ip = Ipv6Addr::new(
        BigEndian::read_u16(&rdata[0..2]),
        BigEndian::read_u16(&rdata[2..4]),
        BigEndian::read_u16(&rdata[4..6]),
        BigEndian::read_u16(&rdata[6..8]),
        BigEndian::read_u16(&rdata[8..10]),
        BigEndian::read_u16(&rdata[10..12]),
        BigEndian::read_u16(&rdata[12..14]),
        BigEndian::read_u16(&rdata[14..16]),
    );
    Ok(Rdata::Aaaa(ip))
}

fn cname_parser<'a>(
    rdata: &'a [u8],
    pkt: &'a [u8],
    rd_name: &'a mut [u8],
) -> Result<Rdata<'a>, ()> {
    name_parser(rdata, pkt, rd_name)?;
    Ok(Rdata::Cname(rd_name))
}

fn ns_parser<'a>(rdata: &[u8], pkt: &[u8], rd_name: &'a mut [u8]) -> Result<Rdata<'a>, ()> {
    name_parser(rdata, pkt, rd_name)?;
    Ok(Rdata::NS(rd_name))
}

fn mx_parser<'a>(rdata: &[u8], pkt: &[u8], rd_name: &'a mut [u8]) -> Result<Rdata<'a>, ()> {
    if rdata.len() < 3 {
        return Err(());
    }

    let preference = BigEndian::read_u16(&rdata[..2]);
    name_parser(&rdata[2..], pkt, rd_name)?;
    let record = RdMx {
        preference,
        exchange: rd_name,
    };

    Ok(Rdata::MX(record))
}

fn ptr_parser<'a>(rdata: &[u8], pkt: &[u8], rd_name: &'a mut [u8]) -> Result<Rdata<'a>, ()> {
    name_parser(rdata, pkt, rd_name)?;
    Ok(Rdata::Ptr(rd_name))
}

fn soa_parser<'a>(
    rdata: &[u8],
    pkt: &[u8],
    rd_name: &'a mut [u8],
    soa_name: &'a mut [u8],
) -> Result<Rdata<'a>, ()> {
    let mut offset = 0;

    let primary_ns_len = name_parser(rdata, pkt, rd_name)?;
    offset += primary_ns_len;
    let mailbox_len = name_parser(&rdata[offset..], pkt, soa_name)?;
    offset += mailbox_len;

    if rdata[offset..].len() < 20 {
        return Err(());
    }

    let serial = BigEndian::read_u32(&rdata[offset..offset + 4]);
    let refresh = BigEndian::read_u32(&rdata[offset..offset + 8]);
    let retry = BigEndian::read_u32(&rdata[offset..offset + 12]);
    let expire = BigEndian::read_u32(&rdata[offset..offset + 16]);
    let minimum_ttl = BigEndian::read_u32(&rdata[offset..offset + 20]);

    let record = RdSoa {
        primary_ns: rd_name,
        mailbox: soa_name,
        serial,
        refresh,
        retry,
        expire,
        minimum_ttl,
    };
    Ok(Rdata::Soa(record))
}

fn srv_parser<'a>(rdata: &[u8], pkt: &[u8], rd_name: &'a mut [u8]) -> Result<Rdata<'a>, ()> {
    if rdata.len() < 7 {
        return Err(());
    }

    let priority = BigEndian::read_u16(&rdata[0..2]);
    let weight = BigEndian::read_u16(&rdata[2..4]);
    let port = BigEndian::read_u16(&rdata[4..6]);
    name_parser(&rdata[6..], pkt, rd_name)?;

    let record = RdSrv {
        priority,
        weight,
        port,
        target: rd_name,
    };
    Ok(Rdata::Srv(record))
}

#[derive(Clone)]
pub(crate) struct DnsCallbacks {
    pub(crate) header: Option<CbDnsHeader>,
    pub(crate) query: Option<CbDnsQuery>,
    pub(crate) answer: Option<CbDnsAnswer>,
    pub(crate) auth: Option<CbDnsAuth>,
    pub(crate) add: Option<CbDnsAdd>,
    pub(crate) opt_add: Option<CbDnsOptAdd>,
    pub(crate) end: Option<CbDnsEnd>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: bool,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: Rcode,
    pub qcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[rustfmt::skip]
mod mask {
   pub(crate) const QR:     u16 = 0b1000_0000_0000_0000;
   pub(crate) const OPCODE: u16 = 0b0111_1000_0000_0000;
   pub(crate) const AA:     u16 = 0b0000_0100_0000_0000;
   pub(crate) const TC:     u16 = 0b0000_0010_0000_0000;
   pub(crate) const RD:     u16 = 0b0000_0001_0000_0000;
   pub(crate) const RA:     u16 = 0b0000_0000_1000_0000;
   pub(crate) const AD:     u16 = 0b0000_0000_0010_0000;
   pub(crate) const CD:     u16 = 0b0000_0000_0001_0000;
   pub(crate) const Z:      u16 = 0b0000_0000_0100_0000;
   pub(crate) const RCODE:  u16 = 0b0000_0000_0000_1111;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    Reserved(u8),
}

impl From<u16> for Opcode {
    fn from(code: u16) -> Opcode {
        use self::Opcode::*;
        match code {
            0 => Query,
            1 => IQuery,
            2 => Status,
            x => Reserved(x as u8),
        }
    }
}

impl From<Opcode> for u16 {
    fn from(code: Opcode) -> Self {
        use self::Opcode::*;
        match code {
            Query => 0,
            IQuery => 1,
            Status => 2,
            Reserved(x) => x.into(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl From<u16> for Rcode {
    fn from(code: u16) -> Rcode {
        use self::Rcode::*;
        match code {
            0 => NoError,
            1 => FormatError,
            2 => ServerFailure,
            3 => NameError,
            4 => NotImplemented,
            5 => Refused,
            x => Reserved(x as u8),
        }
    }
}

impl From<Rcode> for u16 {
    fn from(code: Rcode) -> Self {
        use self::Rcode::*;
        match code {
            NoError => 0,
            FormatError => 1,
            ServerFailure => 2,
            NameError => 3,
            NotImplemented => 4,
            Refused => 5,
            Reserved(code) => code.into(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    A,
    NS,
    MD,
    MF,
    Cname,
    Soa,
    MB,
    MG,
    MR,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    MX,
    Txt,
    // IPv6 host address (RFC 2782)
    Aaaa,
    // service record (RFC 2782)
    Srv,
    // EDNS0 options (RFC 6891)
    Opt,
    // next secure record (RFC 4034, RFC 6762)
    Nsec,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Qtype {
    A,
    NS,
    MD,
    MF,
    Cname,
    Soa,
    MB,
    MG,
    MR,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    MX,
    Txt,
    // IPv6 host address (RFC 2782)
    Aaaa,
    // service record (RFC 2782)
    Srv,
    Axfr,
    Mailb,
    Maila,
    All,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Class {
    IN,
    CS,
    CH,
    HS,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Qclass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    Any = 255,
}

pub struct RR<'a> {
    pub unicast: bool,
    pub name: &'a [u8],
    pub rtype: Type,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Rdata<'a>,
}

pub struct OptRR<'a> {
    pub payload_size: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub rdata: Rdata<'a>,
}

#[derive(Debug)]
pub enum Rdata<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(&'a [u8]),
    MX(RdMx<'a>),
    NS(&'a [u8]),
    Ptr(&'a [u8]),
    Soa(RdSoa<'a>),
    Srv(RdSrv<'a>),
    Txt(&'a [u8]),
    Unknown(&'a [u8]),
}

#[derive(Debug, Clone, Copy)]
pub struct RdMx<'a> {
    pub preference: u16,
    pub exchange: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct RdSoa<'a> {
    pub primary_ns: &'a [u8],
    pub mailbox: &'a [u8],
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct RdSrv<'a> {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use std::cell::RefCell;
    use std::env;
    use std::ffi::c_void;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    // 测试正常DNS头部解析
    #[test]
    fn test_header_valid() {
        let mut data = [0u8; 12];
        data[0] = 0x12;
        data[1] = 0x34;

        // QR=1, OPCODE=0010, AA=1, TC=1, RD=1
        data[2] = 0b1001_0111;
        // RA=1, Z=0, AD=1, CD=1, RCODE=Refused(5)
        data[3] = 0b1011_0101;

        data[4] = 0x00; // QDCOUNT 高8位
        data[5] = 0x01; // QDCOUNT 低8位 -> 1

        data[6] = 0x00; // ANCOUNT 高8位
        data[7] = 0x02; // ANCOUNT 低8位 -> 2

        data[8] = 0x00; // NSCOUNT 高8位
        data[9] = 0x03; // NSCOUNT 低8位 -> 3

        data[10] = 0x00; // ARCOUNT 高8位
        data[11] = 0x04; // ARCOUNT 低8位 -> 4

        let header = header_parser(&data).unwrap();
        assert_eq!(header.id, 0x1234);
        assert!(header.qr);
        assert_eq!(header.opcode, Opcode::Status);
        assert!(header.aa);
        assert!(header.tc);
        assert!(header.rd);
        assert!(header.ra);
        assert!(header.ad);
        assert!(header.cd);
        assert_eq!(header.rcode, Rcode::Refused); // RCODE=5
        assert_eq!(header.qcount, 1);
        assert_eq!(header.ancount, 2);
        assert_eq!(header.nscount, 3);
        assert_eq!(header.arcount, 4);
    }

    // 测试数据长度不足12字节
    #[test]
    fn test_header_invalid_length() {
        let data = [0u8; 11];
        let result = header_parser(&data);
        assert!(result.is_err());
    }

    // 测试Z标志位被置位（RFC规定必须为0）
    #[test]
    fn test_header_z_flag_set() {
        let mut data = [0u8; 12];
        data[3] = mask::Z as u8;
        let result = header_parser(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_opcodes() {
        let mut data = [0u8; 12];
        data[3] = !mask::Z as u8;

        // Query (0)
        data[2] = 0;
        let header1 = header_parser(&data).unwrap();
        assert_eq!(header1.opcode, Opcode::Query);
        assert!(!header1.qr);

        // IQuery (1)
        data[2] = (1 << 3) as u8;
        let header2 = header_parser(&data).unwrap();
        assert_eq!(header2.opcode, Opcode::IQuery);

        // Status (2)
        data[2] = (2 << 3) as u8;
        let header3 = header_parser(&data).unwrap();
        assert_eq!(header3.opcode, Opcode::Status);

        // Reserved (15)
        data[2] = (15 << 3) as u8;
        let header4 = header_parser(&data).unwrap();
        assert_eq!(header4.opcode, Opcode::Reserved(15));
    }

    #[test]
    fn test_header_rcodes() {
        let mut data = [0u8; 12];

        // NoError (0)
        data[3] = 0;
        let header1 = header_parser(&data).unwrap();
        assert_eq!(header1.rcode, Rcode::NoError);

        // FormatError (1)
        data[3] = 1;
        let header2 = header_parser(&data).unwrap();
        assert_eq!(header2.rcode, Rcode::FormatError);

        // ServerFailure (2)
        data[3] = 2;
        let header3 = header_parser(&data).unwrap();
        assert_eq!(header3.rcode, Rcode::ServerFailure);

        // NameError (3)
        data[3] = 3;
        let header4 = header_parser(&data).unwrap();
        assert_eq!(header4.rcode, Rcode::NameError);

        // NotImplemented (4)
        data[3] = 4;
        let header5 = header_parser(&data).unwrap();
        assert_eq!(header5.rcode, Rcode::NotImplemented);

        // Refused (5)
        data[3] = 5;
        let header6 = header_parser(&data).unwrap();
        assert_eq!(header6.rcode, Rcode::Refused);

        // Reserved (15)
        data[3] = 15;
        let header7 = header_parser(&data).unwrap();
        assert_eq!(header7.rcode, Rcode::Reserved(15));
    }

    // 构造一个简单的域名：example.com
    // 格式：[7]example[3]com[0]
    #[test]
    fn test_name_parser_simple() {
        let data = &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let mut name = [0u8; 512];

        let result = name_parser(data, data, &mut name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data.len());

        let name_str = std::str::from_utf8(&name[..11]).unwrap();
        assert_eq!(name_str, "example.com");
    }

    // 多标签域名：www.example.com.cn
    #[test]
    fn test_name_parser_multiple_labels() {
        let data = &[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            2, b'c', b'n', 0,
        ];
        let mut name = [0u8; 512];

        let result = name_parser(data, data, &mut name);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data.len());

        let name_str = std::str::from_utf8(&name[..15]).unwrap();
        assert_eq!(name_str, "www.example.com");
    }

    // 带压缩指针的域名：mail.example.com，其中example.com使用压缩指针
    // [4]mail[0xC0][0x00] 指向开头的 example.com
    #[test]
    fn test_name_parser_compression() {
        let mut data = vec![];
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        data.extend_from_slice(&[4, b'm', b'a', b'i', b'l', 0xC0, 0x00]);

        let mut name = [0u8; 512];
        let result = name_parser(&data[13..], &data, &mut name); // 从mail开始解析

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 7);

        let name_str = std::str::from_utf8(&name[..16]).unwrap();
        assert_eq!(name_str, "mail.example.com");
    }

    #[test]
    fn test_name_parser_errors() {
        let mut name = [0u8; 512];

        // 空数据
        let result = name_parser(&[], &[], &mut name);
        assert!(result.is_err());

        // 无效的压缩指针
        let data = &[0xC0, 0xFF];
        let result = name_parser(data, data, &mut name);
        assert!(result.is_err());

        // 标签长度超出剩余数据长度
        let data = &[5, b'a', b'b', b'c']; // 声明长度5但只有3个字符
        let result = name_parser(data, data, &mut name);
        assert!(result.is_err());

        // 没结束标记
        let data = b"\x04test";
        let pkt = data;
        let result = name_parser(data, pkt, &mut name);
        assert!(result.is_err());

        // 未知的标签类型（前两位既不是00也不是11）
        let data = &[0x40, 0x00];
        let result = name_parser(data, data, &mut name);
        assert!(result.is_err());
    }

    // 长度超过name
    #[test]
    #[allow(clippy::same_item_push)]
    fn test_name_parser_exceeds_buffer() {
        // 构造一个超长域名：64个字符的标签，重复多次
        let mut data = Vec::new();

        for _ in 0..10 {
            // 10个标签，每个标签64字符
            data.push(64); // 标签长度64
            for _ in 0..64 {
                data.push(b'a');
            }
        }
        data.push(0); // 结束标记

        // 总域名长度 = 64*10 + 9(点分隔符) = 649字节
        // 但只提供512字节的缓冲区
        let mut name = [0u8; MAX_NAME]; // 小于域名实际长度

        let result = name_parser(&data, &data, &mut name);
        assert!(result.is_err(), "应返回错误但解析成功");
    }

    #[test]
    fn test_type_parser() {
        assert_eq!(type_parser(&[0x00, 0x01]), Ok(Type::A));
        assert_eq!(type_parser(&[0x00, 0x02]), Ok(Type::NS));
        assert_eq!(type_parser(&[0x00, 0x03]), Ok(Type::MD));
        assert_eq!(type_parser(&[0x00, 0x04]), Ok(Type::MF));
        assert_eq!(type_parser(&[0x00, 0x05]), Ok(Type::Cname));
        assert_eq!(type_parser(&[0x00, 0x06]), Ok(Type::Soa));
        assert_eq!(type_parser(&[0x00, 0x07]), Ok(Type::MB));
        assert_eq!(type_parser(&[0x00, 0x08]), Ok(Type::MG));
        assert_eq!(type_parser(&[0x00, 0x09]), Ok(Type::MR));
        assert_eq!(type_parser(&[0x00, 0x0A]), Ok(Type::Null));
        assert_eq!(type_parser(&[0x00, 0x0B]), Ok(Type::Wks));
        assert_eq!(type_parser(&[0x00, 0x0C]), Ok(Type::Ptr));
        assert_eq!(type_parser(&[0x00, 0x0D]), Ok(Type::Hinfo));
        assert_eq!(type_parser(&[0x00, 0x0E]), Ok(Type::Minfo));
        assert_eq!(type_parser(&[0x00, 0x0F]), Ok(Type::MX));
        assert_eq!(type_parser(&[0x00, 0x10]), Ok(Type::Txt));
        assert_eq!(type_parser(&[0x00, 0x1C]), Ok(Type::Aaaa));
        assert_eq!(type_parser(&[0x00, 0x21]), Ok(Type::Srv));
        assert_eq!(type_parser(&[0x00, 0x29]), Ok(Type::Opt));
        assert_eq!(type_parser(&[0x00, 0x2F]), Ok(Type::Nsec));

        // 测试不支持的记录类型
        assert_eq!(type_parser(&[0x00, 0x00]), Err(())); // 类型0
        assert_eq!(type_parser(&[0x00, 0x11]), Err(())); // 类型17
        assert_eq!(type_parser(&[0x00, 0x1B]), Err(())); // 类型27
        assert_eq!(type_parser(&[0x00, 0x1D]), Err(())); // 类型29
        assert_eq!(type_parser(&[0x00, 0x20]), Err(())); // 类型32
        assert_eq!(type_parser(&[0x00, 0x22]), Err(())); // 类型34
        assert_eq!(type_parser(&[0x00, 0x28]), Err(())); // 类型40
        assert_eq!(type_parser(&[0x00, 0x2A]), Err(())); // 类型42
        assert_eq!(type_parser(&[0x00, 0x2E]), Err(())); // 类型46
        assert_eq!(type_parser(&[0x00, 0x30]), Err(())); // 类型48
        assert_eq!(type_parser(&[0x00, 0xFF]), Err(())); // 类型255
        assert_eq!(type_parser(&[0x01, 0xFF]), Err(()));

        // 测试数据长度不足
        assert_eq!(type_parser(&[]), Err(())); // 空数据
        assert_eq!(type_parser(&[0x00]), Err(())); // 只有1字节
        assert_eq!(type_parser(&[0x01]), Err(())); // 只有1字节(值有效但长度不足)
    }

    #[test]
    fn test_qtype_parser() {
        // 测试A记录 (值1)
        let data_a = [0x00, 0x01];
        assert_eq!(qtype_parser(&data_a), Ok(Qtype::A));

        // 测试MX记录 (值15)
        let data_mx = [0x00, 0x0F];
        assert_eq!(qtype_parser(&data_mx), Ok(Qtype::MX));

        // 测试AAAA记录 (值28)
        let data_aaaa = [0x00, 0x1C];
        assert_eq!(qtype_parser(&data_aaaa), Ok(Qtype::Aaaa));

        // 测试All记录 (值255)
        let data_all = [0x00, 0xFF];
        assert_eq!(qtype_parser(&data_all), Ok(Qtype::All));

        // 测试未知类型
        let data_unknown = [0x12, 0x34];
        assert_eq!(qtype_parser(&data_unknown), Err(()));

        // 测试数据不足
        let data_short = [0x00];
        assert_eq!(qtype_parser(&data_short), Err(()));
    }

    #[test]
    fn test_qclase_parser_valid() {
        // IN 类，unicast=false
        let data_in = [0x00, 0x01];
        let (unicast, qclass) = qclass_parser(&data_in).unwrap();
        assert!(!unicast);
        assert_eq!(qclass, Qclass::IN);

        // CS 类，unicast=true
        let data_cs = [0x80, 0x02]; // 最高位为1表示unicast
        let (unicast, qclass) = qclass_parser(&data_cs).unwrap();
        assert!(unicast);
        assert_eq!(qclass, Qclass::CS);

        // CH 类，unicast=false
        let data_ch = [0x00, 0x03];
        let (unicast, qclass) = qclass_parser(&data_ch).unwrap();
        assert!(!unicast);
        assert_eq!(qclass, Qclass::CH);

        // HS 类，unicast=true
        let data_hs = [0x80, 0x04];
        let (unicast, qclass) = qclass_parser(&data_hs).unwrap();
        assert!(unicast);
        assert_eq!(qclass, Qclass::HS);

        // Any 类，unicast=false
        let data_any = [0x00, 0xFF];
        let (unicast, qclass) = qclass_parser(&data_any).unwrap();
        assert!(!unicast);
        assert_eq!(qclass, Qclass::Any);

        // Any 类，unicast=true
        let data_any_uni = [0x80, 0xFF]; // 最高位为1
        let (unicast, qclass) = qclass_parser(&data_any_uni).unwrap();
        assert!(unicast);
        assert_eq!(qclass, Qclass::Any);
    }

    #[test]
    fn test_qclase_parser_invalid() {
        // 数据不足
        let data_short = [0x00];
        assert!(qclass_parser(&data_short).is_err());

        // 无效的类 (0)
        let data_invalid1 = [0x00, 0x00];
        assert!(qclass_parser(&data_invalid1).is_err());

        // 无效的类 (5)
        let data_invalid2 = [0x00, 0x05];
        assert!(qclass_parser(&data_invalid2).is_err());

        // 无效的类 (254)
        let data_invalid3 = [0x00, 0xFE];
        assert!(qclass_parser(&data_invalid3).is_err());

        // 超出范围 (256)
        let data_overflow = [0x01, 0x00]; // 0x0100 = 256
        assert!(qclass_parser(&data_overflow).is_err());
    }

    #[test]
    fn test_qclase_parser_boundary() {
        // 最大有效值 (Any)
        let data_max_valid = [0x00, 0xFF]; // 255
        assert!(qclass_parser(&data_max_valid).is_ok());

        // 最小有效值 (IN)
        let data_min_valid = [0x00, 0x01]; // 1
        assert!(qclass_parser(&data_min_valid).is_ok());

        // 刚好超出范围 (0)
        let data_below_min = [0x00, 0x00]; // 0
        assert!(qclass_parser(&data_below_min).is_err());

        // 刚好超出范围 (256)
        let data_above_max = [0x01, 0x00]; // 256
        assert!(qclass_parser(&data_above_max).is_err());
    }

    #[test]
    fn test_class_parser_valid() {
        let data_in = [0x00, 0x01];
        let (unicast, class) = class_parser(&data_in).unwrap();
        assert!(!unicast);
        assert_eq!(class, Class::IN);

        let data_cs = [0x80, 0x02]; // 最高位为1表示unicast
        let (unicast, class) = class_parser(&data_cs).unwrap();
        assert!(unicast);
        assert_eq!(class, Class::CS);

        let data_ch = [0x00, 0x03];
        let (unicast, class) = class_parser(&data_ch).unwrap();
        assert!(!unicast);
        assert_eq!(class, Class::CH);

        let data_hs = [0x80, 0x04];
        let (unicast, class) = class_parser(&data_hs).unwrap();
        assert!(unicast);
        assert_eq!(class, Class::HS);
    }

    // 数据不足
    #[test]
    fn test_class_parser_invalid_length() {
        // 空数据
        let data_empty = [];
        assert!(class_parser(&data_empty).is_err());

        // 只有1字节
        let data_short = [0x00];
        assert!(class_parser(&data_short).is_err());
    }

    // 无效Class值
    #[test]
    fn test_class_parser_invalid_class() {
        let data_invalid1 = [0x00, 0x00];
        assert!(class_parser(&data_invalid1).is_err());

        let data_invalid2 = [0x00, 0x05];
        assert!(class_parser(&data_invalid2).is_err());

        let data_invalid3 = [0x00, 0xFF];
        assert!(class_parser(&data_invalid3).is_err());

        // 带Unicast标志的无效值
        let data_invalid_uni = [0x80, 0x05];
        assert!(class_parser(&data_invalid_uni).is_err());
    }

    // 边界值
    #[test]
    fn test_class_parser_boundary() {
        // 最小有效值 (IN)
        let data_min_valid = [0x00, 0x01];
        assert!(class_parser(&data_min_valid).is_ok());

        // 最大有效值 (HS)
        let data_max_valid = [0x00, 0x04];
        assert!(class_parser(&data_max_valid).is_ok());

        // 刚好超出范围 (0)
        let data_below_min = [0x00, 0x00];
        assert!(class_parser(&data_below_min).is_err());

        // 刚好超出范围 (5)
        let data_above_max = [0x00, 0x05];
        assert!(class_parser(&data_above_max).is_err());
    }

    // 构造一个A记录：example.com -> 192.168.1.1
    #[test]
    fn test_record_parser_a_record() {
        let mut data = Vec::new();

        // 域名：example.com
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // 类型：A (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // 类：IN (1), unicast=false
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL：3600秒
        data.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]);
        // RDATA长度：4字节
        data.extend_from_slice(&[0x00, 0x04]);

        // RDATA：192.168.1.1
        data.extend_from_slice(&[192, 168, 1, 1]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (consumed, rr) = result.unwrap();
        assert_eq!(consumed, data.len());
        assert!(!rr.unicast);
        assert_eq!(rr.rtype, Type::A);
        assert_eq!(rr.class, Class::IN);
        assert_eq!(rr.ttl, 3600);

        if let Rdata::A(ip) = rr.rdata {
            assert_eq!(ip.to_string(), "192.168.1.1");
        } else {
            panic!("Expected A record type");
        }

        let name_str = std::str::from_utf8(&name[..11]).unwrap();
        assert_eq!(name_str, "example.com");
    }

    // 构造一个AAAA记录：example.com -> 2001:db8::1
    #[test]
    fn test_record_parser_aaaa_record() {
        let mut data = Vec::new();

        // 域名：example.com
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // 类型：AAAA (28)
        data.extend_from_slice(&[0x00, 0x1C]);
        // 类：IN (1), unicast=true
        data.extend_from_slice(&[0x80, 0x01]);
        // TTL：7200秒
        data.extend_from_slice(&[0x00, 0x00, 0x1C, 0x20]);
        // RDATA长度：16字节
        data.extend_from_slice(&[0x00, 0x10]);

        // RDATA：2001:db8::1
        data.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (consumed, rr) = result.unwrap();
        assert_eq!(consumed, data.len());
        assert!(rr.unicast);
        assert_eq!(rr.rtype, Type::Aaaa);
        assert_eq!(rr.class, Class::IN);
        assert_eq!(rr.ttl, 7200);

        if let Rdata::Aaaa(ip) = rr.rdata {
            assert_eq!(ip.to_string(), "2001:db8::1");
        } else {
            panic!("Expected AAAA record type");
        }
    }

    // 构造一个MX记录：example.com -> 10 mail.example.com
    #[test]
    fn test_record_parser_mx_record() {
        let mut data = Vec::new();

        // 域名：example.com
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // 类型：MX (15)
        data.extend_from_slice(&[0x00, 0x0F]);
        // 类：IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL：1800秒
        data.extend_from_slice(&[0x00, 0x00, 0x07, 0x08]);
        // RDATA长度：2 + 18 = 20字节 (preference + mail.example.com)
        data.extend_from_slice(&[0x00, 0x14]); // 修改为0x14 (20字节)

        // RDATA：preference = 10
        data.extend_from_slice(&[0x00, 0x0A]);
        // RDATA：mail.example.com
        data.extend_from_slice(&[
            4, b'm', b'a', b'i', b'l', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0,
        ]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (consumed, rr) = result.unwrap();
        assert_eq!(consumed, data.len());
        assert_eq!(rr.rtype, Type::MX);

        if let Rdata::MX(mx) = rr.rdata {
            assert_eq!(mx.preference, 10);
            let exchange_str = std::str::from_utf8(&mx.exchange[..16]).unwrap();
            assert_eq!(exchange_str, "mail.example.com");
        } else {
            panic!("Expected MX record type");
        }
    }

    // CNAME记录：www.example.com -> example.com
    #[test]
    fn test_record_parser_cname_record() {
        let mut data = Vec::new();

        // 域名：www.example.com
        data.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        // 类型：CNAME (5)
        data.extend_from_slice(&[0x00, 0x05]);
        // 类：IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL：300秒
        data.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        // RDATA长度：13字节 (example.com)
        data.extend_from_slice(&[0x00, 0x0D]);

        // RDATA：example.com
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (consumed, rr) = result.unwrap();
        assert_eq!(consumed, data.len());
        assert_eq!(rr.rtype, Type::Cname);

        if let Rdata::Cname(cname) = rr.rdata {
            let cname_str = std::str::from_utf8(&cname[..11]).unwrap();
            assert_eq!(cname_str, "example.com");
        } else {
            panic!("Expected CNAME record type");
        }
    }

    // 构造一个TXT记录：example.com -> "v=spf1 include:_spf.google.com ~all"
    #[test]
    fn test_record_parser_txt_record() {
        let mut data = Vec::new();

        // 域名：example.com
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // 类型：TXT (16)
        data.extend_from_slice(&[0x00, 0x10]);
        // 类：IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL：600秒
        data.extend_from_slice(&[0x00, 0x00, 0x02, 0x58]);
        let txt_data = b"v=spf1 include:_spf.google.com ~all";
        // RDATA长度
        data.extend_from_slice(&[0x00, txt_data.len() as u8]);

        // RDATA：TXT数据
        data.extend_from_slice(txt_data);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (consumed, rr) = result.unwrap();
        assert_eq!(consumed, data.len());
        assert_eq!(rr.rtype, Type::Txt);

        if let Rdata::Txt(txt) = rr.rdata {
            assert_eq!(txt, txt_data);
        } else {
            panic!("Expected TXT record type");
        }
    }

    // 构造一个SRV记录：_http._tcp.example.com -> 10 20 80 server.example.com
    #[test]
    fn test_record_parser_srv_record() {
        let mut data = Vec::new();

        // 域名：_http._tcp.example.com
        data.extend_from_slice(&[
            5, b'_', b'h', b't', b't', b'p', 4, b'_', b't', b'c', b'p', 7, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // 类型：SRV (33)
        data.extend_from_slice(&[0x00, 0x21]);
        // 类：IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL：900秒
        data.extend_from_slice(&[0x00, 0x00, 0x03, 0x84]);
        // RDATA长度：6 + 20 = 26字节 (priority + weight + port + server.example.com)
        data.extend_from_slice(&[0x00, 0x1A]);

        // RDATA：priority = 10, weight = 20, port = 80
        data.extend_from_slice(&[0x00, 0x0A, 0x00, 0x14, 0x00, 0x50]);
        // RDATA：server.example.com
        data.extend_from_slice(&[
            6, b's', b'e', b'r', b'v', b'e', b'r', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'c', b'o', b'm', 0,
        ]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (consumed, rr) = result.unwrap();
        assert_eq!(consumed, data.len());
        assert_eq!(rr.rtype, Type::Srv);

        if let Rdata::Srv(srv) = rr.rdata {
            assert_eq!(srv.priority, 10);
            assert_eq!(srv.weight, 20);
            assert_eq!(srv.port, 80);
            let target_str = std::str::from_utf8(&srv.target[..18]).unwrap();
            assert_eq!(target_str, "server.example.com");
        } else {
            panic!("Expected SRV record type");
        }
    }

    // 测试TTL超过i32::MAX的情况
    #[test]
    fn test_record_parser_ttl_overflow() {
        let mut data = Vec::new();

        // 域名：test.com
        data.extend_from_slice(&[4, b't', b'e', b's', b't', 3, b'c', b'o', b'm', 0]);
        // 类型：A (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // 类：IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL：超过i32::MAX (0xFFFFFFFF)
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        // RDATA长度：4字节
        data.extend_from_slice(&[0x00, 0x04]);

        // RDATA：1.2.3.4
        data.extend_from_slice(&[1, 2, 3, 4]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (_, rr) = result.unwrap();
        assert_eq!(rr.ttl, 0);
    }

    #[test]
    fn test_record_parser_errors() {
        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        // 测试数据长度不足（少于最小记录长度）
        let short_data = [0; 5];
        let result = record_parser(
            &short_data,
            &short_data,
            &mut name,
            &mut rd_name,
            &mut soa_name,
        );
        assert!(result.is_err());

        // 测试域名解析失败
        let invalid_name_data = [
            0xFF, // 无效的域名长度
            0x00, 0x01, // 类型：A
            0x00, 0x01, // 类：IN
            0x00, 0x00, 0x0E, 0x10, // TTL
            0x00, 0x04, // RDATA长度
            192, 168, 1, 1, // RDATA
        ];
        let result = record_parser(
            &invalid_name_data,
            &invalid_name_data,
            &mut name,
            &mut rd_name,
            &mut soa_name,
        );
        assert!(result.is_err());

        // 测试RDATA长度超出剩余数据
        let mut invalid_rdata_len = Vec::new();
        invalid_rdata_len.extend_from_slice(&[4, b't', b'e', b's', b't', 0]); // 域名：test
        invalid_rdata_len.extend_from_slice(&[0x00, 0x01]); // 类型：A
        invalid_rdata_len.extend_from_slice(&[0x00, 0x01]); // 类：IN
        invalid_rdata_len.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL
        invalid_rdata_len.extend_from_slice(&[0x00, 0x10]); // RDATA长度：16字节（但实际只有4字节）
        invalid_rdata_len.extend_from_slice(&[1, 2, 3, 4]); // RDATA：只有4字节
        let result = record_parser(
            &invalid_rdata_len,
            &invalid_rdata_len,
            &mut name,
            &mut rd_name,
            &mut soa_name,
        );
        assert!(result.is_err());

        // 测试无效的记录类型
        let mut invalid_type = Vec::new();
        invalid_type.extend_from_slice(&[4, b't', b'e', b's', b't', 0]); // 域名：test
        invalid_type.extend_from_slice(&[0x00, 0x00]); // 类型：0（无效）
        invalid_type.extend_from_slice(&[0x00, 0x01]); // 类：IN
        invalid_type.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL
        invalid_type.extend_from_slice(&[0x00, 0x04]); // RDATA长度
        invalid_type.extend_from_slice(&[1, 2, 3, 4]); // RDATA
        let result = record_parser(
            &invalid_type,
            &invalid_type,
            &mut name,
            &mut rd_name,
            &mut soa_name,
        );
        assert!(result.is_err());

        // 测试无效的类
        let mut invalid_class = Vec::new();
        invalid_class.extend_from_slice(&[4, b't', b'e', b's', b't', 0]); // 域名：test
        invalid_class.extend_from_slice(&[0x00, 0x01]); // 类型：A
        invalid_class.extend_from_slice(&[0x00, 0x00]); // 类：0（无效）
        invalid_class.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL
        invalid_class.extend_from_slice(&[0x00, 0x04]); // RDATA长度
        invalid_class.extend_from_slice(&[1, 2, 3, 4]); // RDATA
        let result = record_parser(
            &invalid_class,
            &invalid_class,
            &mut name,
            &mut rd_name,
            &mut soa_name,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_record_parser_unknown_type() {
        // Test unknown record type (should return Unknown type Rdata)
        let mut data = Vec::new();

        // Domain: test.com
        data.extend_from_slice(&[4, b't', b'e', b's', b't', 3, b'c', b'o', b'm', 0]);
        // Type: 99 (unknown type)
        data.extend_from_slice(&[0x00, 0x63]);
        // Class: IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL: 3600 seconds
        data.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]);
        // RDATA length: 8 bytes
        data.extend_from_slice(&[0x00, 0x08]);

        // RDATA: arbitrary data
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let mut name = [0u8; MAX_NAME];
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = record_parser(&data, &data, &mut name, &mut rd_name, &mut soa_name);
        assert!(result.is_err());
    }

    // OPT record parsing - normal case
    #[test]
    fn test_opt_record_parser_valid() {
        let mut data = Vec::new();

        // NAME: root domain (single 0 byte)
        data.push(0x00);
        // TYPE: OPT (41)
        data.extend_from_slice(&[0x00, 0x29]);
        // CLASS: UDP payload size (4096)
        data.extend_from_slice(&[0x10, 0x00]);
        // TTL field (4 bytes) Extended RCODE: 0
        data.push(0x00);
        // Version: 0
        data.push(0x00);
        // Flags: DO bit set (0x8000)
        data.extend_from_slice(&[0x80, 0x00]);
        // RDLEN: 0 (no RDATA)
        data.extend_from_slice(&[0x00, 0x00]);

        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (offset, opt_rr) = result.unwrap();
        assert_eq!(offset, 11); // 1 + 2 + 2 + 4 + 2 = 11
        assert_eq!(opt_rr.payload_size, 4096);
        assert_eq!(opt_rr.extrcode, 0);
        assert_eq!(opt_rr.version, 0);
        assert_eq!(opt_rr.flags, 0x8000);
    }

    // OPT record parsing - with RDATA
    #[test]
    fn test_opt_record_parser_with_rdata() {
        let mut data = Vec::new();

        // NAME: 根域名
        data.push(0x00);
        // TYPE: OPT (41)
        data.extend_from_slice(&[0x00, 0x29]);
        // CLASS: UDP payload size (1232)
        data.extend_from_slice(&[0x04, 0xD0]);
        // TTL 字段 Extended RCODE: 1
        data.push(0x01);
        // Version: 0
        data.push(0x00);
        // Flags: 0x0000
        data.extend_from_slice(&[0x00, 0x00]);
        // RDLEN: 4（4字节 RDATA）
        data.extend_from_slice(&[0x00, 0x04]);

        // RDATA: 任意数据
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (offset, opt_rr) = result.unwrap();
        assert_eq!(offset, 15); // 11 + 4 = 15
        assert_eq!(opt_rr.payload_size, 1232);
        assert_eq!(opt_rr.extrcode, 1);
        assert_eq!(opt_rr.version, 0);
        assert_eq!(opt_rr.flags, 0x0000);
    }

    // Test OPT record parsing error cases
    #[test]
    fn test_opt_record_parser_errors() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        // Test insufficient data length (less than minimum 11 bytes)
        let short_data = [0; 10];
        let result = opt_record_parser(&short_data, &short_data, &mut rd_name, &mut soa_name);
        assert!(result.is_err());

        // Test NAME is not root domain (not starting with 0 byte)
        let mut invalid_name = Vec::new();
        invalid_name.push(0x01); // Not root domain
        invalid_name.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
        invalid_name.extend_from_slice(&[0x10, 0x00]); // CLASS
        invalid_name.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
        invalid_name.extend_from_slice(&[0x00, 0x00]); // RDLEN
        let result = opt_record_parser(&invalid_name, &invalid_name, &mut rd_name, &mut soa_name);
        assert!(result.is_err());

        // Test invalid record type (not OPT)
        let mut invalid_type = Vec::new();
        invalid_type.push(0x00); // NAME: root domain
        invalid_type.extend_from_slice(&[0x00, 0x01]); // TYPE: A (not OPT)
        invalid_type.extend_from_slice(&[0x10, 0x00]); // CLASS
        invalid_type.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
        invalid_type.extend_from_slice(&[0x00, 0x00]); // RDLEN
        let result = opt_record_parser(&invalid_type, &invalid_type, &mut rd_name, &mut soa_name);
        assert!(result.is_err());

        // Test RDATA length exceeds remaining data
        let mut invalid_rdata_len = Vec::new();
        invalid_rdata_len.push(0x00); // NAME
        invalid_rdata_len.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
        invalid_rdata_len.extend_from_slice(&[0x10, 0x00]); // CLASS
        invalid_rdata_len.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
        invalid_rdata_len.extend_from_slice(&[0x00, 0x10]); // RDLEN: 16 bytes
        invalid_rdata_len.extend_from_slice(&[0x01, 0x02]); // Only 2 bytes of data
        let result = opt_record_parser(
            &invalid_rdata_len,
            &invalid_rdata_len,
            &mut rd_name,
            &mut soa_name,
        );
        assert!(result.is_err());
    }

    // Test OPT record parsing - edge cases
    #[test]
    fn test_opt_record_parser_edge_cases() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        // Test maximum payload size
        let mut max_payload = Vec::new();
        max_payload.push(0x00); // NAME
        max_payload.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
        max_payload.extend_from_slice(&[0xFF, 0xFF]); // CLASS: maximum payload size (65535)
        max_payload.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // TTL: all bits set
        max_payload.extend_from_slice(&[0x00, 0x00]); // RDLEN: 0
        let result = opt_record_parser(&max_payload, &max_payload, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (_, opt_rr) = result.unwrap();
        assert_eq!(opt_rr.payload_size, 65535);
        assert_eq!(opt_rr.extrcode, 255);
        assert_eq!(opt_rr.version, 255);
        assert_eq!(opt_rr.flags, 0xFFFF);

        // Test minimum valid record (exactly 11 bytes)
        let min_valid = [
            0x00, // NAME
            0x00, 0x29, // TYPE: OPT
            0x02, 0x00, // CLASS: 512
            0x00, 0x00, 0x00, 0x00, // TTL
            0x00, 0x00, // RDLEN: 0
        ];
        let result = opt_record_parser(&min_valid, &min_valid, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (offset, opt_rr) = result.unwrap();
        assert_eq!(offset, 11);
        assert_eq!(opt_rr.payload_size, 512);
    }

    // Test OptRR struct field validation
    #[test]
    fn test_opt_record_parser_optrr_fields() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        // Test various payload size values
        let test_cases = [
            (512u16, "Standard DNS UDP payload size"),
            (1232u16, "Common EDNS payload size"),
            (4096u16, "Large payload size"),
            (65535u16, "Maximum payload size"),
        ];

        for (payload_size, description) in test_cases {
            let mut data = Vec::new();
            data.push(0x00); // NAME: root domain
            data.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
            data.extend_from_slice(&payload_size.to_be_bytes()); // CLASS: payload size
            data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
            data.extend_from_slice(&[0x00, 0x00]); // RDLEN: 0

            let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
            assert!(result.is_ok(), "Failed for {}", description);

            let (_, opt_rr) = result.unwrap();
            assert_eq!(
                opt_rr.payload_size, payload_size,
                "Payload size mismatch for {}",
                description
            );
        }
    }

    // Extended RCODE field of OptRR
    #[test]
    fn test_opt_record_parser_extended_rcode() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let test_rcodes = [0u8, 1, 15, 255]; // Test different extended RCODE values
        for extrcode in test_rcodes {
            let mut data = Vec::new();
            data.push(0x00); // NAME
            data.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
            data.extend_from_slice(&[0x10, 0x00]); // CLASS: 4096
            data.push(extrcode); // Extended RCODE
            data.push(0x00); // Version
            data.extend_from_slice(&[0x00, 0x00]); // Flags
            data.extend_from_slice(&[0x00, 0x00]); // RDLEN

            let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
            assert!(result.is_ok(), "Failed for extended RCODE {}", extrcode);

            let (_, opt_rr) = result.unwrap();
            assert_eq!(opt_rr.extrcode, extrcode, "Extended RCODE mismatch");
        }
    }

    // Version field of OptRR
    #[test]
    fn test_opt_record_parser_version() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let test_versions = [0u8, 1, 2, 255]; // Test different version values

        for version in test_versions {
            let mut data = Vec::new();
            data.push(0x00); // NAME
            data.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
            data.extend_from_slice(&[0x10, 0x00]); // CLASS: 4096
            data.push(0x00); // Extended RCODE
            data.push(version); // Version
            data.extend_from_slice(&[0x00, 0x00]); // Flags
            data.extend_from_slice(&[0x00, 0x00]); // RDLEN

            let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
            assert!(result.is_ok(), "Failed for version {}", version);

            let (_, opt_rr) = result.unwrap();
            assert_eq!(opt_rr.version, version, "Version mismatch");
        }
    }

    // Flags field of OptRR
    #[test]
    fn test_opt_record_parser_flags() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        let test_flags = [
            (0x0000u16, "No flags set"),
            (0x8000u16, "DO bit set"),
            (0x4000u16, "Other flag bit"),
            (0xFFFFu16, "All flags set"),
        ];

        for (flags, description) in test_flags {
            let mut data = Vec::new();
            data.push(0x00); // NAME
            data.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
            data.extend_from_slice(&[0x10, 0x00]); // CLASS: 4096
            data.push(0x00); // Extended RCODE
            data.push(0x00); // Version
            data.extend_from_slice(&flags.to_be_bytes()); // Flags
            data.extend_from_slice(&[0x00, 0x00]); // RDLEN

            let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
            assert!(result.is_ok(), "Failed for {}", description);

            let (_, opt_rr) = result.unwrap();
            assert_eq!(opt_rr.flags, flags, "Flags mismatch for {}", description);
        }
    }

    // OptRR rdata field (containing EDNS options)
    #[test]
    fn test_opt_record_parser_rdata_options() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        // Test RDATA containing EDNS options
        let mut data = Vec::new();
        data.push(0x00); // NAME
        data.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT
        data.extend_from_slice(&[0x10, 0x00]); // CLASS: 4096
        data.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // TTL (DO bit set)
        data.extend_from_slice(&[0x00, 0x08]); // RDLEN: 8 bytes

        // RDATA: simulate EDNS options
        // Option Code: 3 (NSID)
        data.extend_from_slice(&[0x00, 0x03]);
        // Option Length: 4
        data.extend_from_slice(&[0x00, 0x04]);
        // Option Data: "test"
        data.extend_from_slice(&[0x74, 0x65, 0x73, 0x74]);

        let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (offset, opt_rr) = result.unwrap();
        assert_eq!(offset, 19); // 11 + 8 = 19
        assert_eq!(opt_rr.payload_size, 4096);
        assert_eq!(opt_rr.extrcode, 0);
        assert_eq!(opt_rr.version, 0);
        assert_eq!(opt_rr.flags, 0x8000); // DO bit set

        match opt_rr.rdata {
            Rdata::Unknown(rdata_bytes) => {
                assert_eq!(rdata_bytes.len(), 8);
                assert_eq!(&rdata_bytes[0..2], &[0x00, 0x03]); // Option Code
                assert_eq!(&rdata_bytes[2..4], &[0x00, 0x04]); // Option Length
                assert_eq!(&rdata_bytes[4..8], &[0x74, 0x65, 0x73, 0x74]); // Option Data
            }
            _ => panic!("Expected Unknown rdata type for OPT record"),
        }
    }

    // Complete field combination for OptRR
    #[test]
    fn test_opt_record_parser_complete_optrr() {
        let mut rd_name = [0u8; MAX_NAME];
        let mut soa_name = [0u8; MAX_NAME];

        // Construct a complete OPT record with all fields
        let mut data = Vec::new();
        data.push(0x00); // NAME: root domain
        data.extend_from_slice(&[0x00, 0x29]); // TYPE: OPT (41)
        data.extend_from_slice(&[0x04, 0xD0]); // CLASS: payload size = 1232
        data.push(0x01); // Extended RCODE: 1
        data.push(0x00); // Version: 0
        data.extend_from_slice(&[0x80, 0x00]); // Flags: DO bit set
        data.extend_from_slice(&[0x00, 0x0C]); // RDLEN: 12 bytes

        // RDATA: two EDNS options
        // First option: NSID (3)
        data.extend_from_slice(&[0x00, 0x03, 0x00, 0x02, 0x41, 0x42]); // Code=3, Len=2, Data="AB"
        // Second option: Custom option (65001)
        data.extend_from_slice(&[0xFD, 0xE9, 0x00, 0x02, 0x43, 0x44]); // Code=65001, Len=2, Data="CD"

        let result = opt_record_parser(&data, &data, &mut rd_name, &mut soa_name);
        assert!(result.is_ok());

        let (offset, opt_rr) = result.unwrap();
        assert_eq!(offset, 23); // 11 + 12 = 23

        assert_eq!(opt_rr.payload_size, 1232);
        assert_eq!(opt_rr.extrcode, 1);
        assert_eq!(opt_rr.version, 0);
        assert_eq!(opt_rr.flags, 0x8000);

        match opt_rr.rdata {
            Rdata::Unknown(rdata_bytes) => {
                assert_eq!(rdata_bytes.len(), 12);
                assert_eq!(&rdata_bytes[0..6], &[0x00, 0x03, 0x00, 0x02, 0x41, 0x42]);
                assert_eq!(&rdata_bytes[6..12], &[0xFD, 0xE9, 0x00, 0x02, 0x43, 0x44]);
            }
            _ => panic!("Expected Unknown rdata type for OPT record"),
        }
    }

    #[test]
    fn test_dns_udp_pcap() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/dns_udp_qa.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_headers = Rc::new(RefCell::new(Vec::<DnsHeader>::new()));
        let captured_queries = Rc::new(RefCell::new(Vec::<(Vec<u8>, Qtype, Qclass, bool)>::new()));
        let captured_answers = Rc::new(RefCell::new(Vec::<String>::new()));
        let captured_authorities = Rc::new(RefCell::new(Vec::<String>::new()));
        let captured_additionals = Rc::new(RefCell::new(Vec::<String>::new()));
        let dns_end_called = Rc::new(RefCell::new(0u32));

        let header_callback = {
            let headers_clone = captured_headers.clone();
            move |header: DnsHeader, _offset: usize, _cb_ctx: *mut c_void| {
                let mut headers_guard = headers_clone.borrow_mut();
                headers_guard.push(header);
                println!(
                    "DNS Header: ID={}, QR={}, OPCODE={:?}, RCODE={:?}, QCOUNT={}, ANCOUNT={}, NSCOUNT={}, ARCOUNT={}",
                    header.id,
                    header.qr,
                    header.opcode,
                    header.rcode,
                    header.qcount,
                    header.ancount,
                    header.nscount,
                    header.arcount
                );
            }
        };

        let query_callback = {
            let queries_clone = captured_queries.clone();
            move |name: &[u8],
                  qtype: Qtype,
                  qclass: Qclass,
                  unicast: bool,
                  _offset: usize,
                  _cb_ctx: *mut c_void| {
                let mut queries_guard = queries_clone.borrow_mut();
                queries_guard.push((name.to_vec(), qtype, qclass, unicast));
                println!(
                    "DNS Query: name={}, qtype={:?}, qclass={:?}, unicast={}",
                    String::from_utf8_lossy(name),
                    qtype,
                    qclass,
                    unicast
                );
            }
        };

        let answer_callback = {
            let answers_clone = captured_answers.clone();
            move |rr: RR, _offset: usize, _cb_ctx: *mut c_void| {
                let mut answers_guard = answers_clone.borrow_mut();
                let name_str = String::from_utf8_lossy(rr.name);
                let rdata_info = match &rr.rdata {
                    Rdata::A(ip) => format!("A: {}", ip),
                    Rdata::Aaaa(ip) => format!("AAAA: {}", ip),
                    Rdata::Cname(cname) => format!("CNAME: {}", String::from_utf8_lossy(cname)),
                    Rdata::NS(ns) => format!("NS: {}", String::from_utf8_lossy(ns)),
                    Rdata::MX(mx) => format!(
                        "MX: {} {}",
                        mx.preference,
                        String::from_utf8_lossy(mx.exchange)
                    ),
                    Rdata::Ptr(ptr) => format!("PTR: {}", String::from_utf8_lossy(ptr)),
                    Rdata::Txt(txt) => format!("TXT: {}", String::from_utf8_lossy(txt)),
                    Rdata::Soa(soa) => format!(
                        "SOA: {} {} {} {} {} {} {}",
                        String::from_utf8_lossy(soa.primary_ns),
                        String::from_utf8_lossy(soa.mailbox),
                        soa.serial,
                        soa.refresh,
                        soa.retry,
                        soa.expire,
                        soa.minimum_ttl
                    ),
                    Rdata::Srv(srv) => format!(
                        "SRV: {} {} {} {}",
                        srv.priority,
                        srv.weight,
                        srv.port,
                        String::from_utf8_lossy(srv.target)
                    ),
                    Rdata::Unknown(data) => format!("Unknown: {} bytes", data.len()),
                };
                let record_info = format!(
                    "{} {} {:?} {} {}",
                    name_str, rr.ttl, rr.rtype, rr.class as u16, rdata_info
                );
                answers_guard.push(record_info.clone());
                println!("DNS Answer: {}", record_info);
            }
        };

        let auth_callback = {
            let auth_clone = captured_authorities.clone();
            move |rr: RR, _offset: usize, _cb_ctx: *mut c_void| {
                let mut auth_guard = auth_clone.borrow_mut();
                let name_str = String::from_utf8_lossy(rr.name);
                let record_info = format!("{} {} {:?}", name_str, rr.ttl, rr.rtype);
                auth_guard.push(record_info.clone());
                println!("DNS Authority: {}", record_info);
            }
        };

        let add_callback = {
            let add_clone = captured_additionals.clone();
            move |rr: RR, _offset: usize, _cb_ctx: *mut c_void| {
                let mut add_guard = add_clone.borrow_mut();
                let name_str = String::from_utf8_lossy(rr.name);
                let record_info = format!("{} {} {:?}", name_str, rr.ttl, rr.rtype);
                add_guard.push(record_info.clone());
                println!("DNS Additional: {}", record_info);
            }
        };

        let end_callback = {
            let end_clone = dns_end_called.clone();
            move |_cb_ctx: *mut c_void| {
                let mut end_guard = end_clone.borrow_mut();
                *end_guard += 1;
                println!("DNS parsing completed");
            }
        };

        let mut protolens = Prolens::<CapPacket>::default();
        protolens.set_cb_dns_header(header_callback);
        protolens.set_cb_dns_query(query_callback);
        protolens.set_cb_dns_answer(answer_callback);
        protolens.set_cb_dns_auth(auth_callback);
        protolens.set_cb_dns_add(add_callback);
        protolens.set_cb_dns_end(end_callback);

        let mut task = protolens.new_task(TransProto::Udp);
        protolens.set_task_parser(&mut task, L7Proto::DnsUdp);

        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let pkt = cap.next_packet(now);
            if pkt.is_none() {
                break;
            }
            let pkt = pkt.unwrap();
            if pkt.decode().is_err() {
                continue;
            }

            protolens.run_task(&mut task, pkt);
        }

        let headers_guard = captured_headers.borrow();
        let queries_guard = captured_queries.borrow();
        let answers_guard = captured_answers.borrow();
        let end_guard = dns_end_called.borrow();

        // Verify there should be 2 DNS messages (request and response)
        assert_eq!(headers_guard.len(), 2, "Should have 2 DNS messages");
        assert_eq!(*end_guard, 2, "DNS end callback should be called 2 times");

        // Verify the first packet is a query (QR=false indicates query)
        let query_header = &headers_guard[0];
        assert!(!query_header.qr, "First packet should be a DNS query");
        assert_eq!(query_header.qcount, 1, "Query packet should have 1 query");
        assert_eq!(
            query_header.ancount, 0,
            "Query packet should have no answers"
        );

        // Verify the second packet is a response (QR=true indicates response)
        let response_header = &headers_guard[1];
        assert!(response_header.qr, "Second packet should be a DNS response");
        assert_eq!(
            response_header.qcount, 1,
            "Response packet should have 1 query"
        );
        assert!(
            response_header.ancount > 0,
            "Response packet should have answer records"
        );

        // Verify query content
        assert_eq!(
            queries_guard.len(),
            2,
            "Should have 2 query records (one in request and one in response)"
        );

        // According to Wireshark capture, the query is for CNAME record of server1.somewebsite15.com
        let query_name = String::from_utf8_lossy(&queries_guard[0].0);
        assert!(
            query_name.contains("server1.somewebsite15.com"),
            "Query domain should contain server1.somewebsite15.com"
        );
        assert_eq!(
            queries_guard[0].1,
            Qtype::Cname,
            "Query type should be CNAME"
        );
        assert_eq!(queries_guard[0].2, Qclass::IN, "Query class should be IN");

        assert!(!answers_guard.is_empty(), "Should have answer records");

        println!("All answer records:");
        for (i, answer) in answers_guard.iter().enumerate() {
            println!("  Answer {}: {}", i, answer);
        }

        let has_cname_record = answers_guard.iter().any(|answer| answer.contains("CNAME"));
        assert!(
            has_cname_record,
            "Response should contain CNAME record type"
        );

        let has_target_ip = answers_guard
            .iter()
            .any(|answer| answer.contains("60.1.1.15"));
        assert!(
            has_target_ip,
            "Response should contain target IP address 60.1.1.15"
        );
    }
}
