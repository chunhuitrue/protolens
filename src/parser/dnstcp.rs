use crate::{
    CbDnsAdd, CbDnsAnswer, CbDnsAuth, CbDnsEnd, CbDnsHeader, CbDnsOptAdd, CbDnsQuery, DnsCallbacks,
    Parser, ParserFactory, ParserFuture, PktStrm, Prolens, dns_parser, packet::*,
};
use byteorder::{BigEndian, ByteOrder};
use std::ffi::c_void;
use std::marker::PhantomData;

pub struct DnsTcpParser<T>
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
    read_buff_size: usize,
    _phantom_t: PhantomData<T>,
}

impl<T> DnsTcpParser<T>
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
            read_buff_size: 0,
            _phantom_t: PhantomData,
        }
    }

    async fn parser_inner(
        strm: *mut PktStrm<T>,
        buff_size: usize,
        cb: DnsCallbacks,
        cb_ctx: *mut c_void,
    ) -> Result<(), ()> {
        let stm = unsafe { &mut *strm };

        loop {
            let (byte, _seq) = stm.readn(2).await?;

            let msg_len = BigEndian::read_u16(byte) as usize;
            if msg_len > buff_size {
                return Err(());
            }

            let (msg, _seq) = stm.readn(msg_len).await?;
            dns_parser(msg, &cb, cb_ctx)?;
        }
    }
}

impl<T> Parser for DnsTcpParser<T>
where
    T: Packet + 'static,
{
    type T = T;

    fn c2s_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let callback = DnsCallbacks {
            header: self.cb_dns_header.clone(),
            query: self.cb_dns_query.clone(),
            answer: self.cb_dns_answer.clone(),
            auth: self.cb_dns_auth.clone(),
            add: self.cb_dns_add.clone(),
            opt_add: self.cb_dns_opt_add.clone(),
            end: self.cb_dns_end.clone(),
        };
        Some(Box::pin(Self::parser_inner(
            strm,
            self.read_buff_size,
            callback,
            cb_ctx,
        )))
    }

    fn s2c_parser(&self, strm: *mut PktStrm<T>, cb_ctx: *mut c_void) -> Option<ParserFuture> {
        let callback = DnsCallbacks {
            header: self.cb_dns_header.clone(),
            query: self.cb_dns_query.clone(),
            answer: self.cb_dns_answer.clone(),
            auth: self.cb_dns_auth.clone(),
            add: self.cb_dns_add.clone(),
            opt_add: self.cb_dns_opt_add.clone(),
            end: self.cb_dns_end.clone(),
        };
        Some(Box::pin(Self::parser_inner(
            strm,
            self.read_buff_size,
            callback,
            cb_ctx,
        )))
    }
}

pub(crate) struct DnsTcpFactory<T> {
    _phantom_t: PhantomData<T>,
}

impl<T> ParserFactory<T> for DnsTcpFactory<T>
where
    T: Packet + 'static,
{
    fn new() -> Self {
        Self {
            _phantom_t: PhantomData,
        }
    }

    fn create(&self, prolens: &Prolens<T>) -> Box<dyn Parser<T = T>> {
        let mut parser = Box::new(DnsTcpParser::new());
        parser.cb_dns_header = prolens.cb_dns_header.clone();
        parser.cb_dns_query = prolens.cb_dns_query.clone();
        parser.cb_dns_answer = prolens.cb_dns_answer.clone();
        parser.cb_dns_auth = prolens.cb_dns_auth.clone();
        parser.cb_dns_add = prolens.cb_dns_add.clone();
        parser.cb_dns_opt_add = prolens.cb_dns_opt_add.clone();
        parser.cb_dns_end = prolens.cb_dns_end.clone();
        parser.read_buff_size = prolens.conf.read_buff;
        parser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsHeader, OptRR, Qclass, Qtype, RR, Rdata, test_utils::*};
    use std::cell::RefCell;
    use std::env;
    use std::ffi::c_void;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_dns_tcp_pcap() {
        let project_root = env::current_dir().unwrap();
        let file_path = project_root.join("tests/pcap/dns_tcp.pcap");
        let mut cap = Capture::init(file_path).unwrap();

        let captured_headers = Rc::new(RefCell::new(Vec::<DnsHeader>::new()));
        let captured_queries = Rc::new(RefCell::new(Vec::<(Vec<u8>, Qtype, Qclass, bool)>::new()));
        let captured_answers = Rc::new(RefCell::new(Vec::<String>::new()));
        let captured_authorities = Rc::new(RefCell::new(Vec::<String>::new()));
        let captured_additionals = Rc::new(RefCell::new(Vec::<String>::new()));
        let captured_opt_records = Rc::new(RefCell::new(Vec::<String>::new()));
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
                let rdata_info = match &rr.rdata {
                    Rdata::A(ip) => format!("A: {}", ip),
                    Rdata::Aaaa(ip) => format!("AAAA: {}", ip),
                    Rdata::Unknown(data) => format!("Unknown: {} bytes", data.len()),
                    _ => format!("Other: {:?}", rr.rtype),
                };
                let record_info = format!(
                    "{} {} {:?} {} {}",
                    name_str, rr.ttl, rr.rtype, rr.class as u16, rdata_info
                );
                add_guard.push(record_info.clone());
                println!("DNS Additional: {}", record_info);
            }
        };

        let opt_add_callback = {
            let opt_clone = captured_opt_records.clone();
            move |opt_rr: OptRR, _offset: usize, _cb_ctx: *mut c_void| {
                let mut opt_guard = opt_clone.borrow_mut();
                let rdata_info = match &opt_rr.rdata {
                    Rdata::Unknown(data) => format!("Unknown: {} bytes", data.len()),
                    _ => "Other".to_string(),
                };
                let record_info = format!(
                    "OPT: payload_size={}, extrcode={}, version={}, flags=0x{:04x}, rdata={}",
                    opt_rr.payload_size, opt_rr.extrcode, opt_rr.version, opt_rr.flags, rdata_info
                );
                opt_guard.push(record_info.clone());
                println!("DNS OPT Additional: {}", record_info);
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
        protolens.set_cb_dns_opt_add(opt_add_callback);
        protolens.set_cb_dns_end(end_callback);

        let mut task = protolens.new_task(TransProto::Tcp);
        protolens.set_task_parser(&mut task, L7Proto::DnsTcp);

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
        let additionals_guard = captured_additionals.borrow();
        let opt_records_guard = captured_opt_records.borrow();
        let end_guard = dns_end_called.borrow();

        // Verify that there should be 2 DNS messages (request and response)
        assert_eq!(headers_guard.len(), 2, "Should have 2 DNS messages");
        assert_eq!(*end_guard, 2, "DNS end callback should be called 2 times");

        // Verify that the first packet is a query
        let query_header = &headers_guard[0];
        assert!(!query_header.qr, "First packet should be a DNS query");
        assert_eq!(query_header.qcount, 1, "Query packet should have 1 query");
        assert_eq!(
            query_header.ancount, 0,
            "Query packet should have no answers"
        );
        assert_eq!(query_header.id, 0xfeb9, "Transaction ID should be 0xfeb9");

        // Verify that the second packet is a response
        let response_header = &headers_guard[1];
        assert!(response_header.qr, "Second packet should be a DNS response");
        assert_eq!(
            response_header.qcount, 1,
            "Response packet should have 1 query"
        );
        assert_eq!(
            response_header.ancount, 13,
            "Response packet should have 13 answer records"
        );
        assert_eq!(
            response_header.arcount, 16,
            "Response packet should have 16 additional records"
        );
        assert_eq!(response_header.id, 0xfeb9, "Transaction ID should match");

        // Verify query content
        assert_eq!(
            queries_guard.len(),
            2,
            "Should have 2 query records (one in request and one in response)"
        );

        // Query is for NS record of root domain
        assert!(
            queries_guard[0].0[0] == 0,
            "Query domain should be root domain (first byte should be 0)"
        );
        assert_eq!(queries_guard[0].1, Qtype::NS, "Query type should be NS");
        assert_eq!(queries_guard[0].2, Qclass::IN, "Query class should be IN");

        println!("All answer records:");
        for (i, answer) in answers_guard.iter().enumerate() {
            println!("  Answer {}: {}", i, answer);
        }
        assert!(!answers_guard.is_empty(), "Should have answer records");
        assert_eq!(answers_guard.len(), 13, "Should have 13 answer records");

        let root_servers = [
            "a.root-servers.net",
            "b.root-servers.net",
            "c.root-servers.net",
            "d.root-servers.net",
            "e.root-servers.net",
            "f.root-servers.net",
            "g.root-servers.net",
            "h.root-servers.net",
            "i.root-servers.net",
            "j.root-servers.net",
            "k.root-servers.net",
            "l.root-servers.net",
            "m.root-servers.net",
        ];
        for server in &root_servers {
            let has_server = answers_guard.iter().any(|answer| answer.contains(server));
            assert!(
                has_server,
                "Response should contain root server: {}",
                server
            );
        }

        // Verify additional records
        println!("All additional records:");
        for (i, additional) in additionals_guard.iter().enumerate() {
            println!("  Additional {}: {}", i, additional);
        }
        assert!(
            !additionals_guard.is_empty(),
            "Should have additional records"
        );
        assert_eq!(
            additionals_guard.len(),
            15,
            "Should have 15 additional records"
        );

        // Verify that additional records contain A and AAAA records
        let has_a_records = additionals_guard.iter().any(|record| record.contains("A:"));
        let has_aaaa_records = additionals_guard
            .iter()
            .any(|record| record.contains("AAAA:"));
        assert!(has_a_records, "Additional records should contain A records");
        assert!(
            has_aaaa_records,
            "Additional records should contain AAAA records"
        );

        // Verify OPT records
        println!("All OPT records:");
        for (i, opt_record) in opt_records_guard.iter().enumerate() {
            println!("  OPT {}: {}", i, opt_record);
        }
        assert!(!opt_records_guard.is_empty(), "Should have OPT records");
        assert_eq!(
            opt_records_guard.len(),
            2,
            "Should have 2 OPT records, one in request packet and one in response packet"
        );

        // Verify basic fields of OPT records
        let opt_record = &opt_records_guard[0];
        assert!(opt_record.contains("OPT:"), "Record should be OPT type");
        assert!(
            opt_record.contains("payload_size="),
            "Should contain payload_size field"
        );
        assert!(
            opt_record.contains("version="),
            "Should contain version field"
        );
    }
}
