#ifndef _H_PROTOLENS_H
#define _H_PROTOLENS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FfiProlens FfiProlens;
typedef struct Task Task;

typedef enum {
    C2S,
    S2C,
    BIDIR,
    DIRUNKNOWN,
} ProlensDirection;

typedef enum {
    ORDPACKET,
    SMTP,
    POP3,
    IMAP,
    HTTP,
    FTPCMD,
    FTPDATA,
    SIP,
    L7UNKNOWN,
} L7Proto;

typedef enum {
    TCP,
    UDP,
    OTHER,
} TransProto;

typedef enum {
    TASK_PENDING,
    TASK_DONE,
    TASK_ERROR,
} TaskResult;

typedef enum {
    None,
    Bit7,
    Bit8,
    Binary,
    QuotedPrintable,
    Base64,
} CTransferEncoding;

typedef enum {
    ENone,
    Compress,
    Deflate,
    Gzip,
    Lzma,
    Br,
    Identity,
    Chunked,
} CEncoding;

#define MAX_ENCODING 8
struct CEncodingArray {
    const CEncoding* ptr;
    size_t len;
    CEncoding buffer[MAX_ENCODING];
};

typedef struct {
    uint8_t ip_type;  // 0: Invalid, 1: IPv4, 2: IPv6
    uint8_t octets[16];
} CIpAddr;

typedef void (*PacketFree)(void *pkt_ptr);

typedef struct {
    TransProto (*trans_proto)(void *pkt_ptr);
    CIpAddr (*sip)(void *pkt_ptr);
    CIpAddr (*dip)(void *pkt_ptr);
    uint16_t (*tu_sport)(void *pkt_ptr);
    uint16_t (*tu_dport)(void *pkt_ptr);
    uint32_t (*seq)(void *pkt_ptr);
    bool (*syn)(void *pkt_ptr);
    bool (*fin)(void *pkt_ptr);
    size_t (*payload_len)(void *pkt_ptr);
    const uint8_t* (*payload)(void *pkt_ptr);
    PacketFree free;
} PacketVTable;

typedef void (*CbStm)(const uint8_t *data, size_t data_len, uint32_t seq, const void *ctx);
typedef void (*CbOrdPkt)(void *pkt_ptr, const void *ctx, ProlensDirection dir);
typedef void (*CbData)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx);
typedef void (*CbDirData)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir);
typedef void (*CbDirEvt)(const void *ctx, ProlensDirection dir);
typedef void (*CbBody)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir, CTransferEncoding te);
typedef void (*CbHttpBody)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir,
                           struct CEncodingArray ce, struct CEncodingArray te);
typedef void (*CbFtpLink)(const uint8_t *ip_ptr, size_t ip_len, uint8_t ip_type, uint16_t port, const void *ctx, ProlensDirection dir);
typedef void (*CbFtpBody)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir);
typedef void (*CbSipBody)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir);

void        protolens_init_vtable(PacketVTable vtable);
FfiProlens *protolens_new(void);
void        protolens_free(FfiProlens *prolens);

Task       *protolens_task_new(FfiProlens *prolens, TransProto l4_proto, void *cb_ctx);
void        protolens_task_free(FfiProlens *prolens, Task *task);
TaskResult  protolens_task_run(FfiProlens *prolens, Task *task, void *pkt_ptr);
void        protolens_task_dbinfo(FfiProlens *prolens, Task *task);

void protolens_set_task_parser(FfiProlens *prolens, Task *task, L7Proto l7_proto);
void protolens_set_cb_task_c2s(FfiProlens *prolens, CbStm callback);
void protolens_set_cb_task_s2c(FfiProlens *prolens, CbStm callback);

void protolens_set_cb_ord_pkt(FfiProlens *prolens, CbOrdPkt callback);

void protolens_set_cb_smtp_user(FfiProlens *prolens, CbData callback);
void protolens_set_cb_smtp_pass(FfiProlens *prolens, CbData callback);
void protolens_set_cb_smtp_mailfrom(FfiProlens *prolens, CbData callback);
void protolens_set_cb_smtp_rcpt(FfiProlens *prolens, CbData callback);
void protolens_set_cb_smtp_header(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_smtp_body_start(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_smtp_body(FfiProlens *prolens, CbBody callback);
void protolens_set_cb_smtp_body_stop(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_smtp_srv(FfiProlens *prolens, CbDirData callback);

void protolens_set_cb_pop3_header(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_pop3_body_start(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_pop3_body(FfiProlens *prolens, CbBody callback);
void protolens_set_cb_pop3_body_stop(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_pop3_clt(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_pop3_srv(FfiProlens *prolens, CbDirData callback);

void protolens_set_cb_imap_header(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_imap_body_start(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_imap_body(FfiProlens *prolens, CbBody callback);
void protolens_set_cb_imap_body_stop(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_imap_clt(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_imap_srv(FfiProlens *prolens, CbDirData callback);

void protolens_set_cb_http_start_line(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_http_header(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_http_body_start(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_http_body(FfiProlens *prolens, CbHttpBody callback);
void protolens_set_cb_http_body_stop(FfiProlens *prolens, CbDirEvt callback);

void protolens_set_cb_ftp_clt(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_ftp_srv(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_ftp_link(FfiProlens *prolens, CbFtpLink callback);

void protolens_set_cb_ftp_body_start(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_ftp_body(FfiProlens *prolens, CbFtpBody callback);
void protolens_set_cb_ftp_body_stop(FfiProlens *prolens, CbDirEvt callback);

void protolens_set_cb_sip_start_line(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_sip_header(FfiProlens *prolens, CbDirData callback);
void protolens_set_cb_sip_body_start(FfiProlens *prolens, CbDirEvt callback);
void protolens_set_cb_sip_body(FfiProlens *prolens, CbSipBody callback);
void protolens_set_cb_sip_body_stop(FfiProlens *prolens, CbDirEvt callback);

typedef void (*CbSipBody)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir);

typedef enum {
    QUERY  = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
} COpcode;

typedef enum {
    NOERROR   = 0,
    FORMERR   = 1,
    SERVFAIL  = 2,
    NXDOMAIN  = 3,
    NOTIMP    = 4,
    REFUSED   = 5,
    YXDOMAIN  = 6,
    YXRRSET   = 7,
    NXRRSET   = 8,
    NOTAUTH   = 9,
    NOTZONE   = 10,
    BADVERS   = 16,
    BADSIG    = 16,
    BADKEY    = 17,
    BADTIME   = 18,
    BADMODE   = 19,
    BADNAME   = 20,
    BADALG    = 21,
    BADTRUNC  = 22,
    BADCOOKIE = 23,
} CRcode;

typedef enum {
    A     = 1,
    NS    = 2,
    CNAME = 5,
    SOA   = 6,
    PTR   = 12,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
    SRV   = 33,
    OPT   = 41,
} CQtype;

typedef enum {
    IN  = 1,
    CS  = 2,
    CH  = 3,
    HS  = 4,
    ANY = 255,
} CQclass;

typedef struct {
    uint16_t id;
    bool     qr;
    COpcode  opcode;
    bool     aa;
    bool     tc;
    bool     rd;
    bool     ra;
    bool     z;
    bool     ad;
    bool     cd;
    CRcode   rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} CHeader;

typedef struct {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum_ttl;
    uint8_t  primary_ns[256];
    size_t   primary_ns_len;
    uint8_t  mailbox[256];
    size_t   mailbox_len;
} CRdSoa;

typedef struct {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    uint8_t  target[256];
    size_t   target_len;
} CRdSrv;

typedef struct {
    uint16_t preference;
    uint8_t  exchange[256];
    size_t   exchange_len;
} CRdMx;

typedef struct {
    uint8_t        name[256];
    size_t         name_len;
    CQtype         qtype;
    CQclass        qclass;
    uint32_t       ttl;
    const uint8_t* rdata_ptr;
    size_t         rdata_len;
    uint8_t        ipv4_addr[4];
    uint8_t        ipv6_addr[16];
    CRdSoa         soa;
    CRdSrv         srv;
    CRdMx          mx;
} CRR;

typedef struct {
    uint8_t        name[256];
    size_t         name_len;
    CQtype         qtype;
    CQclass        qclass;
    uint32_t       ttl;
    const uint8_t* rdata_ptr;
    size_t         rdata_len;
    uint8_t        ipv4_addr[4];
    uint8_t        ipv6_addr[16];
    CRdSoa         soa;
    CRdSrv         srv;
    CRdMx          mx;
} COptRR;

typedef void (*CbDnsHeader)(const CHeader *header, const void *ctx);
typedef void (*CbDnsQuery)(const uint8_t *name, size_t name_len, CQtype qtype, CQclass qclass, const void *ctx);
typedef void (*CbDnsRr)(const CRR *rr, const void *ctx);
typedef void (*CbDnsOptRr)(const COptRR *opt_rr, const void *ctx);
typedef void (*CbDnsEnd)(const void *ctx);

void protolens_set_cb_dns_header(FfiProlens *prolens, CbDnsHeader callback);
void protolens_set_cb_dns_query(FfiProlens *prolens, CbDnsQuery callback);
void protolens_set_cb_dns_answer(FfiProlens *prolens, CbDnsRr callback);
void protolens_set_cb_dns_auth(FfiProlens *prolens, CbDnsRr callback);
void protolens_set_cb_dns_add(FfiProlens *prolens, CbDnsRr callback);
void protolens_set_cb_dns_opt_add(FfiProlens *prolens, CbDnsOptRr callback);
void protolens_set_cb_dns_end(FfiProlens *prolens, CbDnsEnd callback);

#ifdef __cplusplus
}
#endif

#endif
