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

typedef struct {
    L7Proto (*l7_proto)(void* pkt_ptr);
    TransProto (*trans_proto)(void* pkt_ptr);
    CIpAddr (*sip)(void* pkt_ptr);
    CIpAddr (*dip)(void* pkt_ptr);
    uint16_t (*tu_sport)(void* pkt_ptr);
    uint16_t (*tu_dport)(void* pkt_ptr);
    uint32_t (*seq)(void* pkt_ptr);
    bool (*syn)(void* pkt_ptr);
    bool (*fin)(void* pkt_ptr);
    size_t (*payload_len)(void* pkt_ptr);
    const uint8_t* (*payload)(void* pkt_ptr);
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

void        prolens_init_vtable(PacketVTable vtable);
FfiProlens *prolens_new(void);
void        prolens_free(FfiProlens *prolens);

Task       *protolens_task_new(FfiProlens *prolens, void *cb_ctx);
void        protolens_task_free(FfiProlens *prolens, Task *task);
TaskResult  protolens_task_run(FfiProlens *prolens, Task *task, void *pkt_ptr);
void        protolens_task_dbinfo(FfiProlens *prolens, Task *task);

void prolens_set_cb_task_c2s(FfiProlens *prolens, Task *task, CbStm callback);
void prolens_set_cb_task_s2c(FfiProlens *prolens, Task *task, CbStm callback);
void prolens_set_cb_ord_pkt(FfiProlens *prolens, CbOrdPkt callback);

void prolens_set_cb_smtp_user(FfiProlens *prolens, CbData callback);
void prolens_set_cb_smtp_pass(FfiProlens *prolens, CbData callback);
void prolens_set_cb_smtp_mailfrom(FfiProlens *prolens, CbData callback);
void prolens_set_cb_smtp_rcpt(FfiProlens *prolens, CbData callback);
void prolens_set_cb_smtp_header(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_smtp_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_smtp_body(FfiProlens *prolens, CbBody callback);
void prolens_set_cb_smtp_body_stop(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_smtp_srv(FfiProlens *prolens, CbDirData callback);

void prolens_set_cb_pop3_header(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_pop3_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_pop3_body(FfiProlens *prolens, CbBody callback);
void prolens_set_cb_pop3_body_stop(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_pop3_clt(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_pop3_srv(FfiProlens *prolens, CbDirData callback);

void prolens_set_cb_imap_header(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_imap_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_imap_body(FfiProlens *prolens, CbBody callback);
void prolens_set_cb_imap_body_stop(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_imap_clt(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_imap_srv(FfiProlens *prolens, CbDirData callback);

void prolens_set_cb_http_start_line(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_http_header(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_http_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_http_body(FfiProlens *prolens, CbHttpBody callback);
void prolens_set_cb_http_body_stop(FfiProlens *prolens, CbDirEvt callback);

void prolens_set_cb_ftp_clt(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_ftp_srv(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_ftp_link(FfiProlens *prolens, CbFtpLink callback);

void prolens_set_cb_ftp_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_ftp_body(FfiProlens *prolens, CbFtpBody callback);
void prolens_set_cb_ftp_body_stop(FfiProlens *prolens, CbDirEvt callback);

#ifdef __cplusplus
}
#endif

#endif
