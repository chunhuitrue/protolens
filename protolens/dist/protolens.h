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

typedef struct {
    ProlensDirection (*direction)(void* pkt_ptr);
    L7Proto (*l7_proto)(void* pkt_ptr);
    TransProto (*trans_proto)(void* pkt_ptr);
    uint16_t (*tu_sport)(void* pkt_ptr);
    uint16_t (*tu_dport)(void* pkt_ptr);
    uint32_t (*seq)(void* pkt_ptr);
    bool (*syn)(void* pkt_ptr);
    bool (*fin)(void* pkt_ptr);
    size_t (*payload_len)(void* pkt_ptr);
    const uint8_t* (*payload)(void* pkt_ptr);
} PacketVTable;

typedef void (*CbStm)(const uint8_t *data, size_t data_len, uint32_t seq, const void *ctx);
typedef void (*CbOrdPkt)(void *pkt_ptr, const void *ctx);
typedef void (*CbData)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx);
typedef void (*CbDirData)(const uint8_t *data, size_t len, uint32_t seq, const void *ctx, ProlensDirection dir);
typedef void (*CbDirEvt)(const void *ctx, ProlensDirection dir);    

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
void prolens_set_cb_smtp_body(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_smtp_body_stop(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_smtp_clt(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_smtp_srv(FfiProlens *prolens, CbDirData callback);

void prolens_set_cb_pop3_header(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_pop3_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_pop3_body(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_pop3_body_stop(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_pop3_clt(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_pop3_srv(FfiProlens *prolens, CbDirData callback);

void prolens_set_cb_imap_header(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_imap_body_start(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_imap_body(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_imap_body_stop(FfiProlens *prolens, CbDirEvt callback);
void prolens_set_cb_imap_clt(FfiProlens *prolens, CbDirData callback);
void prolens_set_cb_imap_srv(FfiProlens *prolens, CbDirData callback);


#ifdef __cplusplus
}
#endif

#endif
