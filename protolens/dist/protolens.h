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
    CLIENT2SERVER,
    SERVER2CLIENT,
    BIDIRECTION,
    DIRUNKNOWN,
} PktDirection;

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
    PktDirection (*direction)(void* pkt_ptr);
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
typedef void (*CbEvt)(const void *ctx);

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
void prolens_set_cb_smtp_header(FfiProlens *prolens, CbData callback);
void prolens_set_cb_smtp_body_start(FfiProlens *prolens, CbEvt callback);
void prolens_set_cb_smtp_body(FfiProlens *prolens, CbData callback);
void prolens_set_cb_smtp_body_stop(FfiProlens *prolens, CbEvt callback);
void prolens_set_cb_smtp_srv(FfiProlens *prolens, CbData callback);
void prolens_set_cb_pop3_header(FfiProlens *prolens, CbData callback);
void prolens_set_cb_pop3_body_start(FfiProlens *prolens, CbEvt callback);
void prolens_set_cb_pop3_body(FfiProlens *prolens, CbData callback);
void prolens_set_cb_pop3_body_stop(FfiProlens *prolens, CbEvt callback);
void prolens_set_cb_pop3_srv(FfiProlens *prolens, CbData callback);


#ifdef __cplusplus
}
#endif

#endif
