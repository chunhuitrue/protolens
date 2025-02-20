#ifndef __PROTOLENS_H__
#define __PROTOLENS_H__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    Tcp,
    Udp,
    Other
} TransProto;

typedef enum {
    Client2Server,
    Server2Client,
    BiDirection,
    Unknown,
} PktDirection;

typedef enum {
    Smtp,
    Http,
    Undef,
} ParserType;

typedef struct {
    TransProto (*trans_proto)(void* packet);
    uint16_t (*tu_sport)(void* packet);
    uint16_t (*tu_dport)(void* packet);
    uint32_t (*seq)(void* packet);
    bool (*syn)(void* packet);
    bool (*fin)(void* packet);
    size_t (*payload_len)(void* packet);
    const uint8_t* (*payload)(void* packet);
} PacketVTable;

typedef struct Task Task;

Task *task_new(void);
void  task_free(Task* ptr);
Task *task_new_with_parser(ParserType parser_type);
Task *task_init_parser(Task* task_ptr, ParserType parser_type);
void task_run(Task *task_ptr, void *packet_ptr, const PacketVTable *vtable_ptr,
              PktDirection pkt_dir, uint64_t ts);

/* smtp */
typedef void (*SmtpUserCallback)(const char* username);
void task_set_smtp_user_callback(SmtpUserCallback callback);

/* http */

#endif
