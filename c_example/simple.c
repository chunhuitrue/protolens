#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "../protolens/dist/protolens.h"

// 模拟一个简单的数据包结构
typedef struct {
    uint32_t seq;
    uint16_t sport;
    uint16_t dport;
    const uint8_t *payload;
    size_t payload_len;
} TestPacket;

PktDirection packet_direction(void* packet) {
    return CLIENT2SERVER;
}

L7Proto packet_l7_proto(void* packet) {
    return SMTP;
}

TransProto packet_trans_proto(void* packet) {
    return TCP;
}

uint16_t packet_sport(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    return pkt->sport;
}

uint16_t packet_dport(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    return pkt->dport;
}

uint32_t packet_seq(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    return pkt->seq;
}

bool packet_syn(void* packet) {
    return false;
}

bool packet_fin(void* packet) {
    return false;
}

size_t packet_payload_len(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    return pkt->payload_len;
}

const uint8_t* packet_payload(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    return pkt->payload;
}

void callback_task_c2s(const uint8_t *data, size_t data_len, uint32_t seq, const void *ctx) {
    printf("Received task c2s data (seq=%u): len: %d\n", seq, (int)data_len);
}

void callback_smtp_user(const uint8_t* data, size_t len, uint32_t seq, const void* ctx) {
    printf("Received SMTP username (seq=%u): %.*s\n", seq, (int)len, data);
}

void callback_smtp_pass(const uint8_t* data, size_t len, uint32_t seq, const void* ctx) {
    printf("Received SMTP pass (seq=%u): %.*s\n", seq, (int)len, data);
}

int main(void) {
    // 创建 Prolens 实例
    FfiProlens *prolens = prolens_new();
    if (!prolens) {
        printf("Failed to create prolens instance\n");
        return 1;
    }

    // 设置 vtable
    PacketVTable vtable = {
        .direction   = packet_direction,
        .l7_proto    = packet_l7_proto,
        .trans_proto = packet_trans_proto,
        .tu_sport    = packet_sport,
        .tu_dport    = packet_dport,
        .seq         = packet_seq,
        .syn         = packet_syn,
        .fin         = packet_fin,
        .payload_len = packet_payload_len,
        .payload     = packet_payload,
    };
    prolens_init_vtable(vtable);

    // 创建测试数据包
    uint8_t payload[] = "EHLO\r\nAUTH LOGIN\r\nUSER root\r\nPASS 1234\r\n";
    TestPacket test_packet = {
        .seq = 1,
        .sport = 12345,
        .dport = 25,
        .payload = payload,
        .payload_len = sizeof(payload) - 1,
    };
    
    // 设置 SMTP 回调
    printf("simple.c. set smtp cb\n");
    prolens_set_cb_smtp_user(prolens, callback_smtp_user);
    prolens_set_cb_smtp_pass(prolens, callback_smtp_pass);

    // 创建任务
    Task *task = protolens_task_new(prolens, (void *)0x1234);
    if (!task) {
        printf("Failed to create task\n");
        prolens_free(prolens);
        return 1;
    }

    printf("simple.c. task db info:\n");
    protolens_task_dbinfo(prolens, task);

    /* 设置task 流回调 */
    printf("simple.c. set task cb\n");
    prolens_set_cb_task_c2s(prolens, task, callback_task_c2s);
    
    // 运行任务处理数据包
    TaskResult result = protolens_task_run(prolens, task, &test_packet);
    printf("Task result: %d\n", result);

    // 清理资源
    protolens_task_free(prolens, task);
    prolens_free(prolens);
    return 0;
}
