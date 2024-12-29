#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "../dist/protolens.h"

// 模拟一个简单的数据包结构
typedef struct {
    uint32_t seq;
    uint16_t sport;
    uint16_t dport;
    const uint8_t *payload;
    size_t payload_len;
} TestPacket;

// PacketVTable 的回调函数实现
TransProto packet_trans_proto(void* packet) {
    return Tcp;
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

int main(void) {
    // 创建虚函数表
    PacketVTable vtable = {
        .trans_proto = packet_trans_proto,
        .tu_sport = packet_sport,
        .tu_dport = packet_dport,
        .seq = packet_seq,
        .syn = packet_syn,
        .fin = packet_fin,
        .payload_len = packet_payload_len,
        .payload = packet_payload,
    };

    // 创建测试数据包
    uint8_t payload[] = "USER test\r\n";
    TestPacket test_packet = {
        .seq = 1,
        .sport = 12345,
        .dport = 25,  // SMTP port
        .payload = payload,
        .payload_len = sizeof(payload) - 1,
    };

    // 创建并初始化任务
    Task *task = task_new_with_parser(Smtp);
    if (!task) {
        printf("Failed to create task\n");
        return 1;
    }

    // 运行任务处理数据包
    task_run(task, &test_packet, &vtable, Client2Server, 1000);

    // 清理
    task_free(task);
    return 0;
}
