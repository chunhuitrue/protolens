#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "../protolens/dist/protolens.h"

// 模拟一个简单的数据包结构
typedef struct {
    uint32_t       seq;
    uint32_t       sip;
    uint32_t       dip;
    uint16_t       sport;
    uint16_t       dport;
    const uint8_t *payload;
    size_t         payload_len;
} TestPacket;

L7Proto packet_l7_proto(void* packet) {
    return SMTP;
}

TransProto packet_trans_proto(void* packet) {
    return TCP;
}

CIpAddr packet_sip(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    CIpAddr addr = {
        .ip_type = 1,  // IPv4
        .octets = {0}
    };

    addr.octets[0] = (pkt->sip >> 24) & 0xFF;
    addr.octets[1] = (pkt->sip >> 16) & 0xFF;
    addr.octets[2] = (pkt->sip >> 8) & 0xFF;
    addr.octets[3] = pkt->sip & 0xFF;
    return addr;
}

CIpAddr packet_dip(void* packet) {
    TestPacket *pkt = (TestPacket*)packet;
    CIpAddr addr = {
        .ip_type = 1,  // IPv4
        .octets = {0}
    };

    addr.octets[0] = (pkt->dip >> 24) & 0xFF;
    addr.octets[1] = (pkt->dip >> 16) & 0xFF;
    addr.octets[2] = (pkt->dip >> 8) & 0xFF;
    addr.octets[3] = pkt->dip & 0xFF;
    return addr;
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

static uint8_t payload[] = "EHLO\r\nAUTH LOGIN\r\nUSER root\r\nPASS 1234\r\n";
static TestPacket test_packet = {
    .seq         = 1,
    .sip         = 0x0A000001,  // 10.0.0.1
    .dip         = 0x0A000002,  // 10.0.0.2
    .sport       = 12345,
    .dport       = 25,
    .payload     = payload,
    .payload_len = sizeof(payload) - 1
};

void callback_task_c2s(const uint8_t *data, size_t data_len, uint32_t seq, const void *ctx) {
    printf("Received task c2s data (seq=%u): len: %d\n", seq, (int)data_len);
}

void callback_smtp_user(const uint8_t* data, size_t len, uint32_t seq, const void* ctx) {
    printf("Received SMTP username (seq=%u): %.*s\n", seq, (int)len, data);
}

void callback_smtp_pass(const uint8_t* data, size_t len, uint32_t seq, const void* ctx) {
    printf("Received SMTP pass (seq=%u): %.*s\n", seq, (int)len, data);
}

void* thread_main(void* arg) {
    int thread_id = (int)(intptr_t)arg;
    printf("Thread %d started\n", thread_id);

    PacketVTable vtable = {
        .l7_proto    = packet_l7_proto,
        .trans_proto = packet_trans_proto,
        .sip         = packet_sip,
        .dip         = packet_dip,
        .tu_sport    = packet_sport,
        .tu_dport    = packet_dport,
        .seq         = packet_seq,
        .syn         = packet_syn,
        .fin         = packet_fin,
        .payload_len = packet_payload_len,
        .payload     = packet_payload,
    };
    prolens_init_vtable(vtable);
    printf("after prolens_init_vtable\n");
    
    // 每个线程有自己的prolens实例
    FfiProlens *prolens = prolens_new();
    if (!prolens) {
        printf("Thread %d: Failed to create prolens\n", thread_id);
        return NULL;
    }

    // 设置SMTP回调（每个实例独立设置）
    prolens_set_cb_smtp_user(prolens, callback_smtp_user);
    prolens_set_cb_smtp_pass(prolens, callback_smtp_pass);

    // 创建任务
    Task *task = protolens_task_new(prolens, (void*)(intptr_t)thread_id);
    if (!task) {
        printf("Thread %d: Failed to create task\n", thread_id);
        prolens_free(prolens);
        return NULL;
    }

    // 设置任务回调
    prolens_set_cb_task_c2s(prolens, task, callback_task_c2s);

    // 处理数据包
    TaskResult result = protolens_task_run(prolens, task, &test_packet);
    printf("Thread %d task result: %d\n", thread_id, result);

    // 清理资源
    protolens_task_free(prolens, task);
    prolens_free(prolens);

    printf("Thread %d exited\n", thread_id);
    return NULL;
}

int main(void) {
    const int THREAD_NUM = 3;
    pthread_t threads[THREAD_NUM];

    for (int i = 0; i < THREAD_NUM; i++) {
        if (pthread_create(&threads[i], NULL, thread_main, (void*)(intptr_t)i) != 0) {
            perror("pthread_create failed");
            return 1;
        }
    }

    for (int i = 0; i < THREAD_NUM; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
