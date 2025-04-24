#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "../protolens/dist/protolens.h"

#define SMTP_PCAP "../protolens/tests/pcap/smtp.pcap"

typedef struct {
    uint32_t       seq;
    uint32_t       sip;
    uint32_t       dip;
    uint16_t       sport;
    uint16_t       dport;
    const uint8_t *payload;
    size_t         payload_len;

    TransProto l4_proto;
    L7Proto    l7_proto;    
} PcapPacket;

CIpAddr packet_sip(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
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
    PcapPacket *pkt = (PcapPacket*)packet;
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

TransProto packet_trans_proto(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
    return pkt->l4_proto; 
}

uint16_t packet_sport(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
    return pkt->sport;
}

uint16_t packet_dport(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
    return pkt->dport;
}

uint32_t packet_seq(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
    return pkt->seq;
}

bool packet_syn(void* packet) {
    return false;
}

bool packet_fin(void* packet) {
    return false;
}

size_t packet_payload_len(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
    return pkt->payload_len;
}

const uint8_t* packet_payload(void* packet) {
    PcapPacket *pkt = (PcapPacket*)packet;
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

int is_smtp_packet(const u_char *pkt, struct tcphdr *tcp) {
    return ntohs(tcp->th_dport) == 25 || ntohs(tcp->th_sport) == 25;
}

struct user_data {
    FfiProlens *prolens;
    Task       *task;
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip        *ip_header;
    struct tcphdr    *tcp_header;
    PcapPacket        pcap_packet;
    struct user_data *prolens_task = (struct user_data *)user_data;
    
    // 跳过以太网头
    ip_header = (struct ip *)(packet + 14);
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    // 获取TCP头
    tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
    if (!is_smtp_packet(packet, tcp_header)) {
        return;
    }

    // 获取负载
    int           ip_len      = ip_header->ip_hl * 4;
    int           tcp_len     = tcp_header->th_off * 4;
    const u_char *payload     = (u_char *)ip_header + ip_len + tcp_len;
    int           payload_len = ntohs(ip_header->ip_len) - ip_len - tcp_len;

    // 填充数据包结构
    pcap_packet.seq         = ntohl(tcp_header->th_seq);
    pcap_packet.sip         = ntohl(ip_header->ip_src.s_addr);
    pcap_packet.dip         = ntohl(ip_header->ip_dst.s_addr);
    pcap_packet.sport       = ntohs(tcp_header->th_sport);
    pcap_packet.dport       = ntohs(tcp_header->th_dport);
    pcap_packet.payload     = payload;
    pcap_packet.payload_len = payload_len;
    pcap_packet.l4_proto    = TCP;
    pcap_packet.l7_proto    = SMTP;

    TaskResult result = protolens_task_run(prolens_task->prolens, prolens_task->task, &pcap_packet);
    printf("Task result: %d\n", result);
}

int main(void) {
    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 创建 Prolens 实例
    FfiProlens *prolens = protolens_new();
    if (!prolens) {
        printf("Failed to create prolens instance\n");
        return 1;
    }

    // 打开pcap文件
    handle = pcap_open_offline(SMTP_PCAP, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", SMTP_PCAP, errbuf);
        return 1;
    }

    // 设置 vtable
    PacketVTable vtable = {
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
    protolens_init_vtable(vtable);

    // 设置 SMTP 回调
    protolens_set_cb_smtp_user(prolens, callback_smtp_user);
    protolens_set_cb_smtp_pass(prolens, callback_smtp_pass);

    // 创建任务,以为pcap文件中只有一个链接，所以只建立一个task
    Task *task = protolens_task_new(prolens, TCP, (void *)0x1234);
    if (!task) {
        printf("Failed to create task\n");
        protolens_free(prolens);
        return 1;
    }
    protolens_set_task_parser(prolens, task, SMTP);

    /* 设置task 流回调 */
    protolens_set_cb_task_c2s(prolens, callback_task_c2s);

    struct user_data user_data = {
        .prolens = prolens,
        .task    = task,
    };
    
    // 处理数据包
    pcap_loop(handle, 0, packet_handler, (u_char*)&user_data);

    // 清理资源
    protolens_task_free(prolens, task);
    protolens_free(prolens);
    return 0;
}
