#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../dist/protolens.h"

#define SMTP_PCAP "../tests/res/smtp.pcap"

typedef struct {
    uint32_t seq;
    uint16_t sport;
    uint16_t dport;
    const uint8_t *payload;
    size_t payload_len;
} PcapPacket;

TransProto packet_trans_proto(void* packet) {
    return Tcp;
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

static PacketVTable vtable;

void callback_smtp_user(const char* username) {
    printf("Found SMTP username: %s\n", username);
}

int is_smtp_packet(const u_char *pkt, struct tcphdr *tcp) {
    return ntohs(tcp->th_dport) == 25 || ntohs(tcp->th_sport) == 25;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
    Task          *task = (Task *)user_data;
    struct ip     *ip_header;
    struct tcphdr *tcp_header;
    PcapPacket     pcap_packet;

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
    pcap_packet.sport       = ntohs(tcp_header->th_sport);
    pcap_packet.dport       = ntohs(tcp_header->th_dport);
    pcap_packet.payload     = payload;
    pcap_packet.payload_len = payload_len;

    // 确定数据包方向
    PktDirection dir =
        (pcap_packet.dport == 25) ? Client2Server : Server2Client;

    // 处理数据包
    task_run(task, &pcap_packet, &vtable, dir, pkthdr->ts.tv_sec * 1000);
}

int main(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // 打开pcap文件
    handle = pcap_open_offline(SMTP_PCAP, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open pcap file %s: %s\n", SMTP_PCAP, errbuf);
        return 1;
    }

    // 设置pkt的vtabe, 不需要每个线程，每个task都设置
    vtable.trans_proto = packet_trans_proto;
    vtable.tu_sport    = packet_sport,
    vtable.tu_dport    = packet_dport,
    vtable.seq         = packet_seq,
    vtable.syn         = packet_syn,
    vtable.fin         = packet_fin,
    vtable.payload_len = packet_payload_len,
    vtable.payload     = packet_payload,
    
    // 设置SMTP回调, 不需要每个线程，每个task都设置
    task_set_smtp_user_callback(callback_smtp_user);

    // 创建任务
    Task *task = task_new_with_parser(Smtp);
    if (!task) {
        fprintf(stderr, "Failed to create task\n");
        pcap_close(handle);
        return 1;
    }

    // 处理数据包
    pcap_loop(handle, 0, packet_handler, (u_char*)task);

    // 清理
    task_free(task);
    pcap_close(handle);
    return 0;
}
