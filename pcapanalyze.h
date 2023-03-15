//
// Created by LeeXieXie on 2023/3/15.
//

#ifndef PCAPANALYZE_PCAPANALYZE_H
#define PCAPANALYZE_PCAPANALYZE_H
#include <cstdlib>
#include <cstdint>

typedef int32_t bpf_int32;
typedef uint32_t bpf_u_int32;
typedef uint16_t u_short;
typedef uint32_t u_int32;
typedef uint16_t u_int16;
typedef uint8_t u_int8;

/*
 * pcap文件头部
 * magic number(4B): 0xa1b2c3d4 (little endian); 0xd4c3b2a1 (big endian)
 * version_major(2B): 0x0200
 * version_minor(2B): 0x0400
 * thiszone(4B): 0x00000000 (GMT to local correction); 0x00000001 (GMT to local correction);
 * sigfigs(4B): 0x00000000 (accuracy of timestamps)
 * snaplen(4B): 0x0000ffff (max length saved portion of each pkt)
 * linktype(4B): 0x00000001 (LINKTYPE_ETHERNET); 0x00000006 (LINKTYPE_802_11); 0x00000007 (LINKTYPE_802_11_RADIO)
 */
struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major; //主版本号
    u_short version_minor; //次版本号
    bpf_int32 thiszone; //GMT to local correction
    bpf_u_int32 sigfigs; //accuracy of timestamps
    bpf_u_int32 snaplen; //max length saved portion of each pkt
    bpf_u_int32 linktype; //data link type (LINKTYPE_*)
};
//时间戳
struct timestamp {
    bpf_int32 tv_sec; //seconds
    bpf_int32 tv_usec; //microseconds
} timestamp;
/*
 * pcap数据包头部
 * ts_sec(4B): 0x00000000 (timestamp seconds)
 * ts_usec(4B): 0x00000000 (timestamp microseconds)
 * incl_len(4B): 0x00000000 (number of octets of packet saved in file)
 * orig_len(4B): 0x00000000 (actual length of packet)
 */
struct pcap_pkthdr {
    struct timestamp ts; //time stamp
    bpf_u_int32 caplen; //length of portion present
    bpf_u_int32 len; //length this packet (off wire)
};

/*
 * 以太网帧头部
 * dst_mac(6B): 0x000000000000 (destination mac address)
 * src_mac(6B): 0x000000000000 (source mac address)
 * type(2B): 0x0008 (type of the next level protocol)
 */

struct ether_header {
    u_int8 dst_mac[6]; //目的MAC地址
    u_int8 src_mac[6]; //源MAC地址
    u_int16 type;//上层协议类型
}etherHeader;

/*
 * IP头部
 * version(1B): 0x45 (version and header length)
 * tos(1B): 0x00 (type of service)
 * tot_len(2B): 0x0028 (total length)
 * id(2B): 0x0000 (identification)
 * frag_off(2B): 0x0000 (fragment offset field)
 * ttl(1B): 0x40 (time to live)
 * protocol(1B): 0x06 (protocol)
 * check(2B): 0x0000 (checksum)
 * saddr(4B): 0x00000000 (source address)
 * daddr(4B): 0x00000000 (destination address)
 */

struct ip_header {
    u_int8 version; //版本
    u_int8 tos; //服务类型
    u_int16 tot_len; //总长度
    u_int16 id; //标识
    u_int16 frag_off; //标志位
    u_int8 ttl; //生存时间
    u_int8 protocol; //协议类型
    u_int16 check; //校验和
    u_int32 saddr; //源IP地址
    u_int32 daddr; //目的IP地址
}ipHeader;

/*
 * TCP头部
 * src_port(2B): 0x0000 (source port)
 * dst_port(2B): 0x0000 (destination port)
 * seq(4B): 0x00000000 (sequence number)
 * ack_seq(4B): 0x00000000 (acknowledgement number)
 * doff(1B): 0x50 (data offset)
 * fin(1B): 0x00 (FIN control flag)
 * syn(1B): 0x00 (SYN control flag)
 * rst(1B): 0x00 (RST control flag)
 * psh(1B): 0x00 (PSH control flag)
 * ack(1B): 0x00 (ACK control flag)
 * urg(1B): 0x00 (URG control flag)
 * window(2B): 0x0000 (window)
 * check(2B): 0x0000 (checksum)
 * urg_ptr(2B): 0x0000 (urgent pointer)
 */

struct tcp_header {
    u_int16 src_port; //源端口
    u_int16 dst_port; //目的端口
    u_int32 seq; //序列号
    u_int32 ack_seq; //确认号
    u_int8 doff; //数据偏移
    u_int8 fin; //FIN标志
    u_int8 syn; //SYN标志
    u_int8 rst; //RST标志
    u_int8 psh; //PSH标志
    u_int8 ack; //ACK标志
    u_int8 urg; //URG标志
    u_int16 window; //窗口大小
    u_int16 check; //校验和
    u_int16 urg_ptr; //紧急指针
}tcpHeader;

/*
 * UDP头部
 * src_port(2B): 0x0000 (source port)
 * dst_port(2B): 0x0000 (destination port)
 * len(2B): 0x0000 (length)
 * check(2B): 0x0000 (checksum)
 */

struct udp_header {
    u_int16 src_port; //源端口
    u_int16 dst_port; //目的端口
    u_int16 len; //长度
    u_int16 check; //校验和
}udpHeader;

/*
 * ICMP头部
 * type(1B): 0x00 (type)
 * code(1B): 0x00 (code)
 * check(2B): 0x0000 (checksum)
 * id(2B): 0x0000 (identifier)
 * seq(2B): 0x0000 (sequence number)
 */
struct icmp_header {
    u_int8 type; //类型
    u_int8 code; //代码
    u_int16 check; //校验和
    u_int16 id; //标识符
    u_int16 seq; //序列号
}icmpHeader;

/*
 * IGMP头部
 * type(1B): 0x00 (type)
 * max_resp_time(1B): 0x00 (maximum response time)
 * check(2B): 0x0000 (checksum)
 * group(4B): 0x00000000 (group address being reported)
 */

struct  igmp_header {
    u_int8 type; //类型
    u_int8 max_resp_time; //最大响应时间
    u_int16 check; //校验和
    u_int32 group; //组地址
}igmpHeader;

/*
 * ARP头部
 * htype(2B): 0x0000 (hardware type)
 * ptype(2B): 0x0000 (protocol type)
 * hlen(1B): 0x00 (hardware address length)
 * plen(1B): 0x00 (protocol address length)
 * oper(2B): 0x0000 (operation)
 * sha(6B): 0x000000000000 (sender hardware address)
 * spa(4B): 0x00000000 (sender protocol address)
 * tha(6B): 0x000000000000 (target hardware address)
 * tpa(4B): 0x00000000 (target protocol address)
 */

struct arp_header {
    u_int16 htype; //硬件类型
    u_int16 ptype; //协议类型
    u_int8 hlen; //硬件地址长度
    u_int8 plen; //协议地址长度
    u_int16 oper; //操作
    u_int8 sha[6]; //发送方硬件地址
    u_int32 spa; //发送方协议地址
    u_int8 tha[6]; //目的方硬件地址
    u_int32 tpa; //目的方协议地址
}arpHeader;

/*
 * DNS头部
 * id(2B): 0x0000 (identification number)
 * flags(2B): 0x0000 (flags)
 * qdcount(2B): 0x0000 (number of question entries)
 * ancount(2B): 0x0000 (number of answer entries)
 * nscount(2B): 0x0000 (number of authority entries)
 * arcount(2B): 0x0000 (number of resource entries)
 */
struct dns_header {
    u_int16 id; //标识
    u_int16 flags; //标志
    u_int16 qdcount; //问题数
    u_int16 ancount; //回答数
    u_int16 nscount; //授权数
    u_int16 arcount; //附加数
}dnsHeader;

/* DNS查询结构体 */
struct dns_query {
    u_int16 qtype; //查询类型
    u_int16 qclass; //查询类
}dnsQuery;

/* DNS回答结构体 */
struct dns_answer {
    u_int16 type; //回答类型
    u_int16 classanswer; //回答类
    u_int32 ttl; //生存时间
    u_int16 data_len; //数据长度
}dnsAnswer;

/* DNS资源记录结构体 */
struct dns_rr {
    u_int16 type; //资源记录类型
    u_int16 classrr; //资源记录类
    u_int32 ttl; //生存时间
    u_int16 data_len; //数据长度
}dnsRR;

/* DNS压缩结构体 */
struct dns_compression {
    u_int16 offset; //偏移量
}dnsCompression;

#endif //PCAPANALYZE_PCAPANALYZE_H
