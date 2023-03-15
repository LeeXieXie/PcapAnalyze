#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <winsock.h>
#include <ws2tcpip.h>
#include <map>
#include "pcapanalyze.h"
#define MAX_PACKET_SIZE 65535 //最大数据包大小
#define MAX_PACKET_NUM 100000 //最大数据包个数
#define MAX_PACKET_LEN 100000 //最大数据包长度
#define MAX_Namelen 1024 //最大文件名长度
#define SIZE 1024

using namespace std;

int main(int argc, char *argv[]) { //argc是参数个数，argv是参数数组
    if (argc < 1) { //如果参数个数小于1，说明没有输入文件名
        std::cout << "Usage: " << argv[0] << " pcap_file" << std::endl;
        return 0;
    }
    char file_input[MAX_Namelen]; //输入的文件名
    char file_output[MAX_Namelen]; //输出的文件名
    strcpy(file_input, argv[1]); //将输入的文件名复制到file_input中
    strcpy(file_output, argv[2]); //将输入的文件名复制到file_output中

    freopen(file_output, "w", stdout); //将标准输出重定向到file_output文件中

    FILE *fp = nullptr; //定义文件指针
    FILE *output = nullptr; //定义输出文件指针
    int pkt_offset = 0; //数据包偏移量
    int pkt_num = 0; //数据包序号
    int ip_len = 0; //IP数据包长度
    int http_len = 0; //HTTP数据包长度
    int tcp_len = 0; //TCP数据包长度
    int ip_protocol = 0; //IP协议类型
    int udp_len = 0; //UDP数据包长度
    int dns_len = 0; //DNS数据包长度
    int src_port = 0; //源端口
    int dst_port = 0; //目的端口
    int tcp_flag = 0; //TCP标志位

    char standardTime[SIZE];//标准时间
    char src_ip[SIZE]; //源IP
    char dst_ip[SIZE]; //目的IP
    char src_mac[SIZE]; //源MAC
    char dst_mac[SIZE]; //目的MAC
    char http_data[SIZE]; //HTTP数据
    char dns_data[SIZE]; //DNS数据
    char tcp_data[SIZE]; //TCP数据
    char udp_data[SIZE]; //UDP数据
    char ip_data[SIZE]; //IP数据
    char ether_data[SIZE]; //以太网数据



    //定义要读取的数据包头部、以太网帧头部、IP头部、TCP头部、UDP头部、DNS头部
    struct pcap_pkthdr *pcapHeader = nullptr; //要读取的数据包头部
    struct ether_header *etherHeader = nullptr; //要读取的以太网帧头部
    struct ip_header *ipHeader = nullptr; //要读取的IP头部
    struct tcp_header *tcpHeader = nullptr; //要读取的TCP头部
    struct udp_header *udpHeader = nullptr; //要读取的UDP头部
    struct dns_header *dnsHeader = nullptr; //要读取的DNS头部

    /*
     * 初始化，分配内存
     */
    pcapHeader = (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr));
    etherHeader = (struct ether_header *) malloc(sizeof(struct ether_header));
    ipHeader = (struct ip_header *) malloc(sizeof(struct ip_header));
    tcpHeader = (struct tcp_header *) malloc(sizeof(struct tcp_header));
    udpHeader = (struct udp_header *) malloc(sizeof(struct udp_header));
    dnsHeader = (struct dns_header *) malloc(sizeof(struct dns_header));

    std::cout << "Processing!!!" << std::endl;
    if ((fp = fopen(file_input, "rb")) == NULL) { //打开文件
        std::cout << "Open '" << file_input << "' failed!!!" << std::endl;
        exit(0);
    }

    std::cout << "Reading!!!" << std::endl;
    pkt_offset = 24; // pcap文件头部长度为24
    while (fseek(fp, pkt_offset, SEEK_SET) == 0) {
        pkt_num++; //数据包序号
        memset(pcapHeader, 0, sizeof(struct pcap_pkthdr)); //清空数据包头部
        if (fread(pcapHeader, sizeof(struct pcap_pkthdr), 1, fp) != 1) { //读取数据包头部
            std::cout << "Read pcapHeader failed!!!" << std::endl;
            break;
        }
        std::cout << "Packet number: " << pkt_num << std::endl;


        pkt_offset += sizeof(struct pcap_pkthdr); //数据包头部长度为16
        pkt_offset += pcapHeader->caplen; //下一个数据包的偏移量

        //读取pcap包时间戳，转换成标准时间
        time_t time = pcapHeader->ts.tv_sec;//秒
        struct tm *p = localtime(&time);// 转换为本地时间
        strftime(standardTime, sizeof(standardTime), "%Y-%m-%d %H:%M:%S", p); //
        std::cout << "Packet time: " << standardTime << std::endl;

        std::cout << "link layer" << std::endl;
        //读取以太网帧头部
        memset(etherHeader, 0, sizeof(struct ether_header));//清空以太网帧头部
        if (fread(etherHeader, sizeof(struct ether_header), 1, fp) != 1) { //读取以太网帧头部
            std::cout << "Read etherHeader failed!!!" << std::endl;
            continue;
        }
        std::cout << "Source MAC: " << std::endl;
        for (int i = 0; i < 6; ++i) {
            if (i == 5) {
                std::cout << hex << (int) etherHeader->src_mac[i] << endl;
            } else {
                cout << std::hex << (int) etherHeader->src_mac[i] << ":";
            }
        }

        std::cout << "Destination MAC: " << std::endl;
        for (int i = 0; i < 6; ++i) {//6个字节
            if (i == 5) {//最后一个字节
                cout << hex << (int) etherHeader->dst_mac[i] << endl;
            } else {
                cout << hex << (int) etherHeader->dst_mac[i] << ":";
            }
        }
        cout << "Type: " << hex << ntohs(etherHeader->type) << endl;
        if (ntohs(etherHeader->type) != 0x0800) { //如果不是IP数据包，跳过
            cout << "Not IP packet, skip" << endl;
            continue;
        }

        cout << "network layer" << endl;
        //读取IP头部
        //IP 数据报头部长度为20字节
        memset(ipHeader, 0, sizeof(struct ip_header));//清空IP头部
        if (fread(ipHeader, sizeof(struct ip_header), 1, fp) != 1) { //读取IP头部
            std::cout << "Read ipHeader failed!!!" << std::endl;
            continue;
        }

        inet_ntop(AF_INET, &ipHeader->saddr, src_ip, sizeof(src_ip)); //源IP
        inet_ntop(AF_INET, &ipHeader->daddr, dst_ip, sizeof(dst_ip)); //目的IP
        ip_protocol = ntohs(ipHeader->protocol); //IP协议类型

        cout << "Time: " << standardTime << endl;
        cout << "Source IP: " << src_ip << endl;
        cout << "Destination IP: " << dst_ip << endl;

        ip_len = ipHeader->tot_len; //IP数据包长度

        if (ip_protocol == 6) {
            cout << "transport layer" << endl;
            //读取TCP头部
            //TCP头部长度为20字节
            memset(tcpHeader, 0, sizeof(struct tcp_header));//清空TCP头部
            if (fread(tcpHeader, sizeof(struct tcp_header), 1, fp) != 1) { //读取TCP头部
                std::cout << "Read tcpHeader failed!!!" << std::endl;
                continue;
            }
            src_port = ntohs(tcpHeader->src_port); //源端口
            dst_port = ntohs(tcpHeader->dst_port); //目的端口
            tcp_flag = tcpHeader->flag; //TCP标志位
            tcp_len = tcpHeader->len; //TCP数据包长度

            cout << "Source port: " << src_port << endl;
            cout << "Destination port: " << dst_port << endl;
            cout << "TCP flag: " << tcp_flag << endl;

            if (tcp_flag) {
                char flag_name[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
                int j = 0;
                cout << "[";
                int tmp = tcp_flag;
                while (tmp) {
                    if (tmp & 1) { //判断最后一位是否为1
                        cout << flag_name[j] << " ";
                    }
                    tmp = tmp >> 1;//右移一位
                    j++;
                }
                cout << "]" << endl;
            }

            if (tcp_flag == 24) { // 0x11000 = 24 即ACK 和 PSH 位为1
                if (dst_port == 80 || src_port == 80) {
                    cout << "Application layer" << endl;
                    //读取HTTP头部
                    //HTTP头部长度为8字节
                    http_len = tcpHeader->len - 40; //TCP头部长度为20字节，IP头部长度为20字节
                    u_int8 http_content_ascii[MAX_PACKET_LEN]; //HTTP内容
                    char http_content[MAX_PACKET_LEN]; //HTTP内容
                    memset(http_content_ascii, 0, sizeof(http_content_ascii));//清空HTTP内容
                    if (fread(http_content_ascii, http_len, 1, fp) != 1) { //读取HTTP内容
                        std::cout << "Read http_content failed!!!" << std::endl;
                        continue;
                    }

                    for (int i = 0; i < http_len; ++i) {
                        http_content[i] = char(http_content_ascii[i]);//转换为char类型
                    }

                    if (dst_port == 80) {
                        cout << "HTTP request" << endl;
                        cout << "HTTP content: " << http_content << endl;
                    } else if (src_port == 80) {
                        cout << "HTTP response" << endl;
                        cout << "HTTP content: " << http_content << endl;
                    }
                } else if (dst_port == 443) {
                    //读取TLS头部
                    u_int8 *content_type; //TLS内容类型
                    u_int8 *handshake_type; //TLS握手类型
                    u_int8 *version; //TLS版本

                    content_type = (u_int8 *) malloc(sizeof(u_int8));
                    handshake_type = (u_int8 *) malloc(sizeof(u_int8));
                    version = (u_int8 *) malloc(sizeof(u_int8));

                    fread(content_type, sizeof(u_int8), 1, fp);
                    fseek(fp, 4, SEEK_CUR);
                    fread(handshake_type, sizeof(u_int8), 1, fp);

                    if ((*content_type) == 22 && (*handshake_type) == 1) {
                        //Client Hello
                        cout << "application layer" << endl;
                        cout << "TLS Client Hello" << endl;

                        fseek(fp, 37,
                              SEEK_CUR);//跳过Content type, Version, Length, Handshake Protocol 中的 Handshake Type, Length, Version, Random, Session ID Length
                        u_int8 *session_id_length; //Session ID Length
                        session_id_length = (u_int8 *) malloc(sizeof(u_int8));
                        fread(session_id_length, sizeof(u_int8), 1, fp);
                        fseek(fp, (*session_id_length), SEEK_CUR);//跳过Session ID

                        u_int16 *cipher_suites_length; //Cipher Suites Length
                        cipher_suites_length = (u_int16 *) malloc(sizeof(u_int16));
                        fread(cipher_suites_length, sizeof(u_int16), 1, fp);

                        int cipher_suites_num = (*cipher_suites_length) / 2; //Cipher Suites 数量
                        cout << "cipher suites num: " << cipher_suites_num << endl;

                        u_int16 cipher_suites[SIZE]; //Cipher Suites
                        map<int, string> cipher_suites_map;
                        cipher_suites_map[0x00] = "TLS_NULL_WITH_NULL_NULL";
                        cipher_suites_map[0x01] = "TLS_RSA_WITH_NULL_MD5";
                        cipher_suites_map[0x02] = "TLS_RSA_WITH_NULL_SHA";
                        cipher_suites_map[0x03] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
                        cipher_suites_map[0x04] = "TLS_RSA_WITH_RC4_128_MD5";
                        cipher_suites_map[0x05] = "TLS_RSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0x06] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
                        cipher_suites_map[0x07] = "TLS_RSA_WITH_IDEA_CBC_SHA";
                        cipher_suites_map[0x08] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA";
                        cipher_suites_map[0x09] = "TLS_RSA_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x0A] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x0B] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
                        cipher_suites_map[0x0C] = "TLS_DH_DSS_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x0D] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x0E] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
                        cipher_suites_map[0x0F] = "TLS_DH_RSA_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x10] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x11] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
                        cipher_suites_map[0x12] = "TLS_DHE_DSS_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x13] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x14] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
                        cipher_suites_map[0x15] = "TLS_DHE_RSA_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x16] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x17] = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5";
                        cipher_suites_map[0x18] = "TLS_DH_anon_WITH_RC4_128_MD5";
                        cipher_suites_map[0x19] = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
                        cipher_suites_map[0x1A] = "TLS_DH_anon_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x1B] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x1C] = "TLS_KRB5_WITH_DES_CBC_SHA";
                        cipher_suites_map[0x1D] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x1E] = "TLS_KRB5_WITH_RC4_128_SHA";
                        cipher_suites_map[0x1F] = "TLS_KRB5_WITH_IDEA_CBC_SHA";
                        cipher_suites_map[0x20] = "TLS_KRB5_WITH_DES_CBC_MD5";
                        cipher_suites_map[0x21] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5";
                        cipher_suites_map[0x22] = "TLS_KRB5_WITH_RC4_128_MD5";
                        cipher_suites_map[0x23] = "TLS_KRB5_WITH_IDEA_CBC_MD5";
                        cipher_suites_map[0x24] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA";
                        cipher_suites_map[0x25] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA";
                        cipher_suites_map[0x26] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA";
                        cipher_suites_map[0x27] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5";
                        cipher_suites_map[0x28] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5";
                        cipher_suites_map[0x29] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5";
                        cipher_suites_map[0x2A] = "TLS_PSK_WITH_NULL_SHA";
                        cipher_suites_map[0x2B] = "TLS_DHE_PSK_WITH_NULL_SHA";
                        cipher_suites_map[0x2C] = "TLS_RSA_PSK_WITH_NULL_SHA";
                        cipher_suites_map[0x2D] = "TLS_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x2E] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x2F] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x30] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x31] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x32] = "TLS_DH_anon_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x33] = "TLS_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x34] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x35] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x36] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x37] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x38] = "TLS_DH_anon_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x39] = "TLS_RSA_WITH_NULL_SHA256";
                        cipher_suites_map[0x3A] = "TLS_RSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x3B] = "TLS_RSA_WITH_AES_256_CBC_SHA256";
                        cipher_suites_map[0x3C] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x3D] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x3E] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x3F] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
                        cipher_suites_map[0x40] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
                        cipher_suites_map[0x41] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
                        cipher_suites_map[0x42] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
                        cipher_suites_map[0x43] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
                        cipher_suites_map[0x44] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA";
                        cipher_suites_map[0x45] = "TLS_ECDH_ECDSA_WITH_NULL_SHA";
                        cipher_suites_map[0x46] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0x47] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x48] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x49] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x4A] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
                        cipher_suites_map[0x4B] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0x4C] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x4D] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x4E] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x4F] = "TLS_ECDH_RSA_WITH_NULL_SHA";
                        cipher_suites_map[0x50] = "TLS_ECDH_RSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0x51] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x52] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x53] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x54] = "TLS_ECDHE_RSA_WITH_NULL_SHA";
                        cipher_suites_map[0x55] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0x56] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x57] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x58] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x59] = "TLS_ECDH_anon_WITH_NULL_SHA";
                        cipher_suites_map[0x5A] = "TLS_ECDH_anon_WITH_RC4_128_SHA";
                        cipher_suites_map[0x5B] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x5C] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x5D] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x5E] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x5F] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x60] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x61] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x62] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x63] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x64] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x65] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x66] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x67] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x68] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0x69] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x6A] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0x6B] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x6C] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0x6D] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x6E] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0x6F] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0x70] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0x71] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0x72] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0x73] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0x74] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0x75] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0x76] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0x77] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
                        cipher_suites_map[0x78] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0x79] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0x7A] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0x7B] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0x7C] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0x7D] = "TLS_ECDHE_PSK_WITH_NULL_SHA";
                        cipher_suites_map[0x7E] = "TLS_ECDHE_PSK_WITH_NULL_SHA256";
                        cipher_suites_map[0x7F] = "TLS_ECDHE_PSK_WITH_NULL_SHA384";
                        cipher_suites_map[0x80] = "TLS_RSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x81] = "TLS_RSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x82] = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x83] = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x84] = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x85] = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x86] = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x87] = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x88] = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x89] = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x8A] = "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x8B] = "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x8C] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x8D] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x8E] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x8F] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x90] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x91] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x92] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0x93] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0x94] = "TLS_RSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0x95] = "TLS_RSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0x96] = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0x97] = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0x98] = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0x99] = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0x9A] = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0x9B] = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0x9C] = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0x9D] = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0x9E] = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0x9F] = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xA0] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xA1] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xA2] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xA3] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xA4] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xA5] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xA6] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xA7] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xA8] = "TLS_PSK_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0xA9] = "TLS_PSK_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0xAA] = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0xAB] = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0xAC] = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0xAD] = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0xAE] = "TLS_PSK_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xAF] = "TLS_PSK_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xB0] = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xB1] = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xB2] = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256";
                        cipher_suites_map[0xB3] = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384";
                        cipher_suites_map[0xB4] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256";
                        cipher_suites_map[0xB5] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384";
                        cipher_suites_map[0xB6] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xB7] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xB8] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xB9] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xBA] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xBB] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xBC] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xBD] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xBE] = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xBF] = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xC0] = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xC1] = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xC2] = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xC3] = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xC4] = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xC5] = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xC6] = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xC7] = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xC8] = "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xC9] = "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xCA] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xCB] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xCC] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xCD] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xCE] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xCF] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xD0] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xD1] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xD2] = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xD3] = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xD4] = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xD5] = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xD6] = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256";
                        cipher_suites_map[0xD7] = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384";
                        cipher_suites_map[0xD8] = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xD9] = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xDA] = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xDB] = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xDC] = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xDD] = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xDE] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
                        cipher_suites_map[0xDF] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
                        cipher_suites_map[0xE0] = "TLS_RSA_WITH_AES_128_CCM";
                        cipher_suites_map[0xE1] = "TLS_RSA_WITH_AES_256_CCM";
                        cipher_suites_map[0xE2] = "TLS_DHE_RSA_WITH_AES_128_CCM";
                        cipher_suites_map[0xE3] = "TLS_DHE_RSA_WITH_AES_256_CCM";
                        cipher_suites_map[0xE4] = "TLS_RSA_WITH_AES_128_CCM_8";
                        cipher_suites_map[0xE5] = "TLS_RSA_WITH_AES_256_CCM_8";
                        cipher_suites_map[0xE6] = "TLS_DHE_RSA_WITH_AES_128_CCM_8";
                        cipher_suites_map[0xE7] = "TLS_DHE_RSA_WITH_AES_256_CCM_8";
                        cipher_suites_map[0xE8] = "TLS_PSK_WITH_AES_128_CCM";
                        cipher_suites_map[0xE9] = "TLS_PSK_WITH_AES_256_CCM";
                        cipher_suites_map[0xEA] = "TLS_DHE_PSK_WITH_AES_128_CCM";
                        cipher_suites_map[0xEB] = "TLS_DHE_PSK_WITH_AES_256_CCM";
                        cipher_suites_map[0xEC] = "TLS_PSK_WITH_AES_128_CCM_8";
                        cipher_suites_map[0xED] = "TLS_PSK_WITH_AES_256_CCM_8";
                        cipher_suites_map[0xEE] = "TLS_PSK_DHE_WITH_AES_128_CCM_8";
                        cipher_suites_map[0xEF] = "TLS_PSK_DHE_WITH_AES_256_CCM_8";
                        cipher_suites_map[0xF0] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
                        cipher_suites_map[0xF1] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM";
                        cipher_suites_map[0xF2] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8";
                        cipher_suites_map[0xF3] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8";
                        cipher_suites_map[0xFE] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
                        cipher_suites_map[0xFF] = "TLS_FALLBACK_SCSV";
                        cipher_suites_map[0x1301] = "TLS_AES_128_GCM_SHA256";
                        cipher_suites_map[0x1302] = "TLS_AES_256_GCM_SHA384";
                        cipher_suites_map[0x1303] = "TLS_CHACHA20_POLY1305_SHA256";
                        cipher_suites_map[0x1304] = "TLS_AES_128_CCM_SHA256";
                        cipher_suites_map[0x1305] = "TLS_AES_128_CCM_8_SHA256";
                        cipher_suites_map[0x5600] = "TLS_FALLBACK_SCSV";
                        cipher_suites_map[0xC001] = "TLS_ECDH_ECDSA_WITH_NULL_SHA";
                        cipher_suites_map[0xC002] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0xC003] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC004] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC005] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC006] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
                        cipher_suites_map[0xC007] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0xC008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC00A] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC00B] = "TLS_ECDH_RSA_WITH_NULL_SHA";
                        cipher_suites_map[0xC00C] = "TLS_ECDH_RSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0xC00D] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC00E] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC00F] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC010] = "TLS_ECDHE_RSA_WITH_NULL_SHA";
                        cipher_suites_map[0xC011] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
                        cipher_suites_map[0xC012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";


                        memset(cipher_suites, 0, sizeof(cipher_suites));//清空Cipher Suites
                        if (fread(cipher_suites, sizeof(u_int16), cipher_suites_num, fp) !=
                            cipher_suites_num) { //读取Cipher Suites
                            std::cout << "Read cipher_suites failed!!!" << std::endl;
                            continue;
                        }
                        for (int i = 0; i < cipher_suites_num; i++) {
                            cipher_suites[i] = ntohs(cipher_suites[i]);
                            if (cipher_suites[i] > 0) {

                                cout << "cipher suites: " << cipher_suites_map[i] << "(" << hex << cipher_suites[i]
                                     << ")" << endl;
                            }
                        }
                        u_int8 *compression_methods_length;
                        compression_methods_length = (u_int8 *) malloc(sizeof(u_int8));
                        fread(compression_methods_length, sizeof(u_int8), 1, fp);

                        fseek(fp, *compression_methods_length, SEEK_CUR);

                        u_int16 *extensions_length;
                        u_int16 *extension_type;
                        extension_type = (u_int16 *) malloc(sizeof(u_int16));
                        extensions_length = (u_int16 *) malloc(sizeof(u_int16));
                        while (::fread(extension_type, sizeof(u_int16), 1, fp) == 1) {
                            ::fread(extensions_length, sizeof(u_int16), 1, fp);
                            *extension_type = ntohs(*extension_type);
                            *extensions_length = ntohs(*extensions_length);
                            if (*extension_type == 0) {
                                u_int16 *elliptic_curves_length;
                                elliptic_curves_length = (u_int16 *) malloc(sizeof(u_int16));
                                ::fread(elliptic_curves_length, sizeof(u_int16), 1, fp);
                                *elliptic_curves_length = ntohs(*elliptic_curves_length);
                                u_int16 *elliptic_curves;
                                elliptic_curves = (u_int16 *) malloc(sizeof(u_int16) * (*elliptic_curves_length / 2));
                                ::fread(elliptic_curves, sizeof(u_int16), *elliptic_curves_length / 2, fp);
                                for (int i = 0; i < *elliptic_curves_length / 2; i++) {
                                    elliptic_curves[i] = ntohs(elliptic_curves[i]);
                                    cout << "elliptic_curves: " << elliptic_curves[i] << endl;
                                }
                                u_int8 *elliptic_curves_point_format_length;
                                elliptic_curves_point_format_length = (u_int8 *) malloc(sizeof(u_int8));
                                ::fread(elliptic_curves_point_format_length, sizeof(u_int8), 1, fp);
                                u_int8 *elliptic_curves_point_format;
                                elliptic_curves_point_format = (u_int8 *) malloc(
                                        sizeof(u_int8) * (*elliptic_curves_point_format_length));
                                ::fread(elliptic_curves_point_format, sizeof(u_int8),
                                        *elliptic_curves_point_format_length, fp);
                                for (int i = 0; i < *elliptic_curves_point_format_length; i++) {
                                    cout << "elliptic_curves_point_format: " << elliptic_curves_point_format[i] << endl;
                                }
                            } else {
                                fseek(fp, *extensions_length, SEEK_CUR);
                            }
                        }
                    }
                }


            }

            std::cout << "Finished!!!" << std::endl;
            return 0;
        }
    }
}