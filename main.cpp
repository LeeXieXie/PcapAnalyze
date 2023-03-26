#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <cmath>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bitset>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <map>
#include "pcapanalyze.h"
#define MAX_PACKET_SIZE 65535 //最大数据包大小
#define MAX_PACKET_NUM 100000 //最大数据包个数
#define MAX_PACKET_LEN 100000 //最大数据包长度
#define MAX_Namelen 1024 //最大文件名长度
#define SIZE 1024

using namespace std;



//int main(int argc, char *argv[]) { //argc是参数个数，argv是参数数组
//    if (argc < 1) { //如果参数个数小于1，说明没有输入文件名
//        cout << "Usage: " << argv[0] << " pcap_file" << endl;
//        return 0;
//    }
//    char file_input[MAX_Namelen]; //输入的文件名
//    char file_output[MAX_Namelen]; //输出的文件名
//    strcpy(file_input, argv[1]); //将输入的文件名复制到file_input中
//    strcpy(file_output, argv[2]); //将输入的文件名复制到file_output中
//    freopen(file_output, "w", stdout); //将标准输出重定向到file_output文件中
int main(){ //debug

    char file_input[] = "C:\\VScodeGit\\PcapAnalyze\\10.pcap";




    FILE *fp; //定义文件指针
    FILE *output; //定义输出文件指针
    int pkt_offset = 0; //数据包偏移量
    int pkt_num = 0; //数据包序号
    int ip_len = 0; //IPv4数据包长度
    int http_len = 0; //HTTP数据包长度
    int tcp_len = 0; //TCP数据包长度
    int ip_protocol = 0; //IP协议类型
    int udp_len = 0; //UDP数据包长度
    int dns_len = 0; //DNS数据包长度
    int src_port = 0; //源端口
    int dst_port = 0; //目的端口
    int tcp_flag = 0; //TCP标志位

    char standardTime[SIZE];//标准时间
    char src_ip[32]; //源IP
    char dst_ip[32]; //目的IP
    u_int8 src_mac[6]; //源MAC
    u_int8 dst_mac[6]; //目的MAC
    char http_data[SIZE]; //HTTP数据
    char dns_data[SIZE]; //DNS数据
    char tcp_data[SIZE]; //TCP数据
    char udp_data[SIZE]; //UDP数据
    char ip_data[SIZE]; //IPv4数据
    char ether_data[SIZE]; //以太网数据



    //定义要读取的数据包头部、以太网帧头部、IP头部、TCP头部、UDP头部、DNS头部
    struct pcap_pkthdr *pcapHeader = (struct pcap_pkthdr *)malloc(sizeof(pcap_pkthdr)); //要读取的数据包头部
    struct ether_header *etherHeader = (struct ether_header *)malloc(sizeof(ether_header)); //要读取的以太网帧头部
    struct ip_header *ipHeader = (struct ip_header *)malloc(sizeof(ip_header)); //要读取的IPv4头部
    struct tcp_header *tcpHeader = (struct tcp_header *)malloc(sizeof(tcp_header)); //要读取的TCP头部
    struct udp_header *udpHeader = (struct udp_header *)malloc(sizeof(udp_header)); //要读取的UDP头部
    struct dns_header *dnsHeader = (struct dns_header *)malloc(sizeof(dns_header)); //要读取的DNS头部

//    struct ether_header *etherHeader; //要读取的以太网帧头部
//    struct ip_header *ipHeader; //要读取的IPv4头部
//    struct tcp_header *tcpHeader; //要读取的TCP头部
//    struct udp_header *udpHeader; //要读取的UDP头部
//    struct dns_header *dnsHeader; //要读取的DNS头部
//
//    /*
//     * 初始化，分配内存
//     */
//    pcapHeader = (struct pcap_pkthdr *) malloc(sizeof(pcap_pkthdr));
//    etherHeader = (struct ether_header *) malloc(sizeof(ether_header));
//    ipHeader = (ip_header *) malloc(sizeof(ip_header));
//    cout << sizeof(ip_header) << endl;
//    tcpHeader = (struct tcp_header *) malloc(sizeof(tcp_header));
//    udpHeader = (struct udp_header *) malloc(sizeof(udp_header));
//    dnsHeader = (struct dns_header *) malloc(sizeof(dns_header));
    cout << "Processing!!!" << endl;
    if ((fp = fopen(file_input, "rb")) == NULL) { //打开文件
        cout << "Open '" << file_input << "' failed!!!" << endl;
        exit(0);
    }
    cout << "Reading!!!" << endl;
    pkt_offset = 24; // pcap文件头部长度为24
    while (fseek(fp, pkt_offset, SEEK_SET) == 0) {
        pkt_num++; //数据包序号
        memset(pcapHeader, 0, sizeof(pcap_pkthdr)); //清空数据包头部
        if (fread(pcapHeader, 16, 1, fp) != 1) { //读取数据包头部
            cout << "Read end of " << file_input << endl;
            break;
        }
        cout << "----------------------------------------" << endl;
        cout << "Packet No. " << dec << pkt_num << endl;


        pkt_offset += 16 + pcapHeader->caplen; //下一个数据包的偏移量

        //读取pcap包时间戳，转换成标准时间
        time_t time = pcapHeader->ts.tv_sec;//秒
        struct tm *p = localtime(&time);// 转换为本地时间
        strftime(standardTime, sizeof(standardTime), "%Y-%m-%d %H:%M:%S", p); //
        cout << "Packet time: " << standardTime << endl;
        cout << "----------------------------------------" << endl;
        cout << "link layer" << endl;
        //读取以太网帧头部
//        cout << ftell(fp) << endl ;

        memset(etherHeader, 0, sizeof(ether_header));//清空以太网帧头部
        if (fread(etherHeader, sizeof(ether_header) + 2, 1, fp) != 1) { //读取以太网帧头部
            cout << "Read etherHeader failed!!!" << endl;
            continue;
        }
        cout << "Source MAC: ";
        for (int i = 0; i < 6; ++i) {
            if (i == 5) {
                cout << hex << (int) etherHeader->src_mac[i] << endl;
            } else {
                cout << hex << (int) etherHeader->src_mac[i] << ":";
            }
        }


        cout << "Destination MAC: ";
        for (int i = 0; i < 6; ++i) {//6个字节
            if (i == 5) {//最后一个字节
                cout << hex << (int) etherHeader->dst_mac[i] << endl;
            } else {
                cout << hex << (int) etherHeader->dst_mac[i] << ":";
            }
        }

        cout << "Type: " << hex << ntohs(etherHeader->type);

        if (ntohs(etherHeader->type) == 0x800){
            cout << "(IPv4)" << endl;
        }
        else if (ntohs(etherHeader->type) == 0x86dd){
            cout << "(IPv6)" << endl;
        }else{
            cout << "(Unknown)" << endl;
        }

        cout << "----------------------------------------" << endl;
        cout << "network layer" << endl;
        //读取IP头部
        //IP数据报头部长度为20字节
        //fpos_t fpos; //debug
        //fgetpos(fp, &fpos);//debug
        fseek(fp,-2,SEEK_CUR);//debug
        //fgetpos(fp, &fpos);//debug
        memset(ipHeader, 0, 20);//清空IP头部
        if (fread(ipHeader, 20, 1, fp) != 1) { //读取IP头部
            cout << "Read ipHeader failed!!!" << endl;
            continue;
        }
        //fgetpos(fp, &fpos); //debug
//        cout << "Version: " << dec << (int) ipHeader->version << endl; //debug
//        cout << "Protocol: " << dec << (int) ipHeader->protocol << endl; //debug
//        printf("%X\n",ipHeader->version); //debug
        if (ntohs(etherHeader->type) == 0x800){
            inet_ntop(AF_INET, (void *)&(ipHeader->saddr), src_ip, INET_ADDRSTRLEN); //源IP
            inet_ntop(AF_INET, (void *)&(ipHeader->daddr), dst_ip, INET_ADDRSTRLEN); //目的IP
        }else if (ntohs(etherHeader->type) == 0x86dd){
            inet_ntop(AF_INET6, (void *)&(ipHeader->saddr), src_ip, INET6_ADDRSTRLEN); //源IP
            inet_ntop(AF_INET6, (void *)&(ipHeader->daddr), dst_ip, INET6_ADDRSTRLEN); //目的IP
        }

        ip_protocol = ipHeader->protocol; //IP协议类型

        cout << "Time: " << standardTime << endl;
        cout << "Source IP: " << src_ip << endl;
        cout << "Destination IP: " << dst_ip << endl;

        ip_len = ntohs(ipHeader->tot_len); //IP数据包长度

        if (ip_protocol == 6) {
            cout << "----------------------------------------" << endl;
            cout << "transport layer" << endl;
            cout << "TCP" << endl;
            //读取TCP头部
            //TCP头部长度为20字节
            fpos_t fpos;
            fgetpos(fp, &fpos);
            memset(tcpHeader, 0, sizeof(tcp_header));
            if (fread(tcpHeader, sizeof(tcp_header), 1, fp) != 1) { //读取TCP头部
                cout << "Read tcpHeader failed!!!" << endl;
                continue;
            }
            fgetpos(fp, &fpos);
            src_port = ntohs(tcpHeader->src_port); //源端口
            dst_port = ntohs(tcpHeader->dst_port); //目的端口
            tcp_flag = tcpHeader->flag; //TCP标志位

            cout << "Source port: " << dec << src_port << endl;
            cout << "Destination port: " << dec << dst_port << endl;
            cout << "TCP flag: " << hex << tcp_flag << endl;

            if (tcp_flag) {
                char flag_name[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
                int j = 0;
                cout << "[";
                int tmp = tcp_flag;
                while (tmp) {
                    if (tmp & 1) { //判断最后一位是否为1
                        cout << flag_name[j] << ",";
                    }
                    tmp = tmp >> 1;//右移一位
                    j++;
                }
                cout << "]" << endl;
            }
            if (tcp_flag == 0x18) { // 0x11000 = 24 即ACK 和 PSH 位为1
                if (dst_port == 0x50 || src_port == 0x50) {
                    cout << "----------------------------------------" << endl;
                    cout << "Application layer" << endl;
                    //读取HTTP头部
                    //HTTP头部长度为8字节
                    http_len = tcpHeader->len - 40; //TCP头部长度为20字节，IP头部长度为20字节
                    u_int8 http_content_ascii[MAX_PACKET_LEN]; //HTTP内容
                    char http_content[MAX_PACKET_LEN]; //HTTP内容
                    memset(http_content_ascii, 0, sizeof(u_int8));//清空HTTP内容
                    if (fread(http_content_ascii, sizeof(u_int8 ), http_len, fp) != http_len) { //读取HTTP内容
                        cout << "Read http_content failed!!!" << endl;
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
                        cout << "----------------------------------------" << endl;
                        cout << "application layer" << endl;
                        cout << "TLS Client Hello" << endl;

                        fseek(fp, 37,SEEK_CUR);//跳过Content type, Version, Length, Handshake Protocol 中的 Handshake Type, Length, Version, Random, Session ID Length
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
                        cipher_suites_map[0xC015] = "TLS_ECDH_anon_WITH_NULL_SHA";
                        cipher_suites_map[0xC016] = "TLS_ECDH_anon_WITH_RC4_128_SHA";
                        cipher_suites_map[0xC017] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC018] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC019] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC01A] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC01B] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC01C] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC01D] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC01E] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC01F] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC020] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC021] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC022] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0xC024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0xC025] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0xC026] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0xC028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0xC029] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0xC02A] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0xC02D] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0xC02E] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0xC030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0xC031] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
                        cipher_suites_map[0xC032] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
                        cipher_suites_map[0xC033] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
                        cipher_suites_map[0xC034] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
                        cipher_suites_map[0xC035] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
                        cipher_suites_map[0xC036] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
                        cipher_suites_map[0xC037] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
                        cipher_suites_map[0xC038] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
                        cipher_suites_map[0xC039] = "TLS_ECDHE_PSK_WITH_NULL_SHA";
                        // TODO: add more cipher suites


                        if (fread(cipher_suites, sizeof(u_int16), cipher_suites_num, fp) !=
                            cipher_suites_num) { //读取Cipher Suites
                            cout << "Read cipher_suites failed!!!" << endl;
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
                        while (fread(extension_type, sizeof(u_int16), 1, fp) == 1) {//读取扩展
                            fread(extensions_length, sizeof(u_int16), 1, fp);
                            *extension_type = ntohs(*extension_type);//转换字节序
                            *extensions_length = ntohs(*extensions_length);//
                            if (*extension_type == 0) {// Server Name Indication
                                u_int16 *server_name_list_length;
                                u_int8 *server_name_type;
                                u_int16 *server_name_length;
                                server_name_list_length = (u_int16 *) malloc(sizeof(u_int16));
                                server_name_type = (u_int8 *) malloc(sizeof(u_int8));
                                server_name_length = (u_int16 *) malloc(sizeof(u_int16));
                                fread(server_name_list_length, sizeof(u_int16), 1, fp);
                                *server_name_list_length = ntohs(*server_name_list_length);
                                fread(server_name_type, sizeof(u_int8), 1, fp);
                                fread(server_name_length, sizeof(u_int16), 1, fp);
                                *server_name_length = ntohs(*server_name_length);
                                char *server_name;
                                server_name = (char *) malloc(*server_name_length + 1);
                                fread(server_name, sizeof(char), *server_name_length, fp);
                                server_name[*server_name_length] = '\0';
                                cout << "Server Name: " << server_name << endl;
                                free(server_name);
                                free(server_name_length);
                                free(server_name_type);
                                free(server_name_list_length);
                            } else if (*extension_type == 10) {// Supported Elliptic Curves
                                u_int16 *elliptic_curves_length;
                                u_int16 *elliptic_curve;
                                map<u_int16, string> elliptic_curve_map;
                                // TODO: add more elliptic curves


                                elliptic_curves_length = (u_int16 *) malloc(sizeof(u_int16));
                                elliptic_curve = (u_int16 *) malloc(sizeof(u_int16));
                                fread(elliptic_curves_length, sizeof(u_int16), 1, fp);
                                *elliptic_curves_length = ntohs(*elliptic_curves_length);
                                while (*elliptic_curves_length > 0) {
                                    fread(elliptic_curve, sizeof(u_int16), 1, fp);
                                    *elliptic_curve = ntohs(*elliptic_curve);
                                    cout << "Elliptic Curve: " << elliptic_curve_map[*elliptic_curve] << "("
                                         << hex << *elliptic_curve << ")" << endl;
                                    *elliptic_curves_length -= 2;
                                }
                                free(elliptic_curve);
                                free(elliptic_curves_length);
                            } else if (*extension_type == 11) {// Supported Point Formats
                                u_int8 *supported_point_formats_length;
                                u_int8 *supported_point_format;
                                supported_point_formats_length = (u_int8 *) malloc(sizeof(u_int8));
                                supported_point_format = (u_int8 *) malloc(sizeof(u_int8));
                                fread(supported_point_formats_length, sizeof(u_int8), 1, fp);
                                while (*supported_point_formats_length > 0) {
                                    fread(supported_point_format, sizeof(u_int8), 1, fp);
                                    cout << "Supported Point Format: " << (int) *supported_point_format << endl;
                                    *supported_point_formats_length -= 1;
                                }
                                free(supported_point_format);
                                free(supported_point_formats_length);
                            } else if ((*extension_type) == 13) {// Signature Algorithms
                                map<u_int16, string> signature_algorithm_map;
                                signature_algorithm_map[0x0401] = "RSA_PKCS1_SHA1";
                                signature_algorithm_map[0x0402] = "RSA_PKCS1_SHA256";
                                signature_algorithm_map[0x0501] = "ECDSA_SHA1";
                                //TODO: add more



                                u_int16 *signature_algorithms_length;
                                u_int16 *signature_algorithm;
                                signature_algorithms_length = (u_int16 *) malloc(sizeof(u_int16));
                                signature_algorithm = (u_int16 *) malloc(sizeof(u_int16));
                                fread(signature_algorithms_length, sizeof(u_int16), 1, fp);
                                *signature_algorithms_length = ntohs(*signature_algorithms_length);
                                while (*signature_algorithms_length > 0) {
                                    fread(signature_algorithm, sizeof(u_int16), 1, fp);
                                    *signature_algorithm = ntohs(*signature_algorithm);
                                    cout << "Signature Algorithm: " << signature_algorithm_map[*signature_algorithm]
                                         << "(" << hex << *signature_algorithm << ")" << endl;
                                    *signature_algorithms_length -= 2;
                                }
                                free(signature_algorithm);
                                free(signature_algorithms_length);
                            } else if (*extension_type == 35) {// Session Ticket TLS
                                u_int32 *ticket_lifetime_hint;
                                u_int16 *ticket_length;
                                ticket_lifetime_hint = (u_int32 *) malloc(sizeof(u_int32));
                                ticket_length = (u_int16 *) malloc(sizeof(u_int16));
                                fread(ticket_lifetime_hint, sizeof(u_int32), 1, fp);
                                fread(ticket_length, sizeof(u_int16), 1, fp);
                                *ticket_lifetime_hint = ntohl(*ticket_lifetime_hint);
                                *ticket_length = ntohs(*ticket_length);
                                cout << "Ticket Lifetime Hint: " << *ticket_lifetime_hint << endl;
                                cout << "Ticket Length: " << *ticket_length << endl;
                                fseek(fp, *ticket_length, SEEK_CUR);
                                free(ticket_length);
                            }
                        }
                    }


                }
            }
        } else if (ip_protocol == 17) {// UDP
            cout << "----------------------------------------" << endl;
            cout << "application protocol: UDP" << endl;
            //UDP 8 bytes
            if (fread(udpHeader, sizeof(udp_header), 1, fp) != 1) {
                cout << "Error reading UDP header" << endl;
                continue;
            }
            src_port = ntohs(udpHeader->src_port);
            dst_port = ntohs(udpHeader->dst_port);

            int udp_length = ntohs(udpHeader->len);
            int udp_checksum = ntohs(udpHeader->check);
            cout << "Source Port: " << dec <<src_port << endl;
            cout << "Destination Port: " << dec << dst_port << endl;
            cout << "Length: " << udp_length << endl;
            cout << "Checksum: " << udp_checksum << endl;

            //DNS
            if (src_port == 53 || dst_port == 53) {
                cout << "application protocol: DNS" << endl;
                dns_len = ip_len - 28 - 12; //ip_len - ip_header_len - udp_header_len
                if (fread(dnsHeader, sizeof(dns_header), 1, fp) != 1) {
                    cout << "Error reading DNS header" << endl;
                    continue;
                }
                u_int16 transaction_id = ntohs(dnsHeader->id);
                u_int16 flags = ntohs(dnsHeader->flags);
                u_int16 questions = ntohs(dnsHeader->qdcount);
                u_int16 answer_rrs = ntohs(dnsHeader->ancount);

                cout << "Transaction ID: " << transaction_id << endl;
                cout << "Flags: " << flags << endl;
                cout << "Questions: " << questions << endl;
                cout << "Answer RRs: " << answer_rrs << endl;

                u_int8 dns_content_ascii[MAX_PACKET_LEN];
                char dns_content[MAX_PACKET_LEN];
                memset(dns_content_ascii, 0, sizeof(u_int8));
                if (fread(dns_content_ascii, sizeof(u_int8), dns_len - 12, fp) != dns_len - 12) {
                    cout << "Error reading DNS content" << endl;
                    continue;
                }

                int p = 0; //dns_content index
                bool flag = true; // if flag is true, then it is a letter, otherwise it is a dot
                for (int i = 0; i < dns_len - 12; i++) {//dns_len - 12 is the length of dns_content_ascii
                    if (dns_content_ascii[i] == 0x00) {// 0x00 is the end of a domain name
                        if (flag) {// if flag is true, then it is a letter, otherwise it is a dot
                            dns_content[p] = '.';// replace 0x00 with a dot
                            p++;// move to the next position
                            flag = false;// set flag to false
                        }
                    } else {
                        dns_content[p] = dns_content_ascii[i];// copy the letter to dns_content
                        p++;
                        flag = true;//
                    }
                }
                cout << "DNS Content: " << dns_content << endl;

                if (answer_rrs) {
                    cout << "Answer RRs: ";
                    for (int i = 0; i < answer_rrs; i++) {
                        u_int16 name;
                        u_int16 type;
                        u_int16 class_;
                        u_int32 ttl;
                        u_int16 data_len;
                        u_int32 ip;
                        fread(&name, sizeof(u_int16), 1, fp);
                        fread(&type, sizeof(u_int16), 1, fp);
                        fread(&class_, sizeof(u_int16), 1, fp);
                        fread(&ttl, sizeof(u_int32), 1, fp);
                        fread(&data_len, sizeof(u_int16), 1, fp);
                        fread(&ip, sizeof(u_int32), 1, fp);
                        name = ntohs(name);
                        type = ntohs(type);
                        class_ = ntohs(class_);
                        ttl = ntohl(ttl);
                        data_len = ntohs(data_len);
                        ip = ntohl(ip);
                        cout << "Name: " << name << endl;
                        cout << "Type: " << type << endl;
                        cout << "Class: " << class_ << endl;
                        cout << "TTL: " << ttl << endl;
                        cout << "Data Length: " << data_len << endl;
                        cout << "IP: " << ip << endl;
                    }
                }
            }
        }
    }
    fclose(fp);
    free(pcapHeader);
    free(etherHeader);
    free(ipHeader);
    free(tcpHeader);
    free(udpHeader);
    free(dnsHeader);

    cout << "-----------------------------" << endl;
    cout << "finish" << endl;
    return 0;
}
