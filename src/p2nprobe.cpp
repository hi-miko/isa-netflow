// Patrik Uher
// xuherp02

// TODO get rid of pointless libraries
// #include <cstdlib>
// #include <string>
// #include <vector>

#include <cstdint>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pcap/pcap.h>              // pcap functions
#include <netinet/if_ether.h>       // ether_header struct
#include <netinet/ip.h>             // ip struct
#include <netinet/tcp.h>            // tcp struct
#include <arpa/inet.h>              // inet functions
#include <chrono>

#include "client-args.hpp"
#include "flow-manager.hpp"

using namespace std;

// Global client args variable
ClientArgs args = ClientArgs();
FlowManager fm = FlowManager();

// TODO scary function that can be changed
int32_t time_handle(struct timeval ts)
{
    // TODO change the types if it works
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();

    uint32_t pckt_timestamp_ms = (ts.tv_sec * 1000) + (ts.tv_usec / 1000);
    auto epoch_ms = chrono::duration_cast<chrono::milliseconds>(epoch).count();
    cout << "\t\tepoch cnt: " << epoch_ms << "ms" << endl;
    cout << "\t\tpacket timestamp: " << pckt_timestamp_ms << "ms" << endl;

    return static_cast<int32_t>(pckt_timestamp_ms - epoch_ms);
}

void pcap_reader(u_char *user, const struct pcap_pkthdr *header, const u_char *packet_bytes)
{
    if (header->caplen != header->len)
    {
        // dropped cause packet wasn't recorded/transmitted fully
        cout << "Dropped, packed wasnt transmitted correctly" << endl;
        return;
    }

    struct ether_header *ethernet_header = (struct ether_header *) packet_bytes;

    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
    {
        // dropped cause ethernet header wasn't ETHERTYPE_IP
        cout << "Dropped, expecting IP (0x" << hex << ETHERTYPE_IP << "), got '0x" << hex << ntohs(ethernet_header->ether_type) << dec << "'" << dec << endl;

        return;
    }

    struct ip *ip_hdr = (struct ip*)(packet_bytes + sizeof(struct ether_header));

    if (ip_hdr->ip_p != IPPROTO_TCP)
    {
        // Dropped cause packet is not TCP
        cout << "Dropped, not TCP" << endl;
        return;
    }

    pack_info packet;

    int32_t pckt_relative_time = time_handle(header->ts);

    packet.relative_timestamp = pckt_relative_time;
    packet.ip_octets = ntohs(ip_hdr->ip_len);

    // 1 Byte values don't need to be translated to host values
    packet.ip_proto_type = ip_hdr->ip_p;

    // TODO do I not have to change this to host byte order?
    packet.src_ip = ntohl(ip_hdr->ip_src.s_addr);
    packet.dst_ip = ip_hdr->ip_dst.s_addr;

    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet_bytes + sizeof(struct ether_header) + sizeof(struct ip));

    packet.src_port = ntohs(tcp_hdr->th_sport);
    packet.dst_port = ntohs(tcp_hdr->th_dport);

    packet.tcp_flags = tcp_hdr->th_flags;

    fm.save_packet(&packet, args.active_timeout, args.inactive_timeout);

    // TODO remove this debug print later (right now its nice)
    static int packet_cnt = 1;

    cout << "Packet number: " << packet_cnt << endl;

    cout << "\tSec: " << header->ts.tv_sec << "\n\tUsec: " << header->ts.tv_usec << endl;
    cout << "\tmiliseconds: " << (header->ts.tv_sec * 1000) + (header->ts.tv_usec / 1000) << "ms" << endl;
    cout << "\trelative time: " << pckt_relative_time << "ms" << endl;
    cout << "\tIP packet size: " << ntohs(ip_hdr->ip_len) << endl;

    packet_cnt++;

    char srcip[16];
    char dstip[16];

    // inet_ntop automatically translates the ip addresses with ntohl, so when saving do so too
    inet_ntop(AF_INET, &(ip_hdr->ip_src), srcip, sizeof(srcip));
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dstip, sizeof(dstip));

    cout << "\tsrc ip: " << srcip << endl;
    cout << "\tdst ip: " << dstip << endl;

    cout << "\tsrc port: " << ntohs(tcp_hdr->th_sport) << endl;
    cout << "\tdst port: " << ntohs(tcp_hdr->th_dport) << endl;

    auto tflags = tcp_hdr->th_flags;
    cout << "\tTCP flags: ";
    if (tflags & TH_FIN)  std::cout << "FIN ";
    if (tflags & TH_SYN)  std::cout << "SYN ";
    if (tflags & TH_RST)  std::cout << "RST ";
    if (tflags & TH_PUSH) std::cout << "PSH ";
    if (tflags & TH_ACK)  std::cout << "ACK ";
    if (tflags & TH_URG)  std::cout << "URG ";
    std::cout << std::endl;
}

int main(int argc, char **argv)
{
    args.check_args(argc, argv);

    // TODO don't forget that main program should not print anything but errors
    args.print_args();

    char errbuf[PCAP_ERRBUF_SIZE];
    // TODO try to create an errornious pcap file to see how my code would react, it should not segfault
    pcap_t *pcap_fp = pcap_open_offline(args.pcap_file_path.c_str(), errbuf);

    if (pcap_fp == NULL)
    {
        cerr << "Error: when opening pcap file: " << errbuf << endl;
        return 1;
    }

    if (pcap_loop(pcap_fp, -1, pcap_reader, NULL) < 0)
    {
        cerr << "Error when reading pcap file: " << pcap_geterr(pcap_fp) << endl;
        return 1;
    }

    // TODO prints all the flows remember to remove later
    fm.print_flows();
}
