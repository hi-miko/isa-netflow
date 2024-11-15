// Patrik Uher
// xuherp02

// TODO get rid of pointless libraries
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

#include "client-args.hpp"
#include "flow-manager.hpp"
#include "debug-info.hpp"

using namespace std;

// Global client args variable
// TODO maybe rething globals in favor of facade class?
ClientArgs args = ClientArgs();
FlowManager fm = FlowManager();

// TODO scary function that can be changed
int64_t time_handle(struct timeval ts)
{
    int64_t pckt_timestamp_ms = (ts.tv_sec * 1000 + ts.tv_usec / 1000);

    auto epoch_ms = chrono::duration_cast<chrono::milliseconds>(args.epoch).count();

    if(debugActive)
    {
        cout << "[[ TIMESTAMPS ]]" << endl;
        cout << "epoch: " << epoch_ms << "ms" << endl;
        cout << "timestamp ms (nocutoff): " << (ts.tv_sec * 1000 + ts.tv_usec / 1000) << "ms" << endl;
        cout << "packet timestamp: " << pckt_timestamp_ms << "ms" << endl;
        cout << endl;
    }

    return pckt_timestamp_ms - epoch_ms;
}

void print_raw_packet(pack_info *packet, const struct pcap_pkthdr *header)
{
    static int packet_cnt = 1;

    cout << "[[ PACKET INFO ]]" << endl;

    cout << "Packet number: " << packet_cnt << endl;

    cout << "\tSec: " << header->ts.tv_sec << "\n\tUsec: " << header->ts.tv_usec << endl;
    cout << "\tmiliseconds: " << (header->ts.tv_sec * 1000) + (header->ts.tv_usec / 1000) << "ms" << endl;
    cout << "\trelative time: " << packet->relative_timestamp << "ms" << endl;
    cout << "\tIP packet size: " << packet->ip_octets << endl;

    packet_cnt++;

    char srcip[16];
    char dstip[16];

    uint32_t networkSaddr = htonl(packet->src_ip);
    uint32_t networkDaddr = htonl(packet->dst_ip);

    // inet_ntop automatically translates the ip addresses with ntohl, so when saving do so too
    inet_ntop(AF_INET, &networkSaddr, srcip, sizeof(srcip));
    inet_ntop(AF_INET, &networkDaddr, dstip, sizeof(dstip));

    cout << "\tsrc ip: " << srcip << endl;
    cout << "\tdst ip: " << dstip << endl;

    cout << "\tsrc port: " << packet->src_port << endl;
    cout << "\tdst port: " << packet->dst_port << endl;

    cout << "\tTCP flags: ";
    if (packet->tcp_flags & TH_FIN)  std::cout << "FIN ";
    if (packet->tcp_flags & TH_SYN)  std::cout << "SYN ";
    if (packet->tcp_flags & TH_RST)  std::cout << "RST ";
    if (packet->tcp_flags & TH_PUSH) std::cout << "PSH ";
    if (packet->tcp_flags & TH_ACK)  std::cout << "ACK ";
    if (packet->tcp_flags & TH_URG)  std::cout << "URG ";

    cout << endl << endl;
}

void pcap_reader(u_char *user, const struct pcap_pkthdr *header, const u_char *packet_bytes)
{
    (void)user; // gets rid of unused variable error

    if (header->caplen != header->len)
    {
        if(debugActive)
        {
            // dropped cause packet wasn't recorded/transmitted fully
            cout << "[Warning]: Dropped packed, not transmitted correctly" << endl;
        }
        return;
    }

    struct ether_header *ethernet_header = (struct ether_header *) packet_bytes;

    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
    {
        if(debugActive)
        {
            // dropped cause ethernet header wasn't ETHERTYPE_IP
            cout << "[Warning]: Dropped packet, expecting IP (0x" << hex << ETHERTYPE_IP << "), got '0x" << hex << ntohs(ethernet_header->ether_type) << dec << "'" << dec << endl;
        }

        return;
    }

    struct ip *ip_hdr = (struct ip*)(packet_bytes + sizeof(struct ether_header));

    if (ip_hdr->ip_p != IPPROTO_TCP)
    {
        if(debugActive)
        {
            // Dropped cause packet is not TCP
            cout << "[Warning]: Dropped packet, not TCP" << endl;
        }

        return;
    }

    // every data value in packet should be in host byte order
    pack_info packet;

    // timestamps don't have to be converted to host byte order
    packet.relative_timestamp = time_handle(header->ts);
    packet.ip_octets = ntohs(ip_hdr->ip_len);

    // 1 Byte values don't need to be translated to host values
    packet.ip_proto_type = ip_hdr->ip_p;

    packet.src_ip = ntohl(ip_hdr->ip_src.s_addr);
    packet.dst_ip = ntohl(ip_hdr->ip_dst.s_addr);

    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet_bytes + sizeof(struct ether_header) + sizeof(struct ip));

    packet.src_port = ntohs(tcp_hdr->th_sport);
    packet.dst_port = ntohs(tcp_hdr->th_dport);

    packet.tcp_flags = tcp_hdr->th_flags;

    // fm.add_to_flow(&packet, args.active_timeout, args.inactive_timeout);


    if(debugActive)
    {
        print_raw_packet(&packet, header);
    }
}

int main(int argc, char **argv)
{
    args.check_args(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];
    // TODO try to create an errornious pcap file to see how my code would react, it should not segfault
    pcap_t *pcap_fp = pcap_open_offline(args.pcap_file_path.c_str(), errbuf);

    if (pcap_fp == NULL)
    {
        cerr << "[Error]: when opening pcap file: " << errbuf << endl;
        return 1;
    }

    if (pcap_loop(pcap_fp, -1, pcap_reader, NULL) < 0)
    {
        cerr << "[Error]: when reading pcap file: " << pcap_geterr(pcap_fp) << endl;
        return 1;
    }

    // if(args.debug)
    // {
    //     fm.print_flows();
    // }
}
