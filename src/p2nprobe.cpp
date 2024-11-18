// Patrik Uher
// xuherp02

// TODO get rid of pointless libraries
#include <chrono>
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

ClientArgs args = ClientArgs();
FlowManager fm = FlowManager();

int64_t time_handle(struct timeval ts)
{
    int64_t pckt_timestamp_us = (ts.tv_sec * (1e6) + ts.tv_usec);

    auto epoch_us = chrono::duration_cast<chrono::microseconds>(args.epoch).count();

    if(debugActive)
    {
        cout << "[[ TIMESTAMPS ]]" << endl;
        cout << "epoch: " << epoch_us << "us" << endl;
        cout << "timestamp us (nocutoff): " << (ts.tv_sec * (1e6) + ts.tv_usec) << "us" << endl;
        cout << "packet timestamp: " << pckt_timestamp_us << "us" << endl;
        cout << endl;
    }

    return pckt_timestamp_us - epoch_us;
}

void print_raw_packet(pack_info *packet, const struct pcap_pkthdr *header)
{
    static int packet_cnt = 1;
    static int64_t ts_seq_check = 0;

    cout << "[[ PACKET INFO ]]" << endl;

    cout << "Packet number: " << packet_cnt << endl;

    cout << "\tSec: " << header->ts.tv_sec << "\n\tUsec: " << header->ts.tv_usec << endl;
    cout << "\tmiliseconds: " << (header->ts.tv_sec * 1000) + (header->ts.tv_usec / 1000) << "ms" << endl;
    cout << "\trelative time: " << packet->relative_timestamp << "us" << endl;
    // under normal circumstances should never be 0 normally, since for that to happen the packet would have
    // to be captured, added to a pcap file and that pcap file read within 1 usec, which seems unlikely
    if(ts_seq_check != 0)
    {
        if(abs(ts_seq_check) < abs(packet->relative_timestamp))
        {
            cout << "[Warning E35]: packet was recieved sooner than the previous one" << endl;
        }
    }

    ts_seq_check = packet->relative_timestamp;

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
    // relative time is in useconds here, but will need to be sent with mseconds
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

    fm.add_to_flow(&packet, args.active_timeout, args.inactive_timeout);


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

    if(debugActive)
    {
        fm.print_flows();
    }

    // closes the pcap file pointer that was openned with pcap_open_offline
    pcap_close(pcap_fp);
}
