// Patrik Uher
// xuherp02

// TODO get rid of pointless libraries
// #include <cstdlib>
// #include <string>
// #include <vector>

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

using namespace std;

void pcap_reader(u_char *user, const struct pcap_pkthdr *header, const u_char *packet_bytes)
{
    static int packet_cnt = 1;

    if (header->caplen != header->len)
    {
        // dropped cause packet wasn't recorded/transmitted fully
        return;
    }

    struct ether_header *ethernet_header = (struct ether_header *) packet_bytes;

    // if (ethernet_header->ether_type != ETHERTYPE_IP)
    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
    {
        // TODO drop packet, maybe I could count them or something
        cout << "Dropped, not IP (" << dec << ethernet_header->ether_type << dec << ")" << endl;
        return;
    }

    struct ip *ip_hdr = (struct ip*)(packet_bytes + sizeof(struct ether_header));

    if (ip_hdr->ip_p != IPPROTO_TCP)
    {
        // TODO drop non tcp packets
        cout << "Dropped, not TCP" << endl;
        return;
    }

    cout << "Packet number: " << packet_cnt << endl;

    cout << "\tSec: " << header->ts.tv_sec << "\n\tUsec: " << header->ts.tv_usec << endl;
    cout << "\tIP packet size: " << ntohs(ip_hdr->ip_len) << endl;

    packet_cnt++;

    char srcip[16];
    char dstip[16];

    // inet_ntop automatically translates the ip addresses with ntohl, so when saving do so too
    inet_ntop(AF_INET, &(ip_hdr->ip_src), srcip, sizeof(srcip));
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dstip, sizeof(dstip));

    cout << "\tsrc ip: " << srcip << endl;
    cout << "\tdst ip: " << dstip << endl;
    
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet_bytes + sizeof(struct ether_header) + sizeof(struct ip));

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

    // TODO since I have all the data I need to create a flow (and send it), I should now make the flow class and a flow manager
    // class. Where the first one will have info on individual flows and the second one will have the active flow hashmap and 
    // inactive flow vector (these data structures are just thought of, they can change)
}

int main(int argc, char **argv)
{
    ClientArgs args = ClientArgs();
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
}
