// Patrik Uher
// xuherp02

#include <cstdint>
#include <iostream>
#include <netinet/ip.h>             // for IPPROTO_TCP macro
#include <netinet/tcp.h>            // for TCP flag macros
#include <arpa/inet.h>              // inet functions

#include "flow.hpp"
#include "debug-info.hpp"
#include "pack-info.hpp"

// Global variable to count the sequence of flows
int Flow::flow_seq_cnt = 0;

Flow::Flow(pack_info *packet)
{
    // all values are in host byte order, to print the ip addrs
    // first you must convert them to network byte order and
    // then use the inet_ntop() function or print it manually

    Flow::src_ip = packet->src_ip;
    Flow::dst_ip = packet->dst_ip;

    Flow::src_port = packet->src_port;
    Flow::dst_port = packet->dst_port;

    Flow::packet_cnt = 1;
    Flow::ip_octet_cnt = packet->ip_octets;
    
    Flow::first_packet_time = packet->relative_timestamp;
    Flow::last_packet_time = packet->relative_timestamp;
    
    Flow::tcp_flags = packet->tcp_flags;
    Flow::ip_proto_type = IPPROTO_TCP;

    // flow seq numbers start with 1
    Flow::flow_seq_num = ++(Flow::flow_seq_cnt);
}

/** A function to check the timeouts of a flow, this function is later used when trying
*   to add packet info to a flow
*   returns a timeout status enum type: active or inactive
*/
tm_status_t Flow::check_timeouts(pack_info *packet, uint32_t active_timeout, uint32_t inactive_timeout)
{
    auto active_diff = labs(Flow::first_packet_time) - labs(Flow::last_packet_time);
    
    if(debugActive)
    {
        std::cout << "[[ FLOW AC/INAC CHECK ]]" << std::endl;
        std::cout << "active diff: " << active_diff << std::endl;
        std::cout << "active tm comparison: " << (active_diff / 1e6) << " >= " << static_cast<int64_t>(active_timeout) << std::endl;
    }

    if((active_diff / 1e6) >= static_cast<int64_t>(active_timeout))
    {
        if(debugActive)
        {
            std::cout << "Flow should be inactivated due to active timeout" << std::endl;
        }

        return tm_status_t::INACTIVE;
    }

    auto inactive_diff = labs(Flow::last_packet_time) - labs(packet->relative_timestamp);

    if(debugActive)
    {
        std::cout << "last packet: " << Flow::last_packet_time << " - relative_timestamp: " << packet->relative_timestamp << std::endl;
        std::cout << "inactive diff: " << inactive_diff << std::endl;
        std::cout << "inactive tm comparison: " << (inactive_diff / 1e6) << " >= " << static_cast<int64_t>(inactive_timeout) << std::endl;
        std::cout << std::endl;
    }

    if((inactive_diff / 1e6) >= static_cast<int64_t>(inactive_timeout))
    {
        if(debugActive)
        {
            std::cout << "Flow should be inactivated due to inactive timeout" << std::endl;
        }

        return tm_status_t::INACTIVE;
    }

    return tm_status_t::ACTIVE;
}

/** Adds packet information to a flow
*/
void Flow::add_packet(pack_info *packet)
{

    Flow::tcp_flags = Flow::tcp_flags | packet->tcp_flags;
    Flow::packet_cnt += 1;
    Flow::ip_octet_cnt += packet->ip_octets;
    Flow::last_packet_time = packet->relative_timestamp;
}

/** Function used to print information of a flow, used for debugging
*/
void Flow::print_flow()
{

    char srcip[16];
    char dstip[16];

    uint32_t networkSaddr = htonl(Flow::src_ip);
    uint32_t networkDaddr = htonl(Flow::dst_ip);

    inet_ntop(AF_INET, &networkSaddr, srcip, sizeof(srcip));
    inet_ntop(AF_INET, &networkDaddr, dstip, sizeof(dstip));

    std::cout << "flow [ " << Flow::flow_seq_num << " ]" << ":" << std::endl;
    // std::cout << "flow:" << std::endl;
    std::cout << "\tsource ip: " << srcip << std::endl;
    std::cout << "\tdestination ip: " << dstip << std::endl;
    std::cout << "\tsource port: " << Flow::src_port << std::endl;
    std::cout << "\tdestination port: " << Flow::dst_port << std::endl;

    std::cout << "\tpacket count: " << Flow::packet_cnt << std::endl;
    std::cout << "\tip octet count: " << Flow::ip_octet_cnt << std::endl;

    std::cout << "\tfirst time: " << Flow::first_packet_time << std::endl;
    std::cout << "\tlast time: " << Flow::last_packet_time << std::endl;

    std::cout << "\tTCP flags: ";
    if (Flow::tcp_flags & TH_FIN)  std::cout << "FIN ";
    if (Flow::tcp_flags & TH_SYN)  std::cout << "SYN ";
    if (Flow::tcp_flags & TH_RST)  std::cout << "RST ";
    if (Flow::tcp_flags & TH_PUSH) std::cout << "PSH ";
    if (Flow::tcp_flags & TH_ACK)  std::cout << "ACK ";
    if (Flow::tcp_flags & TH_URG)  std::cout << "URG ";
    std::cout << std::endl;

    // else and else if branches should not ever run,
    // they are here for debug print testing
    if(Flow::ip_proto_type == IPPROTO_TCP)
    {
        std::cout << "\tip protocol: TCP" << std::endl;
    }
    else if (Flow::ip_proto_type == IPPROTO_UDP)
    {
        std::cout << "\tip protocol: UDP" << std::endl;
    }
    else
    {
        std::cout << "\tip protocol: unknown" << std::endl;
    }
}
