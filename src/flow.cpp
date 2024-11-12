#include <cstdint>
#include <iostream>
#include <netinet/ip.h>             // for IPPROTO_TCP macro
#include <netinet/tcp.h>            // for TCP flag macros
#include <string>
#include "flow.hpp"

Flow::Flow(pack_info *packet)
{
    // TODO hopefully I do ntons already here
    Flow::src_ip = packet->src_ip;
    Flow::dst_ip = packet->dst_ip;

    Flow::packet_cnt = 1;
    Flow::ip_octet_cnt = packet->ip_octets;
    
    Flow::first_packet_time = packet->relative_timestamp;
    Flow::last_packet_time = packet->relative_timestamp;
    
    Flow::tcp_flags = packet->tcp_flags;
    Flow::ip_proto_type = IPPROTO_TCP;

    Flow::generate_flow_id();
}

void Flow::generate_flow_id()
{
    // TODO add the tcp protocol if needed, but I don't think I do
    Flow::flow_id = std::to_string(Flow::src_ip); 
    Flow::flow_id.append(std::to_string(Flow::dst_ip));
    Flow::flow_id.append(std::to_string(Flow::src_port));
    Flow::flow_id.append(std::to_string(Flow::dst_port));

    // TODO remove debug prints
    std::cout << "flow id: " << Flow::flow_id << std::endl;
}

tm_status_t Flow::add_packet(pack_info *packet, uint32_t active_timeout, uint32_t inactive_timeout)
{
    // TODO there might be some fuckery going on if the packets aren't ordered by timestamps, so that should be fixed (maybe order
    // them myself if thats the case), or maybe do something like if the newest packet isn't newer than last packet and activeTM still
    // is ok then don't set the newest packet as the last packet
    auto active_diff = abs(Flow::first_packet_time) - abs(Flow::last_packet_time);
    if((active_diff / 1000) >= active_timeout)
    {
        std::cout << "Flow should be inactivated due to active timeout" << std::endl;
        return INACTIVE;
    }

    auto inactive_diff = abs(Flow::last_packet_time) - abs(packet->relative_timestamp);
    if((inactive_diff / 1000) >= inactive_timeout)
    {
        std::cout << "Flow should be inactivated due to inactive timeout" << std::endl;
        return INACTIVE;
    }

    Flow::tcp_flags = Flow::tcp_flags | packet->tcp_flags;
    Flow::packet_cnt += 1;
    Flow::ip_octet_cnt += packet->ip_octets;
    Flow::last_packet_time = packet->relative_timestamp;

    return ACTIVE; 
}

void Flow::print_flow()
{
    std::cout << "flow:" << std::endl;
    std::cout << "\tsource ip: " << Flow::src_ip << std::endl;
    std::cout << "\tdestination ip: " << Flow::dst_ip << std::endl;
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

    std::cout << "\tip protocol: " << Flow::ip_proto_type << std::endl;
}
