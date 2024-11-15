#ifndef PACK_INFO_HPP
#define PACK_INFO_HPP

#include <cstdint>

struct packet_info
{
    uint32_t src_ip;
    uint32_t dst_ip;

    uint32_t ip_octets;

    // timestamp relative to the export program
    // this should be enough precision to even allow for parsing pcap files created at the start of the epoch
    int64_t relative_timestamp;
    
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t tcp_flags;
    uint8_t ip_proto_type;

};

using pack_info = struct packet_info;

#endif // FLOW_MANAGER_HPP
