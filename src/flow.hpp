#ifndef FLOW_HPP
#define FLOW_HPP

#include <cstdint>
#include "pack-info.hpp"

enum tm_status_t 
{
    ACTIVE = 2,
    INACTIVE = 3,
};

class Flow
{
    public:
        uint32_t src_ip;
        uint32_t dst_ip;

        uint32_t packet_cnt;
        uint32_t ip_octet_cnt;
        
        int64_t first_packet_time;
        // when the last packed was recieved, for inactive timeout
        int64_t last_packet_time;

        uint16_t src_port;
        uint16_t dst_port;

        // commulative OR of the TCP flags
        uint8_t tcp_flags;
        uint8_t ip_proto_type;
    
    private:
        static int flow_seq_cnt;
        int flow_seq_num;
    public:
        Flow(pack_info *);
        void add_packet(pack_info *);
        tm_status_t check_timeouts(pack_info *, uint32_t, uint32_t);
        void print_flow();
};

#endif // FLOW_HPP
