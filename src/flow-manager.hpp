#ifndef FLOW_MANAGER_HPP
#define FLOW_MANAGER_HPP

#include <unordered_map>
#include <string>
#include <vector>

#include "flow.hpp"

class FlowManager
{
    public:
        std::unordered_map<std::string, Flow *> active_flows;
        std::vector<Flow *> inactive_flows;

    public:
        FlowManager();
        ~FlowManager();
        void add_to_flow(pack_info *, uint32_t, uint32_t);
        void print_flows();

    private:
        // string in the form of:
        // [src_ip][dst_ip][src_port][dst_port]
        // protocol is ignored since we only export tcp packets
        std::string generate_packet_id(pack_info *);
};

#endif // FLOW_MANAGER_HPP
