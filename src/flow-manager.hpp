#ifndef FLOW_MANAGER_HPP
#define FLOW_MANAGER_HPP

#include "flow.hpp"
#include <unordered_map>
#include <vector>

class FlowManager
{
    public:
        std::unordered_map<std::string, Flow *> active_flows;
        std::vector<Flow *> inactive_flows;

    public:
        FlowManager();
        ~FlowManager();
        void save_packet(pack_info *, uint32_t, uint32_t);
        void print_flows();

    private:
        // string in the form of:
        // [src_ip][dst_ip][src_port][dst_port]
        std::string generate_packet_id(pack_info *);
};

#endif // FLOW_MANAGER_HPP
