#include <iostream>
#include "flow-manager.hpp"

using fm = FlowManager;

fm::FlowManager()
{

}

fm::~FlowManager()
{
    for(auto i: fm::active_flows)
    {
        delete i.second; 
    }

    for(auto i: fm::inactive_flows)
    {
        delete i; 
    }
}

std::string fm::generate_packet_id(pack_info *packet)
{
    std::string packet_id;

    packet_id = std::to_string(packet->src_ip); 
    packet_id.append(std::to_string(packet->dst_ip));
    packet_id.append(std::to_string(packet->src_port));
    packet_id.append(std::to_string(packet->dst_port));

    std::cout << "packet id: " << packet_id << std::endl;

    return packet_id;
}

void fm::save_packet(pack_info *packet, uint32_t active_timeout, uint32_t inactive_timeout)
{
    std::string pack_id = generate_packet_id(packet);

    auto flow_it = fm::active_flows.find(pack_id);
    if(flow_it == fm::active_flows.end())
    {
        // flow was not found, create one
        Flow *new_flow = new Flow(packet);
        fm::active_flows[pack_id] = new_flow;
    }
    else
    {
        Flow *found_flow = flow_it->second;

        tm_status_t timeout_status = found_flow->add_packet(packet, active_timeout, inactive_timeout);

        // checks both active and inactive timeout since, the result is the same
        if(timeout_status == tm_status_t::INACTIVE)
        {
            fm::inactive_flows.push_back(found_flow);         
            fm::active_flows.erase(flow_it);
        }
    }
}

void fm::print_flows()
{
    std::cout << "------ [[ ACTIVE FLOWS ]] ------" << std::endl;
    for(auto& element: fm::active_flows)
    {
        element.second->print_flow();
    }

    std::cout << "------ [[ INACTIVE FLOWS ]] ------" << std::endl;
    for(auto& element: fm::inactive_flows)
    {
        element->print_flow();
    }
}
