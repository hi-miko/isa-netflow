// Patrik Uher
// xuherp02

#include <iostream>
#include "flow-manager.hpp"
#include "debug-info.hpp"

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

/** Generates the packet id as described in flow-manager.hpp
*/
std::string fm::generate_packet_id(pack_info *packet)
{
    std::string packet_id;

    packet_id = std::to_string(packet->src_ip); 
    packet_id.append(std::to_string(packet->dst_ip));
    packet_id.append(std::to_string(packet->src_port));
    packet_id.append(std::to_string(packet->dst_port));
    packet_id.append(std::to_string(packet->ip_proto_type));

    if(debugActive)
    {
        std::cout << "[[ FLOW MANAGER PACKET ID ]]" << std::endl;
        std::cout << "packet id: " << packet_id << std::endl;
        std::cout << std::endl;
    }

    return packet_id;
}

/** A function that checks if a flow already exists and if it does adds current packet information into it
*   Active and Inactive timeouts are also checked and based on them instead of adding packet information to an existing 
*   flow, it creates a new one
*/
void fm::add_to_flow(pack_info *packet, uint32_t active_timeout, uint32_t inactive_timeout)
{
    std::string pack_id = fm::generate_packet_id(packet);

    auto flow_it = fm::active_flows.find(pack_id);
    if(flow_it != fm::active_flows.end())
    {
        Flow *found_flow = flow_it->second;

        tm_status_t timeout_status = found_flow->check_timeouts(packet, active_timeout, inactive_timeout);

        // checks both active and inactive timeout since, the result is the same
        if(timeout_status == tm_status_t::ACTIVE)
        {
            // flow was found and is active so update the flow and return
            found_flow->add_packet(packet);
            return;
        }
        else
        {
            fm::inactive_flows.push_back(found_flow);         
            fm::active_flows.erase(flow_it);
        }
    }
    
    // flow not found or previous flow was inactivated
    Flow *new_flow = new Flow(packet);
    fm::active_flows[pack_id] = new_flow;
}

/** A simple function that prints all active and inactive flows, used for debugging
*/
void fm::print_flows()
{
    using namespace std;

    cout << "------ [[ ACTIVE FLOWS ]] ------" << std::endl;
    for(auto& element: fm::active_flows)
    {
        element.second->print_flow();
    }
    cout << endl;

    cout << "------ [[ INACTIVE FLOWS ]] ------" << std::endl;
    for(auto& element: fm::inactive_flows)
    {
        element->print_flow();
    }
    cout << endl;
}
