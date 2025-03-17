// Patrik Uher
// xuherp02

#include <cstdint>
#include <iostream>
#include <cstring>
#include <exception>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "packet-composer.hpp"
#include "debug-info.hpp"

using namespace std;
using pc = PacketComposer;

pc::PacketComposer()
{
	pc::packet = nullptr;
	pc::packet_end = nullptr;
	pc::packet_free_bytes = 0;
	pc::packet_member_count = 0;
	pc::packet_size = 0;
}

/** A method used to clear a packet, so a new one can be created
*/
void pc::clear_packet()
{
	if(pc::packet != nullptr)
	{
		delete[] pc::packet;
	}

	pc::packet = nullptr;
	pc::packet_end = nullptr;
	pc::packet_free_bytes = 0;
	pc::packet_member_count = 0;
	pc::packet_size = 0;
}

/** A method used to allocate bytes to a packet
*/
void pc::allocate_packet(size_t size)
{
	if(pc::packet != nullptr)
	{
        cerr << "Error: Packet already initialized" << endl;
		exit(1);
	}
	try
	{
        // Allocation failed
		pc::packet = new char[size];
	}
	catch (exception& e)
	{
        cerr << "Error: " << e.what() << endl;
		exit(99);
	}

	pc::packet_end = pc::packet;
	pc::packet_free_bytes = size;
	pc::packet_size = size;
}

/** A method for adding 1 byte numbers into a packet
*/
void pc::packet_add_uint8(uint8_t number)
{
	if(pc::packet == nullptr)
	{
		cerr << "Error: Packet is not initialized!" << endl;
		exit(1);
	}
	
	if(pc::packet_free_bytes < sizeof(number))
	{
		cerr << "Error: Trying to copy to out of bounds!" << endl;
		exit(1);
	}
	
    // don't need htons because its only a 1 byte value
	uint8_t h_number = number;

	auto ret = memcpy(reinterpret_cast<void *>(pc::packet_end), reinterpret_cast<void *>(&h_number), sizeof(h_number));
    if(ret == nullptr)
    {
        cerr << "Error: memcpy failed to copy to packet" << endl;
		exit(99);
    }

	pc::packet_end += sizeof(number);
	pc::packet_free_bytes -= sizeof(number);
	pc::packet_member_count++;
}

/** A method for adding 2 byte numbers into a packet
*/
void pc::packet_add_uint16(uint16_t number)
{
	if(pc::packet == nullptr)
	{
		cerr << "Error: Packet is not initialized!" << endl;
		exit(1);
	}
	
	if(pc::packet_free_bytes < sizeof(number))
	{
		cerr << "Error: Trying to copy to out of bounds!" << endl;
		exit(1);
	}
	
	uint16_t h_number = htons(number);

	auto ret = memcpy(reinterpret_cast<void *>(pc::packet_end), reinterpret_cast<void *>(&h_number), sizeof(h_number));
    if(ret == nullptr)
    {
        cerr << "Error: memcpy failed to copy to packet" << endl;
		exit(99);
    }

	pc::packet_end += sizeof(number);
	pc::packet_free_bytes -= sizeof(number);
	pc::packet_member_count++;
}

/** A method for adding 4 byte numbers into a packet
*/
void pc::packet_add_uint32(uint32_t number)
{
	if(pc::packet == nullptr)
	{
		cerr << "Error: Packet is not initialized!" << endl;
		exit(1);
	}
	
	if(pc::packet_free_bytes < sizeof(number))
	{
		cerr << "Error: Trying to copy to out of bounds!" << endl;
		exit(1);
	}
	
	uint32_t h_number = htonl(number);

	auto ret = memcpy(reinterpret_cast<void *>(pc::packet_end), reinterpret_cast<void *>(&h_number), sizeof(h_number));
    if(ret == nullptr)
    {
        cerr << "Error: memcpy failed to copy to packet" << endl;
		exit(99);
    }

	pc::packet_end += sizeof(number);
	pc::packet_free_bytes -= sizeof(number);
	pc::packet_member_count++;
}

/** A method that creates and returns a packet filled with data based on the netflow v5 header and body
*/
pc::packet_t pc::create_netflow_packet(std::chrono::duration<long, std::ratio<1l, 1000000000l>> dev_epoch, int total_flows, std::vector<Flow *> flow_buffer)
{
    auto now = std::chrono::system_clock::now();
    auto curr_epoch = now.time_since_epoch();
    auto curr_epoch_s = chrono::duration_cast<chrono::seconds>(curr_epoch).count();
    auto curr_epoch_us = chrono::duration_cast<chrono::microseconds>(curr_epoch).count();
    auto curr_epoch_ms = chrono::duration_cast<chrono::milliseconds>(curr_epoch).count();
    auto dev_epoch_ms = chrono::duration_cast<chrono::milliseconds>(dev_epoch).count();

    // 1 flow has 48 bytes and the header has 24 bytes
    pc::allocate_packet(24 + (flow_buffer.size() * 48));

    // netflow v5 header
    pc::packet_add_uint16(5);
    pc::packet_add_uint16(flow_buffer.size());
    pc::packet_add_uint32(static_cast<uint32_t>(curr_epoch_ms - dev_epoch_ms));
    pc::packet_add_uint32(static_cast<uint32_t>(curr_epoch_s));
    pc::packet_add_uint32(static_cast<uint32_t>(curr_epoch_us % 1000000000));
    pc::packet_add_uint32(static_cast<uint32_t>(total_flows));
    // 0's are added when a data field has nothing that should be added to it, or when there needs to be padding
    pc::packet_add_uint8(0);
    pc::packet_add_uint8(0);
    pc::packet_add_uint16(0);

    for(auto& flow: flow_buffer)
    {
        pc::packet_add_uint32(flow->src_ip);
        pc::packet_add_uint32(flow->dst_ip);

        pc::packet_add_uint32(0);
        pc::packet_add_uint16(0);
        pc::packet_add_uint16(0);

        pc::packet_add_uint32(flow->packet_cnt);
        pc::packet_add_uint32(flow->ip_octet_cnt);

        // convert from usecs that the program uses to msecs
        pc::packet_add_uint32(flow->first_packet_time/1000);
        pc::packet_add_uint32(flow->last_packet_time/1000);

        pc::packet_add_uint16(flow->src_port);
        pc::packet_add_uint16(flow->dst_port);

        // padding
        pc::packet_add_uint8(0);

        pc::packet_add_uint8(flow->tcp_flags);
        pc::packet_add_uint8(flow->ip_proto_type);

        pc::packet_add_uint8(0);
        pc::packet_add_uint16(0);
        pc::packet_add_uint16(0);
        pc::packet_add_uint8(0);
        pc::packet_add_uint8(0);

        // padding
        pc::packet_add_uint16(0);
    }

    if(debugActive)
    {
        pc::print_packet_info();
    }

    return pc::packet;
}

/** Prints the data of the packet that is being constructed
*/
void pc::print_packet_info()
{
	cout << "[[ PACKET CREATION INFO ]] " << endl;
    cout << endl;
	cout << "\tbytes: " << pc::packet_size << endl;
	cout << "\tmember count: " << pc::packet_member_count << endl;
    // if this method is used at the of packet creation this should be 0, if not a wrong amount of bytes were allocated to the packet
	cout << "\tfree space: " << pc::packet_free_bytes << endl;
    cout << endl;
}
