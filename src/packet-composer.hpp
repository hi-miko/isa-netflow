// Patrik Uher
// xuherp02

#include <cstdint>
#include <chrono>
#include <vector>

#include "flow.hpp"

using namespace std;

#ifndef PACKET_COMPOSER_HPP
#define PACKET_COMPOSER_HPP

class PacketComposer
{
public:
	using packet_t = char *;

	// points to the start of the packet
	packet_t packet;

	size_t packet_member_count;
	size_t packet_size;

private:
	packet_t packet_end;
	size_t packet_free_bytes;

public:
	// public methods
	PacketComposer();

	void clear_packet();
	void print_packet_info();
    packet_t create_netflow_packet(std::chrono::duration<long, std::ratio<1l, 1000000000l>>, int, std::vector<Flow *>);

private:
	void allocate_packet(size_t);
	void packet_add_uint8(uint8_t);
	void packet_add_uint16(uint16_t);
	void packet_add_uint32(uint32_t);
    void packet_create_nfheader();
};

#endif // PACKET_COMPOSER_HPP
