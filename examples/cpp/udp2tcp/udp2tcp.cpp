// udp2tcp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

bool load_filters(const CNdisApi& api, const bool is_server, const uint16_t port)
{
	// Allocate table filters for 3 filters
	const DWORD table_size = sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * 2;
	auto* filter_table = static_cast<PSTATIC_FILTER_TABLE>(malloc(table_size));

	if (!filter_table)
		return false;
	
	memset(filter_table, 0, table_size);

	filter_table->m_TableSize = 3;

	//****************************************************************************************
	// 1. Incoming TCP packets filter: REDIRECT IN TCP packets with PORT == "port" IPv4
	// Common values
	filter_table->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
	filter_table->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
	filter_table->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_REDIRECT;
	filter_table->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE;

	// Network layer filter
	filter_table->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV4;
	filter_table->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
	filter_table->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_TCP;

	// Transport layer filter 
	filter_table->m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = TCPUDP;
	if (is_server)
	{
		filter_table->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_DEST_PORT;
		filter_table->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = port;
		filter_table->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = port;
	}
	else
	{
		filter_table->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_SRC_PORT;
		filter_table->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = port;
		filter_table->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = port;
	}

	//**************************************************************************************
	// 2. Outgoing UDP packets filter: REDIRECT OUT UDP packets with PORT "port"
	// Common values
	filter_table->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
	filter_table->m_StaticFilters[1].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
	filter_table->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_REDIRECT;
	filter_table->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

	// Network layer filter
	filter_table->m_StaticFilters[1].m_NetworkFilter.m_dwUnionSelector = IPV4;
	filter_table->m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
	filter_table->m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_UDP;

	// Transport layer filter 
	filter_table->m_StaticFilters[1].m_TransportFilter.m_dwUnionSelector = TCPUDP;
	if (is_server)
	{
		filter_table->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_SRC_PORT;
		filter_table->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = port;
		filter_table->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = port;
	}
	else
	{
		filter_table->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_DEST_PORT;
		filter_table->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = port;
		filter_table->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = port;
	}

	//***************************************************************************************
	// 2. Pass all packets (skipped by previous filters) without processing in user mode
	// Common values
	filter_table->m_StaticFilters[2].m_Adapter.QuadPart = 0; // applied to all adapters
	filter_table->m_StaticFilters[2].m_ValidFields = 0;
	filter_table->m_StaticFilters[2].m_FilterAction = FILTER_PACKET_PASS;
	filter_table->m_StaticFilters[2].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;


	return api.SetPacketFilterTable(filter_table);
}

int main()
{
	auto is_server = false;
	uint16_t port = 0;
	pcap::pcap_file_storage file_stream ("capture.pcap");
	
	auto ndis_api = std::make_unique<ndisapi::simple_packet_filter>(
		[&is_server, &port, &file_stream](HANDLE, INTERMEDIATE_BUFFER& buffer)
		{
			if (auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); ntohs(
				ethernet_header->h_proto) == ETH_P_IP)
			{
				if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1); ip_header->ip_p ==
					IPPROTO_TCP)
				{
					if (auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
						sizeof(DWORD) * ip_header->ip_hl); is_server?(ntohs(tcp_header->th_dport) == port):(ntohs(tcp_header->th_sport) == port))
					{
						auto* const payload = reinterpret_cast<unsigned char*>(tcp_header) + 4 * tcp_header->th_off;
						const auto payload_length = buffer.m_Length - (sizeof(ether_header) + 4 * ip_header->ip_hl + 4 *
							tcp_header->th_off);

						auto* const udp_header = reinterpret_cast<udphdr_ptr>(tcp_header);
						udp_header->length = htons(static_cast<uint16_t>(payload_length) + sizeof(udphdr));
						memmove(reinterpret_cast<unsigned char*>(udp_header) + sizeof(udphdr), payload, payload_length);
						ip_header->ip_p = IPPROTO_UDP;
						ip_header->ip_len = htons(4 * ip_header->ip_hl + sizeof(udphdr) + static_cast<uint16_t>(payload_length));
						buffer.m_Length = sizeof(ether_header) + 4 * ip_header->ip_hl + sizeof(udphdr) + static_cast<uint32_t>(payload_length);
						
						CNdisApi::RecalculateUDPChecksum(&buffer);
						CNdisApi::RecalculateIPChecksum(&buffer);

						file_stream << buffer;
					}
				}
			}

			return ndisapi::simple_packet_filter::packet_action::pass;
		},
		[&is_server, &port, &file_stream](HANDLE, INTERMEDIATE_BUFFER& buffer)
		{
			if (auto* const ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); ntohs(
				ethernet_header->h_proto) == ETH_P_IP)
			{
				if (auto* const ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1); ip_header->ip_p ==
					IPPROTO_UDP)
				{
					if (auto* const udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
						sizeof(DWORD) * ip_header->ip_hl); is_server ? (ntohs(udp_header->th_sport) == port) : (ntohs(udp_header->th_dport) == port))
					{
						file_stream << buffer;
						
						auto* const payload = reinterpret_cast<unsigned char*>(udp_header) + sizeof(udphdr);
						const auto payload_length = buffer.m_Length - (payload - reinterpret_cast<unsigned char*>(ethernet_header));

						auto* const tcp_header = reinterpret_cast<tcphdr_ptr>(udp_header);
						memmove(reinterpret_cast<unsigned char*>(tcp_header) + sizeof(tcphdr), payload, payload_length);
						tcp_header->th_off = TCP_NO_OPTIONS;  // header size offset for packed data
						tcp_header->th_flags = TH_ACK;  // set packet type to ACK
						tcp_header->th_win = htons(65000);
						tcp_header->th_urp = 0;
						ip_header->ip_p = IPPROTO_TCP;
						ip_header->ip_len = htons(4 * ip_header->ip_hl + sizeof(tcphdr) + static_cast<uint16_t>(payload_length));
						buffer.m_Length = sizeof(ether_header) + 4 * ip_header->ip_hl + sizeof(tcphdr) + static_cast<uint32_t>(payload_length);
						
						CNdisApi::RecalculateTCPChecksum(&buffer);
						CNdisApi::RecalculateIPChecksum(&buffer);
					}
				}
			}

			return ndisapi::simple_packet_filter::packet_action::pass;
		});

	if (ndis_api->IsDriverLoaded())
	{
		std::cout << "WinpkFilter is loaded" << std::endl << std::endl;
	}
	else
	{
		std::cout << "WinpkFilter is not loaded" << std::endl << std::endl;
		return 1;
	}

	std::cout << "Available network interfaces:" << std::endl << std::endl;
	size_t index = 0;
	size_t mode = 0;
	
	for (auto& e : ndis_api->get_interface_names_list())
	{
		std::cout << ++index << ")\t" << e << std::endl;
	}

	std::cout << std::endl << "Select interface to filter:";
	std::cin >> index;

	if (index > ndis_api->get_interface_names_list().size())
	{
		std::cout << "Wrong parameter was selected. Out of range." << std::endl;
		return 0;
	}

	std::cout << std::endl << "Specify server(1) or client mode(0):";
	std::cin >> mode;

	if (mode != 0 && mode != 1)
	{
		std::cout << "Wrong parameter was selected. Please specify 0 or 1." << std::endl;
		return 0;
	}

	is_server = mode ? true : false;

	std::cout << std::endl << "Specify UDP port number:";
	std::cin >> port;

	if (port == 0)
	{
		std::cout << "Wrong parameter was selected. Please specify port number between 1 and 65535." << std::endl;
		return 0;
	}

	load_filters(*ndis_api, is_server, port);

	ndis_api->start_filter(index - 1);

	std::cout << "Press any key to stop filtering" << std::endl;

	std::ignore = _getch();

	std::cout << "Exiting..." << std::endl;

	return 0;
}

