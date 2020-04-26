// ipv6_parser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

class ipv6_parser
{
public:
	// ********************************************************************************
	/// <summary>
	/// parses IP headers until the transport payload
	/// </summary>
	/// <param name="ip_header">pointer to IP header</param>
	/// <param name="packet_size">size of IP packet in octets</param>
	/// <param name="ip_proto">returns IPPROTO_ value</param>
	/// <returns>pointer to IP packet payload (TCP, UDP, ICMPv6 and etc..)</returns>
	// ********************************************************************************
	static std::pair<void*, unsigned char> find_transport_header(
		const ipv6hdr_ptr ip_header,		
		const unsigned packet_size
	)
	{
		unsigned char next_proto = 0;
		ipv6ext_ptr next_header = nullptr;
		void* the_header = nullptr;

		//
		// Parse IPv6 headers
		//

		// Check if this IPv6 packet
		if (ip_header->ip6_v != 6)
		{
			return { nullptr, next_proto };
		}

		// Find the first header
		next_proto = ip_header->ip6_next;
		next_header = reinterpret_cast<ipv6ext_ptr>(ip_header + 1);

		// Loop until we find the last IP header
		while (TRUE)
		{
			// Ensure that current header is still within the packet
			if (reinterpret_cast<char*>(next_header) > reinterpret_cast<char*>(ip_header) + packet_size - sizeof(ipv6ext))
			{
				return { nullptr, next_proto };
			}

			switch (next_proto)
			{
				// Fragmentation
			case IPPROTO_FRAGMENT:
			{
				const auto frag = reinterpret_cast<ipv6ext_frag_ptr>(next_header);

				// If this isn't the FIRST fragment, there won't be a TCP/UDP header anyway
				if ((frag->ip6_offlg & 0xFC) != 0)
				{
					// The offset is non-zero
					next_proto = frag->ip6_next;

					return { nullptr, next_proto };
				}

				// Otherwise it's either an entire segment or the first fragment
				next_proto = frag->ip6_next;

				// Return next octet following the fragmentation header
				next_header = reinterpret_cast<ipv6ext_ptr>(reinterpret_cast<char*>(next_header) + sizeof(ipv6ext_frag));

				return { next_header, next_proto };
			}

			// Headers we just skip over
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
				next_proto = next_header->ip6_next;

				// As per RFC 2460 : ip6ext_len specifies the extended
				// header length, in units of 8 octets *not including* the
				// first 8 octets.

				next_header = reinterpret_cast<ipv6ext_ptr>(reinterpret_cast<char*>(next_header) + 8 + (next_header->ip6_len) * 8);
				break;

			default:
				// No more IPv6 headers to skip
				return { next_header, next_proto };
			}
		}
	}
};

int main()
{
	auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
		[](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			const auto ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

			if (ntohs(ethernet_header->h_proto) == ETH_P_IPV6)
			{
				const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

				const auto transport_header = ipv6_parser::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

				if (transport_header.first && transport_header.second == IPPROTO_TCP)
				{
					const auto tcp_header = reinterpret_cast<tcphdr_ptr>(transport_header.first);

					auto process = process_lookup<net::ip_address_v6>::get_process_helper().lookup_process_for_tcp<false>(
						ip_session<net::ip_address_v6>(ip_header->ip6_dst, ip_header->ip6_src, ntohs(tcp_header->th_dport), ntohs(tcp_header->th_sport)));

					if (process == nullptr)
					{
						process_lookup<net::ip_address_v6>::get_process_helper().actualize(true, false);
						process = process_lookup<net::ip_address_v6>::get_process_helper().lookup_process_for_tcp<false>(
							ip_session<net::ip_address_v6>(ip_header->ip6_dst, ip_header->ip6_src, ntohs(tcp_header->th_dport), ntohs(tcp_header->th_sport)));
					}

					std::cout << net::ip_address_v6(ip_header->ip6_src) << ":" << ntohs(tcp_header->th_sport) << " --> " <<
						net::ip_address_v6(ip_header->ip6_dst) << ":" << ntohs(tcp_header->th_dport);

					if (process != nullptr)
						std::wcout << " Id: " << process->id << " Name: " << process->name << " PathName: " << process->path_name << "\n";
					else
						std::wcout << "\n";
				}
			}

			return ndisapi::packet_action::pass;
		},
		[](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			const auto ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

			if (ntohs(ethernet_header->h_proto) == ETH_P_IPV6)
			{
				const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ethernet_header + 1);

				const auto transport_header = ipv6_parser::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

				if (transport_header.first && transport_header.second == IPPROTO_TCP)
				{
					const auto tcp_header = reinterpret_cast<tcphdr_ptr>(transport_header.first);

					auto process = process_lookup<net::ip_address_v6>::get_process_helper().lookup_process_for_tcp<false>(
						ip_session<net::ip_address_v6>(ip_header->ip6_src, ip_header->ip6_dst, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport)));

					if(process == nullptr)
					{
						process_lookup<net::ip_address_v6>::get_process_helper().actualize(true, false);
						process = process_lookup<net::ip_address_v6>::get_process_helper().lookup_process_for_tcp<false>(
							ip_session<net::ip_address_v6>(ip_header->ip6_src, ip_header->ip6_dst, ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport)));
					}

					std::cout << net::ip_address_v6(ip_header->ip6_src) << ":" << ntohs(tcp_header->th_sport) << " --> " <<
						net::ip_address_v6(ip_header->ip6_dst) << ":" << ntohs(tcp_header->th_dport);

					if (process != nullptr)
						std::wcout << " Id: " << process->id << " Name: " << process->name << " PathName: " << process->path_name << "\n";
					else
						std::wcout << "\n";
				}
			}

			return ndisapi::packet_action::pass;
		}, true);

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

	ndis_api->start_filter(index - 1);

	std::cout << "Press any key to stop filtering" << std::endl;

	std::ignore = _getch();

	std::cout << "Exiting..." << std::endl;

	return 0;
}

