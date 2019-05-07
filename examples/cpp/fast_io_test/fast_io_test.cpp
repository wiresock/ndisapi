// fast_io_test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

int main()
{
	auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
		nullptr,
		[](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			thread_local ndisapi::local_redirector redirect{ 666 };

			const auto ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

			if (ntohs(ether_header->h_proto) == ETH_P_IP)
			{
				const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

				if (ip_header->ip_p == IPPROTO_TCP)
				{
					const auto tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD)*ip_header->ip_hl);

					if(ntohs(tcp_header->th_dport) == 4455)
					{
						if(redirect.process_client_to_server_packet(buffer))
						{
							CNdisApi::RecalculateTCPChecksum(&buffer);
							CNdisApi::RecalculateIPChecksum(&buffer);
							buffer.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
						}
					}
					else if(ntohs(tcp_header->th_sport) == redirect.get_proxy_port())
					{
						if (redirect.process_server_to_client_packet(buffer))
						{
							CNdisApi::RecalculateTCPChecksum(&buffer);
							CNdisApi::RecalculateIPChecksum(&buffer);
							buffer.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
						}
					}
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
	for (auto& e : ndis_api->get_interface_list())
	{
		std::cout << ++index << ")\t" << e << std::endl;
	}

	std::cout << std::endl << "Select interface to filter:";
	std::cin >> index;

	if (index > ndis_api->get_interface_list().size())
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

