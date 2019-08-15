// dns_proxy.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

int main()
{
	net::ip_address_v4 dns_server_ip_address_v4;
	
	// Redirects all DNS packet to dns_server_ip_address_v4:53
	ndisapi::udp_proxy_server<ndisapi::udp_proxy_socket<net::ip_address_v4>> proxy([&dns_server_ip_address_v4](
		net::ip_address_v4 local_address, const uint16_t local_port, net::ip_address_v4 remote_address, const uint16_t remote_port)->
		std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<ndisapi::udp_proxy_server<ndisapi::
		udp_proxy_socket<net::ip_address_v4>>::negotiate_context_t>>
	{
		if (remote_port == 53)
		{
			std::cout << "Redirecting DNS " << local_address << ":" << local_port << " -> " << remote_address << ":" << remote_port << " to " << dns_server_ip_address_v4 << ":53\n";
			return std::make_tuple(dns_server_ip_address_v4, 53, nullptr);
		}
		else
		{
			return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
		}
	});
	
	if (proxy.IsDriverLoaded())
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
	for (auto& e : proxy.get_interface_list())
	{
		std::cout << ++index << ")\t" << e << std::endl;
	}

	std::cout << std::endl << "Select interface to filter:";
	std::cin >> index;

	if (index > proxy.get_interface_list().size())
	{
		std::cout << "Wrong parameter was selected. Out of range." << std::endl;
		return 0;
	}

	std::string dns_address;
	std::cout << std::endl << "DNS server IP address to forward requests to: ";
	std::cin >> dns_address;
	dns_server_ip_address_v4 = net::ip_address_v4(dns_address);

	proxy.start(index - 1);

	std::cout << "Press any key to stop filtering" << std::endl;

	std::ignore = _getch();

	std::cout << "Exiting..." << std::endl;

	return 0;
}

