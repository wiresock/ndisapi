// dns_proxy.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

void log_printer(const char* log)
{
	static std::mutex log_lock;  // NOLINT(clang-diagnostic-exit-time-destructors)

	std::lock_guard<std::mutex> lock(log_lock);

	std::cout << log << std::endl;
}

int main()
{
	try {
		std::string dns_address;
		std::cout << std::endl << "DNS server IP address to forward requests to: ";
		std::cin >> dns_address;
		auto dns_server_ip_address_v4 = net::ip_address_v4(dns_address);

		// Redirects all DNS packet to dns_server_ip_address_v4:53
		ndisapi::udp_proxy_server<ndisapi::udp_proxy_socket<net::ip_address_v4>> proxy([&dns_server_ip_address_v4](
			const net::ip_address_v4 local_address, const uint16_t local_port, const net::ip_address_v4 remote_address, const uint16_t remote_port)->
			std::tuple<net::ip_address_v4, uint16_t, std::unique_ptr<ndisapi::udp_proxy_server<ndisapi::
			udp_proxy_socket<net::ip_address_v4>>::negotiate_context_t>>
		{
			if (remote_port == 53)
			{
				std::cout << "Redirecting DNS " << local_address << ":" << local_port << " -> " << remote_address << ":" << remote_port << " to " << dns_server_ip_address_v4 << ":53\n";
				return std::make_tuple(dns_server_ip_address_v4, 53, nullptr);
			}

			return std::make_tuple(net::ip_address_v4{}, 0, nullptr);
		}, dns_server_ip_address_v4, log_printer, ndisapi::log_level::all);

		proxy.start();

		std::cout << "Press any key to stop filtering" << std::endl;

		std::ignore = _getch();

		std::cout << "Exiting..." << std::endl;
	}
	catch(const std::exception& ex)
	{
		std::cout << "exception occurred: " << ex.what() << std::endl;
	}

	return 0;
}

