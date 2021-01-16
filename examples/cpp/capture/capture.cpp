// capture.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

int main()
{
	try {
		std::string file_name;
		pcap::pcap_file_storage file_stream;

		auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
			[&file_stream](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
			{
				file_stream << buffer;

				return ndisapi::packet_action::pass;
			},
			[&file_stream](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
			{
				file_stream << buffer;

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

		std::cout << std::endl << "Enter filename to save the capture:";
		std::cin >> file_name;

		file_stream.open(file_name);

		if (!file_stream)
		{
			std::cout << "Failed to open " << file_name << "\n";
			return 0;
		}

		ndis_api->start_filter(index - 1);

		std::cout << "Press any key to stop filtering" << std::endl;

		std::ignore = _getch();

		std::cout << "Exiting..." << std::endl;
	}
	catch(const std::exception& ex)
	{
		std::cout << "Exception occurred: " << ex.what() << std::endl;
	}

	return 0;
}

