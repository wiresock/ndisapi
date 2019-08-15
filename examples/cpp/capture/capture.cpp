// capture.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <fstream>

int main()
{
	std::string file_name;
	std::ofstream file_stream;
	
	auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
		[&file_stream](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			static auto last_time_stamp = time(nullptr);
			static uint32_t sequence = 0;

			const auto current_time = time(nullptr);
			if (current_time == last_time_stamp)
			{
				++sequence;
			}
			else
			{
				last_time_stamp = current_time;
				sequence = 0;
			}
		
			const auto ethernet_header = reinterpret_cast<char*>(buffer.m_IBuffer);

			file_stream << pcap::pcap_record_header(static_cast<const uint32_t>(current_time), sequence, buffer.m_Length, buffer.m_Length, ethernet_header);
			
			return ndisapi::packet_action::pass;
		},
		[&file_stream](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			static auto last_time_stamp = time(nullptr);
			static uint32_t sequence = 0;

			const auto current_time = time(nullptr);
			if (current_time == last_time_stamp)
			{
				++sequence;
			}
			else
			{
				last_time_stamp = current_time;
				sequence = 0;
			}

			const auto ethernet_header = reinterpret_cast<char*>(buffer.m_IBuffer);

			file_stream << pcap::pcap_record_header(static_cast<const uint32_t>(current_time), sequence, buffer.m_Length, buffer.m_Length, ethernet_header);

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

	std::cout << std::endl << "Enter filename to save the capture:";
	std::cin >> file_name;

	file_stream.open(file_name, std::ofstream::binary |std::ofstream::out |  std::ofstream::trunc);

	if (file_stream)
	{
		const pcap::pcap_file_header header{ 2,4,0,0,1514,pcap::LINKTYPE_ETHERNET };
		file_stream << header;
	}
	else
	{
		std::cout << "Failed to open " << file_name << "\n";
		return 0;
	}

	ndis_api->start_filter(index - 1);

	std::cout << "Press any key to stop filtering" << std::endl;

	std::ignore = _getch();

	std::cout << "Exiting..." << std::endl;

	file_stream.close();

	return 0;
}

