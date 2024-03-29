// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  dnstrace.cpp  
/// Abstract: Defines the entry point for the console application.
/// </summary>
// --------------------------------------------------------------------------------

#include "stdafx.h"

static const unsigned short ipport_dns = 53;

std::string get_type(const uint16_t type)
{
	switch (type)
	{
	case 1:
		return std::string("A");
	case 2:
		return std::string("NS");
	case 5:
		return std::string("CNAME");
	case 6:
		return std::string("SOA");
	case 11:
		return std::string("WKS");
	case 12:
		return std::string("PTR");
	case 15:
		return std::string("MX");
	case 28:
		return std::string("AAA");
	case 33:
		return std::string("SRV");
	case 255:
		return std::string("ANY");
	default:
		break;
	}

	return std::string("UNKNOWN");
}

size_t get_url_size(char data[])
{
	size_t i = 0;
	size_t to_skip = data[0];

	// skip each set of chars until (0) at the end
	while (to_skip != 0)
	{
		i += to_skip + 1;
		to_skip = data[i];
	}
	// return the length of the array including the (0) at the end
	return i + 1;
}

std::string get_url(char data[])
{
	const auto length = get_url_size(data) - 1;

	std::vector<char> url;
	url.reserve(length);

	size_t i = 0;
	size_t to_read = data[0];
	size_t start = 0;
	i++;

	while (to_read != 0)
	{
		if (start)
			url.push_back('.');

		// get everything between the dots
		for (; i <= start + to_read; i++)
			url.push_back(data[i]);

		// next chunk
		to_read = data[i];
		start = i;

		i++;
	}

	return std::string(url.cbegin(), url.cend());
}

void dump_dns_response_data(const dns_header_ptr dns_header_ptr, const uint16_t length)
{
	PDNS_RECORD dns_query_result_ptr = nullptr;

	auto dns_message_buffer_ptr = reinterpret_cast<PDNS_MESSAGE_BUFFER>(dns_header_ptr);

	// Convert DNS header to host order
	DNS_BYTE_FLIP_HEADER_COUNTS(&dns_message_buffer_ptr->MessageHead);

	std::cout << std::setw(16) << "id: " << dns_message_buffer_ptr->MessageHead.Xid << std::endl;
	std::cout << std::setw(16) << "# questions: " << dns_message_buffer_ptr->MessageHead.QuestionCount << std::endl;
	std::cout << std::setw(16) << "# answers: " << dns_message_buffer_ptr->MessageHead.AnswerCount << std::endl;
	std::cout << std::setw(16) << "# ns: " << dns_message_buffer_ptr->MessageHead.NameServerCount << std::endl;
	std::cout << std::setw(16) << "# ar: " << dns_message_buffer_ptr->MessageHead.AdditionalCount << std::endl;

	auto num_questions = dns_message_buffer_ptr->MessageHead.QuestionCount;

	if (num_questions)
		std::cout << "QUESTIONS" << std::endl;

	auto p_data = reinterpret_cast<char*>(dns_header_ptr + 1);
	while (num_questions--)
	{
		const auto q_record_ptr = reinterpret_cast<qr_record_ptr>(p_data + get_url_size(p_data));
		std::cout << std::setw(16) << "TYPE: " << get_type(ntohs(q_record_ptr->type)) << std::endl;
		std::cout << std::setw(16) << "CLASS: " << ntohs(q_record_ptr->clas) << std::endl;
		std::cout << std::setw(16) << "URL: " << get_url(p_data) << std::endl;

		p_data = reinterpret_cast<char*>(q_record_ptr + 1);
	}

	if (dns_message_buffer_ptr->MessageHead.AnswerCount)
		std::cout << "ANSWERS" << std::endl;

	// Get DNS records from the DNS response
	const auto dns_status = DnsExtractRecordsFromMessage_W(
		dns_message_buffer_ptr,
		length,
		&dns_query_result_ptr
	);

	// Revert changes in DNS header
	DNS_BYTE_FLIP_HEADER_COUNTS(&dns_message_buffer_ptr->MessageHead);

	if (dns_status == 0)
	{
		auto dns_record_ptr = dns_query_result_ptr;

		while (dns_record_ptr)
		{
			if (dns_record_ptr->wType == DNS_TYPE_A)
			{
				net::ip_address_v4 ipv4_address;

				ipv4_address.s_addr = dns_record_ptr->Data.A.IpAddress;

				std::cout << std::setw(16) << "A: " << std::string(ipv4_address) << std::endl;
			}
			else if (dns_record_ptr->wType == DNS_TYPE_AAAA)
			{
				net::ip_address_v6 ipv6_address;

				memcpy_s(
					ipv6_address.s6_addr,
					sizeof(ipv6_address.s6_addr),
					dns_record_ptr->Data.AAAA.Ip6Address.IP6Byte,
					sizeof(dns_record_ptr->Data.AAAA.Ip6Address.IP6Byte)
				);

				std::cout << std::setw(16) << "AAA: " << std::string(ipv6_address) << std::endl;
			}
			else if (dns_record_ptr->wType == DNS_TYPE_CNAME)
			{
				std::wcout << std::setw(16) << L"CNAME: " << dns_record_ptr->Data.CNAME.pNameHost << std::endl;
			}

			dns_record_ptr = dns_record_ptr->pNext;
		}
	}

	if (dns_query_result_ptr)
	{
		DnsRecordListFree(dns_query_result_ptr, DnsFreeRecordList);
	}
}

int main()
{
	auto ndis_api = std::make_unique<ndisapi::simple_packet_filter>(
		[](HANDLE, INTERMEDIATE_BUFFER& buffer)
		{
			if (const auto ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer); ntohs(
				ether_header->h_proto) == ETH_P_IP)
			{
				if (const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1); ip_header->ip_p ==
					IPPROTO_UDP)
				{
					if (const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) +
						sizeof(DWORD) * ip_header->ip_hl); ntohs(udp_header->th_sport) == ipport_dns)
					{
						std::cout << "IP HEADER" << std::endl;
						std::cout << std::setfill(' ') << std::setw(16) << "source : " << static_cast<unsigned>(
								ip_header->ip_src.S_un.S_un_b.s_b1) << "."
							<< static_cast<unsigned>(ip_header->ip_src.S_un.S_un_b.s_b2) << "."
							<< static_cast<unsigned>(ip_header->ip_src.S_un.S_un_b.s_b3) << "."
							<< static_cast<unsigned>(ip_header->ip_src.S_un.S_un_b.s_b4) << std::endl;
						std::cout << std::setw(16) << "dest : " << static_cast<unsigned>(ip_header->ip_dst.S_un.S_un_b.
								s_b1) << "."
							<< static_cast<unsigned>(ip_header->ip_dst.S_un.S_un_b.s_b2) << "."
							<< static_cast<unsigned>(ip_header->ip_dst.S_un.S_un_b.s_b3) << "."
							<< static_cast<unsigned>(ip_header->ip_dst.S_un.S_un_b.s_b4) << std::endl;
						std::cout << "UDP HEADER" << std::endl;
						std::cout << std::setw(16) << "source port : " << static_cast<unsigned>(ntohs(
							udp_header->th_sport)) << std::endl;
						std::cout << std::setw(16) << "dest port : " << static_cast<unsigned>(ntohs(
							udp_header->th_dport)) << std::endl;

						const auto dns_header = reinterpret_cast<dns_header_ptr>(udp_header + 1);

						std::cout << "DNS HEADER" << std::endl;

						dump_dns_response_data(
							dns_header,
							static_cast<uint16_t>(buffer.m_Length - (reinterpret_cast<char*>(dns_header) -
								reinterpret_cast<char*>(ether_header))));

						std::cout << std::setw(80) << std::setfill('-') << "-" << std::endl;
					}
				}
			}
			return ndisapi::simple_packet_filter::packet_action::pass;
		},
		nullptr
	);

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
