// sni_inspector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <optional>

class tls_parser
{
	static constexpr auto server_name_len = 256;
	static constexpr auto tls_header_len = 5;
	static constexpr auto tls_handshake_content_type = 0x16;
	static constexpr auto tls_handshake_type_client_hello = 0x01;

	static std::optional<std::string> parse_server_name_extension(const uint8_t* data, const size_t length) 
	{
		size_t position = 2; // skip server name list length

		while (position + 3 < length) 
		{
			const auto len = (static_cast<size_t>(data[position + 1]) << 8) + static_cast<size_t>(data[position + 2]);

			if (position + 3 + len > length)
			{
				std::cout << "Invalid TLS client hello" << "\n";
				return std::nullopt;
			}

			switch (data[position]) // name type
			{ 
			case 0x00: // host_name
				return std::string(reinterpret_cast<const char*>(data + position + 3), len);
			default:
				std::cout << "Unknown server name extension name type: " << data[position] << "\n";
				break;
			}
			position += 3 + len;
		}
		
		// Check we ended where we expected to
		if (position != length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		std::cout << "No Host header included in this request" << "\n";
		return std::nullopt;
	}

	static std::optional<std::string> parse_extensions(const uint8_t* data, const size_t length) 
	{
		size_t position = 0;

		// Parse each 4 bytes for the extension header
		while (position + 4 <= length) 
		{
			// Extension Length
			const auto len = (static_cast<size_t>(data[position + 2]) << 8) + static_cast<size_t>(data[position + 3]);

			// Check if it's a server name extension
			if (data[position] == 0x00 && data[position + 1] == 0x00) 
			{
				// There can be only one extension of each type, so we break our state and move p to beginning of the extension here
				if (position + 4 + len > length)
				{
					std::cout << "Invalid TLS client hello" << "\n";
					return std::nullopt;
				}

				return parse_server_name_extension(data + position + 4, len);
			}
			position += 4 + len; // Advance to the next extension header
		}

		// Check we ended where we expected to
		if (position != length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		std::cout << "No Host header included in this request" << "\n";
		return std::nullopt;
	}

public:

	// ********************************************************************************
	/// <summary>
	/// Parse a TLS packet for the Server Name Indication extension in the client
	/// hello handshake, returning the first server name found
	/// </summary>
	/// <param name="data">SSL packet pointer</param>
	/// <param name="length">SSL packet size</param>
	/// <returns>optional string with SNI found </returns>
	// ********************************************************************************
	static std::optional<std::string> parse_tls_header(const uint8_t* data, size_t length) 
	{
		size_t position = tls_header_len;

		// Check that our TCP payload is at least large enough for a TLS header
		if (length < tls_header_len)
		{
			std::cout << "Incomplete TLS client hello" << "\n";
			return std::nullopt;
		}

		// SSL 2.0 compatible Client Hello
		// High bit of first byte (length) and content type is Client Hello
		// See RFC5246 Appendix E.2
		if (data[0] & 0x80 && data[2] == 1) 
		{
			std::cout << "Received SSL 2.0 Client Hello which can not support SNI." << "\n";
			return std::nullopt;
		}

		const auto tls_content_type = data[0];
		if (tls_content_type != tls_handshake_content_type) 
		{
			std::cout << "Request did not begin with TLS handshake." << "\n";
			return std::nullopt;
		}

		const auto tls_version_major = data[1];
		const auto tls_version_minor = data[2];
		if (tls_version_major < 3) 
		{
			std::cout << "Received SSL " << tls_version_major << "." << tls_version_minor << " handshake which can not support SNI." << "\n";
			return std::nullopt;
		}

		// TLS record length
		auto len = (static_cast<size_t>(data[3]) << 8) + static_cast<size_t>(data[4]) + tls_header_len;
		length = min(length, len);

		// Check we received entire TLS record length
		if (length < len)
			return std::nullopt;

		// Handshake
		if (position + 1 > length) 
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		if (data[position] != tls_handshake_type_client_hello) 
		{
			std::cout << "Not a client hello" << "\n";
			return std::nullopt;
		}

		// Skip past fixed length records:
		//   1	Handshake Type
		//   3	Length
		//   2	Version (again)
		//   32	Random
		//   to	Session ID Length

		position += 38;

		// Session ID
		if (position + 1 > length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = static_cast<size_t>(data[position]);
		position += 1 + len;

		// Cipher Suites
		if (position + 2 > length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = (static_cast<size_t>(data[position]) << 8) + static_cast<size_t>(data[position + 1]);
		position += 2 + len;

		// Compression Methods
		if (position + 1 > length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = static_cast<size_t>(data[position]);
		position += 1 + len;

		if (position == length && tls_version_major == 3 && tls_version_minor == 0) 
		{
			std::cout << "Received SSL 3.0 handshake without extensions" << "\n";
			return std::nullopt;
		}

		// Extensions
		if (position + 2 > length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = (static_cast<size_t>(data[position]) << 8) + static_cast<size_t>(data[position + 1]);
		position += 2;

		if (position + len > length)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		return parse_extensions(data + position, len);
	}
};

class http_parser
{
	static constexpr auto server_name_len = 256;
	static constexpr auto http_request_min_len = 26;

	static size_t next_header(const char** data, size_t* length) 
	{
		// walk data stream until the end of the header
		while (*length > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') 
		{
			(*length)--;
			(*data)++;
		}

		// advanced past the <CR><LF> pair
		*data += 2;
		*length -= 2;

		// Find the length of the next header
		size_t header_length = 0;
		while (*length > header_length + 1
			&& (*data)[header_length] != '\r'
			&& (*data)[header_length + 1] != '\n')
		{
			header_length++;
		}

		return header_length;
	}

	static std::optional<std::string> get_header(const char* header, const char* data, size_t length) 
	{
		size_t len;

		auto header_len = strlen(header);

		// loop through headers stopping at first blank line
		while ((len = next_header(&data, &length)) != 0)
		{
			if (len > header_len && _strnicmp(header, data, header_len) == 0)
			{
				// skip leading whitespace
				while (header_len < len && isblank(data[header_len]))
					header_len++;

				return std::string(data + header_len, len - header_len);
			}
		}

		// if there is no data left after reading all the headers then we do not
		// have a complete HTTP request, there must be a blank line
		if (length == 0)
		{
			std::cout << "Incomplete HTTP request" << "\n";
			return std::nullopt;
		}

		std::cout << "No Host header included in HTTP request" << "\n";
		return std::nullopt;
	}

public:

	// ********************************************************************************
	/// <summary>
	/// Parses a HTTP request for the Host: header
	/// </summary>
	/// <param name="data">HTTP payload pointer</param>
	/// <param name="length">HTTP payload data size</param>
	/// <returns>Optional string from the Host: header</returns>
	// ********************************************************************************
	static std::optional<std::string> parse_http_header(const char* data, const size_t length)
	{
		if (length < http_request_min_len)
			return std::nullopt;

		auto host = get_header("Host:", data, length);

		if (!host.has_value())
			return host;

		// Trim the port if it follows the hostname

		for (auto i = host.value().size() - 1; i > 0; --i)
		{
			if (host.value()[i] == ':')
			{
				host.value().erase(i);
				break;
			}

			if (!isdigit(host.value()[i]))
				break;
		}

		return host;
	}
};

int main()
{
	auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
		nullptr,
		[](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			const auto ethernet_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

			if (ntohs(ethernet_header->h_proto) == ETH_P_IP)
			{
				const auto ip_header = reinterpret_cast<iphdr_ptr>(ethernet_header + 1);

				if (ip_header->ip_p == IPPROTO_TCP)
				{
					const auto tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD)*ip_header->ip_hl);

					if(ntohs(tcp_header->th_dport) == 443)
					{
						const auto payload = reinterpret_cast<unsigned char*>(tcp_header) + 4 * tcp_header->th_off;
						const auto payload_length = buffer.m_Length - (sizeof(ether_header) + 4 * ip_header->ip_hl + 4 * tcp_header->th_off);

						if ((payload[0] == 0x16) && (payload[5] == 0x1))
						{
							std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport) << " --> " <<
								net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) << " SNI: ";

							std::cout << tls_parser::parse_tls_header(payload, payload_length).value_or("no SNI") << std::endl;
						}
					}
					else if (ntohs(tcp_header->th_dport) == 80)
					{
						const auto payload = reinterpret_cast<unsigned char*>(tcp_header) + 4 * tcp_header->th_off;
						const auto payload_length = buffer.m_Length - (sizeof(ether_header) + 4 * ip_header->ip_hl + 4 * tcp_header->th_off);

						if (payload_length > 26)
						{
							if (auto host = http_parser::parse_http_header(reinterpret_cast<char*>(payload), payload_length); host.has_value())
							{
								std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport) << " --> " <<
									net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) << " Host: ";

								std::cout << host.value() << std::endl;
							}
							else
							{
								std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport) << " --> " <<
									net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) << " length: ";

								std::cout << payload_length << std::endl;
							}
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

