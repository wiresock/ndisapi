// fast_io_test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <optional>

//std::optional<std::string> get_tls_sni(unsigned char* bytes, const size_t length)
//{
//	// TLS hello sanity check
//	if ((bytes[0] != 0x16) || // type is 0x16 (handshake record) 
//		((ntohs(*reinterpret_cast<unsigned short*>(&bytes[3])) + 5) > length) || // handshake message size
//		(bytes[5] != 0x1) // handshake message type 0x01 (client hello) 
//		)
//	{
//		return std::nullopt;
//	}
//
//	const auto session_id_length = bytes[43];
//	auto current_pointer = bytes + 1 + 43 + session_id_length;
//
//	// offset validity check
//	if ((current_pointer - bytes) > length)
//	{
//		// malformed SSL Hello
//		std::cout << "malformed SSL Hello" << "\n";
//		return std::nullopt;
//	}
//
//	const auto cipher_suites_length = ntohs(*reinterpret_cast<unsigned short*>(current_pointer));
//	current_pointer += 2 + cipher_suites_length;
//
//	// offset validity check
//	if ((current_pointer - bytes) > length)
//	{
//		// malformed SSL Hello
//		std::cout << "malformed SSL Hello" << "\n";
//		return std::nullopt;
//	}
//
//	const auto compression_length = *current_pointer;
//	current_pointer += 1 + compression_length;
//	const auto max_char = current_pointer + 2 + ntohs(*reinterpret_cast<unsigned short*>(current_pointer));
//
//	// offset validity check
//	if((max_char - bytes) > length)
//	{
//		// malformed SSL Hello
//		std::cout << "malformed SSL Hello" << "\n";
//		return std::nullopt;
//	}
//
//	current_pointer += 2;
//	unsigned short extension_type = 1;
//	while (current_pointer < max_char && extension_type != 0)
//	{
//		extension_type = ntohs(*reinterpret_cast<unsigned short*>(current_pointer));
//		current_pointer += 2;
//		const auto extension_length = ntohs(*reinterpret_cast<unsigned short*>(current_pointer));
//		current_pointer += 2;
//		if (extension_type == 0)
//		{
//			current_pointer += 3;
//			const auto name_length = ntohs(*reinterpret_cast<unsigned short*>(current_pointer));
//			current_pointer += 2;
//			return std::string(reinterpret_cast<char*>(current_pointer), name_length);
//		}
//
//		current_pointer += extension_length;
//	}
//
//	if (current_pointer != max_char)
//	{
//		// incomplete SSL Hello
//		std::cout << "incomplete SSL Hello" << "\n";
//	}
//
//	return std::nullopt; // SNI was not present
//}
//
//std::optional<std::string> get_http_host(unsigned char* bytes, const size_t length)
//{
//	return std::nullopt;
//}

class tls_parser
{
	static constexpr auto server_name_len = 256;
	static constexpr auto tls_header_len = 5;
	static constexpr auto tls_handshake_content_type = 0x16;
	static constexpr auto tls_handshake_type_client_hello = 0x01;

	static std::optional<std::string> parse_server_name_extension(const uint8_t* data, const size_t data_len) 
	{
		size_t pos = 2; // skip server name list length

		while (pos + 3 < data_len) 
		{
			const auto len = (static_cast<size_t>(data[pos + 1]) << 8) + static_cast<size_t>(data[pos + 2]);

			if (pos + 3 + len > data_len)
			{
				std::cout << "Invalid TLS client hello" << "\n";
				return std::nullopt;
			}

			switch (data[pos]) // name type
			{ 
			case 0x00: // host_name
				return std::string(reinterpret_cast<const char*>(data + pos + 3), len);
			default:
				std::cout << "Unknown server name extension name type: " << data[pos] << "\n";
			}
			pos += 3 + len;
		}
		
		// Check we ended where we expected to
		if (pos != data_len)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		std::cout << "No Host header included in this request" << "\n";
		return std::nullopt;
	}

	static std::optional<std::string> parse_extensions(const uint8_t* data, const size_t data_len) 
	{
		size_t pos = 0;

		// Parse each 4 bytes for the extension header
		while (pos + 4 <= data_len) 
		{
			// Extension Length
			const auto len = (static_cast<size_t>(data[pos + 2]) << 8) + static_cast<size_t>(data[pos + 3]);

			// Check if it's a server name extension
			if (data[pos] == 0x00 && data[pos + 1] == 0x00) 
			{
				// There can be only one extension of each type, so we break our state and move p to beginning of the extension here
				if (pos + 4 + len > data_len)
				{
					std::cout << "Invalid TLS client hello" << "\n";
					return std::nullopt;
				}

				return parse_server_name_extension(data + pos + 4, len);
			}
			pos += 4 + len; // Advance to the next extension header
		}

		// Check we ended where we expected to
		if (pos != data_len)
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
	/// <param name="data_len">SSL packet size</param>
	/// <returns>optional string with SNI found </returns>
	// ********************************************************************************
	static std::optional<std::string> parse_tls_header(const uint8_t* data, size_t data_len) 
	{
		size_t pos = tls_header_len;

		// Check that our TCP payload is at least large enough for a TLS header
		if (data_len < tls_header_len)
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
		data_len = min(data_len, len);

		// Check we received entire TLS record length
		if (data_len < len)
			return std::nullopt;

		// Handshake
		if (pos + 1 > data_len) 
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		if (data[pos] != tls_handshake_type_client_hello) 
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

		pos += 38;

		// Session ID
		if (pos + 1 > data_len)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = static_cast<size_t>(data[pos]);
		pos += 1 + len;

		// Cipher Suites
		if (pos + 2 > data_len)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = (static_cast<size_t>(data[pos]) << 8) + static_cast<size_t>(data[pos + 1]);
		pos += 2 + len;

		// Compression Methods
		if (pos + 1 > data_len)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = static_cast<size_t>(data[pos]);
		pos += 1 + len;

		if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) 
		{
			std::cout << "Received SSL 3.0 handshake without extensions" << "\n";
			return std::nullopt;
		}

		// Extensions
		if (pos + 2 > data_len)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		len = (static_cast<size_t>(data[pos]) << 8) + static_cast<size_t>(data[pos + 1]);
		pos += 2;

		if (pos + len > data_len)
		{
			std::cout << "Invalid TLS client hello" << "\n";
			return std::nullopt;
		}

		return parse_extensions(data + pos, len);
	}
};

//char* get_tls_sni(unsigned char* bytes, int* len)
//{
//	unsigned char* curr;
//	unsigned char sidlen = bytes[43];
//	curr = bytes + 1 + 43 + sidlen;
//	unsigned short cslen = ntohs(*(unsigned short*)curr);
//	curr += 2 + cslen;
//	unsigned char cmplen = *curr;
//	curr += 1 + cmplen;
//	unsigned char* maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
//	curr += 2;
//	unsigned short ext_type = 1;
//	unsigned short ext_len;
//	while (curr < maxchar && ext_type != 0)
//	{
//		ext_type = ntohs(*(unsigned short*)curr);
//		curr += 2;
//		ext_len = ntohs(*(unsigned short*)curr);
//		curr += 2;
//		if (ext_type == 0)
//		{
//			curr += 3;
//			unsigned short namelen = ntohs(*(unsigned short*)curr);
//			curr += 2;
//			*len = namelen;
//			return (char*)curr;
//		}
//		else curr += ext_len;
//	}
//	if (curr != maxchar) throw std::exception("incomplete SSL Client Hello");
//	return NULL; //SNI was not present
//}

#define SERVER_NAME_LEN 256

static std::optional<std::string> parse_http_header(const char*, size_t);
static std::optional<std::string> get_header(const char*, const char*, size_t);
static size_t next_header(const char**, size_t*);

/*
 * Parses a HTTP request for the Host: header
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid HTTP request
 *
 */
static std::optional<std::string> parse_http_header(const char* data, size_t data_len) 
{
	auto result = get_header("Host:", data, data_len);

	if (!result)
		return result;

	//  if the user specifies the port in the request, it is included here.
	//  Host: example.com:80
	//  Host: [2001:db8::1]:8080
	//  so we trim off port portion

	for(auto i = result.value().size() - 1; i >= 0; --i)
	{
		if (result.value()[i] == ':')
			result.value().erase(i);
		else if (!isdigit(result.value()[i]))
			break;
	}

	return result;
}

static std::optional<std::string> get_header(const char* header, const char* data, size_t data_len) {
	size_t len, header_len;

	header_len = strlen(header);

	/* loop through headers stopping at first blank line */
	while ((len = next_header(&data, &data_len)) != 0)
		if (len > header_len && _strnicmp(header, data, header_len) == 0) {
			/* Eat leading whitespace */
			while (header_len < len && isblank(data[header_len]))
				header_len++;

			return std::string(data + header_len, len - header_len);
		}

	/* If there is no data left after reading all the headers then we do not
	 * have a complete HTTP request, there must be a blank line */
	if (data_len == 0)
		return std::nullopt;
		//return -1;

	return std::nullopt;
	//return -2;
}

static size_t
next_header(const char** data, size_t* len) {
	size_t header_len;

	/* perhaps we can optimize this to reuse the value of header_len, rather
	 * than scanning twice.
	 * Walk our data stream until the end of the header */
	while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
		(*len)--;
		(*data)++;
	}

	/* advanced past the <CR><LF> pair */
	*data += 2;
	*len -= 2;

	/* Find the length of the next header */
	header_len = 0;
	while (*len > header_len + 1
		&& (*data)[header_len] != '\r'
		&& (*data)[header_len + 1] != '\n')
		header_len++;

	return header_len;
}

int main()
{
	auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
		nullptr,
		[](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
		{
			const auto ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

			if (ntohs(ether_header->h_proto) == ETH_P_IP)
			{
				const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

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

						if (auto host = parse_http_header(reinterpret_cast<char*>(payload), payload_length); host.has_value())
						{
							std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport) << " --> " <<
								net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) << " Host: ";

							std::cout << host.value() << std::endl;
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

