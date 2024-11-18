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
    static constexpr auto sni_extension_type = 0x0000;

    static std::optional<std::string> parse_server_name_extension(const uint8_t* data, const size_t length)
    {
        size_t position = 0;

        if (position + 2 > length)
        {
            // Incomplete Server Name List Length
            return std::nullopt;
        }

        size_t server_name_list_length = (data[position] << 8) | data[position + 1];
        position += 2;

        // Adjust server_name_list_length if not enough data
        if (position + server_name_list_length > length)
        {
            // Incomplete Server Name List, adjusting length
            server_name_list_length = length - position;
        }

        while (position + 3 <= length)
        {
            const uint8_t name_type = data[position];
            uint16_t name_length = static_cast<uint16_t>(data[position + 1] << 8) | data[position + 2];
            position += 3;

            // Adjust name_length if not enough data
            if (position + name_length > length)
            {
                // Incomplete Server Name, adjusting length
                name_length = static_cast<uint16_t>(length - position);
            }

            if (name_type == 0x00) // Hostname
            {
                std::string server_name(reinterpret_cast<const char*>(data + position), name_length);
                return server_name;
            }

            position += name_length;
        }

        // No valid Server Name found
        return std::nullopt;
    }

    static std::optional<std::string> parse_extensions(const uint8_t* data, const size_t length)
    {
        size_t position = 0;

        // Parse each extension
        while (position + 4 <= length)
        {
            // Extension Type and Length
            const uint16_t extension_type = static_cast<uint16_t>(data[position] << 8) | data[position + 1];
            uint16_t extension_length = static_cast<uint16_t>(data[position + 2] << 8) | data[position + 3];
            position += 4;

            // Adjust extension_length if not enough data
            if (position + extension_length > length)
            {
                // Incomplete Extension, adjusting length
                extension_length = static_cast<uint16_t>(length - position);
            }

            if (extension_type == sni_extension_type) // Server Name Extension
            {
                return parse_server_name_extension(data + position, extension_length);
            }

            position += extension_length;
        }

        return std::nullopt;
    }

public:
    // ********************************************************************************
    /// <summary>
    /// Parse a TLS packet for the Server Name Indication extension in the client
    /// hello handshake, returning the first server name found.
    /// </summary>
    /// <param name="data">Pointer to the TLS packet data.</param>
    /// <param name="length">Length of the TLS packet data.</param>
    /// <returns>Optional string containing the extracted SNI, if found.</returns>
    // ********************************************************************************
    static std::optional<std::string> parse_tls_header(const uint8_t* data, size_t length)
    {
        size_t position = tls_header_len;

        // Check that we have at least enough data for the TLS header
        if (length < tls_header_len)
        {
            // Incomplete TLS header
            return std::nullopt;
        }

        // SSL 2.0 Client Hello (not supported for SNI)
        if (data[0] & 0x80 && data[2] == 1)
        {
            // Received SSL 2.0 Client Hello which cannot support SNI.
            return std::nullopt;
        }

        // Ensure the content type is Handshake
        if (data[0] != tls_handshake_content_type)
        {
            // Request did not begin with TLS handshake.
            return std::nullopt;
        }

        // Extract TLS version
        const auto tls_version_major = data[1];
        const auto tls_version_minor = data[2];

        // Read the TLS record length
        size_t record_length = (static_cast<size_t>(data[3]) << 8) + static_cast<size_t>(data[4]);

        // Adjust record_length to the available data
        record_length = min(record_length, length - tls_header_len);

        // Proceed to parse the Handshake message
        if (position + 1 > length)
        {
            // Incomplete Handshake message
            return std::nullopt;
        }

        // Check Handshake Type
        if (data[position] != tls_handshake_type_client_hello)
        {
            // Not a ClientHello message
            return std::nullopt;
        }

        // Handshake Length
        if (position + 4 > length)
        {
            // Incomplete Handshake Length
            return std::nullopt;
        }
        size_t handshake_length = (static_cast<size_t>(data[position + 1]) << 16) +
            (static_cast<size_t>(data[position + 2]) << 8) +
            static_cast<size_t>(data[position + 3]);
        position += 4;

        // Skip Version (2 bytes)
        if (position + 2 > length)
        {
            // Incomplete Version info
            return std::nullopt;
        }
        position += 2;

        // Skip Random (32 bytes)
        if (position + 32 > length)
        {
            // Incomplete Random data
            return std::nullopt;
        }
        position += 32;

        // Session ID Length
        if (position + 1 > length)
        {
            // Incomplete Session ID Length
            return std::nullopt;
        }
        size_t session_id_length = data[position];
        position += 1;

        // Adjust session_id_length if not enough data
        if (position + session_id_length > length)
        {
            // Incomplete Session ID, adjusting length
            session_id_length = length - position;
        }
        position += session_id_length;

        // Cipher Suites Length
        if (position + 2 > length)
        {
            // Incomplete Cipher Suites Length
            return std::nullopt;
        }
        size_t cipher_suites_length = (static_cast<size_t>(data[position]) << 8) + data[position + 1];
        position += 2;

        // Adjust cipher_suites_length if not enough data
        if (position + cipher_suites_length > length)
        {
            // Incomplete Cipher Suites, adjusting length
            cipher_suites_length = length - position;
        }
        position += cipher_suites_length;

        // Compression Methods Length
        if (position + 1 > length)
        {
            // Incomplete Compression Methods Length
            return std::nullopt;
        }
        size_t compression_methods_length = data[position];
        position += 1;

        // Adjust compression_methods_length if not enough data
        if (position + compression_methods_length > length)
        {
            // Incomplete Compression Methods, adjusting length
            compression_methods_length = length - position;
        }
        position += compression_methods_length;

        // Check if there are extensions
        if (position + 2 > length)
        {
            // No Extensions present or incomplete extensions length
            return std::nullopt;
        }
        size_t extensions_length = (static_cast<size_t>(data[position]) << 8) + data[position + 1];
        position += 2;

        // Adjust extensions_length if not enough data
        if (position + extensions_length > length)
        {
            // Incomplete Extensions, adjusting length
            extensions_length = length - position;
        }

        // Parse Extensions
        return parse_extensions(data + position, extensions_length);
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
            // Incomplete HTTP request
            return std::nullopt;
        }

        // No Host header included in HTTP request
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
    const auto ndis_api = std::make_unique<ndisapi::fastio_packet_filter>(
        nullptr,
        [](HANDLE, const INTERMEDIATE_BUFFER& buffer)
        {
            if (auto* const ethernet_header = reinterpret_cast<ether_header const*>(buffer.m_IBuffer); ntohs(
                ethernet_header->h_proto) == ETH_P_IP)
            {
                if (auto* const ip_header = reinterpret_cast<iphdr const*>(ethernet_header + 1); ip_header->ip_p ==
                    IPPROTO_TCP)
                {
                    if (auto* const tcp_header = reinterpret_cast<tcphdr const*>(reinterpret_cast<uint8_t const*>(ip_header) +
                        sizeof(DWORD) * ip_header->ip_hl); ntohs(tcp_header->th_dport) == 443)
                    {
                        const auto* const payload = reinterpret_cast<uint8_t const*>(tcp_header) +
                            static_cast<ptrdiff_t>(4 * tcp_header->th_off);
                        const auto payload_length = buffer.m_Length - (sizeof(ether_header) +
                            static_cast<ptrdiff_t>(4 * ip_header->ip_hl) + static_cast<ptrdiff_t>(4 * tcp_header->th_off));

                        if ((payload[0] == 0x16) && (payload[5] == 0x1))
                        {
                            std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport) <<
                                " --> " <<
                                net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) << " SNI: ";
                            
                            std::cout << tls_parser::parse_tls_header(payload, payload_length).value_or("no SNI") <<
                                '\n';
                        }
                    }
                    else if (ntohs(tcp_header->th_dport) == 80)
                    {
                        auto* const payload = reinterpret_cast<uint8_t const*>(tcp_header) +
                            static_cast<ptrdiff_t>(4 * tcp_header->th_off);

                        if (const auto payload_length = buffer.m_Length - 
                            (sizeof(ether_header) + static_cast<ptrdiff_t>(4 * ip_header->ip_hl) +
                            static_cast<ptrdiff_t>(4 * tcp_header->th_off)); payload_length > 26)
                        {
                            if (const auto host = http_parser::parse_http_header(
                                reinterpret_cast<char const*>(payload), payload_length); host.has_value())
                            {
                                std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport)
                                    << " --> " <<
                                    net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) <<
                                    " Host: ";

                                std::cout << host.value() << '\n';
                            }
                            else
                            {
                                std::cout << net::ip_address_v4(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport)
                                    << " --> " <<
                                    net::ip_address_v4(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) <<
                                    " length: ";

                                std::cout << payload_length << '\n';
                            }
                        }
                    }
                }
            }

            return ndisapi::fastio_packet_filter::packet_action::pass;
        }, true);

    if (ndis_api->IsDriverLoaded())
    {
        std::cout << "WinpkFilter is loaded" << '\n' << '\n';
    }
    else
    {
        std::cout << "WinpkFilter is not loaded" << '\n' << '\n';
        return 1;
    }

    std::cout << "Available network interfaces:" << '\n' << '\n';
    size_t index = 0;
    for (auto& e : ndis_api->get_interface_names_list())
    {
        std::cout << ++index << ")\t" << e << '\n';
    }

    std::cout << '\n' << "Select interface to filter:";
    std::cin >> index;

    if (index > ndis_api->get_interface_names_list().size())
    {
        std::cout << "Wrong parameter was selected. Out of range." << '\n';
        return 0;
    }

    ndis_api->start_filter(index - 1);

    std::cout << "Press any key to stop filtering" << '\n';

    std::ignore = _getch();

    std::cout << "Exiting..." << '\n';

    return 0;
}
