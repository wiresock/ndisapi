// sni_inspector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

#ifdef ICMP
#undef ICMP
#endif //ICMP

#include "pcapplusplus/RawPacket.h"
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/IPLayer.h"
#include "pcapplusplus/TcpLayer.h"
#include "pcapplusplus/SSLLayer.h"
#include "pcapplusplus/SSLHandshake.h"

using packet_filter = ndisapi::simple_packet_filter;
using packet_action = ndisapi::simple_packet_filter::packet_action;

packet_action auto_parse_ethernet_frame_sni(INTERMEDIATE_BUFFER& buffer)
{
	timespec ts{};
	std::ignore = timespec_get(&ts, TIME_UTC);

	pcpp::RawPacket raw_packet(buffer.m_IBuffer, static_cast<int>(buffer.m_Length), ts, false);
	const pcpp::Packet parsed_packet(&raw_packet);

	// verify packet is TCP and SSL/TLS
	if (!parsed_packet.isPacketOfType(pcpp::TCP) || !parsed_packet.isPacketOfType(pcpp::SSL))
		return packet_action::pass;

	// go over all SSL messages in this packet
	auto* ssl_layer = parsed_packet.getLayerOfType<pcpp::SSLLayer>();
	while (ssl_layer != nullptr)
	{
		// check if the layer is an handshake message
		if (const pcpp::SSLRecordType rec_type = ssl_layer->getRecordType(); rec_type == pcpp::SSL_HANDSHAKE)
		{
			const auto handshake_layer = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl_layer);
			if (handshake_layer == nullptr)
				continue;

			// try to find client-hello message
			if (const auto* client_hello_message = handshake_layer->getHandshakeMessageOfType<
				pcpp::SSLClientHelloMessage>(); client_hello_message != nullptr)
			{
				if (const auto sni_ext = client_hello_message->getExtensionOfType<
					pcpp::SSLServerNameIndicationExtension>(); sni_ext != nullptr)
				{
					std::cout << std::endl << "SNI:\t" << sni_ext->getHostName() << std::endl;
					std::cout << "TLS FP:\t" << client_hello_message->generateTLSFingerprint().toString() << std::endl;

					if (const auto ssl_ver_ext = client_hello_message->getExtensionOfType<
						pcpp::SSLSupportedVersionsExtension>(); ssl_ver_ext != nullptr)
					{
						for (auto&& ver: ssl_ver_ext->getSupportedVersions())
						{
							std::cout << "TLS VER:\t" << ver.toString() << std::endl;
						}

						for (int index = 0; index < client_hello_message->getExtensionCount(); ++index)
						{
							if (client_hello_message->getExtension(index)->getTypeAsInt() == 65037)
								std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!Encrypted Client Hello Extension is present!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
						}
					}
					else
					{
						std::cout << "TLS VER:\t" << client_hello_message->getHandshakeVersion().toString() << std::endl;
					}
				}
			}
		}

		ssl_layer = parsed_packet.getNextLayerOfType<pcpp::SSLLayer>(ssl_layer);
	}

	return packet_action::pass;
}

int main()
{
	const auto ndis_api = std::make_unique<ndisapi::simple_packet_filter>(
		nullptr,
		[](HANDLE, INTERMEDIATE_BUFFER& buffer)
		{
			return auto_parse_ethernet_frame_sni(buffer);
		});

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
