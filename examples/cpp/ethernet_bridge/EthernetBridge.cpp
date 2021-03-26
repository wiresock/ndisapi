// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  EthernetBridge.cpp
/// Abstract: EthernetBridge class implementation
/// </summary>
// --------------------------------------------------------------------------------

#include "stdafx.h"

const size_t maximum_packet_block = 510;

bool ethernet_bridge::start_bridge(std::vector<size_t> const& interfaces)
{
	bridged_interfaces_ = interfaces;

	// Check for the duplicates and remove if any
	std::sort(bridged_interfaces_.begin(), bridged_interfaces_.end());
	const auto last = std::unique(bridged_interfaces_.begin(), bridged_interfaces_.end());
	bridged_interfaces_.erase(last, bridged_interfaces_.end());

	// We should have at least two network interfaces and network interfaces indexes must be in range
	if ((bridged_interfaces_.size() < 2) ||
		(*std::max_element(bridged_interfaces_.begin(), bridged_interfaces_.end()) >= network_interfaces_.size())
		)
		return false;

	// Sort network interfaces so that Wi-Fi interface is at the end of the list
	std::sort(bridged_interfaces_.begin(), bridged_interfaces_.end(), [this](auto, auto b)
	{
		if (network_interfaces_[b]->is_wlan())
			return true;
		else
			return false;
	});

	// Start Ethernet Bridge working threads
	if (is_running_.test_and_set())
	{
		// already running
		return false;
	}

	for (auto&& adapter : interfaces)
	{
		working_threads_.push_back(
			std::thread(
				&ethernet_bridge::bridge_working_thread,
				this,
				adapter
			)
		);

	}

	return true;
}

void ethernet_bridge::stop_bridge()
{
	is_running_.clear();

	for (auto&& adapter : bridged_interfaces_)
		network_interfaces_[adapter]->release();

	// Wait for working threads to exit
	for (auto&& t : working_threads_)
	{
		if (t.joinable())
			t.join();
	}

	// Release working threads objects
	working_threads_.clear();
}

std::vector<std::pair<string, string>> ethernet_bridge::get_interface_list()
{
	std::vector<std::pair<string, string>> result;
	result.reserve(network_interfaces_.size());

	for (auto& e : network_interfaces_)
	{
		result.push_back(std::make_pair(e->get_friendly_name(), e->get_internal_name()));
	}

	return result;
}

std::optional<std::size_t> ethernet_bridge::find_target_adapter_by_mac(net::mac_address const & address)
{
	std::shared_lock<std::shared_mutex> lock(mac_table_lock_);
	if (mac_table_.count(address))
		return mac_table_[address];
	else
		return {};
}

bool ethernet_bridge::update_target_adapter_by_mac(const std::size_t index, net::mac_address const & address)
{
	bool result = false;
	{
		std::shared_lock<std::shared_mutex> lock(mac_table_lock_);

		if (mac_table_.count(address) && mac_table_[address] == index)
		{
			return result;
		}
		else
		{
			result = true;
		}
	}

	{
		std::unique_lock<std::shared_mutex> lock(mac_table_lock_);
		mac_table_[address] = index;
	}

	return result;
}

void ethernet_bridge::initialize_network_interfaces()
{
	TCP_AdapterList			ad_list;
	std::vector<char>		friendly_name(MAX_PATH * 4);

	GetTcpipBoundAdaptersInfo(&ad_list);

	for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
	{
		if ((static_cast<NdisMedium>(ad_list.m_nAdapterMediumList[i]) == NdisMedium::NdisMedium802_3) ||
			(static_cast<NdisMedium>(ad_list.m_nAdapterMediumList[i]) == NdisMedium::NdisMediumNative802_11)
			)
		{
			CNdisApi::ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                                        friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			auto adapter = std::make_unique<network_adapter>(
				*this,
				ad_list.m_nAdapterHandle[i],
				ad_list.m_czCurrentAddress[i],
				std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
				std::string(friendly_name.data()));

			network_interfaces_.push_back(std::move(adapter));
		}
	}
}

void ethernet_bridge::bridge_working_thread(const size_t index)
{
	const auto packet_buffer = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

#ifdef _DEBUG
	using namespace std::string_literals;
	pcap::pcap_file_storage capture_in("bridge_in_"s + std::to_string(index) + ".pcap"s);
	std::map<std::size_t, pcap::pcap_file_storage> capture_out;
	for (auto&& a : bridged_interfaces_)
		capture_out[a] = pcap::pcap_file_storage("bridge_"s + std::to_string(index) + "_to_"s + std::to_string(a)+ ".pcap"s);
#endif //_DEBUG

	//
	// Thread reads packets from the network interface and duplicates non-local packets to the second
	//

	auto& adapters = network_interfaces_;

	//
	// Initialize Requests
	//

	using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
		sizeof(NDISRD_ETH_Packet)*(maximum_packet_block - 1), 0x1000>;

	// 1. Allocate memory using unique_ptr for auto-delete on thread exit
	const auto read_request_ptr = std::make_unique<request_storage_type_t>();
	const auto bridge_request_ptr = std::make_unique<request_storage_type_t>();
	const auto mstcp_bridge_request_ptr = std::make_unique<request_storage_type_t>();

	// 2. Get raw pointers for convenience
	auto read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr.get());
	auto bridge_request = reinterpret_cast<PETH_M_REQUEST>(bridge_request_ptr.get());
	auto mstcp_bridge_request = reinterpret_cast<PETH_M_REQUEST>(mstcp_bridge_request_ptr.get());

	read_request->hAdapterHandle = adapters[index]->get_adapter();

	read_request->dwPacketsNumber = maximum_packet_block;

	//
	// Initialize packet buffers
	//

	for (unsigned i = 0; i < maximum_packet_block; ++i)
	{
		read_request->EthPacket[i].Buffer = &packet_buffer[i];
	}

	// Set event for helper driver
	if (!adapters[index]->set_packet_event())
	{
		return;
	}

	if (!adapters[index]->is_wlan())
	{
		if (!adapters[index]->set_hw_filter(NDIS_PACKET_TYPE_PROMISCUOUS))
			return;
	}

	adapters[index]->set_mode(MSTCP_FLAG_SENT_LISTEN | MSTCP_FLAG_RECV_LISTEN | MSTCP_FLAG_FILTER_DIRECT | MSTCP_FLAG_LOOPBACK_BLOCK);

	while (is_running_.test_and_set())
	{
		[[maybe_unused]]auto wait_status = adapters[index]->wait_event(INFINITE);

		// Reset event, as we don't need to wake up all working threads at once

		if (is_running_.test_and_set())
			[[maybe_unused]]auto reset_status = adapters[index]->reset_event();
		else
		{
			break;
		}

		// Start reading packet from the driver

		while (ReadPackets(read_request))
		{

			for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
			{
#ifdef _DEBUG
				capture_in << *read_request->EthPacket[i].Buffer;
#endif //_DEBUG
				if (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
				{
					auto ether_header = reinterpret_cast<ether_header_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer);
					update_target_adapter_by_mac(index, net::mac_address(ether_header->h_source));
				}
			}

			//
			// WLAN requires MAC NAT
			//
			if (adapters[index]->is_wlan())
			{
				// Process packets from WLAN:
				// Need to lookup correct MAC address for each packet by its IP address
				// and replace destination MAC address
				for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
				{
					auto ether_header = reinterpret_cast<ether_header_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer);
					if (ntohs(ether_header->h_proto) == ETH_P_IP)
					{
						const auto ip_hdr = reinterpret_cast<iphdr*>(read_request->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

						auto dest_mac = adapters[index]->get_mac_by_ip(static_cast<net::ip_address_v4>(ip_hdr->ip_dst));
						if (static_cast<bool>(dest_mac))
						{
							memcpy(ether_header->h_dest, &dest_mac[0], ETH_ALEN);
						}
					}

					if (ntohs(ether_header->h_proto) == ETH_P_ARP)
					{
						auto arp_hdr = reinterpret_cast<ether_arp_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

						if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST)
						{

						}
						else
						{
							auto dest_mac = adapters[index]->get_mac_by_ip(*reinterpret_cast<net::ip_address_v4*>(arp_hdr->arp_tpa));
							if (static_cast<bool>(dest_mac))
							{
								memcpy(ether_header->h_dest, &dest_mac[0], ETH_ALEN);
								memcpy(arp_hdr->arp_tha, &dest_mac[0], ETH_ALEN);
							}
						}
					}
				}
			}

			for (auto&& a : bridged_interfaces_)
			{
				if (a == index)
					continue;

				if (adapters[a]->is_wlan())
				{
					// Process packets to WLAN:
					// Need to change source MAC to WLAN adapter MAC 
					// and save pair IP->MAC for the future
					for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
					{
						auto ether_header = reinterpret_cast<ether_header_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer);

						//
						// ARP processing. Here we save pairs of IP and MAC addresses for future use
						//
						if (ntohs(ether_header->h_proto) == ETH_P_ARP)
						{
							auto arp_hdr = reinterpret_cast<ether_arp_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

							if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST)
							{
								// ARP request

								// Save pair of IP and MAC
								adapters[a]->set_mac_for_ip(
									*reinterpret_cast<net::ip_address_v4*>(arp_hdr->arp_spa),
									&arp_hdr->arp_sha[0]
								);

								// Replace source MAC in ARP request to WLAN adapter one
								memmove(&arp_hdr->arp_sha[0], &adapters[a]->get_hw_address()[0], ETH_ALEN);
							}
							else
							{
								// ARP reply

								// Save pair of IP and MAC
								adapters[a]->set_mac_for_ip(
									*reinterpret_cast<net::ip_address_v4*>(arp_hdr->arp_spa),
									&arp_hdr->arp_sha[0]
								);

								// Replace source MAC in ARP reply to WLAN adapter one
								memmove(&arp_hdr->arp_sha[0], &adapters[a]->get_hw_address()[0], ETH_ALEN);
							}

						}

						//
						// DHCP requests preprocessing (there is no sense to send UNI-CAST DHCP requests if we use MAC NAT)
						//
						if (ntohs(ether_header->h_proto) == ETH_P_IP)
						{
							const auto ip_header = reinterpret_cast<iphdr_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

							if (ip_header->ip_p == IPPROTO_UDP)
							{
								const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD)*ip_header->ip_hl);
								if (ntohs(udp_header->th_dport) == IPPORT_DHCPS)
								{
									const auto dhcp = reinterpret_cast<dhcp_packet*>(udp_header + 1);

									if ((dhcp->op == BOOTREQUEST) &&
										(dhcp->flags == 0)
										)
									{
										// Change DHCP flags to broadcast 
										dhcp->flags = htons(0x8000);
										RecalculateUDPChecksum(read_request->EthPacket[i].Buffer);
										RecalculateIPChecksum(read_request->EthPacket[i].Buffer);
									}

								}
							}
						}

						// Replace source MAC in Ethernet header
						memmove(&ether_header->h_source, &adapters[a]->get_hw_address()[0], ETH_ALEN);
					}
				}

				for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
				{
					auto ether_header = reinterpret_cast<ether_header_ptr>(read_request->EthPacket[i].Buffer->m_IBuffer);

					if (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						// For outgoing packets add to list only originated from the current interface (to skip possible loopback indications)
						if (adapters[index]->is_local(packet_buffer[i].m_IBuffer + ETH_ALEN) ||
							(adapters[a]->is_local(packet_buffer[i].m_IBuffer + ETH_ALEN)))
						{
							auto destination = find_target_adapter_by_mac(static_cast<net::mac_address>(ether_header->h_dest));
							if (destination && (destination.value() != a))
								continue;

							bridge_request->EthPacket[bridge_request->dwPacketsNumber].Buffer = &packet_buffer[i];
#ifdef _DEBUG
							capture_out[a] << *bridge_request->EthPacket[bridge_request->dwPacketsNumber].Buffer;
#endif //_DEBUG
							++bridge_request->dwPacketsNumber;
						}
					}
					else
					{
						// For incoming packets don't add to list packets destined to local interface (they are not supposed to be bridged anythere else)
						if (!adapters[index]->is_local(packet_buffer[i].m_IBuffer))
						{
							auto destination = find_target_adapter_by_mac(static_cast<net::mac_address>(ether_header->h_dest));
							if (destination && (destination.value() != a))
								continue;

							bridge_request->EthPacket[bridge_request->dwPacketsNumber].Buffer = &packet_buffer[i];
#ifdef _DEBUG
							capture_out[a] << *bridge_request->EthPacket[bridge_request->dwPacketsNumber].Buffer;
#endif //_DEBUG
							++bridge_request->dwPacketsNumber;
						}
					}

					// For local indications add only directed or broadcast/multi-cast
					if ((packet_buffer[i].m_IBuffer[0] & 0x01)
						|| adapters[a]->is_local(packet_buffer[i].m_IBuffer)
						)
					{
						mstcp_bridge_request->EthPacket[mstcp_bridge_request->dwPacketsNumber].Buffer = &packet_buffer[i];
#ifdef _DEBUG
						capture_out[a] << *mstcp_bridge_request->EthPacket[mstcp_bridge_request->dwPacketsNumber].Buffer;
#endif //_DEBUG
						++mstcp_bridge_request->dwPacketsNumber;
					}
				}

				bridge_request->hAdapterHandle = adapters[a]->get_adapter();
				mstcp_bridge_request->hAdapterHandle = adapters[a]->get_adapter();

				if (bridge_request->dwPacketsNumber)
				{
					SendPacketsToAdapter(bridge_request);
					bridge_request->dwPacketsNumber = 0;
				}

				if (mstcp_bridge_request->dwPacketsNumber)
				{
					SendPacketsToMstcp(mstcp_bridge_request);
					mstcp_bridge_request->dwPacketsNumber = 0;
				}

			}

			read_request->dwPacketsSuccess = 0;
		}
	}

	is_running_.clear();
}