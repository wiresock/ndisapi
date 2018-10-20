/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  EthernetBridge.cpp                                      */
/*                                                                       */
/* Abstract: EthernetBridge class implementation                         */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/
#include "stdafx.h"

const size_t	maximum_packet_block = 512;

bool EthernetBridge::StartBridge(std::vector<size_t> const& interfaces)
{
	m_BridgedInterfaces = interfaces;

	// Check for the duplicates and remove if any
	std::sort(m_BridgedInterfaces.begin(), m_BridgedInterfaces.end());
	auto last = std::unique(m_BridgedInterfaces.begin(), m_BridgedInterfaces.end());
	m_BridgedInterfaces.erase(last, m_BridgedInterfaces.end());

	// We should have at least two network interfaces and network interfaces indexes must be in range
	if ((m_BridgedInterfaces.size() < 2) ||
		(*std::max_element(m_BridgedInterfaces.begin(), m_BridgedInterfaces.end()) >= m_NetworkInterfaces.size())
		)
		return false;

	// Sort network interfaces so that Wi-Fi interface is at the end of the list
	std::sort(m_BridgedInterfaces.begin(), m_BridgedInterfaces.end(), [this](auto, auto b)
	{
		if (m_NetworkInterfaces[b]->IsWLAN())
			return true;
		else
			return false;
	});

	// Start Ethernet Bridge working threads
	if (m_bIsRunning.test_and_set())
	{
		// already running
		return false;
	}

	for (auto&& adapter : interfaces)
	{
		m_WorkingThreads.push_back(
			std::thread(
				&EthernetBridge::BridgeWorkingThread,
				this,
				adapter
			)
		);

	}

	return true;
}

void EthernetBridge::StopBridge()
{
	m_bIsRunning.clear();

	for (auto&& adapter : m_BridgedInterfaces)
		m_NetworkInterfaces[adapter]->Release();

	// Wait for working threads to exit
	for (auto&& t : m_WorkingThreads)
	{
		if (t.joinable())
			t.join();
	}

	// Release working threads objects
	m_WorkingThreads.clear();
}

std::vector<std::pair<string, string>> EthernetBridge::GetInterfaceList()
{
	std::vector<std::pair<string, string>> result;
	result.reserve(m_NetworkInterfaces.size());

	for (auto& e : m_NetworkInterfaces)
	{
		result.push_back(std::make_pair(e->GetFriendlyName(), e->GetInternalName()));
	}

	return result;
}

std::optional<std::size_t> EthernetBridge::FindTargetAdapterByMac(mac_address const & address)
{
	std::shared_lock<std::shared_mutex> lock(m_MacTableLock);
	if (m_MacTable.count(address))
		return m_MacTable[address];
	else
		return {};
}

bool EthernetBridge::UpdateTargetAdapterByMac(std::size_t index, mac_address const & address)
{
	bool result = false;
	{
		std::shared_lock<std::shared_mutex> lock(m_MacTableLock);

		if (m_MacTable.count(address) && m_MacTable[address] == index)
		{
			return result;
		}
		else
		{
			result = true;
		}
	}

	{
		std::unique_lock<std::shared_mutex> lock(m_MacTableLock);
		m_MacTable[address] = index;
	}

	return result;
}

void EthernetBridge::InitializeNetworkInterfaces()
{
	TCP_AdapterList			AdList;
	std::vector<char>		szFriendlyName(MAX_PATH * 4);

	GetTcpipBoundAdaptersInfo(&AdList);

	for (size_t i = 0; i < AdList.m_nAdapterCount; ++i)
	{
		if ((static_cast<NdisMedium>(AdList.m_nAdapterMediumList[i]) == NdisMedium::NdisMedium802_3) ||
			(static_cast<NdisMedium>(AdList.m_nAdapterMediumList[i]) == NdisMedium::NdisMediumNative802_11)
			)
		{
			CNdisApi::ConvertWindows2000AdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName.data(), static_cast<DWORD>(szFriendlyName.size()));

			auto pAdapter = std::make_unique<CNetworkAdapter>(
				*this,
				AdList.m_nAdapterHandle[i],
				AdList.m_czCurrentAddress[i],
				std::string((const char*)AdList.m_szAdapterNameList[i]),
				std::string(szFriendlyName.data()));

			m_NetworkInterfaces.push_back(std::move(pAdapter));
		}
	}
}

void EthernetBridge::BridgeWorkingThread(size_t index)
{
	PETH_M_REQUEST							ReadRequest, BridgeRequest, MstcpBridgeRequest;
	std::unique_ptr<INTERMEDIATE_BUFFER[]>	PacketBuffer = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

	//
	// Thread reads packets from the network interface and duplicates non local packets to the second
	//

	auto& Adapters = m_NetworkInterfaces;

	ULONG_PTR dwThreadIndex = reinterpret_cast<ULONG_PTR>(Adapters[index]->GetAdapter());

	//
	// Initialize Requests
	//

	using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
		sizeof(NDISRD_ETH_Packet)*(maximum_packet_block - 1)>;

	// 1. Allocate memory using unique_ptr for auto-delete on thread exit
	auto ReadRequestPtr = std::make_unique<request_storage_type_t>();
	auto BridgeRequestPtr = std::make_unique<request_storage_type_t>();
	auto MstcpBridgeRequestPtr = std::make_unique<request_storage_type_t>();

	// 2. Get raw pointers for convinience
	ReadRequest = reinterpret_cast<PETH_M_REQUEST>(ReadRequestPtr.get());
	BridgeRequest = reinterpret_cast<PETH_M_REQUEST>(BridgeRequestPtr.get());
	MstcpBridgeRequest = reinterpret_cast<PETH_M_REQUEST>(MstcpBridgeRequestPtr.get());

	ReadRequest->hAdapterHandle = Adapters[index]->GetAdapter();

	ReadRequest->dwPacketsNumber = maximum_packet_block;

	//
	// Initialize packet buffers
	//
	ZeroMemory(PacketBuffer.get(), sizeof(INTERMEDIATE_BUFFER)*maximum_packet_block);

	for (unsigned i = 0; i < maximum_packet_block; ++i)
	{
		ReadRequest->EthPacket[i].Buffer = &PacketBuffer[i];
	}

	// Set event for helper driver
	if (!Adapters[index]->SetPacketEvent())
	{
		return;
	}

	if (!Adapters[index]->IsWLAN())
	{
		if (!Adapters[index]->SetHwFilter(NDIS_PACKET_TYPE_PROMISCUOUS))
			return;
	}

	Adapters[index]->SetMode(MSTCP_FLAG_SENT_LISTEN | MSTCP_FLAG_RECV_LISTEN | MSTCP_FLAG_FILTER_DIRECT | MSTCP_FLAG_LOOPBACK_BLOCK);

	while (m_bIsRunning.test_and_set())
	{
		Adapters[index]->WaitEvent(INFINITE);

		// Reset event, as we don't need to wake up all working threads at once

		if (m_bIsRunning.test_and_set())
			Adapters[index]->ResetEvent();
		else
		{
			break;
		}

		// Start reading packet from the driver

		while (ReadPackets(ReadRequest))
		{
			for (size_t i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
			{
				if (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
				{
					ether_header_ptr pEtherHdr = reinterpret_cast<ether_header_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer);
					UpdateTargetAdapterByMac(index, mac_address(pEtherHdr->h_source));
				}
			}

			//
			// WLAN requires MAC NAT
			//
			if (Adapters[index]->IsWLAN())
			{
				// Process packets from WLAN:
				// Need to lookup correct MAC address for each packet by its IP address
				// and replace destination MAC address
				for (size_t i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
				{
					ether_header_ptr pEtherHdr = reinterpret_cast<ether_header_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer);
					if (ntohs(pEtherHdr->h_proto) == ETH_P_IP)
					{
						iphdr_ptr pIpHdr = (iphdr*)(ReadRequest->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

						auto dest_mac = Adapters[index]->GetMacByIp(pIpHdr->ip_dst);
						if (dest_mac)
						{
							memcpy(pEtherHdr->h_dest, &dest_mac[0], ETH_ALEN);
						}
					}

					if (ntohs(pEtherHdr->h_proto) == ETH_P_ARP)
					{
						ether_arp_ptr pArpHdr = reinterpret_cast<ether_arp_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

						if (ntohs(pArpHdr->ea_hdr.ar_op) == ARPOP_REQUEST)
						{

						}
						else
						{
							auto dest_mac = Adapters[index]->GetMacByIp(*reinterpret_cast<in_addr*>(pArpHdr->arp_tpa));
							if (dest_mac)
							{
								memcpy(pEtherHdr->h_dest, &dest_mac[0], ETH_ALEN);
								memcpy(pArpHdr->arp_tha, &dest_mac[0], ETH_ALEN);
							}
						}
					}
				}
			}

			for (auto&& a : m_BridgedInterfaces)
			{
				if (a == index)
					continue;

				if (Adapters[a]->IsWLAN())
				{
					// Process packets to WLAN:
					// Need to change source MAC to WLAN adapter MAC 
					// and save pair IP->MAC for the future
					for (size_t i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
					{
						ether_header_ptr pEtherHdr = reinterpret_cast<ether_header_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer);

						//
						// ARP processing. Here we save pairs of IP and MAC addresses for future use
						//
						if (ntohs(pEtherHdr->h_proto) == ETH_P_ARP)
						{
							ether_arp_ptr pArpHdr = reinterpret_cast<ether_arp_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

							if (ntohs(pArpHdr->ea_hdr.ar_op) == ARPOP_REQUEST)
							{
								// ARP request

								// Save pair of IP and MAC
								Adapters[a]->SetMacForIp(
									*reinterpret_cast<in_addr*>(pArpHdr->arp_spa),
									&pArpHdr->arp_sha[0]
								);

								// Replace source MAC in ARP request to WLAN adapter one
								memmove(&pArpHdr->arp_sha[0], &Adapters[a]->GetHwAddress()[0], ETH_ALEN);
							}
							else
							{
								// ARP reply

								// Save pair of IP and MAC
								Adapters[a]->SetMacForIp(
									*reinterpret_cast<in_addr*>(pArpHdr->arp_spa),
									&pArpHdr->arp_sha[0]
								);

								// Replace source MAC in ARP reply to WLAN adapter one
								memmove(&pArpHdr->arp_sha[0], &Adapters[a]->GetHwAddress()[0], ETH_ALEN);
							}

						}

						//
						// DHCP requests preprocessing (there is no sense to send UNICAST DHCP requests if we use MAC NAT)
						//
						if (ntohs(pEtherHdr->h_proto) == ETH_P_IP)
						{
							iphdr_ptr pIpHeader = reinterpret_cast<iphdr_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);

							if (pIpHeader->ip_p == IPPROTO_UDP)
							{
								udphdr_ptr pUdpHeader = reinterpret_cast<udphdr_ptr>(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);
								if (ntohs(pUdpHeader->th_dport) == IPPORT_DHCPS)
								{
									dhcp_packet* pDhcp = reinterpret_cast<dhcp_packet*>(pUdpHeader + 1);

									if ((pDhcp->op == BOOTREQUEST) &&
										(pDhcp->flags == 0)
										)
									{
										// Change DHCP flags to broadcast 
										pDhcp->flags = htons(0x8000);
										RecalculateUDPChecksum(ReadRequest->EthPacket[i].Buffer);
										RecalculateIPChecksum(ReadRequest->EthPacket[i].Buffer);
									}

								}
							}
						}

						// Replace source MAC in Ethernet header
						memmove(&pEtherHdr->h_source, &Adapters[a]->GetHwAddress()[0], ETH_ALEN);
					}
				}

				for (size_t i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
				{
					ether_header_ptr pEtherHdr = reinterpret_cast<ether_header_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer);

					if (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						// For outgoing packets add to list only orginated from the current interface (to skip possible loopback indications)
						if (Adapters[index]->IsLocal(PacketBuffer[i].m_IBuffer + ETH_ALEN) ||
							(Adapters[a]->IsLocal(PacketBuffer[i].m_IBuffer + ETH_ALEN)))
						{
							auto destination = FindTargetAdapterByMac(pEtherHdr->h_dest);
							if (destination && (destination.value() != a))
								continue;

							BridgeRequest->EthPacket[BridgeRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
							++BridgeRequest->dwPacketsNumber;
						}
					}
					else
					{
						// For incoming packets don't add to list packets destined to local interface (they are not supposed to be bridged anythere else)
						if (!Adapters[index]->IsLocal(PacketBuffer[i].m_IBuffer))
						{
							auto destination = FindTargetAdapterByMac(pEtherHdr->h_dest);
							if (destination && (destination.value() != a))
								continue;

							BridgeRequest->EthPacket[BridgeRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
							++BridgeRequest->dwPacketsNumber;
						}
					}

					// For local indications add only directed or broadcast/multicast
					if ((PacketBuffer[i].m_IBuffer[0] & 0x01)
						|| Adapters[a]->IsLocal(PacketBuffer[i].m_IBuffer)
						)
					{
						MstcpBridgeRequest->EthPacket[MstcpBridgeRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
						++MstcpBridgeRequest->dwPacketsNumber;
					}
				}

				BridgeRequest->hAdapterHandle = Adapters[a]->GetAdapter();
				MstcpBridgeRequest->hAdapterHandle = Adapters[a]->GetAdapter();

				if (BridgeRequest->dwPacketsNumber)
				{
					SendPacketsToAdapter(BridgeRequest);
					BridgeRequest->dwPacketsNumber = 0;
				}

				if (MstcpBridgeRequest->dwPacketsNumber)
				{
					SendPacketsToMstcp(MstcpBridgeRequest);
					MstcpBridgeRequest->dwPacketsNumber = 0;
				}

			}

			ReadRequest->dwPacketsSuccess = 0;
		}
	}

	m_bIsRunning.clear();
}