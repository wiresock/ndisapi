/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ebridge.cpp                                             */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

const size_t	maximum_packet_block = 512;

void EthernetBridge::StartBridge(size_t First, size_t Second)
{
	// Start Ethernet Bridge working threads
	m_BridgedInterfaces = make_pair(First, Second);

	m_bIsRunning.test_and_set();

	m_WorkingThreads.push_back(
		std::thread(
			EthernetBridge::BridgeWorkingThread,
			this,
			First,
			Second
			)
		);

	m_WorkingThreads.push_back(
		std::thread(
			EthernetBridge::BridgeWorkingThread,
			this,
			Second,
			First
		)
	);
}

void EthernetBridge::StopBridge()
{
	m_bIsRunning.clear();

	m_NetworkInterfaces[m_BridgedInterfaces.first]->Release();
	m_NetworkInterfaces[m_BridgedInterfaces.second]->Release();

	// Wait for working threads to exit
	for (auto& t : m_WorkingThreads)
	{
		if (t.joinable())
			t.join();
	}

	// Release working threads objects
	m_WorkingThreads.clear();
}

std::vector<string> EthernetBridge::GetInterfaceList()
{
	std::vector<string> result;
	result.reserve(m_NetworkInterfaces.size());

	for (auto& e : m_NetworkInterfaces)
	{
		result.push_back(e->GetFriendlyName());
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

void EthernetBridge::BridgeWorkingThread(EthernetBridge* eBridgePtr, size_t First, size_t Second)
{
	PETH_M_REQUEST			ReadRequest, BridgeRequest, MstcpBridgeRequest;
	std::unique_ptr<INTERMEDIATE_BUFFER[]> PacketBuffer = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

	//
	// Each working thread gets a pair of network interfaces
	// Thread reads packets from the first network interface and duplicates non local packets to the second
	//
	
	auto& Adapters = eBridgePtr->m_NetworkInterfaces;

	ULONG_PTR dwThreadIndex = reinterpret_cast<ULONG_PTR>(Adapters[First]->GetAdapter());

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

	ReadRequest->hAdapterHandle = Adapters[First]->GetAdapter();
	BridgeRequest->hAdapterHandle = Adapters[Second]->GetAdapter();
	MstcpBridgeRequest->hAdapterHandle = Adapters[Second]->GetAdapter();
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
	if (!Adapters[First]->SetPacketEvent())
	{
		return;
	}

	if (!Adapters[First]->IsWLAN())
	{
		if (!Adapters[First]->SetHwFilter(NDIS_PACKET_TYPE_PROMISCUOUS))
			return;
	}

	Adapters[First]->SetMode(MSTCP_FLAG_SENT_LISTEN|MSTCP_FLAG_RECV_LISTEN|MSTCP_FLAG_FILTER_DIRECT|MSTCP_FLAG_LOOPBACK_BLOCK);
	 
	while (eBridgePtr->m_bIsRunning.test_and_set())
	{
		Adapters[First]->WaitEvent(INFINITE);
 
		// Reset event, as we don't need to wake up all working threads at once
 
		if (eBridgePtr->m_bIsRunning.test_and_set())
			Adapters[First]->ResetEvent();
		else
		{
			break;
		}
 
		// Start reading packet from the driver
 
		while (eBridgePtr->ReadPackets(ReadRequest))
		{
			//
			// WLAN requires MAC NAT
			//
			if (Adapters[First]->IsWLAN())
			{
				// Process packets from WLAN:
				// Need to lookup correct MAC address for each packet by its IP address
				// and replace destination MAC address
				for (size_t i = 0; i < ReadRequest->dwPacketsNumber; ++i)
				{
					ether_header_ptr pEtherHdr = reinterpret_cast<ether_header_ptr>(ReadRequest->EthPacket[i].Buffer->m_IBuffer);
					if (ntohs(pEtherHdr->h_proto) == ETH_P_IP)
					{
						iphdr_ptr pIpHdr = (iphdr*)(ReadRequest->EthPacket[i].Buffer->m_IBuffer + ETHER_HEADER_LENGTH);
						
						auto dest_mac = Adapters[First]->GetMacByIp(pIpHdr->ip_dst);
						if (!(dest_mac == mac_address::empty))
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
							auto dest_mac = Adapters[First]->GetMacByIp(*reinterpret_cast<in_addr*>(pArpHdr->arp_tpa));
							if (!(dest_mac == mac_address::empty))
							{
								memcpy(pEtherHdr->h_dest, &dest_mac[0], ETH_ALEN);
								memcpy(pArpHdr->arp_tha, &dest_mac[0], ETH_ALEN);
							}
						}
					}
				}
			}

			if (Adapters[Second]->IsWLAN())
			{
				// Process packets to WLAN:
				// Need to change source MAC to WLAN adapter MAC 
				// and save pair IP->MAC for the future
				for (size_t i = 0; i < ReadRequest->dwPacketsNumber; ++i)
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
							Adapters[Second]->SetMacForIp(
								*reinterpret_cast<in_addr*>(pArpHdr->arp_spa), 
								&pArpHdr->arp_sha[0]
							);

							// Replace source MAC in ARP request to WLAN adapter one
							memmove(&pArpHdr->arp_sha[0], &Adapters[Second]->GetHwAddress()[0], ETH_ALEN);
						}
						else
						{
							// ARP reply
							
							// Save pair of IP and MAC
							Adapters[Second]->SetMacForIp(
								*reinterpret_cast<in_addr*>(pArpHdr->arp_spa), 
								&pArpHdr->arp_sha[0]
							);

							// Replace target MAC in ARP request to WLAN adapter one
							memmove(&pArpHdr->arp_sha[0], &Adapters[Second]->GetHwAddress()[0], ETH_ALEN);
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
					memmove(&pEtherHdr->h_source, &Adapters[Second]->GetHwAddress()[0], ETH_ALEN);

					// Mark packet as MAC NAT applied
					ReadRequest->EthPacket[i].Buffer->m_Reserved[0] = 1;
				}
			}
 
			for (size_t i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
			{
 
				if (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				{
					// For outgoing packets add to list only orginated from the current interface (to skip possible loopback indications)
					if(Adapters[First]->IsLocal(PacketBuffer[i].m_IBuffer + ETH_ALEN)||
						(Adapters[Second]->IsLocal(PacketBuffer[i].m_IBuffer + ETH_ALEN)))
					{
						BridgeRequest->EthPacket[BridgeRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
						++BridgeRequest->dwPacketsNumber;
					}
				}
				else
				{
					// For incoming packets don't add to list packets destined to local interface (they are not supposed to be bridged anythere else)
					if(!Adapters[First]->IsLocal(PacketBuffer[i].m_IBuffer))
					{
						BridgeRequest->EthPacket[BridgeRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
						++BridgeRequest->dwPacketsNumber;
					} 
				}

				// For local indications add only directed or broadcast/multicast
				if ((PacketBuffer[i].m_IBuffer[0] & 0x01)
					|| Adapters[Second]->IsLocal(PacketBuffer[i].m_IBuffer)
					)
				{
					MstcpBridgeRequest->EthPacket[MstcpBridgeRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
					++MstcpBridgeRequest->dwPacketsNumber;
				}
			}
 
			if (BridgeRequest->dwPacketsNumber)
			{
				eBridgePtr->SendPacketsToAdapter(BridgeRequest);
				BridgeRequest->dwPacketsNumber = 0;
			}

			if (MstcpBridgeRequest->dwPacketsNumber)
			{
				eBridgePtr->SendPacketsToMstcp(MstcpBridgeRequest);
				MstcpBridgeRequest->dwPacketsNumber = 0;
			}
 
			ReadRequest->dwPacketsSuccess = 0;
		}
	}

	eBridgePtr->m_bIsRunning.clear();
}


int main(int argc, char* argv[])
{
	EthernetBridge eBridge;
	size_t first, second, index = 0;

	//
	// Check if driver us loaded properly
	if (!eBridge.IsDriverLoaded())
	{
		cout << "Driver not installed on this system of failed to load. Please install WinpkFilter drivers first." << endl;
		return 0;
	}

	cout << "Available network interfaces:" << endl << endl;
	for (auto& e : eBridge.GetInterfaceList())
	{
		cout << ++index <<") " << e << endl;
	}

	cout << endl;

	cout << "Select first interface:";
	cin >> first;
	cout << "Select second interface:";
	cin >> second;

	if (first > eBridge.GetInterfaceList().size() || second > eBridge.GetInterfaceList().size() || first == second)
	{
		cout << "Wrong parameters were selected. Interfaces are equal or out of range." << endl;
		return 0;
	}

	--first;
	--second;

	try {
		eBridge.StartBridge(first, second);
	}
	catch (const std::system_error& error)
	{
		std::cout << "Error: " << error.code()
			<< " - " << error.code().message() << '\n';

		return 0;
	}

	cout << "Press any key to stop bridging" << endl;
 
	std::ignore = _getch();

	printf("Exiting... \n");
 
	return 0;
}

