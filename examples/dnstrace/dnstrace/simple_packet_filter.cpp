/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  simple_packet_filter.cpp                                */
/*                                                                       */
/* Abstract: Simple packet filter class defintion                        */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

bool simple_packet_filter::start_filter(size_t Adapter)
{
	if (m_bIsRunning.test_and_set())
		return false;

	m_Adapter = Adapter;
	m_WorkingThread = std::thread(&simple_packet_filter::filter_working_thread, this);

	return true;
}

bool simple_packet_filter::stop_filter()
{
	if (!m_bIsRunning.test_and_set())
	{
		m_bIsRunning.clear();
		return false;
	}

	m_bIsRunning.clear();

	m_NetworkInterfaces[m_Adapter]->Release();

	// Wait for working thread to exit
	if (m_WorkingThread.joinable())
		m_WorkingThread.join();

	return true;
}

std::vector<std::string> simple_packet_filter::get_interface_list()
{
	std::vector<std::string> result;
	result.reserve(m_NetworkInterfaces.size());

	for (auto&& e : m_NetworkInterfaces)
	{
		result.push_back(e->GetFriendlyName());
	}

	return result;
}

void simple_packet_filter::initialize_network_interfaces()
{
	TCP_AdapterList			AdList;
	std::vector<char>		szFriendlyName(MAX_PATH * 4);

	GetTcpipBoundAdaptersInfo(&AdList);

	for (size_t i = 0; i < AdList.m_nAdapterCount; ++i)
	{
		CNdisApi::ConvertWindows2000AdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName.data(), static_cast<DWORD>(szFriendlyName.size()));

		m_NetworkInterfaces.push_back(
			std::make_unique<network_adapter>(
				this,
				AdList.m_nAdapterHandle[i],
				AdList.m_czCurrentAddress[i],
				std::string((const char*)AdList.m_szAdapterNameList[i]),
				std::string(szFriendlyName.data())));
	}
}

void simple_packet_filter::filter_working_thread()
{
	PETH_M_REQUEST ReadRequest, WriteAdapterRequest, WriteMstcpRequest;
	std::unique_ptr<INTERMEDIATE_BUFFER[]> PacketBuffer =
		std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

	//
	// Initialize Requests
	//

	using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
		sizeof(NDISRD_ETH_Packet)*(maximum_packet_block - 1)>;

	// 1. Allocate memory using unique_ptr for auto-delete on thread exit
	auto ReadRequestPtr = std::make_unique<request_storage_type_t>();
	auto WriteAdapterRequestPtr = std::make_unique<request_storage_type_t>();
	auto WriteMstcpRequestPtr = std::make_unique<request_storage_type_t>();

	// 2. Get raw pointers for convinience
	ReadRequest = reinterpret_cast<PETH_M_REQUEST>(ReadRequestPtr.get());
	WriteAdapterRequest = reinterpret_cast<PETH_M_REQUEST>(WriteAdapterRequestPtr.get());
	WriteMstcpRequest = reinterpret_cast<PETH_M_REQUEST>(WriteMstcpRequestPtr.get());

	ReadRequest->hAdapterHandle = m_NetworkInterfaces[m_Adapter]->GetAdapter();
	WriteAdapterRequest->hAdapterHandle = m_NetworkInterfaces[m_Adapter]->GetAdapter();
	WriteMstcpRequest->hAdapterHandle = m_NetworkInterfaces[m_Adapter]->GetAdapter();

	ReadRequest->dwPacketsNumber = maximum_packet_block;

	//
	// Initialize packet buffers
	//
	ZeroMemory(PacketBuffer.get(), sizeof(INTERMEDIATE_BUFFER)*maximum_packet_block);

	for (unsigned i = 0; i < maximum_packet_block; ++i)
	{
		ReadRequest->EthPacket[i].Buffer = &PacketBuffer[i];
	}

	//
	// Set events for helper driver
	//
	if (!m_NetworkInterfaces[m_Adapter]->SetPacketEvent())
	{
		return;
	}

	m_NetworkInterfaces[m_Adapter]->SetMode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

	while (m_bIsRunning.test_and_set())
	{
		m_NetworkInterfaces[m_Adapter]->WaitEvent(INFINITE);

		if (m_bIsRunning.test_and_set())
			m_NetworkInterfaces[m_Adapter]->ResetEvent();
		else
		{
			break;
		}

		while (ReadPackets(ReadRequest))
		{
			for (size_t i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
			{
				PacketAction packetAction = PacketAction::pass;

				if ((filter_outgoing_packet != nullptr) && (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
					packetAction = filter_outgoing_packet(PacketBuffer[i]);

				if ((filter_incoming_packet != nullptr) && (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
					packetAction = filter_incoming_packet(PacketBuffer[i]);

				// Place packet back into the flow if was allowed to
				if (packetAction == PacketAction::pass)
				{
					if (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						WriteAdapterRequest->EthPacket[WriteAdapterRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
						++WriteAdapterRequest->dwPacketsNumber;
					}
					else
					{
						WriteMstcpRequest->EthPacket[WriteMstcpRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
						++WriteMstcpRequest->dwPacketsNumber;
					}
				}
			}

			if (WriteAdapterRequest->dwPacketsNumber)
			{
				SendPacketsToAdapter(WriteAdapterRequest);
				WriteAdapterRequest->dwPacketsNumber = 0;
			}

			if (WriteMstcpRequest->dwPacketsNumber)
			{
				SendPacketsToMstcp(WriteMstcpRequest);
				WriteMstcpRequest->dwPacketsNumber = 0;
			}

			ReadRequest->dwPacketsSuccess = 0;
		}
	}

	m_bIsRunning.clear();
}