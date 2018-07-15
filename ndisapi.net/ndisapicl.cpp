/*************************************************************************/
/*                Copyright (c) 2000-2018 NT Kernel Resources.           */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisapicl.h                                             */
/*                                                                       */
/* Abstract: .NET NdisApi interface defintions                           */
/*                                                                       */
/* Environment:                                                          */
/*   .NET User mode                                                      */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

NdisApi::NdisApiDotNet::NdisApiDotNet(String^ deviceName)
{
	if (deviceName == nullptr)
		m_pNdisApi = new CNdisApi();
	else
		m_pNdisApi = new CNdisApi(marshal_as<std::wstring>(deviceName).c_str());
}

//
// Finalizer
//
NdisApi::NdisApiDotNet::!NdisApiDotNet()
{
	// Release CNdisApi
	if (m_pNdisApi)
		delete m_pNdisApi;
}

//
// Destructor
//
NdisApi::NdisApiDotNet::~NdisApiDotNet()
{
	this->!NdisApiDotNet();
}

UInt32 NdisApi::NdisApiDotNet::GetVersion()
{
	return UInt32(m_pNdisApi->GetVersion());
}

Tuple<Boolean,List<NdisApi::NetworkAdapter^>^>^ NdisApi::NdisApiDotNet::GetTcpipBoundAdaptersInfo()
{
	auto netList = gcnew List<NdisApi::NetworkAdapter^>();
	TCP_AdapterList adapterList = { 0 };

	if (m_pNdisApi->GetTcpipBoundAdaptersInfo(&adapterList))
	{
		for (size_t i = 0; i < adapterList.m_nAdapterCount; i++)
		{
			netList->Add(
				gcnew NdisApi::NetworkAdapter(
					gcnew String(reinterpret_cast<char*>(adapterList.m_szAdapterNameList[i])),
					GetAdapterFriendlyName(reinterpret_cast<char*>(adapterList.m_szAdapterNameList[i])),
					IntPtr(adapterList.m_nAdapterHandle[i]),
					(NDIS_MEDIUM)(adapterList.m_nAdapterMediumList[i] + 1),
					gcnew PhysicalAddress(gcnew cli::array<unsigned char>{
						adapterList.m_czCurrentAddress[i][0],
							adapterList.m_czCurrentAddress[i][1],
							adapterList.m_czCurrentAddress[i][2],
							adapterList.m_czCurrentAddress[i][3],
							adapterList.m_czCurrentAddress[i][4],
							adapterList.m_czCurrentAddress[i][5]}),
					adapterList.m_usMTU[i]
				));
		}

		return Tuple::Create(true, netList);
	}

	return Tuple::Create(false, netList);
}

Boolean NdisApi::NdisApiDotNet::SendPacketToMstcp(IntPtr hAdapter, RawPacket ^ packet)
{
	ETH_REQUEST sendRequest = { 0 };
	INTERMEDIATE_BUFFER intermediateBuffer = {0};

	InitializeSendPacketRequest (hAdapter, packet, sendRequest, intermediateBuffer);

	return Boolean(m_pNdisApi->SendPacketToMstcp(&sendRequest));
}

Boolean NdisApi::NdisApiDotNet::SendPacketToAdapter(IntPtr hAdapter, RawPacket ^ packet)
{
	ETH_REQUEST sendRequest = { 0 };
	INTERMEDIATE_BUFFER intermediateBuffer = { 0 };

	InitializeSendPacketRequest(hAdapter, packet, sendRequest, intermediateBuffer);

	return Boolean(m_pNdisApi->SendPacketToAdapter(&sendRequest));
}

NdisApi::RawPacket^ NdisApi::NdisApiDotNet::ReadPacket(IntPtr hAdapter)
{
	INTERMEDIATE_BUFFER intermediateBuffer = {0};
	ETH_REQUEST readRequest{ static_cast<HANDLE>(hAdapter), &intermediateBuffer };
	
	if (m_pNdisApi->ReadPacket(&readRequest))
	{
		auto packet = gcnew RawPacket();
		packet->Data = gcnew array<Byte>(intermediateBuffer.m_Length);

		pin_ptr<Byte> pinPtrArray = &packet->Data[packet->Data->GetLowerBound(0)];
		memcpy_s( pinPtrArray, packet->Data->Length, intermediateBuffer.m_IBuffer, intermediateBuffer.m_Length);

		packet->DeviceFlags = static_cast<PACKET_FLAG>(intermediateBuffer.m_dwDeviceFlags);
		packet->NdisFlags = intermediateBuffer.m_Flags;
		packet->Dot1q = intermediateBuffer.m_8021q;
		packet->FilterId = intermediateBuffer.m_FilterID;

		return packet;
	}

	return nullptr;
}

Boolean NdisApi::NdisApiDotNet::SendPacketsToMstcp(IntPtr hAdapter, NdisBufferResource^ packetBuffer, List<RawPacket^>^ packetList)
{
	InitializeSendPacketRequestList(hAdapter, packetBuffer, packetList);
	
	return Boolean(m_pNdisApi->SendPacketsToMstcp(packetBuffer->Request));
}

Boolean NdisApi::NdisApiDotNet::SendPacketsToAdapter(IntPtr hAdapter, NdisBufferResource^ packetBuffer, List<RawPacket^>^ packetList)
{
	InitializeSendPacketRequestList(hAdapter, packetBuffer, packetList);

	return Boolean(m_pNdisApi->SendPacketsToAdapter(packetBuffer->Request));
}

Tuple<Boolean, List<NdisApi::RawPacket^>^>^ NdisApi::NdisApiDotNet::ReadPackets(IntPtr hAdapter, NdisBufferResource^ packetBuffer)
{
	auto intermediateBufferListPtr = packetBuffer->Buffer;
	PETH_M_REQUEST readRequestPtr = packetBuffer->Request;

	readRequestPtr->hAdapterHandle = static_cast<HANDLE>(hAdapter);
	readRequestPtr->dwPacketsNumber = packetBuffer->Size;
	readRequestPtr->dwPacketsSuccess = 0;

	for (int i = 0; i < packetBuffer->Size; ++i)
	{
		readRequestPtr->EthPacket[i].Buffer = &intermediateBufferListPtr[i];
	}

	if (m_pNdisApi->ReadPackets(readRequestPtr))
	{
		auto PacketList = gcnew List<NdisApi::RawPacket^>(readRequestPtr->dwPacketsSuccess);

		for (unsigned i = 0; i < readRequestPtr->dwPacketsSuccess; ++i)
		{
			auto packet = gcnew RawPacket();
			packet->Data = gcnew array<Byte>(intermediateBufferListPtr[i].m_Length);

			pin_ptr<Byte> pinPtrArray = &packet->Data[packet->Data->GetLowerBound(0)];
			memcpy_s(pinPtrArray, packet->Data->Length, intermediateBufferListPtr[i].m_IBuffer, intermediateBufferListPtr[i].m_Length);

			packet->DeviceFlags = static_cast<PACKET_FLAG>(intermediateBufferListPtr[i].m_dwDeviceFlags);
			packet->NdisFlags = intermediateBufferListPtr[i].m_Flags;
			packet->Dot1q = intermediateBufferListPtr[i].m_8021q;
			packet->FilterId = intermediateBufferListPtr[i].m_FilterID;

			PacketList->Add(packet);
		}

		return Tuple::Create(true, PacketList);
	}

	return Tuple::Create(false, gcnew List<NdisApi::RawPacket^>());
}

Boolean NdisApi::NdisApiDotNet::SetAdapterMode(IntPtr hAdapter, MSTCP_FLAGS filterFlags)
{
	ADAPTER_MODE adapterMode{ static_cast<HANDLE>(hAdapter), static_cast<UInt32>(filterFlags) };
	return Boolean(m_pNdisApi->SetAdapterMode(&adapterMode));
}

Boolean NdisApi::NdisApiDotNet::GetAdapterMode(IntPtr hAdapter, MSTCP_FLAGS % filterFlags)
{
	ADAPTER_MODE adapterMode{ static_cast<HANDLE>(hAdapter), 0 };

	Boolean retVal = m_pNdisApi->GetAdapterMode(&adapterMode);

	if (retVal)
		filterFlags = static_cast<MSTCP_FLAGS>(adapterMode.dwFlags);

	return retVal;
}

Boolean NdisApi::NdisApiDotNet::FlushAdapterPacketQueue(IntPtr hAdapter)
{
	return Boolean(m_pNdisApi->FlushAdapterPacketQueue(static_cast<HANDLE>(hAdapter)));
}

Boolean NdisApi::NdisApiDotNet::GetAdapterPacketQueueSize(IntPtr hAdapter, UInt32 % queueSize)
{
	DWORD dwQueueSize = 0;
	Boolean retVal = m_pNdisApi->GetAdapterPacketQueueSize(static_cast<HANDLE>(hAdapter), &dwQueueSize);
	
	if (retVal)
		queueSize = dwQueueSize;

	return retVal;
}

Boolean NdisApi::NdisApiDotNet::SetPacketEvent(IntPtr hAdapter, ManualResetEvent ^ eventObject)
{
	if(eventObject != nullptr)
		return Boolean(m_pNdisApi->SetPacketEvent(
			static_cast<HANDLE>(hAdapter),
			static_cast<HANDLE>(eventObject->SafeWaitHandle->DangerousGetHandle()))
		);
	else
		return Boolean(m_pNdisApi->SetPacketEvent(
			static_cast<HANDLE>(hAdapter),
			static_cast<HANDLE>(0))
		);
}

Boolean NdisApi::NdisApiDotNet::SetWANEvent(ManualResetEvent ^ eventObject)
{
	if (eventObject != nullptr)
		return Boolean(m_pNdisApi->SetWANEvent(
			static_cast<HANDLE>(eventObject->SafeWaitHandle->DangerousGetHandle()))
		);
	else
		return Boolean(m_pNdisApi->SetWANEvent(
			static_cast<HANDLE>(0))
		);
}

Boolean NdisApi::NdisApiDotNet::SetAdapterListChangeEvent(ManualResetEvent ^ eventObject)
{
	if (eventObject != nullptr)
		return Boolean(m_pNdisApi->SetAdapterListChangeEvent(
			static_cast<HANDLE>(eventObject->SafeWaitHandle->DangerousGetHandle()))
		);
	else
		return Boolean(m_pNdisApi->SetAdapterListChangeEvent(
			static_cast<HANDLE>(0))
		);
}

Boolean NdisApi::NdisApiDotNet::NdisrdRequest(PacketOidData ^ oidData, Boolean bSet)
{
	Boolean retVal = false;

	if ((oidData == nullptr) || (oidData->Data == nullptr))
		return retVal;

	try {
		auto oidRequest = std::make_unique < uint8_t[]>(sizeof(PACKET_OID_DATA) + oidData->Data->Length - 1);
		auto oidRequestPtr = reinterpret_cast<PPACKET_OID_DATA>(oidRequest.get());

		oidRequestPtr->hAdapterHandle = static_cast<HANDLE>(oidData->Adapter);
		oidRequestPtr->Oid = oidData->Oid;
		oidRequestPtr->Length = oidData->Data->Length;

		pin_ptr<Byte> pinPtrArray = &oidData->Data[oidData->Data->GetLowerBound(0)];
		memcpy_s(oidRequestPtr->Data, oidData->Data->Length, pinPtrArray, oidData->Data->Length);
		
		retVal = m_pNdisApi->NdisrdRequest(oidRequestPtr, bSet ? TRUE : FALSE);

		if (retVal)
		{
			memcpy_s(pinPtrArray, oidData->Data->Length, oidRequestPtr->Data, oidData->Data->Length);
		}
	}
	catch (std::bad_alloc const&)
	{
		throw gcnew System::OutOfMemoryException();
	}

	return retVal;
}

Tuple<Boolean, List<NdisApi::RasLinkInfo^>^>^ NdisApi::NdisApiDotNet::GetRasLinks(IntPtr hAdapter)
{
	RAS_LINKS rasLinks = {0};

	Boolean bResult(m_pNdisApi->GetRasLinks(static_cast<HANDLE>(hAdapter), &rasLinks));

	if (bResult)
	{
		List<NdisApi::RasLinkInfo^>^ retVal = gcnew List<NdisApi::RasLinkInfo^>(rasLinks.nNumberOfLinks);
		for (unsigned i = 0; i < rasLinks.nNumberOfLinks; ++i)
		{
			array<Byte>^ protocolBuffer = gcnew array<Byte>(rasLinks.RasLinks[i].ProtocolBufferLength);
			pin_ptr<Byte> pinPtrArray = &protocolBuffer[protocolBuffer->GetLowerBound(0)];
			memcpy_s(pinPtrArray, protocolBuffer->Length, rasLinks.RasLinks[i].ProtocolBuffer, rasLinks.RasLinks[i].ProtocolBufferLength);

			RasLinkInfo^ rasLinkInfo = gcnew RasLinkInfo(
				rasLinks.RasLinks[i].LinkSpeed,
				rasLinks.RasLinks[i].MaximumTotalSize,
				gcnew PhysicalAddress(gcnew cli::array<unsigned char>{
				rasLinks.RasLinks[i].RemoteAddress[0],
					rasLinks.RasLinks[i].RemoteAddress[1],
					rasLinks.RasLinks[i].RemoteAddress[2],
					rasLinks.RasLinks[i].RemoteAddress[3],
					rasLinks.RasLinks[i].RemoteAddress[4],
					rasLinks.RasLinks[i].RemoteAddress[5]}),
				gcnew PhysicalAddress(gcnew cli::array<unsigned char>{
					rasLinks.RasLinks[i].LocalAddress[0],
						rasLinks.RasLinks[i].LocalAddress[1],
						rasLinks.RasLinks[i].LocalAddress[2],
						rasLinks.RasLinks[i].LocalAddress[3],
						rasLinks.RasLinks[i].LocalAddress[4],
						rasLinks.RasLinks[i].LocalAddress[5]}),
					protocolBuffer);

			retVal->Add(rasLinkInfo);
		}
		
		return Tuple::Create(true, retVal);
	}

	return Tuple::Create(false, gcnew List<NdisApi::RasLinkInfo^>());
}

Boolean NdisApi::NdisApiDotNet::SetHwPacketFilter(IntPtr hAdapter, UInt32 hwFilter)
{
	return Boolean(m_pNdisApi->SetHwPacketFilter(
		static_cast<HANDLE>(hAdapter),
		hwFilter));
}

Boolean NdisApi::NdisApiDotNet::GetHwPacketFilter(IntPtr hAdapter, UInt32 % hwFilter)
{
	DWORD dwFilter = 0;
	Boolean retVal = m_pNdisApi->GetHwPacketFilter(static_cast<HANDLE>(hAdapter), &dwFilter);

	if (retVal)
		hwFilter = dwFilter;

	return retVal;
}

Boolean NdisApi::NdisApiDotNet::SetHwPacketFilterEvent(IntPtr hAdapter, ManualResetEvent ^ eventObject)
{
	if (eventObject != nullptr)
		return Boolean(m_pNdisApi->SetHwPacketFilterEvent(
			static_cast<HANDLE>(hAdapter),
			static_cast<HANDLE>(eventObject->SafeWaitHandle->DangerousGetHandle()))
		);
	else
		return Boolean(m_pNdisApi->SetHwPacketFilterEvent(
			static_cast<HANDLE>(hAdapter),
			static_cast<HANDLE>(0))
		);
}

Boolean NdisApi::NdisApiDotNet::SetPacketFilterTable(List<StaticFilter^>^ filterList)
{
	if ((filterList == nullptr) || (filterList->Count == 0))
		return Boolean(m_pNdisApi->SetPacketFilterTable(nullptr));

	try {
		auto staticFilterTableMem = std::make_unique <char[]>(sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER)*(filterList->Count - 1));
		auto staticFilterTable = reinterpret_cast<PSTATIC_FILTER_TABLE>(staticFilterTableMem.get());

		// Convert from array<StaticFilter^>^ to STATIC_FILTER_TABLE
		ConvertToStaticFilterTable(*staticFilterTable, filterList);

		return Boolean(m_pNdisApi->SetPacketFilterTable(staticFilterTable));
	}
	catch (std::bad_alloc const&)
	{
		throw gcnew System::OutOfMemoryException();
	}
}

Boolean NdisApi::NdisApiDotNet::ResetPacketFilterTable()
{
	return Boolean(m_pNdisApi->ResetPacketFilterTable());
}

Boolean NdisApi::NdisApiDotNet::GetPacketFilterTableSize(UInt32 % dwTableSize)
{
	DWORD tableSize = 0;
	Boolean retVal = m_pNdisApi->GetPacketFilterTableSize(&tableSize);

	if (retVal)
		dwTableSize = tableSize;

	return retVal;
}

Tuple<Boolean, List<NdisApi::StaticFilter^>^>^ NdisApi::NdisApiDotNet::GetPacketFilterTable()
{
	UInt32 dwTableSize{0};

	if (GetPacketFilterTableSize(dwTableSize))
	{
		if (dwTableSize == 0)
			return Tuple::Create(true, gcnew List<NdisApi::StaticFilter^>());

		try {
			auto staticFilterTableMem = std::make_unique <char[]>(sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER)*(dwTableSize - 1));
			auto staticFilterTable = reinterpret_cast<PSTATIC_FILTER_TABLE>(staticFilterTableMem.get());

			staticFilterTable->m_TableSize = dwTableSize;

			if (m_pNdisApi->GetPacketFilterTable(staticFilterTable))
				return Tuple::Create(true, ConvertFromStaticFilterTable(*staticFilterTable));
			else
				return Tuple::Create(false, gcnew List<NdisApi::StaticFilter^>());
		}
		catch (std::bad_alloc const&)
		{
			throw gcnew System::OutOfMemoryException();
		}
	}
	else
		return Tuple::Create(false, gcnew List<NdisApi::StaticFilter^>());
}

Tuple<Boolean, List<NdisApi::StaticFilter^>^>^ NdisApi::NdisApiDotNet::GetPacketFilterTableResetStats()
{
	DWORD dwTableSize{ 0 };

	if (m_pNdisApi->GetPacketFilterTableSize(&dwTableSize))
	{
		if (dwTableSize == 0)
			return Tuple::Create(true, gcnew List<NdisApi::StaticFilter^>());

		try {
			auto staticFilterTableMem = std::make_unique <char[]>(sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER)*(dwTableSize - 1));
			auto staticFilterTable = reinterpret_cast<PSTATIC_FILTER_TABLE>(staticFilterTableMem.get());

			if (m_pNdisApi->GetPacketFilterTableResetStats(staticFilterTable))
				return Tuple::Create(true, ConvertFromStaticFilterTable(*staticFilterTable));
			else
				return Tuple::Create(false, gcnew List<NdisApi::StaticFilter^>());
		}
		catch (std::bad_alloc const&)
		{
			throw gcnew System::OutOfMemoryException();
		}
	}
	else
		return Tuple::Create(false, gcnew List<NdisApi::StaticFilter^>());
}

Boolean NdisApi::NdisApiDotNet::IsDriverLoaded()
{
	return Boolean(m_pNdisApi->IsDriverLoaded());
}

Boolean NdisApi::NdisApiDotNet::SetMTUDecrement(UInt32 dwMTUDecrement)
{
	return Boolean(CNdisApi::SetMTUDecrement(dwMTUDecrement));
}

UInt32 NdisApi::NdisApiDotNet::GetMTUDecrement()
{
	return UInt32(CNdisApi::GetMTUDecrement());
}

Boolean NdisApi::NdisApiDotNet::SetAdaptersStartupMode(UInt32 dwStartupMode)
{
	return Boolean(CNdisApi::SetAdaptersStartupMode(dwStartupMode));
}

UInt32 NdisApi::NdisApiDotNet::GetAdaptersStartupMode()
{
	return UInt32(CNdisApi::GetAdaptersStartupMode());
}

Boolean NdisApi::NdisApiDotNet::IsNdiswanIp(String ^ adapterName)
{
	return Boolean(CNdisApi::IsNdiswanIp(marshal_as<std::string>(adapterName).c_str()));
}

Boolean NdisApi::NdisApiDotNet::IsNdiswanIpv6(String ^ adapterName)
{
	return Boolean(CNdisApi::IsNdiswanIpv6(marshal_as<std::string>(adapterName).c_str()));
}

Boolean NdisApi::NdisApiDotNet::IsNdiswanBh(String ^ adapterName)
{
	return Boolean(CNdisApi::IsNdiswanBh(marshal_as<std::string>(adapterName).c_str()));
}

String ^ NdisApi::NdisApiDotNet::GetAdapterFriendlyName(std::string const & adapterName)
{
	OSVERSIONINFO verInfo{ sizeof(OSVERSIONINFO) };
	std::vector<char> friendlyName(MAX_PATH);

#pragma warning(push)
#pragma warning(disable: 4996)
	GetVersionEx(&verInfo);
#pragma warning(pop)

	if (verInfo.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		if (verInfo.dwMajorVersion > 4)
		{
			// Windows 2000 and later
			CNdisApi::ConvertWindows2000AdapterName(adapterName.c_str(), &friendlyName[0], static_cast<DWORD>(friendlyName.size()));
		}
		else if (verInfo.dwMajorVersion == 4)
		{
			// Windows NT 4.0	
			CNdisApi::ConvertWindowsNTAdapterName(adapterName.c_str(), &friendlyName[0], static_cast<DWORD>(friendlyName.size()));
		}
	}
	else
	{
		// Windows 9x/ME
		CNdisApi::ConvertWindows9xAdapterName(adapterName.c_str(), &friendlyName[0], static_cast<DWORD>(friendlyName.size()));
	}

	return gcnew String(&friendlyName[0]);
}

void NdisApi::NdisApiDotNet::InitializeSendPacketRequest(IntPtr hAdapter, RawPacket ^ packet, _ETH_REQUEST& sendRequest, _INTERMEDIATE_BUFFER& intermediateBuffer)
{
	sendRequest.hAdapterHandle = static_cast<HANDLE>(hAdapter);
	sendRequest.EthPacket.Buffer = &intermediateBuffer;

	intermediateBuffer.m_dwDeviceFlags = static_cast<UInt32>(packet->DeviceFlags);
	intermediateBuffer.m_Flags = packet->NdisFlags;
	intermediateBuffer.m_FilterID = packet->FilterId;
	intermediateBuffer.m_8021q = packet->Dot1q;
	intermediateBuffer.m_Length = packet->Data->Length;

	pin_ptr<Byte> pinPtrArray = &packet->Data[packet->Data->GetLowerBound(0)];

	// Truncate packet if exceeeds MAX_ETHER_FRAME
	memcpy_s(intermediateBuffer.m_IBuffer, MAX_ETHER_FRAME, pinPtrArray, (std::min)(packet->Data->Length, MAX_ETHER_FRAME));

	// Recalculate checksums if flags are set
	if ((packet->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_TCP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_TCP_V4)
		CNdisApi::RecalculateTCPChecksum(&intermediateBuffer);

	if ((packet->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_UDP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_UDP_V4)
		CNdisApi::RecalculateUDPChecksum(&intermediateBuffer);

	if ((packet->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_ICMP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_ICMP_V4)
		CNdisApi::RecalculateUDPChecksum(&intermediateBuffer);

	if ((packet->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_IP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_IP_V4)
		CNdisApi::RecalculateUDPChecksum(&intermediateBuffer);
}

void NdisApi::NdisApiDotNet::InitializeSendPacketRequestList(IntPtr hAdapter, NdisBufferResource^ packetBuffer, List<RawPacket^>^ packetList)
{
	PETH_M_REQUEST sendRequestPtr = packetBuffer->Request;
	PINTERMEDIATE_BUFFER intermediateBufferListPtr = packetBuffer->Buffer;

	for (int i = 0; i < (std::min)(packetList->Count, packetBuffer->Size); ++i)
	{
		sendRequestPtr->EthPacket[i].Buffer = &intermediateBufferListPtr[i];

		intermediateBufferListPtr[i].m_dwDeviceFlags = static_cast<UInt32>(packetList[i]->DeviceFlags);
		intermediateBufferListPtr[i].m_Flags = packetList[i]->NdisFlags;
		intermediateBufferListPtr[i].m_FilterID = packetList[i]->FilterId;
		intermediateBufferListPtr[i].m_8021q = packetList[i]->Dot1q;
		intermediateBufferListPtr[i].m_Length = packetList[i]->Data->Length;

		pin_ptr<Byte> pinPtrArray = &packetList[i]->Data[packetList[i]->Data->GetLowerBound(0)];

		// Truncate packet if exceeeds MAX_ETHER_FRAME
		memcpy_s(intermediateBufferListPtr[i].m_IBuffer, MAX_ETHER_FRAME, pinPtrArray, (std::min)(packetList[i]->Data->Length, MAX_ETHER_FRAME));

		// Recalculate checksums if flags are set
		if ((packetList[i]->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_TCP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_TCP_V4)
			CNdisApi::RecalculateTCPChecksum(&intermediateBufferListPtr[i]);

		if ((packetList[i]->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_UDP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_UDP_V4)
			CNdisApi::RecalculateUDPChecksum(&intermediateBufferListPtr[i]);

		if ((packetList[i]->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_ICMP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_ICMP_V4)
			CNdisApi::RecalculateUDPChecksum(&intermediateBufferListPtr[i]);

		if ((packetList[i]->Checksums & RawPacket::CHECKSUM_FLAG::RECALCULATE_IP_V4) == RawPacket::CHECKSUM_FLAG::RECALCULATE_IP_V4)
			CNdisApi::RecalculateUDPChecksum(&intermediateBufferListPtr[i]);
	}

	sendRequestPtr->hAdapterHandle = static_cast<HANDLE>(hAdapter);
	sendRequestPtr->dwPacketsNumber = packetList->Count;
	sendRequestPtr->dwPacketsSuccess = 0;
}

void NdisApi::NdisApiDotNet::ConvertToStaticFilterTable(_STATIC_FILTER_TABLE& staticFilterTable, List<StaticFilter^>^ filterList)
{
	staticFilterTable.m_TableSize = filterList->Count;
	auto& filterTable = staticFilterTable.m_StaticFilters;

	for (int i = 0; i < filterList->Count; ++i)
	{
		filterTable[i].m_Adapter.QuadPart = (ULONGLONG)(static_cast<HANDLE>(filterList[i]->Adapter));
		filterTable[i].m_dwDirectionFlags = static_cast<UInt32>(filterList[i]->DirectionFlags);
		filterTable[i].m_FilterAction = static_cast<UInt32>(filterList[i]->FilterAction);
		filterTable[i].m_ValidFields = static_cast<UInt32>(filterList[i]->ValidFields);

		if ((filterTable[i].m_ValidFields & DATA_LINK_LAYER_VALID) && (filterList[i]->DataLinkFilter != nullptr))
		{
			filterTable[i].m_DataLinkFilter.m_dwUnionSelector = ETH_802_3;
			filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields = 
				static_cast<UInt32>(filterList[i]->DataLinkFilter->ValidFields);

			if (filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_SRC_ADDRESS)
			{
				for (int j = 0; j < ETHER_ADDR_LENGTH; ++j)
				{
					filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[j] =
						filterList[i]->DataLinkFilter->SrcAddress->GetAddressBytes()[j];
				}
			}

			if (filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_DEST_ADDRESS)
			{
				for (int j = 0; j < ETHER_ADDR_LENGTH; ++j)
				{
					filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[j] =
						filterList[i]->DataLinkFilter->DestAddress->GetAddressBytes()[j];
				}
			}

			if (filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_PROTOCOL)
			{
				filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_Protocol = filterList[i]->DataLinkFilter->Protocol;
			}
		}

		if ((filterTable[i].m_ValidFields & NETWORK_LAYER_VALID) && (filterList[i]->NetworkFilter != nullptr))
		{
			switch (filterList[i]->NetworkFilter->IpAddressFamily)
			{
			case AddressFamily::InterNetwork:
				filterTable[i].m_NetworkFilter.m_dwUnionSelector = IPV4;
				filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields = 
					static_cast<UInt32>(filterList[i]->NetworkFilter->ValidFields);
				if (filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_SRC_ADDRESS)
				{
					filterTable[i].m_NetworkFilter.m_IPv4.m_SrcAddress.m_AddressType = 
						static_cast<UInt32>(filterList[i]->NetworkFilter->SrcAddress->AddressType);

					in_addr start_ip{
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[3]
					};
					in_addr end_ip{
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[3]
					};
					filterTable[i].m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpRange.m_StartIp = start_ip.S_un.S_addr;
					filterTable[i].m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpRange.m_EndIp = end_ip.S_un.S_addr;
				}

				if (filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_DEST_ADDRESS)
				{
					filterTable[i].m_NetworkFilter.m_IPv4.m_DestAddress.m_AddressType = 
						static_cast<UInt32>(filterList[i]->NetworkFilter->DestAddress->AddressType);

					in_addr start_ip{
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[3]
					};
					in_addr end_ip{
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[3]
					};
					filterTable[i].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpRange.m_StartIp = start_ip.S_un.S_addr;
					filterTable[i].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpRange.m_EndIp = end_ip.S_un.S_addr;
				}

				if (filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_PROTOCOL)
				{
					filterTable[i].m_NetworkFilter.m_IPv4.m_Protocol = filterList[i]->NetworkFilter->Protocol;
				}

				break;
			case AddressFamily::InterNetworkV6:
				filterTable[i].m_NetworkFilter.m_dwUnionSelector = IPV6;
				filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields = 
					static_cast<UInt32>(filterList[i]->NetworkFilter->ValidFields);
				if (filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_SRC_ADDRESS)
				{
					filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_AddressType = 
						static_cast<UInt32>(filterList[i]->NetworkFilter->SrcAddress->AddressType);

					in_addr6 start_ip{
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[3],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[4],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[5],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[6],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[7],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[8],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[9],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[10],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[11],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[12],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[13],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[14],
						filterList[i]->NetworkFilter->SrcAddress->StartRange->GetAddressBytes()[15]
					};
					in_addr6 end_ip{
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[3],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[4],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[5],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[6],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[7],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[8],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[9],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[10],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[11],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[12],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[13],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[14],
						filterList[i]->NetworkFilter->SrcAddress->EndRange->GetAddressBytes()[15]
					};
					filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp = start_ip;
					filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp = end_ip;
				}

				if (filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_DEST_ADDRESS)
				{
					filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_AddressType = 
						static_cast<UInt32>(filterList[i]->NetworkFilter->DestAddress->AddressType);

					in_addr6 start_ip{
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[3],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[4],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[5],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[6],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[7],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[8],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[9],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[10],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[11],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[12],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[13],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[14],
						filterList[i]->NetworkFilter->DestAddress->StartRange->GetAddressBytes()[15]
					};
					in_addr6 end_ip{
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[0],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[1],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[2],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[3],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[4],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[5],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[6],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[7],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[8],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[9],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[10],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[11],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[12],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[13],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[14],
						filterList[i]->NetworkFilter->DestAddress->EndRange->GetAddressBytes()[15]
					};
					filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp = start_ip;
					filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp = end_ip;
				}

				if (filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_PROTOCOL)
				{
					filterTable[i].m_NetworkFilter.m_IPv6.m_Protocol = filterList[i]->NetworkFilter->Protocol;
				}
				break;
			default:
				break;
			}

			if ((filterTable[i].m_ValidFields & TRANSPORT_LAYER_VALID) && (filterList[i]->TransportFilter != nullptr))
			{
				filterTable[i].m_TransportFilter.m_dwUnionSelector = TCPUDP;
				filterTable[i].m_TransportFilter.m_TcpUdp.m_ValidFields = 
					static_cast<UInt32>(filterList[i]->TransportFilter->ValidFields);

				if (filterTable[i].m_TransportFilter.m_TcpUdp.m_ValidFields & TCPUDP_SRC_PORT)
				{
					filterTable[i].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange =
						filterList[i]->TransportFilter->SrcPort.startRange;
					filterTable[i].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange =
						filterList[i]->TransportFilter->SrcPort.endRange;
				}

				if (filterTable[i].m_TransportFilter.m_TcpUdp.m_ValidFields & TCPUDP_DEST_PORT)
				{
					filterTable[i].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange =
						filterList[i]->TransportFilter->DestPort.startRange;
					filterTable[i].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange =
						filterList[i]->TransportFilter->DestPort.endRange;
				}

				if (filterTable[i].m_TransportFilter.m_TcpUdp.m_ValidFields & TCPUDP_TCP_FLAGS)
				{
					filterTable[i].m_TransportFilter.m_TcpUdp.m_TCPFlags =
						filterList[i]->TransportFilter->TCPFlags;
				}
			}
		}
	}
}

List<NdisApi::StaticFilter^>^ NdisApi::NdisApiDotNet::ConvertFromStaticFilterTable(_STATIC_FILTER_TABLE& staticFilterTable)
{
	auto filterList = gcnew List<StaticFilter^>();

	auto& filterTable = staticFilterTable.m_StaticFilters;

	for (size_t i = 0; i < staticFilterTable.m_TableSize; ++i)
	{
		auto staticFilter = gcnew StaticFilter();

		staticFilter->Adapter = static_cast<IntPtr>(static_cast<LONGLONG>(filterTable[i].m_Adapter.QuadPart));
		staticFilter->DirectionFlags = static_cast<PACKET_FLAG>(filterTable[i].m_dwDirectionFlags);
		staticFilter->FilterAction = static_cast<StaticFilter::FILTER_PACKET_ACTION>(filterTable[i].m_FilterAction);
		staticFilter->ValidFields = static_cast<StaticFilter::STATIC_FILTER_FIELDS>(filterTable[i].m_ValidFields);

		staticFilter->LastReset = filterTable[i].m_LastReset;
		staticFilter->PacketsIn = filterTable[i].m_PacketsIn.QuadPart;
		staticFilter->BytesIn = filterTable[i].m_BytesIn.QuadPart;
		staticFilter->PacketsOut = filterTable[i].m_PacketsOut.QuadPart;
		staticFilter->BytesOut = filterTable[i].m_BytesOut.QuadPart;

		if (filterTable[i].m_ValidFields & DATA_LINK_LAYER_VALID)
		{
			switch (filterTable[i].m_DataLinkFilter.m_dwUnionSelector)
			{
			case ETH_802_3:
			{
				staticFilter->DataLinkFilter = gcnew Eth802dot3Filter(
					static_cast<Eth802dot3Filter::ETH_802_3_FLAGS> (filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields),
					(filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_SRC_ADDRESS) ?
					gcnew PhysicalAddress(
						gcnew cli::array<unsigned char>{
					filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[0],
						filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[1],
						filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[2],
						filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[3],
						filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[4],
						filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_SrcAddress[5]
				}) : nullptr,
						(filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_DEST_ADDRESS) ?
						gcnew PhysicalAddress(
							gcnew cli::array<unsigned char>{
						filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[0],
							filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[1],
							filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[2],
							filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[3],
							filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[4],
							filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_DestAddress[5]
					}) : nullptr,
							(filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields & ETH_802_3_PROTOCOL) ?
							filterTable[i].m_DataLinkFilter.m_Eth8023Filter.m_Protocol : 0
							);
			}
				break;
			default:
				break;
			}
		}

		if (filterTable[i].m_ValidFields & NETWORK_LAYER_VALID)
		{
			switch (filterTable[i].m_NetworkFilter.m_dwUnionSelector)
			{
			case IPV4:
			{
				staticFilter->NetworkFilter = gcnew IpAddressFilter(
					AddressFamily::InterNetwork,
					static_cast<IpAddressFilter::IP_FILTER_FIELDS>(filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields),
					(filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_SRC_ADDRESS) ?
					gcnew IpNetRange(
						static_cast<IpNetRange::ADDRESS_TYPE>(filterTable[i].m_NetworkFilter.m_IPv4.m_SrcAddress.m_AddressType),
						gcnew IPAddress(filterTable[i].m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpRange.m_StartIp),
						gcnew IPAddress(filterTable[i].m_NetworkFilter.m_IPv4.m_SrcAddress.m_IpRange.m_EndIp)
					) : nullptr,
					(filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_DEST_ADDRESS) ?
					gcnew IpNetRange(
						static_cast<IpNetRange::ADDRESS_TYPE>(filterTable[i].m_NetworkFilter.m_IPv4.m_DestAddress.m_AddressType),
						gcnew IPAddress(filterTable[i].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpRange.m_StartIp),
						gcnew IPAddress(filterTable[i].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpRange.m_EndIp)
					) : nullptr,
					(filterTable[i].m_NetworkFilter.m_IPv4.m_ValidFields & IP_V4_FILTER_PROTOCOL) ?
					filterTable[i].m_NetworkFilter.m_IPv4.m_Protocol : 0
				);
				break;
			case IPV6:
				staticFilter->NetworkFilter = gcnew IpAddressFilter(
					AddressFamily::InterNetworkV6,
					static_cast<IpAddressFilter::IP_FILTER_FIELDS>(filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields),
					(filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_SRC_ADDRESS) ?
					gcnew IpNetRange(
						static_cast<IpNetRange::ADDRESS_TYPE>(filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_AddressType),
						gcnew IPAddress(
							gcnew cli::array<unsigned char>
				{
					filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[0],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[1],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[2],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[3],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[4],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[5],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[6],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[7],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[8],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[9],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[10],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[11],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[12],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[13],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[14],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_StartIp.u.Byte[15]
				}
				),
						gcnew IPAddress(
							gcnew cli::array<unsigned char>
				{
					filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[0],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[1],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[2],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[3],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[4],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[5],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[6],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[7],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[8],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[9],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[10],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[11],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[12],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[13],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[14],
						filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_IpRange.m_EndIp.u.Byte[15]
				})): nullptr,
							(filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_DEST_ADDRESS) ?
						gcnew IpNetRange(
							static_cast<IpNetRange::ADDRESS_TYPE>(filterTable[i].m_NetworkFilter.m_IPv6.m_SrcAddress.m_AddressType),
							gcnew IPAddress(
								gcnew cli::array<unsigned char>
					{
						filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[0],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[1],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[2],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[3],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[4],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[5],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[6],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[7],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[8],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[9],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[10],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[11],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[12],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[13],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[14],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_StartIp.u.Byte[15]
					}
					),
							gcnew IPAddress(
								gcnew cli::array<unsigned char>
					{
						filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[0],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[1],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[2],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[3],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[4],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[5],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[6],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[7],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[8],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[9],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[10],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[11],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[12],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[13],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[14],
							filterTable[i].m_NetworkFilter.m_IPv6.m_DestAddress.m_IpRange.m_EndIp.u.Byte[15]
					})): nullptr,
								(filterTable[i].m_NetworkFilter.m_IPv6.m_ValidFields & IP_V6_FILTER_PROTOCOL) ?
							filterTable[i].m_NetworkFilter.m_IPv6.m_Protocol : 0
							);
			}
				break;
			default:
				break;
			}
		}
			
		if (filterTable[i].m_ValidFields & TRANSPORT_LAYER_VALID)
		{
			switch (filterTable[i].m_TransportFilter.m_dwUnionSelector)
			{
			case TCPUDP:
				staticFilter->TransportFilter = gcnew TcpUdpFilter(
					static_cast<TcpUdpFilter::TCPUDP_FILTER_FIELDS>(filterTable[i].m_TransportFilter.m_TcpUdp.m_ValidFields),
					{ 
						filterTable[i].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange,
						filterTable[i].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange
					},
					{
						filterTable[i].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange,
						filterTable[i].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange
					},
					filterTable[i].m_TransportFilter.m_TcpUdp.m_TCPFlags
					);
				break;
			default:
				break;
			}
		}

		filterList->Add(staticFilter);
	}

	return filterList;
}

//====================================================================================================

NdisApi::NdisBufferResource::NdisBufferResource(Int32 size)
{
	_size = size;

	try {
		_intermediateBufferPtr = new INTERMEDIATE_BUFFER[size];
		_dataRequest = new uint8_t[sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet)*(size - 1)];
	}
	catch (std::bad_alloc const&)
	{
		if (_intermediateBufferPtr)
			delete[] _intermediateBufferPtr;

		if (_dataRequest)
			delete[] _dataRequest;

		throw gcnew System::OutOfMemoryException();
	}
}

NdisApi::NdisBufferResource::!NdisBufferResource()
{
	if(_intermediateBufferPtr)
		delete[] _intermediateBufferPtr;

	if (_dataRequest)
		delete[] _dataRequest;
}

NdisApi::NdisBufferResource::~NdisBufferResource()
{
	this->!NdisBufferResource();
}