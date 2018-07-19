/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  NetworkAdapter.cpp                                      */
/*                                                                       */
/* Abstract: Network interface wrapper class defintions                  */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"
#include "NetworkAdapter.h"

const mac_address mac_address::empty;

// Set network filter for the interface
inline unsigned long CNetworkAdapter::GetHwFilter() 
{ 
	unsigned long result = 0;

	m_api.GetHwPacketFilter(m_hAdapter, &result);

	return result;
}

void CNetworkAdapter::Release()
{
	// This function releases packets in the adapter queue and stops listening the interface
	m_Event.signal();

	// Restore old packet filter
	if (m_dwNetworkFilter) 
		SetHwFilter(m_dwNetworkFilter);

	// Reset adapter mode and flush the packet queue
	m_CurrentMode.dwFlags = 0;
	m_CurrentMode.hAdapterHandle = m_hAdapter;
	m_api.SetAdapterMode(&m_CurrentMode);
	m_api.FlushAdapterPacketQueue(m_hAdapter);
}

void CNetworkAdapter::SetMode(unsigned dwFlags)
{
	m_CurrentMode.dwFlags = dwFlags;
	m_CurrentMode.hAdapterHandle = m_hAdapter;
	m_api.SetAdapterMode(&m_CurrentMode);
}

void CNetworkAdapter::SetMacForIp(in_addr & ip, unsigned char* mac)
{
	std::lock_guard<std::mutex> guard(m_Ip2MacMutex);
	
	m_Ip2Mac[ip] = mac;
}

mac_address CNetworkAdapter::GetMacByIp(in_addr & ip)
{
	std::lock_guard<std::mutex> guard(m_Ip2MacMutex);

	auto search = m_Ip2Mac.find(ip);

	if (search != m_Ip2Mac.end())
	{
		return search->second;
	}

	return mac_address();
}

void CNetworkAdapter::InitializeInterface() noexcept
{
	//
	// Saves original packet filter
	//
	m_dwNetworkFilter = GetHwFilter();

	//
	// Query physical media for the network interface to check is this is WLAN network adapter
	//
	PPACKET_OID_DATA pPhysMediumRequest = (PPACKET_OID_DATA)new char[sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1];
	pPhysMediumRequest->Length = sizeof(DWORD);
	pPhysMediumRequest->Oid = OID_GEN_PHYSICAL_MEDIUM;

	pPhysMediumRequest->hAdapterHandle = m_hAdapter;
	if (m_api.NdisrdRequest(pPhysMediumRequest, FALSE))
	{
		if (static_cast<NdisPhysicalMedium>(*((PDWORD)(pPhysMediumRequest->Data))) ==
			NdisPhysicalMedium::NdisPhysicalMediumNative802_11)
		{
			m_bIsWLAN = true;
		}
	}
}