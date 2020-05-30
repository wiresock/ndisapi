/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/* Module Name:  NetworkInterface.cpp	                                 */
/*                                                                       */
/* Abstract: CNetworkInterface implementation file			             */
/*                                                                       */
/*                                                                       */
/*************************************************************************/

#include "StdAfx.h"
#include ".\networkinterface.h"

CNetworkInterface::CNetworkInterface(void)
: m_szInternalName(_T(""))
, m_szUserFriendlyName(_T(""))
, m_bIsWan(false)
, m_NATState(NONE)
, m_Index(0)
{
	memset(m_chMACAddr, 0, ETHER_ADDR_LENGTH);
}

CNetworkInterface::~CNetworkInterface(void)
{
	while(!m_IpList.IsEmpty())
	{
		CIpAddr* pIpAddr = (CIpAddr*)m_IpList.RemoveHead();
		delete pIpAddr;
	}
}

// Uses IP helper APi to query system for the MTU's associated with current network interface
void CNetworkInterface::InitMTUInformation(void)
{
	PMIB_IFTABLE		ifTable;
	DWORD				dwSize = 0;
	DWORD				dwRetVal = 0;
	DWORD				dwMTU	= 0;
	DWORD				dwSpeed	= 0;


	// Allocate memory for our pointers
	ifTable = (MIB_IFTABLE*) malloc(sizeof(MIB_IFTABLE));

	if(!ifTable)
		return;

	// Make an initial call to GetIfTable to get the
	// necessary size into the dwSize variable
	if (GetIfTable(ifTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
	{
		free(ifTable);
		
		ifTable = (MIB_IFTABLE *) malloc (dwSize);

		if(!ifTable)
			return;

		if (GetIfTable(ifTable, &dwSize, 0) != NO_ERROR)
		{
			if(ifTable)
				free(ifTable);

			return;
		}
	}

	for(unsigned int m = 0; m < ifTable->dwNumEntries; m++)
	{
		if(m_Index == ifTable->table[m].dwIndex)
		{	
			m_MTU	= (unsigned short)ifTable->table[m].dwMtu;

			break;
		}

	}

	if(ifTable)
		free(ifTable);

	return;
}

// Uses IP helper APi to query system for the IP's associated with current network interface
int CNetworkInterface::InitIPInformation(void)
{
	DWORD				dwOutputBufferZize = 0;
	PIP_ADAPTER_INFO	pAdapterInfo = NULL;
	PIP_ADAPTER_INFO	pAdapter = NULL;
	PIP_ADDR_STRING		pIpString = NULL;

	if (ERROR_BUFFER_OVERFLOW == GetAdaptersInfo(pAdapterInfo, &dwOutputBufferZize))
	{
		// Allocate required amount of memory from the heap
		pAdapterInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOutputBufferZize);

		if(pAdapterInfo)
		{
			if(ERROR_SUCCESS == GetAdaptersInfo(pAdapterInfo, &dwOutputBufferZize))
			{
				// Walk the list of adapters and get IP's associated with this adapter
				pAdapter = pAdapterInfo;
				while (pAdapter)
				{
					if ((((pAdapter->Type == MIB_IF_TYPE_PPP)||(pAdapter->Type == MIB_IF_TYPE_SLIP))&&(m_bIsWan))||
						(!memcmp(m_chMACAddr, pAdapter->Address, ETHER_ADDR_LENGTH)))
					{
						pIpString = &pAdapter->IpAddressList;
						
						while (pIpString)
						{
							CIpAddr* pIpAddr = new CIpAddr;
							pIpAddr->m_szIp = pIpString->IpAddress.String;
							pIpAddr->m_szMask = pIpString->IpMask.String;
							pIpAddr->m_Ip.S_un.S_addr = htonl(inet_addr(pIpAddr->m_szIp));

							m_IpList.AddTail(pIpAddr);
							pIpString = pIpString->Next;

							m_Index = pAdapter->Index;
						}
					}

					pAdapter = pAdapter->Next;
				}
			}

			// Free buffer
			HeapFree(GetProcessHeap(), 0, pAdapterInfo);
		}
	}
	return 0;
}

// Returnes TRUE if specified IP belongs to current interface
BOOL CNetworkInterface::IsLocalAddress(in_addr* pIp)
{
	CIpAddr* pIpAddr;

	if(m_IpList.IsEmpty())
		return FALSE;

	POSITION pos = m_IpList.GetHeadPosition();

	for (int i = 0; i < m_IpList.GetCount(); ++i)
	{
		pIpAddr = (CIpAddr*)m_IpList.GetNext(pos);

		if (pIpAddr->m_Ip.S_un.S_addr == ntohl(pIp->S_un.S_addr))
			return TRUE;
	}

	return FALSE;
}
