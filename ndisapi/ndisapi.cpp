/*************************************************************************/
/*              Copyright (c) 2000-2017 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisapi.cpp                                             */
/*                                                                       */
/* Description: API exported C++ class and C API definitioons            */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#include "precomp.h"

#if _MSC_VER >= 1910
#include <mutex>
#include <shared_mutex>
#endif // _MSC_VER >= 1910

#define DEVICE_NDISWANIP "\\DEVICE\\NDISWANIP"
#define USER_NDISWANIP "WAN Network Interface (IP)"
#define DEVICE_NDISWANBH "\\DEVICE\\NDISWANBH"
#define USER_NDISWANBH "WAN Network Interface (BH)"
#define DEVICE_NDISWANIPV6 "\\DEVICE\\NDISWANIPV6"
#define USER_NDISWANIPV6 "WAN Network Interface (IPv6)"
#define REGSTR_COMPONENTID_NDISWANIP "ms_ndiswanip"
#define REGSTR_COMPONENTID_NDISWANIPV6 "ms_ndiswanipv6"
#define REGSTR_COMPONENTID_NDISWANBH "ms_ndiswanbh"
#define REGSTR_VAL_CONNECTION "\\Connection"
#define REGSTR_VAL_NAME "Name"
#define REGSTR_VAL_SERVICE_NAME "ServiceName"
#define REGSTR_VAL_DRIVER_DESC "DriverDesc"
#define REGSTR_VAL_TITLE "Title"

#define REGSTR_NETWORK_CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
#define REGSTR_NETWORK_CARDS TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
#define REGSTR_MSTCP_CLASS_NET "SYSTEM\\CurrentControlSet\\Services\\Class\\Net\\"
#define REGSTR_NETWORK_CONTROL_CLASS TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}")

#define OID_GEN_CURRENT_PACKET_FILTER			0x0001010E

// OS version information
CVersionInfo CNdisApi::ms_Version;

class CNdisApi::CWow64Helper
{
public:
#if _MSC_VER < 1910
	~CWow64Helper()
	{
		::CloseHandle(m_hWin32Mutex);
	}
#endif //_MSC_VER < 1910

	static CWow64Helper& getInstance()
	{
		static CWow64Helper    instance;	// Guaranteed to be destroyed.
											// Instantiated on first use.
		return instance;
	}

	void Update(TCP_AdapterList_WOW64 adapterListWow64);

	ULONGLONG From32to64Handle(unsigned int handle)
	{
#if _MSC_VER >= 1910
		std::shared_lock <std::shared_mutex> _lock(m_SharedLock);
#else
		InternalLock();
#endif // _MSC_VER >= 1910

		ULONGLONG result = m_Handle32to64[handle];

#if _MSC_VER < 1910
		InternalUnlock();
#endif _MSC_VER < 1910

		return result;
	}

	unsigned int From64to32Handle(ULONGLONG handle)
	{
		unsigned int result = 0;

#if _MSC_VER >= 1910
		std::shared_lock <std::shared_mutex> _lock(m_SharedLock);
#else
		InternalLock();
#endif // _MSC_VER >= 1910

		for (unsigned int i = 1; i < ADAPTER_LIST_SIZE + 1; ++i)
		{
			if (m_Handle32to64[i] == handle)
			{
				return i;
			}
		}

#if _MSC_VER < 1910
		InternalUnlock();
#endif _MSC_VER < 1910
		return result;
	}

private:
#if _MSC_VER >= 1910
	CWow64Helper() = default;

	CWow64Helper(CWow64Helper const&) = delete;
	CWow64Helper& operator=(CWow64Helper const&) = delete;
#else
	CWow64Helper() : m_hWin32Mutex(::CreateMutex(NULL, FALSE, NULL))
	{
		memset((void*)m_Handle32to64, 0, sizeof(m_Handle32to64));
	}

	// Synchronize an acess to m_Handle32to64 using Win32 mutex
	DWORD InternalLock() { return ::WaitForSingleObject(m_hWin32Mutex, INFINITE); }
	void InternalUnlock() { ::ReleaseMutex(m_hWin32Mutex); }

	CWow64Helper(CWow64Helper const&);				// Don't Implement
	CWow64Helper& operator=(CWow64Helper const&);	// Don't implement
#endif // 

#if _MSC_VER >= 1910
	std::shared_mutex				m_SharedLock;
#else
	HANDLE							m_hWin32Mutex;
#endif //_MSC_VER >= 1910

	ULONGLONG						m_Handle32to64[ADAPTER_LIST_SIZE + 1];
};

void CNdisApi::CWow64Helper::Update(TCP_AdapterList_WOW64 adapterListWow64)
{
#if _MSC_VER >= 1910
	std::unique_lock <std::shared_mutex> _lock(m_SharedLock);
#else
	InternalLock();
#endif // _MSC_VER >= 1910

	if (m_Handle32to64[0] == 0)
	{
		// First call to GetTcpipBoundAdaptersInfo, initialize m_Handle32to64
		m_Handle32to64[0] = (-1);

		for (unsigned i = 0; i < adapterListWow64.m_nAdapterCount; ++i)
		{
			m_Handle32to64[i + 1] = adapterListWow64.m_nAdapterHandle[i].QuadPart;
		}
	}
	else
	{
		for (unsigned i = 0; i < adapterListWow64.m_nAdapterCount; ++i)
		{
			// Check if we already have adapterListWow64.m_nAdapterHandle[i] adapter in the translation table
			bool bAlreadyExists = false;

			for (unsigned j = 1; j < ADAPTER_LIST_SIZE + 1; ++j)
			{
				if (m_Handle32to64[j] == adapterListWow64.m_nAdapterHandle[i].QuadPart)
				{
					bAlreadyExists = true;
					break;
				}
			}

			if (!bAlreadyExists)
			{
				// This is a new interface, not present in the table
				// Search through the table for the first entry which can be replaced

				unsigned pos = 0;

				for (unsigned j = 1; j < ADAPTER_LIST_SIZE + 1; ++j)
				{
					for (unsigned k = 0; k < adapterListWow64.m_nAdapterCount; ++k)
					{
						if (m_Handle32to64[j] == adapterListWow64.m_nAdapterHandle[k].QuadPart)
							break;

						// We are at the last element and m_Handle32to64[j] is not found
						if (k == (adapterListWow64.m_nAdapterCount - 1))
						{
							pos = j;
						}

						if (pos)
							break;
					}
				}

				if (pos)
				{
					m_Handle32to64[pos] = adapterListWow64.m_nAdapterHandle[i].QuadPart;
				}
			}
		}
	}

#if _MSC_VER < 1910
	InternalUnlock();
#endif _MSC_VER < 1910
}

//
// This is the constructor of a class that has been exported.
// see ndisapi.h for the class definition
//
CNdisApi::CNdisApi(const TCHAR* pszFileName): m_Wow64Helper(CWow64Helper::getInstance())
{
	TCHAR pszFullName[FILE_NAME_SIZE];

	// Format full file name
#if _MSC_VER >= 1700
	_tcscpy_s(pszFullName, FILE_NAME_SIZE, _T("\\\\.\\"));
	_tcscat_s(pszFullName, FILE_NAME_SIZE, pszFileName);
#else
	_tcscpy(pszFullName, _T("\\\\.\\"));
	_tcscat(pszFullName, pszFileName);
#endif //_MSC_VER >= 1700

	m_bIsLoadSuccessfully = FALSE;

	// We open driver for overlapped I/O, though none of current driver services are processed asynchronously
	m_hFileHandle = ::CreateFile(pszFullName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);

	// If driver is opened succesfully we initialize our OVERLAPPED structure
	if (m_hFileHandle == INVALID_HANDLE_VALUE)
	{
		m_ovlp.hEvent = 0;
	}
	else
	{
		m_ovlp.hEvent = CreateEvent(0, TRUE, FALSE, NULL);
		if (m_ovlp.hEvent)
		{
			m_bIsLoadSuccessfully = TRUE;
		}
	}

	m_BytesReturned = 0;

	//
	// Check if we are running in WOW64
	//
	m_bIsWow64Process = FALSE;

	if (ms_Version.IsWindowsXPOrGreater())
	{
		HMODULE hKernel32 = ::GetModuleHandle(TEXT("kernel32.dll"));
		if (hKernel32)
		{
			m_pfnIsWow64Process = (IsWow64ProcessPtr)::GetProcAddress(hKernel32, "IsWow64Process");
			if (m_pfnIsWow64Process)
			{
				m_pfnIsWow64Process(GetCurrentProcess(), &m_bIsWow64Process);
			}
		}
	}

	if(m_bIsWow64Process)
	{
		// Initialize CWow64Helper::m_Handle32to64
		TCP_AdapterList AdaptersList = {0};
		GetTcpipBoundAdaptersInfo(&AdaptersList);
	}
}

CNdisApi::~CNdisApi()
{
	if (m_hFileHandle != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(m_hFileHandle);
	}

	if (m_ovlp.hEvent)
	{
		::CloseHandle(m_ovlp.hEvent);
	}
}

BOOL CNdisApi::DeviceIoControl(DWORD dwService, void *BuffIn, int SizeIn, void *BuffOut, int SizeOut, unsigned long *SizeRet, LPOVERLAPPED povlp) const
{
	BOOL Ret = 0;

	// Supports overlapped and nonoverlapped IO

	if (!SizeRet) SizeRet = &m_BytesReturned;

	if (m_hFileHandle != INVALID_HANDLE_VALUE)
	{
		if (povlp == NULL)
			Ret = ::DeviceIoControl(m_hFileHandle, dwService, BuffIn, SizeIn, BuffOut, SizeOut, SizeRet, &m_ovlp);
		else
			Ret = ::DeviceIoControl(m_hFileHandle, dwService, BuffIn, SizeIn, BuffOut, SizeOut, SizeRet, povlp);

	}

	return Ret;
}

ULONG CNdisApi::GetVersion() const
{
	ULONG nDriverAPIVersion = 0xFFFFFFFF;

	BOOL bIOResult = DeviceIoControl(
		IOCTL_NDISRD_GET_VERSION,
		&nDriverAPIVersion,
		sizeof(ULONG),
		&nDriverAPIVersion,
		sizeof(ULONG),
		NULL,   // Bytes Returned
		NULL
	);

	return nDriverAPIVersion;
}

BOOL CNdisApi::GetTcpipBoundAdaptersInfo(PTCP_AdapterList pAdapters) const
{
	BOOL bIOResult = FALSE;
	TCP_AdapterList_WOW64	adaptersList = {0};

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		// In case of WOW64 process pass our own structure to driver
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_GET_TCPIP_INTERFACES,
			&adaptersList,
			sizeof(TCP_AdapterList_WOW64),
			&adaptersList,
			sizeof(TCP_AdapterList_WOW64),
			NULL,   // Bytes Returned
			NULL
		);

		if (bIOResult)
		{
			// Update WOW64 handle conversion helper
			m_Wow64Helper.Update(adaptersList);

			// Zero-initialize
			ZeroMemory(pAdapters, sizeof(TCP_AdapterList));

			// Simply copy all the fields except adapters handles
			pAdapters->m_nAdapterCount = adaptersList.m_nAdapterCount;
			memmove(pAdapters->m_szAdapterNameList, adaptersList.m_szAdapterNameList, sizeof(pAdapters->m_szAdapterNameList));
			memmove(pAdapters->m_nAdapterMediumList, adaptersList.m_nAdapterMediumList, sizeof(pAdapters->m_nAdapterMediumList));
			memmove(pAdapters->m_czCurrentAddress, adaptersList.m_czCurrentAddress, sizeof(pAdapters->m_czCurrentAddress));
			memmove(pAdapters->m_usMTU, adaptersList.m_usMTU, sizeof(pAdapters->m_usMTU));

			// Convert 64 bit handles to 32 bit ones
			for (size_t i = 0; i < pAdapters->m_nAdapterCount; ++i)
			{
				pAdapters->m_nAdapterHandle[i] = (HANDLE)(m_Wow64Helper.From64to32Handle(adaptersList.m_nAdapterHandle[i].QuadPart));
			}
		}
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_GET_TCPIP_INTERFACES,
			pAdapters,
			sizeof(TCP_AdapterList),
			pAdapters,
			sizeof(TCP_AdapterList),
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SendPacketToMstcp(PETH_REQUEST pPacket) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ETH_REQUEST_WOW64 EthRequest;
		INTERMEDIATE_BUFFER_WOW64 Buffer;

		// Initialize INTERMEDIATE_BUFFER_WOW64
		Buffer.m_dwDeviceFlags = pPacket->EthPacket.Buffer->m_dwDeviceFlags;
		Buffer.m_Flags = pPacket->EthPacket.Buffer->m_Flags;
		Buffer.m_8021q = pPacket->EthPacket.Buffer->m_8021q;
		Buffer.m_FilterID = pPacket->EthPacket.Buffer->m_FilterID;
		memmove(Buffer.m_Reserved, pPacket->EthPacket.Buffer->m_Reserved, sizeof(ULONG) * 4);
		Buffer.m_Length = pPacket->EthPacket.Buffer->m_Length;
		memmove(Buffer.m_IBuffer, pPacket->EthPacket.Buffer->m_IBuffer, Buffer.m_Length);

		// Initialize ETH_REQUEST_WOW64
		EthRequest.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPacket->hAdapterHandle);
		EthRequest.EthPacket.Buffer.HighPart = 0;
		EthRequest.EthPacket.Buffer.LowPart = (ULONG_PTR)&Buffer;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
			&EthRequest,
			sizeof(ETH_REQUEST_WOW64),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);

	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SEND_PACKET_TO_MSTCP,
			pPacket,
			sizeof(ETH_REQUEST),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SendPacketToAdapter(PETH_REQUEST pPacket) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ETH_REQUEST_WOW64 EthRequest;
		INTERMEDIATE_BUFFER_WOW64 Buffer;

		// Initialize INTERMEDIATE_BUFFER_WOW64
		Buffer.m_dwDeviceFlags = pPacket->EthPacket.Buffer->m_dwDeviceFlags;
		Buffer.m_Flags = pPacket->EthPacket.Buffer->m_Flags;
		Buffer.m_8021q = pPacket->EthPacket.Buffer->m_8021q;
		Buffer.m_FilterID = pPacket->EthPacket.Buffer->m_FilterID;
		memmove(Buffer.m_Reserved, pPacket->EthPacket.Buffer->m_Reserved, sizeof(ULONG) * 4);
		Buffer.m_Length = pPacket->EthPacket.Buffer->m_Length;
		memmove(Buffer.m_IBuffer, pPacket->EthPacket.Buffer->m_IBuffer, Buffer.m_Length);

		// Initialize ETH_REQUEST_WOW64
		EthRequest.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPacket->hAdapterHandle);
		EthRequest.EthPacket.Buffer.HighPart = 0;
		EthRequest.EthPacket.Buffer.LowPart = (ULONG_PTR)&Buffer;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
			&EthRequest,
			sizeof(ETH_REQUEST_WOW64),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);

	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER,
			pPacket,
			sizeof(ETH_REQUEST),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::ReadPacket(PETH_REQUEST pPacket) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ETH_REQUEST_WOW64 EthRequest;
		INTERMEDIATE_BUFFER_WOW64 Buffer;

		// Initialize ETH_REQUEST_WOW64
		EthRequest.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPacket->hAdapterHandle);
		EthRequest.EthPacket.Buffer.HighPart = 0;
		EthRequest.EthPacket.Buffer.LowPart = (ULONG_PTR)&Buffer;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_READ_PACKET,
			&EthRequest,
			sizeof(ETH_REQUEST_WOW64),
			&EthRequest,
			sizeof(ETH_REQUEST_WOW64),
			NULL,   // Bytes Returned
			NULL
		);

		if (bIOResult)
		{
			// Copy the resulting packet from INTERMEDIATE_BUFFER_WOW64 to INTERMEDIATE_BUFFER
			pPacket->EthPacket.Buffer->m_dwDeviceFlags = Buffer.m_dwDeviceFlags;
			pPacket->EthPacket.Buffer->m_Flags = Buffer.m_Flags;
			pPacket->EthPacket.Buffer->m_8021q = Buffer.m_8021q;
			pPacket->EthPacket.Buffer->m_FilterID = Buffer.m_FilterID;
			memmove(pPacket->EthPacket.Buffer->m_Reserved, Buffer.m_Reserved, sizeof(ULONG) * 4);
			pPacket->EthPacket.Buffer->m_Length = Buffer.m_Length;
			memmove(pPacket->EthPacket.Buffer->m_IBuffer, Buffer.m_IBuffer, Buffer.m_Length);
		}
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_READ_PACKET,
			pPacket,
			sizeof(ETH_REQUEST),
			pPacket,
			sizeof(ETH_REQUEST),
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SendPacketsToMstcp(PETH_M_REQUEST pPackets) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		PETH_M_REQUEST_WOW64 pEthRequest = NULL;
		PINTERMEDIATE_BUFFER_WOW64 Buffers = NULL;

		pEthRequest = (PETH_M_REQUEST_WOW64)malloc(sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1));
		Buffers = (PINTERMEDIATE_BUFFER_WOW64)malloc(pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));

		if (Buffers && pEthRequest)
		{
			memset(pEthRequest, 0, sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1));
			memset(Buffers, 0, pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));
			pEthRequest->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPackets->hAdapterHandle);
			pEthRequest->dwPacketsNumber = pPackets->dwPacketsNumber;

			for (unsigned i = 0; i < pPackets->dwPacketsNumber; ++i)
			{
				// Initialize INTERMEDIATE_BUFFER_WOW64
				Buffers[i].m_dwDeviceFlags = pPackets->EthPacket[i].Buffer->m_dwDeviceFlags;
				Buffers[i].m_Flags = pPackets->EthPacket[i].Buffer->m_Flags;
				Buffers[i].m_8021q = pPackets->EthPacket[i].Buffer->m_8021q;
				Buffers[i].m_FilterID = pPackets->EthPacket[i].Buffer->m_FilterID;
				memmove(Buffers[i].m_Reserved, pPackets->EthPacket[i].Buffer->m_Reserved, sizeof(ULONG) * 4);
				Buffers[i].m_Length = pPackets->EthPacket[i].Buffer->m_Length;
				memmove(Buffers[i].m_IBuffer, pPackets->EthPacket[i].Buffer->m_IBuffer, Buffers[i].m_Length);

				// Initialize ETH_REQUEST_WOW64
				pEthRequest->EthPacket[i].Buffer.HighPart = 0;
				pEthRequest->EthPacket[i].Buffer.LowPart = (ULONG_PTR)&Buffers[i];
			}

			bIOResult = DeviceIoControl(
				IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
				pEthRequest,
				sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1),
				NULL,
				0,
				NULL,   // Bytes Returned
				NULL
			);

			free(Buffers);
			free(pEthRequest);
		}
		else
		{
			if (Buffers)
				free(Buffers);

			if (pEthRequest)
				free(pEthRequest);

			return FALSE;
		}
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP,
			pPackets,
			sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet)*(pPackets->dwPacketsNumber - 1),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SendPacketsToAdapter(PETH_M_REQUEST pPackets) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		PETH_M_REQUEST_WOW64 pEthRequest = NULL;
		PINTERMEDIATE_BUFFER_WOW64 Buffers = NULL;

		pEthRequest = (PETH_M_REQUEST_WOW64)malloc(sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1));
		Buffers = (PINTERMEDIATE_BUFFER_WOW64)malloc(pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));

		if (Buffers && pEthRequest)
		{
			memset(pEthRequest, 0, sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1));
			memset(Buffers, 0, pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));
			pEthRequest->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPackets->hAdapterHandle);
			pEthRequest->dwPacketsNumber = pPackets->dwPacketsNumber;

			for (unsigned i = 0; i < pPackets->dwPacketsNumber; ++i)
			{
				// Initialize INTERMEDIATE_BUFFER_WOW64
				Buffers[i].m_dwDeviceFlags = pPackets->EthPacket[i].Buffer->m_dwDeviceFlags;
				Buffers[i].m_Flags = pPackets->EthPacket[i].Buffer->m_Flags;
				Buffers[i].m_8021q = pPackets->EthPacket[i].Buffer->m_8021q;
				Buffers[i].m_FilterID = pPackets->EthPacket[i].Buffer->m_FilterID;
				memmove(Buffers[i].m_Reserved, pPackets->EthPacket[i].Buffer->m_Reserved, sizeof(ULONG) * 4);
				Buffers[i].m_Length = pPackets->EthPacket[i].Buffer->m_Length;
				memmove(Buffers[i].m_IBuffer, pPackets->EthPacket[i].Buffer->m_IBuffer, Buffers[i].m_Length);

				// Initialize ETH_REQUEST_WOW64
				pEthRequest->EthPacket[i].Buffer.HighPart = 0;
				pEthRequest->EthPacket[i].Buffer.LowPart = (ULONG_PTR)&Buffers[i];
			}

			bIOResult = DeviceIoControl(
				IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
				pEthRequest,
				sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1),
				NULL,
				0,
				NULL,   // Bytes Returned
				NULL
			);

			free(Buffers);
			free(pEthRequest);
		}
		else
		{
			if (Buffers)
				free(Buffers);

			if (pEthRequest)
				free(pEthRequest);

			return FALSE;
		}
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER,
			pPackets,
			sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet)*(pPackets->dwPacketsNumber - 1),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::ReadPackets(PETH_M_REQUEST pPackets) const
{
	BOOL bIOResult = FALSE;
	unsigned i = 0;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		PETH_M_REQUEST_WOW64 pEthRequest = (PETH_M_REQUEST_WOW64)malloc(sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1));

		if (!pEthRequest)
			return bIOResult;

		PINTERMEDIATE_BUFFER_WOW64 Buffers = (PINTERMEDIATE_BUFFER_WOW64)malloc(pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));

		if (!Buffers)
		{
			if (pEthRequest)
				free(pEthRequest);

			return bIOResult;
		}

		memset(pEthRequest, 0, sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1));
		memset(Buffers, 0, pPackets->dwPacketsNumber * sizeof(INTERMEDIATE_BUFFER_WOW64));

		if (Buffers && pEthRequest)
		{
			pEthRequest->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pPackets->hAdapterHandle);
			pEthRequest->dwPacketsNumber = pPackets->dwPacketsNumber;

			for (i = 0; i < pPackets->dwPacketsNumber; ++i)
			{
				// Initialize ETH_REQUEST_WOW64
				pEthRequest->EthPacket[i].Buffer.HighPart = 0;
				pEthRequest->EthPacket[i].Buffer.LowPart = (ULONG_PTR)&Buffers[i];
			}

			bIOResult = DeviceIoControl(
				IOCTL_NDISRD_READ_PACKETS,
				pEthRequest,
				sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1),
				pEthRequest,
				sizeof(ETH_M_REQUEST_WOW64) + sizeof(NDISRD_ETH_Packet_WOW64)*(pPackets->dwPacketsNumber - 1),
				NULL,   // Bytes Returned
				NULL
			);

			if(bIOResult)
			{
				pPackets->dwPacketsSuccess = pEthRequest->dwPacketsSuccess;

				for (i = 0; i < pEthRequest->dwPacketsSuccess; ++i)
				{
					// Copy back
					pPackets->EthPacket[i].Buffer->m_dwDeviceFlags = Buffers[i].m_dwDeviceFlags;
					pPackets->EthPacket[i].Buffer->m_Flags = Buffers[i].m_Flags;
					pPackets->EthPacket[i].Buffer->m_8021q = Buffers[i].m_8021q;
					pPackets->EthPacket[i].Buffer->m_FilterID = Buffers[i].m_FilterID;
					memmove(pPackets->EthPacket[i].Buffer->m_Reserved, Buffers[i].m_Reserved, sizeof(ULONG) * 4);
					pPackets->EthPacket[i].Buffer->m_Length = Buffers[i].m_Length;
					memmove(pPackets->EthPacket[i].Buffer->m_IBuffer, Buffers[i].m_IBuffer, Buffers[i].m_Length);
				}
			}

			free(Buffers);
			free(pEthRequest);
		}
		else
		{
			if (Buffers)
				free(Buffers);

			if (pEthRequest)
				free(pEthRequest);

			return FALSE;
		}
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_READ_PACKETS,
			pPackets,
			sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet)*(pPackets->dwPacketsNumber - 1),
			pPackets,
			sizeof(ETH_M_REQUEST) + sizeof(NDISRD_ETH_Packet)*(pPackets->dwPacketsNumber - 1),
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SetAdapterMode(PADAPTER_MODE pMode) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ADAPTER_MODE_WOW64 AdapterMode;
		AdapterMode.dwFlags = pMode->dwFlags;
		AdapterMode.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pMode->hAdapterHandle);

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_ADAPTER_MODE,
			&AdapterMode,
			sizeof(ADAPTER_MODE_WOW64),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_ADAPTER_MODE,
			pMode,
			sizeof(ADAPTER_MODE),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::GetAdapterMode(PADAPTER_MODE pMode) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ADAPTER_MODE_WOW64 AdapterMode;
		AdapterMode.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)pMode->hAdapterHandle);

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_GET_ADAPTER_MODE,
			&AdapterMode,
			sizeof(ADAPTER_MODE_WOW64),
			&AdapterMode,
			sizeof(ADAPTER_MODE_WOW64),
			NULL,   // Bytes Returned
			NULL
		);

		if(bIOResult)
			pMode->dwFlags = AdapterMode.dwFlags;

	}
	else
#endif // _WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_GET_ADAPTER_MODE,
			pMode,
			sizeof(ADAPTER_MODE),
			pMode,
			sizeof(ADAPTER_MODE),
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::FlushAdapterPacketQueue(HANDLE hAdapter) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ULARGE_INTEGER h64Adapter;
		h64Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)hAdapter);

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
			&h64Adapter,
			sizeof(ULARGE_INTEGER),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE,
			&hAdapter,
			sizeof(HANDLE),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::GetAdapterPacketQueueSize(HANDLE hAdapter, PDWORD pdwSize) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ULARGE_INTEGER h64Adapter;
		h64Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)hAdapter);

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
			&h64Adapter,
			sizeof(ULARGE_INTEGER),
			pdwSize,
			sizeof(DWORD),
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_ADAPTER_QUEUE_SIZE,
			&hAdapter,
			sizeof(HANDLE),
			pdwSize,
			sizeof(DWORD),
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
	}

BOOL CNdisApi::SetPacketEvent(HANDLE hAdapter, HANDLE hWin32Event) const
{
	HANDLE			hRing0Event = NULL;
	ADAPTER_EVENT	AdapterEvent;

	AdapterEvent.hAdapterHandle = hAdapter;

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT
		hRing0Event = hWin32Event;
	}
	else
	{
		// Windows 9x/ME
		HANDLE(WINAPI *pfOpenVxDHandle)(HANDLE);
		HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

		if (!hKernel32Dll)
			return FALSE;

		pfOpenVxDHandle = (HANDLE(WINAPI *)(HANDLE))GetProcAddress(hKernel32Dll, "OpenVxDHandle");

		if (!pfOpenVxDHandle)
			return FALSE;

		if (hWin32Event)
			hRing0Event = pfOpenVxDHandle(hWin32Event);
		else
			hRing0Event = NULL;

		FreeLibrary(hKernel32Dll);
	}

	AdapterEvent.hEvent = hRing0Event;

	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ADAPTER_EVENT_WOW64 AdapterEvent64;
		AdapterEvent64.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)AdapterEvent.hAdapterHandle);
		AdapterEvent64.hEvent.HighPart = 0;
		AdapterEvent64.hEvent.LowPart = (ULONG_PTR)AdapterEvent.hEvent;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_EVENT,
			&AdapterEvent64,
			sizeof(ADAPTER_EVENT_WOW64),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_EVENT,
			&AdapterEvent,
			sizeof(ADAPTER_EVENT),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
	}

BOOL CNdisApi::SetWANEvent(HANDLE hWin32Event) const
{
	HANDLE			hRing0Event = NULL;

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT
		hRing0Event = hWin32Event;
	}
	else
	{
		// Windows 9x/ME
		HANDLE(WINAPI *pfOpenVxDHandle)(HANDLE);
		HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

		if (!hKernel32Dll)
			return FALSE;

		pfOpenVxDHandle = (HANDLE(WINAPI *)(HANDLE))GetProcAddress(hKernel32Dll, "OpenVxDHandle");

		if (!pfOpenVxDHandle)
			return FALSE;

		if (hWin32Event)
			hRing0Event = pfOpenVxDHandle(hWin32Event);
		else
			hRing0Event = NULL;

		FreeLibrary(hKernel32Dll);
	}

	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ULARGE_INTEGER ulRing0Event;
		ulRing0Event.HighPart = 0;
		ulRing0Event.LowPart = (ULONG_PTR)hRing0Event;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_WAN_EVENT,
			&ulRing0Event,
			sizeof(ULARGE_INTEGER),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_WAN_EVENT,
			&hRing0Event,
			sizeof(HANDLE),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SetAdapterListChangeEvent(HANDLE hWin32Event) const
{
	HANDLE			hRing0Event = NULL;

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT
		hRing0Event = hWin32Event;
	}
	else
	{
		// Windows 9x/ME
		HANDLE(WINAPI *pfOpenVxDHandle)(HANDLE);
		HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

		if (!hKernel32Dll)
			return FALSE;

		pfOpenVxDHandle = (HANDLE(WINAPI *)(HANDLE))GetProcAddress(hKernel32Dll, "OpenVxDHandle");

		if (!pfOpenVxDHandle)
			return FALSE;

		if (hWin32Event)
			hRing0Event = pfOpenVxDHandle(hWin32Event);
		else
			hRing0Event = NULL;

		FreeLibrary(hKernel32Dll);
	}

	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ULARGE_INTEGER ulRing0Event;
		ulRing0Event.HighPart = 0;
		ulRing0Event.LowPart = (ULONG_PTR)hRing0Event;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_ADAPTER_EVENT,
			&ulRing0Event,
			sizeof(ULARGE_INTEGER),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_ADAPTER_EVENT,
			&hRing0Event,
			sizeof(HANDLE),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::NdisrdRequest(PPACKET_OID_DATA OidData, BOOL Set) const
{
	OVERLAPPED Overlap;
	DWORD dwLength = OidData->Length;

	Overlap.Offset = 0;
	Overlap.OffsetHigh = 0;
	Overlap.hEvent = CreateEvent(
		NULL,
		FALSE,
		FALSE,
		NULL
	);

	if (Overlap.hEvent == NULL)
	{
		return FALSE;
	}

	if (!ResetEvent(Overlap.hEvent))
	{
		::CloseHandle(Overlap.hEvent);
		return FALSE;
	}

	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		PPACKET_OID_DATA_WOW64 OidData64 = (PPACKET_OID_DATA_WOW64)malloc(sizeof(PACKET_OID_DATA_WOW64) + OidData->Length - 1);
		if (OidData64)
		{
			OidData64->hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)OidData->hAdapterHandle);
			OidData64->Oid = OidData->Oid;
			OidData64->Length = OidData->Length;
			if (Set)
				memmove(OidData64->Data, OidData->Data, OidData->Length);

			bIOResult = DeviceIoControl(
				(DWORD)Set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
				OidData64,
				sizeof(PACKET_OID_DATA_WOW64) - 1 + OidData->Length,
				OidData64,
				sizeof(PACKET_OID_DATA_WOW64) - 1 + OidData->Length,
				NULL,   // Bytes Returned
				&Overlap
			);

			if ((!bIOResult) && (ERROR_IO_PENDING == GetLastError()))
			{
				WaitForSingleObject(Overlap.hEvent, INFINITE);

				if (!Set)
				{
					memmove(OidData->Data, OidData64->Data, OidData64->Length);
					OidData->Length = OidData64->Length;
				}
			}
			else
				if (!bIOResult)
				{
					::CloseHandle(Overlap.hEvent);
					free(OidData64);
					return FALSE;
				}

			free(OidData64);
		}
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			(DWORD)Set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
			OidData,
			sizeof(PACKET_OID_DATA) - 1 + OidData->Length,
			OidData,
			sizeof(PACKET_OID_DATA) - 1 + OidData->Length,
			NULL,   // Bytes Returned
			&Overlap
		);

		if ((!bIOResult) && (ERROR_IO_PENDING == GetLastError()))
			WaitForSingleObject(Overlap.hEvent, INFINITE);
		else
			if (!bIOResult)
			{
				::CloseHandle(Overlap.hEvent);
				return FALSE;
			}
	}

	::CloseHandle(Overlap.hEvent);

	if (dwLength == OidData->Length)
		return TRUE;
	else
		return FALSE;
}

BOOL CNdisApi::GetRasLinks(HANDLE hAdapter, PRAS_LINKS pLinks) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ULARGE_INTEGER h64Adapter;
		h64Adapter.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)hAdapter);

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_GET_RAS_LINKS,
			&h64Adapter,
			sizeof(ULARGE_INTEGER),
			pLinks,
			sizeof(RAS_LINKS),
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif // _WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_GET_RAS_LINKS,
			&hAdapter,
			sizeof(HANDLE),
			pLinks,
			sizeof(RAS_LINKS),
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SetHwPacketFilter(HANDLE hAdapter, DWORD Filter) const
{
	BOOL bRet = FALSE;
	PPACKET_OID_DATA pPacket = (PPACKET_OID_DATA)malloc(sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1);

	if (pPacket)
	{
		pPacket->Length = sizeof(DWORD);
		pPacket->Oid = OID_GEN_CURRENT_PACKET_FILTER;
		pPacket->hAdapterHandle = hAdapter;

		*((PDWORD)pPacket->Data) = Filter;
		bRet = NdisrdRequest(pPacket, TRUE);

		free(pPacket);
	}

	return bRet;
}

BOOL CNdisApi::GetHwPacketFilter(HANDLE hAdapter, PDWORD pFilter) const
{
	BOOL bRet = FALSE;

	PPACKET_OID_DATA pPacket = (PPACKET_OID_DATA)malloc(sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1);

	if (pPacket)
	{
		pPacket->Length = sizeof(DWORD);
		pPacket->Oid = OID_GEN_CURRENT_PACKET_FILTER;
		pPacket->hAdapterHandle = hAdapter;

		if (NdisrdRequest(pPacket, FALSE))
		{
			*pFilter = *((PDWORD)pPacket->Data);

			bRet = TRUE;
		}

		free(pPacket);
	}
	return bRet;
}

BOOL CNdisApi::SetHwPacketFilterEvent(HANDLE hAdapter, HANDLE hWin32Event) const
{
	HANDLE			hRing0Event = NULL;
	ADAPTER_EVENT	AdapterEvent;

	AdapterEvent.hAdapterHandle = hAdapter;

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT
		hRing0Event = hWin32Event;
	}
	else
	{
		// Windows 9x/ME
		HANDLE(WINAPI *pfOpenVxDHandle)(HANDLE);
		HINSTANCE hKernel32Dll = LoadLibrary(TEXT("kernel32.dll"));

		if (!hKernel32Dll)
			return FALSE;

		pfOpenVxDHandle = (HANDLE(WINAPI *)(HANDLE))GetProcAddress(hKernel32Dll, "OpenVxDHandle");

		if (!pfOpenVxDHandle)
			return FALSE;

		if (hWin32Event)
			hRing0Event = pfOpenVxDHandle(hWin32Event);
		else
			hRing0Event = NULL;

		FreeLibrary(hKernel32Dll);
	}

	AdapterEvent.hEvent = hRing0Event;

	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		ADAPTER_EVENT_WOW64 AdapterEvent64;
		AdapterEvent64.hAdapterHandle.QuadPart = m_Wow64Helper.From32to64Handle((unsigned)AdapterEvent.hAdapterHandle);
		AdapterEvent64.hEvent.HighPart = 0;
		AdapterEvent64.hEvent.LowPart = (ULONG_PTR)AdapterEvent.hEvent;

		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT,
			&AdapterEvent64,
			sizeof(ADAPTER_EVENT_WOW64),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}
	else
#endif //_WIN64
	{
		bIOResult = DeviceIoControl(
			IOCTL_NDISRD_SET_ADAPTER_HWFILTER_EVENT,
			&AdapterEvent,
			sizeof(ADAPTER_EVENT),
			NULL,
			0,
			NULL,   // Bytes Returned
			NULL
		);
	}

	return bIOResult;
}

BOOL CNdisApi::SetPacketFilterTable(PSTATIC_FILTER_TABLE pFilterList) const
{
	BOOL bIOResult = FALSE;

#ifndef _WIN64
	if (m_bIsWow64Process)
	{
		// Adapter handle values in the table contain values which are not valid for the driver
		// and we need to pre-process filter table before passing it to the driver

		for (unsigned i = 0; i < pFilterList->m_TableSize; ++i)
		{
			if (pFilterList->m_StaticFilters[i].m_Adapter.QuadPart)
				pFilterList->m_StaticFilters[i].m_Adapter.QuadPart =
					m_Wow64Helper.From32to64Handle((unsigned)pFilterList->m_StaticFilters[i].m_Adapter.LowPart);
		}
	}
#endif //_WIN64

	bIOResult = DeviceIoControl(
		IOCTL_NDISRD_SET_PACKET_FILTERS,
		pFilterList,
		sizeof(STATIC_FILTER_TABLE) + (pFilterList->m_TableSize - ANY_SIZE) * sizeof(STATIC_FILTER),
		NULL,
		0,
		NULL,   // Bytes Returned
		NULL
	);

	return bIOResult;
}

BOOL CNdisApi::ResetPacketFilterTable() const
{
	BOOL bIOResult = FALSE;

	bIOResult = DeviceIoControl(
		IOCTL_NDISRD_RESET_PACKET_FILTERS,
		NULL,
		0,
		NULL,
		0,
		NULL,   // Bytes Returned
		NULL
	);

	return bIOResult;
}

BOOL CNdisApi::GetPacketFilterTableSize(PDWORD pdwTableSize) const
{
	BOOL bIOResult = FALSE;

	bIOResult = DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_TABLESIZE,
		NULL,
		0,
		pdwTableSize,
		sizeof(DWORD),
		NULL,   // Bytes Returned
		NULL
	);

	return bIOResult;
}

BOOL CNdisApi::GetPacketFilterTable(PSTATIC_FILTER_TABLE pFilterList) const
{
	BOOL bIOResult = FALSE;

	bIOResult = DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS,
		NULL,
		0,
		pFilterList,
		sizeof(STATIC_FILTER_TABLE) + (pFilterList->m_TableSize - ANY_SIZE) * sizeof(STATIC_FILTER),
		NULL,   // Bytes Returned
		NULL
	);
#ifndef _WIN64
	if (bIOResult && m_bIsWow64Process)
	{
		// Adapter handle values in the table contain values which are not valid for the client
		// and we need to post-process filter table before passing it to the client

		for (unsigned i = 0; i < pFilterList->m_TableSize; ++i)
		{
			pFilterList->m_StaticFilters[i].m_Adapter.QuadPart =
				m_Wow64Helper.From64to32Handle(pFilterList->m_StaticFilters[i].m_Adapter.QuadPart);
		}
	}
#endif //_WIN64

	return bIOResult;
}

BOOL CNdisApi::GetPacketFilterTableResetStats(PSTATIC_FILTER_TABLE pFilterList) const
{
	BOOL bIOResult = FALSE;

	bIOResult = DeviceIoControl(
		IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS,
		NULL,
		0,
		pFilterList,
		sizeof(STATIC_FILTER_TABLE) + (pFilterList->m_TableSize - ANY_SIZE) * sizeof(STATIC_FILTER),
		NULL,   // Bytes Returned
		NULL
	);

#ifndef _WIN64
	if (bIOResult && m_bIsWow64Process)
	{
		// Adapter handle values in the table contain values which are not valid for the client
		// and we need to post-process filter table before passing it to the client

		for (unsigned i = 0; i < pFilterList->m_TableSize; ++i)
		{
			pFilterList->m_StaticFilters[i].m_Adapter.QuadPart = 
				m_Wow64Helper.From64to32Handle(pFilterList->m_StaticFilters[i].m_Adapter.QuadPart);
		}
	}
#endif //_WIN64

	return bIOResult;
}

BOOL CNdisApi::IsDriverLoaded() const
{
	return m_bIsLoadSuccessfully;
}

// ********************************************************************************
/// <summary>
/// Initializes Fast I/O shared memory section
/// Supported for Windows Vista and later. WOW64 is not supported.
/// </summary>
/// <param name="pFastIo">Pointer to user allocated memory to be used as a shared section</param>
/// <param name="dwSize">Size in bytes of allocated memory</param>
/// <returns>Status of the operation</returns>
// ********************************************************************************
BOOL CNdisApi::InitializeFastIo(PFAST_IO_SECTION pFastIo, DWORD dwSize) const
{
	// Only supported for Vista and later. Can't be used in WOW64 mode.
	if (!IsWindowsVistaOrLater() || m_bIsWow64Process || (dwSize < sizeof(FAST_IO_SECTION)))
		return FALSE;

	INITIALIZE_FAST_IO_PARAMS params = { pFastIo, dwSize };

	BOOL bIOResult = DeviceIoControl(
		IOCTL_NDISRD_INITIALIZE_FAST_IO,
		&params,
		sizeof(INITIALIZE_FAST_IO_PARAMS),
		NULL,
		0,
		NULL,   // Bytes Returned
		NULL
	);

	return bIOResult;
}

// ********************************************************************************
/// <summary>
/// Reads a bunch of packets from the driver packet queues
/// Adapter handle is stored in INTERMEDIATE_BUFFER.m_hAdapter
/// </summary>
/// <param name="Packets">Array of INTERMEDIATE_BUFFER pointers</param>
/// <param name="dwPacketsNum">Number of packets in the array above</param>
/// <param name="pdwPacketsSuccess">Number of packets successfully read from the driver</param>
/// <returns>Status of the operation</returns>
// ********************************************************************************
BOOL CNdisApi::ReadPacketsUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketsSuccess) const
{
	if (m_bIsWow64Process)
		return FALSE;

	UNSORTED_READ_SEND_REQUEST request = {Packets, dwPacketsNum};

	BOOL bIOResult = DeviceIoControl(
			IOCTL_NDISRD_READ_PACKETS_UNSORTED,
			&request,
			sizeof(UNSORTED_READ_SEND_REQUEST),
			&request,
			sizeof(UNSORTED_READ_SEND_REQUEST),
			NULL,   // Bytes Returned
			NULL
		);

	*pdwPacketsSuccess = request.packets_num;

	return bIOResult;
}

BOOL CNdisApi::SendPacketsToAdaptersUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) const
{
	if (m_bIsWow64Process)
		return FALSE;

	UNSORTED_READ_SEND_REQUEST request = { Packets, dwPacketsNum };

	BOOL bIOResult = DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED,
		&request,
		sizeof(UNSORTED_READ_SEND_REQUEST),
		&request,
		sizeof(UNSORTED_READ_SEND_REQUEST),
		NULL,   // Bytes Returned
		NULL
	);

	*pdwPacketSuccess = request.packets_num;

	return bIOResult;
}

BOOL CNdisApi::SendPacketsToMstcpUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) const
{
	if (m_bIsWow64Process)
		return FALSE;

	UNSORTED_READ_SEND_REQUEST request = { Packets, dwPacketsNum };

	BOOL bIOResult = DeviceIoControl(
		IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED,
		&request,
		sizeof(UNSORTED_READ_SEND_REQUEST),
		&request,
		sizeof(UNSORTED_READ_SEND_REQUEST),
		NULL,   // Bytes Returned
		NULL
	);

	*pdwPacketSuccess = request.packets_num;

	return bIOResult;
}

DWORD CNdisApi::GetBytesReturned() const
{
	return m_BytesReturned;
}

BOOL CNdisApi::SetMTUDecrement(DWORD dwMTUDecrement)
{
	HKEY hKey;

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT, 2000 or XP
		if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("MTUDecrement"), NULL, REG_DWORD, (CONST BYTE*)&dwMTUDecrement, sizeof(DWORD)))
			{
				RegCloseKey(hKey);
				return TRUE;
			}

			RegCloseKey(hKey);
			return FALSE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		// Windows 9x/ME
		if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("MTUDecrement"), NULL, REG_DWORD, (CONST BYTE*)&dwMTUDecrement, sizeof(DWORD)))
			{
				RegCloseKey(hKey);
				return TRUE;
			}

			RegCloseKey(hKey);
			return FALSE;
		}
		else
		{
			return FALSE;
		}
	}
}

DWORD CNdisApi::GetMTUDecrement()
{
	HKEY hKey;
	DWORD dwMTUDecrement;
	DWORD dwSize = sizeof(DWORD);

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT, 2000 or XP
		if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("MTUDecrement"), NULL, NULL, (BYTE*)&dwMTUDecrement, &dwSize))
			{
				RegCloseKey(hKey);
				return dwMTUDecrement;
			}

			RegCloseKey(hKey);
			return 0;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		// Windows 9x/ME
		if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("MTUDecrement"), NULL, NULL, (BYTE*)&dwMTUDecrement, &dwSize))
			{
				RegCloseKey(hKey);
				return dwMTUDecrement;
			}

			RegCloseKey(hKey);
			return 0;
		}
		else
		{
			return 0;
		}
	}

}

BOOL CNdisApi::SetAdaptersStartupMode(DWORD dwStartupMode)
{
	HKEY hKey;

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT, 2000 or XP
		if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("StartupMode"), NULL, REG_DWORD, (CONST BYTE*)&dwStartupMode, sizeof(DWORD)))
			{
				RegCloseKey(hKey);
				return TRUE;
			}

			RegCloseKey(hKey);
			return FALSE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		// Windows 9x/ME
		if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegSetValueEx(hKey, TEXT("StartupMode"), NULL, REG_DWORD, (CONST BYTE*)&dwStartupMode, sizeof(DWORD)))
			{
				RegCloseKey(hKey);
				return TRUE;
			}

			RegCloseKey(hKey);
			return FALSE;
		}
		else
		{
			return FALSE;
		}
	}
}

DWORD CNdisApi::GetAdaptersStartupMode()
{
	HKEY hKey;
	DWORD dwStartupMode;
	DWORD dwSize = sizeof(DWORD);

	if (ms_Version.IsWindowsNTPlatform())
	{
		// Windows NT, 2000 or XP
		if (ERROR_SUCCESS == RegCreateKey(HKEY_LOCAL_MACHINE, WINNT_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("StartupMode"), NULL, NULL, (BYTE*)&dwStartupMode, &dwSize))
			{
				RegCloseKey(hKey);
				return dwStartupMode;
			}

			RegCloseKey(hKey);
			return 0;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		// Windows 9x/ME
		if (ERROR_SUCCESS == RegCreateKeyA(HKEY_LOCAL_MACHINE, WIN9X_REG_PARAM, &hKey))
		{
			if (ERROR_SUCCESS == RegQueryValueEx(hKey, TEXT("StartupMode"), NULL, NULL, (BYTE*)&dwStartupMode, &dwSize))
			{
				RegCloseKey(hKey);
				return dwStartupMode;
			}

			RegCloseKey(hKey);
			return 0;
		}
		else
		{
			return 0;
		}
	}

}

//Enumerate all subkeys of HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
//and look for the componentid = ms_ndiswanip, and then grab the linkage subkey and the export string it seems to work for
//at least both windows 7 and windows 10.
// Possible componentid values:
// ms_ndiswanip
// ms_ndiswanipv6
// ms_ndiswanbh
BOOL CNdisApi::IsNdiswanInterface(LPCSTR adapterName, LPCSTR ndiswanName)
{
	LONG	lStatus = ERROR_SUCCESS;
	HKEY    TargetKey = NULL;
	HKEY    ConnectionKey = NULL;
	HKEY	LinkageKey = NULL;
	int		i = 0;
	TCHAR	Buffer[MAX_PATH] = { 0 };
	char	TempBuffer[MAX_PATH] = { 0 };
	DWORD	BufferLength = MAX_PATH;
	DWORD	TempBufferLength = MAX_PATH;
	DWORD	RegType = 0;
	bool	bRetVal = FALSE;

	lStatus = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		REGSTR_NETWORK_CONTROL_CLASS,
		0,
		KEY_READ,
		&TargetKey
	);

	if (lStatus == ERROR_SUCCESS)
	{
		while ((ERROR_NO_MORE_ITEMS != RegEnumKeyEx(TargetKey, i, Buffer, &BufferLength, 0, 0, 0, 0)) && (!bRetVal))
		{
			lStatus = RegOpenKeyEx(TargetKey, Buffer, 0, KEY_READ, &ConnectionKey);
			if (lStatus == ERROR_SUCCESS)
			{
				lStatus = RegQueryValueExA(ConnectionKey, "ComponentId", 0, &RegType, (LPBYTE)TempBuffer, &TempBufferLength);
				TempBufferLength = MAX_PATH;

				if (lStatus == ERROR_SUCCESS)
				{
					if (0 == _stricmp(TempBuffer, ndiswanName))
					{
						lStatus = RegOpenKeyEx(ConnectionKey, TEXT("Linkage"), 0, KEY_READ, &LinkageKey);
						if (lStatus == ERROR_SUCCESS)
						{
							lStatus = RegQueryValueExA(LinkageKey, "Export", 0, &RegType, (LPBYTE)TempBuffer, &TempBufferLength);
							TempBufferLength = MAX_PATH;

							if (lStatus == ERROR_SUCCESS)
							{
								if (0 == _stricmp(TempBuffer, adapterName))
								{
									bRetVal = TRUE;
								}
							}
							RegCloseKey(LinkageKey);
						}
					}
				}
				RegCloseKey(ConnectionKey);
			}
			i++;
			BufferLength = MAX_PATH;
		}

		RegCloseKey(TargetKey);
	}

	return bRetVal;
}


BOOL CNdisApi::IsNdiswanIp(LPCSTR adapterName)
{
	//
	// Before Windows 10 NDISWANIP can be identified bt internal name
	//
	if (!ms_Version.IsWindows10OrGreater() /*before Windows 10*/)
	{
		if (_stricmp(adapterName, DEVICE_NDISWANIP) == 0)
		{
			return TRUE;
		}
	}

	return IsNdiswanInterface(adapterName, REGSTR_COMPONENTID_NDISWANIP);
}

BOOL CNdisApi::IsNdiswanIpv6(LPCSTR adapterName)
{
	//
	// Before Windows 10 NDISWANIPV6 can be identified bt internal name
	//
	if (!ms_Version.IsWindows10OrGreater() /*before Windows 10*/)
	{
		if (_stricmp(adapterName, DEVICE_NDISWANIPV6) == 0)
		{
			return TRUE;
		}
	}

	return IsNdiswanInterface(adapterName, REGSTR_COMPONENTID_NDISWANIPV6);
}

BOOL CNdisApi::IsNdiswanBh(LPCSTR adapterName)
{
	//
	// Before Windows 10 NDISWANBH can be identified bt internal name
	//
	if (!ms_Version.IsWindows10OrGreater() /*before Windows 10*/)
	{
		if (_stricmp(adapterName, DEVICE_NDISWANBH) == 0)
		{
			return TRUE;
		}
	}

	return IsNdiswanInterface(adapterName, REGSTR_COMPONENTID_NDISWANBH);
}


BOOL
CNdisApi::ConvertWindowsNTAdapterName(
	LPCSTR szAdapterName,
	LPSTR szUserFriendlyName,
	DWORD dwUserFriendlyNameLength
)
{
	HKEY		hKeyAdapters, hKeyAdapter;
	DWORD		dwType, dwIndex = 0;
	FILETIME	time;
	char		szSubKey[MAX_PATH * 2], szServiceName[MAX_PATH * 2];
	DWORD		dwSubKeyLength = MAX_PATH * 2;
	DWORD		dwServiceNameLength = MAX_PATH * 2;
	BOOL		bRet = TRUE;

	LONG lResult = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		REGSTR_NETWORK_CARDS,
		0,
		KEY_READ,
		&hKeyAdapters
	);

	if (lResult == ERROR_SUCCESS)
	{
		// Enumerate bound interfaces
		while (RegEnumKeyExA(hKeyAdapters, dwIndex, szSubKey, &dwSubKeyLength, NULL, NULL, NULL, &time) == ERROR_SUCCESS)
		{
			// Subkey retrieved, open subkey
			lResult = RegOpenKeyExA(
				hKeyAdapters,
				szSubKey,
				0,
				KEY_READ,
				&hKeyAdapter
			);

			if (lResult == ERROR_SUCCESS)
			{
				lResult = RegQueryValueExA(hKeyAdapter, REGSTR_VAL_SERVICE_NAME, NULL, &dwType, (LPBYTE)szServiceName, &dwServiceNameLength);
				if (lResult == ERROR_SUCCESS)
				{
					if (_stricmp(szServiceName, &szAdapterName[strlen("\\Device\\")]) == 0)
					{
						lResult = RegQueryValueExA(hKeyAdapter, REGSTR_VAL_TITLE, NULL, &dwType, (LPBYTE)szUserFriendlyName, &dwUserFriendlyNameLength);

						RegCloseKey(hKeyAdapter);
						RegCloseKey(hKeyAdapters);

						if (lResult == ERROR_SUCCESS)
						{
							return TRUE;
						}
						else
						{
							return FALSE;
						}
					}
				}
				else
				{
					bRet = FALSE;
				}
				RegCloseKey(hKeyAdapter);
				dwServiceNameLength = MAX_PATH * 2;
			}
			else
			{
				bRet = FALSE;
			}

			dwIndex++;
			dwSubKeyLength = MAX_PATH;
		}

		RegCloseKey(hKeyAdapters);

	}
	else
	{
		bRet = FALSE;
	}

	return bRet;
}

BOOL
CNdisApi::ConvertWindows2000AdapterName(
	LPCSTR szAdapterName,
	LPSTR szUserFriendlyName,
	DWORD dwUserFriendlyNameLength
)
{
	HKEY		hKey;
	char		szFriendlyNameKey[MAX_PATH * 2];
	DWORD		dwType;

#if _MSC_VER >= 1700
	if (IsNdiswanIp(szAdapterName))
	{
		strcpy_s(szUserFriendlyName, dwUserFriendlyNameLength, USER_NDISWANIP);
		return TRUE;
	}

	if (IsNdiswanBh(szAdapterName))
	{
		strcpy_s(szUserFriendlyName, dwUserFriendlyNameLength, USER_NDISWANBH);
		return TRUE;
	}

	if (IsNdiswanIpv6(szAdapterName))
	{
		strcpy_s(szUserFriendlyName, dwUserFriendlyNameLength, USER_NDISWANIPV6);
		return TRUE;
	}

	strcpy_s(szFriendlyNameKey, MAX_PATH * 2, REGSTR_NETWORK_CONTROL_KEY);
	strcpy_s((char*)szFriendlyNameKey + strlen(szFriendlyNameKey), MAX_PATH * 2 - strlen(szFriendlyNameKey), &szAdapterName[strlen("\\Device\\")]);
	strcpy_s((char*)szFriendlyNameKey + strlen(szFriendlyNameKey), MAX_PATH * 2 - strlen(szFriendlyNameKey), REGSTR_VAL_CONNECTION);
#else
	if (IsNdiswanIp(szAdapterName))
	{
		strcpy(szUserFriendlyName, USER_NDISWANIP);
		return TRUE;
	}

	if (IsNdiswanBh(szAdapterName))
	{
		strcpy(szUserFriendlyName, USER_NDISWANBH);
		return TRUE;
	}

	if (IsNdiswanIpv6(szAdapterName))
	{
		strcpy(szUserFriendlyName, USER_NDISWANIPV6);
		return TRUE;
	}

	strcpy(szFriendlyNameKey, REGSTR_NETWORK_CONTROL_KEY);
	strcpy((char*)szFriendlyNameKey + strlen(szFriendlyNameKey), &szAdapterName[strlen("\\Device\\")]);
	strcpy((char*)szFriendlyNameKey + strlen(szFriendlyNameKey), REGSTR_VAL_CONNECTION);

#endif //_MSC_VER >= 1700


	LONG lResult = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		szFriendlyNameKey,
		0,
		KEY_READ,
		&hKey
	);

	if (lResult == ERROR_SUCCESS)
	{
		lResult = RegQueryValueExA(hKey, REGSTR_VAL_NAME, NULL, &dwType, (LPBYTE)szUserFriendlyName, &dwUserFriendlyNameLength);

		RegCloseKey(hKey);
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

BOOL
CNdisApi::ConvertWindows9xAdapterName(
	LPCSTR szAdapterName,
	LPSTR szUserFriendlyName,
	DWORD dwUserFriendlyNameLength
)
{
	HKEY		hKey;
	char		szFriendlyNameKey[MAX_PATH * 2];
	DWORD		dwType;
	BOOL		bRet = TRUE;

#if _MSC_VER >= 1700
	strcpy_s(szFriendlyNameKey, MAX_PATH * 2, REGSTR_MSTCP_CLASS_NET);
	strcpy_s((PCHAR)szFriendlyNameKey + strlen(szFriendlyNameKey), MAX_PATH * 2 - strlen(szFriendlyNameKey), szAdapterName);
#else
	strcpy(szFriendlyNameKey, REGSTR_MSTCP_CLASS_NET);
	strcpy((PCHAR)szFriendlyNameKey + strlen(szFriendlyNameKey), szAdapterName);
#endif //_MSC_VER >= 1700

	LONG lResult = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		szFriendlyNameKey,
		0,
		KEY_READ,
		&hKey
	);

	if (lResult == ERROR_SUCCESS)
	{
		lResult = RegQueryValueExA(hKey, REGSTR_VAL_DRIVER_DESC, NULL, &dwType, (LPBYTE)szUserFriendlyName, &dwUserFriendlyNameLength);
		if (lResult != ERROR_SUCCESS)
		{
			bRet = FALSE;
		}
		RegCloseKey(hKey);
	}
	else
	{
		bRet = FALSE;
	}

	return bRet;
}

//
// Function recalculates IP checksum
//
void
CNdisApi::RecalculateIPChecksum(
	PINTERMEDIATE_BUFFER pPacket
)
{
	unsigned short word16;
	unsigned int sum = 0;
	unsigned int i = 0;
	PUCHAR buff;

	iphdr_ptr pIpHeader = (iphdr_ptr)&pPacket->m_IBuffer[sizeof(ether_header)];

	// Initialize checksum to zero
	pIpHeader->ip_sum = 0;
	buff = (PUCHAR)pIpHeader;

	// Calculate IP header checksum
	for (i = 0; i < pIpHeader->ip_hl * sizeof(DWORD); i = i + 2)
	{
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum = sum + word16;
	}

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	pIpHeader->ip_sum = htons((unsigned short)sum);
}

//
// Function recalculates ICMP checksum
//
void
CNdisApi::RecalculateICMPChecksum(
	PINTERMEDIATE_BUFFER pPacket
)
{
	unsigned short word16, padd = 0;
	unsigned int i, sum = 0;
	PUCHAR buff;
	DWORD dwIcmpLen;
	icmphdr_ptr pIcmpHeader = NULL;
	iphdr_ptr pIpHeader = (iphdr_ptr)&pPacket->m_IBuffer[sizeof(ether_header)];

	// Sanity check
	if (pIpHeader->ip_p == IPPROTO_ICMP)
	{
		pIcmpHeader = (icmphdr_ptr)(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);
	}
	else
		return;

	dwIcmpLen = ntohs(pIpHeader->ip_len) - pIpHeader->ip_hl * 4;

	if ((dwIcmpLen / 2) * 2 != dwIcmpLen)
	{
		padd = 1;
		pPacket->m_IBuffer[dwIcmpLen + pIpHeader->ip_hl * 4 + sizeof(ether_header)] = 0;
	}

	buff = (PUCHAR)pIcmpHeader;
	pIcmpHeader->checksum = 0;

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 bit words
	for (i = 0; i< dwIcmpLen + padd; i = i + 2) {
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum = sum + (unsigned long)word16;
	}

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	pIcmpHeader->checksum = ntohs((unsigned short)sum);
}

//
// Function recalculates TCP checksum
//
void
CNdisApi::RecalculateTCPChecksum(
	PINTERMEDIATE_BUFFER pPacket
)
{
	tcphdr_ptr pTcpHeader = NULL;
	unsigned short word16, padd = 0;
	unsigned int i, sum = 0;
	PUCHAR buff;
	DWORD dwTcpLen;

	iphdr_ptr pIpHeader = (iphdr_ptr)&pPacket->m_IBuffer[sizeof(ether_header)];

	// Sanity check
	if (pIpHeader->ip_p == IPPROTO_TCP)
	{
		pTcpHeader = (tcphdr_ptr)(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);
	}
	else
		return;

	dwTcpLen = ntohs(pIpHeader->ip_len) - pIpHeader->ip_hl * 4;//pPacket->m_Length - ((PUCHAR)(pTcpHeader) - pPacket->m_IBuffer);

	if ((dwTcpLen / 2) * 2 != dwTcpLen)
	{
		padd = 1;
		pPacket->m_IBuffer[dwTcpLen + pIpHeader->ip_hl * 4 + sizeof(ether_header)] = 0;
	}

	buff = (PUCHAR)pTcpHeader;
	pTcpHeader->th_sum = 0;

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for (i = 0; i< dwTcpLen + padd; i = i + 2) {
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum = sum + (unsigned long)word16;
	}

	// add the TCP pseudo header which contains:
	// the IP source and destination addresses,

	sum = sum + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w2);
	sum = sum + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w2);

	// the protocol number and the length of the TCP packet
	sum = sum + IPPROTO_TCP + (unsigned short)dwTcpLen;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	pTcpHeader->th_sum = htons((unsigned short)sum);
}

//
// Function recalculates UDP checksum
//
void
CNdisApi::RecalculateUDPChecksum(
	PINTERMEDIATE_BUFFER pPacket
)
{
	udphdr_ptr pUdpHeader = NULL;
	unsigned short word16, padd = 0;
	unsigned int i, sum = 0;
	PUCHAR buff;
	DWORD dwUdpLen;

	iphdr_ptr pIpHeader = (iphdr_ptr)&pPacket->m_IBuffer[sizeof(ether_header)];

	// Sanity check
	if (pIpHeader->ip_p == IPPROTO_UDP)
	{
		pUdpHeader = (udphdr_ptr)(((PUCHAR)pIpHeader) + sizeof(DWORD)*pIpHeader->ip_hl);
	}
	else
		return;

	dwUdpLen = ntohs(pIpHeader->ip_len) - pIpHeader->ip_hl * 4;//pPacket->m_Length - ((PUCHAR)(pTcpHeader) - pPacket->m_IBuffer);

	if ((dwUdpLen / 2) * 2 != dwUdpLen)
	{
		padd = 1;
		pPacket->m_IBuffer[dwUdpLen + pIpHeader->ip_hl * 4 + sizeof(ether_header)] = 0;
	}

	buff = (PUCHAR)pUdpHeader;
	pUdpHeader->th_sum = 0;

	// make 16 bit words out of every two adjacent 8 bit words and 
	// calculate the sum of all 16 vit words
	for (i = 0; i< dwUdpLen + padd; i = i + 2) {
		word16 = ((buff[i] << 8) & 0xFF00) + (buff[i + 1] & 0xFF);
		sum = sum + (unsigned long)word16;
	}

	// add the UDP pseudo header which contains:
	// the IP source and destination addresses,

	sum = sum + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_src.S_un.S_un_w.s_w2);
	sum = sum + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w1) + ntohs(pIpHeader->ip_dst.S_un.S_un_w.s_w2);

	// the protocol number and the length of the UDP packet
	sum = sum + IPPROTO_UDP + (unsigned short)dwUdpLen;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	pUdpHeader->th_sum = ntohs((unsigned short)sum);
}

HANDLE __stdcall OpenFilterDriver ( const TCHAR* pszFileName )
{
	return (HANDLE)(new CNdisApi (pszFileName));
}
 
VOID __stdcall CloseFilterDriver ( HANDLE hOpen )
{
	delete (CNdisApi*)hOpen;
}

DWORD __stdcall GetDriverVersion ( HANDLE hOpen )
{
	if (!hOpen)
		return 0;

	CNdisApi* pApi = (CNdisApi*)(hOpen);
	
	return pApi->GetVersion ();
}

BOOL __stdcall GetTcpipBoundAdaptersInfo ( HANDLE hOpen, PTCP_AdapterList pAdapters )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetTcpipBoundAdaptersInfo ( pAdapters );
}

BOOL __stdcall SendPacketToMstcp ( HANDLE hOpen, PETH_REQUEST pPacket )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->SendPacketToMstcp ( pPacket );
}

BOOL __stdcall SendPacketToAdapter ( HANDLE hOpen, PETH_REQUEST pPacket )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->SendPacketToAdapter ( pPacket );
}

BOOL __stdcall ReadPacket ( HANDLE hOpen, PETH_REQUEST pPacket )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->ReadPacket ( pPacket );
}

BOOL __stdcall SendPacketsToMstcp ( HANDLE hOpen, PETH_M_REQUEST pPackets )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->SendPacketsToMstcp ( pPackets );
}

BOOL __stdcall SendPacketsToAdapter ( HANDLE hOpen, PETH_M_REQUEST pPackets )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->SendPacketsToAdapter ( pPackets );
}

BOOL __stdcall ReadPackets ( HANDLE hOpen, PETH_M_REQUEST pPackets )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->ReadPackets ( pPackets );
}

BOOL __stdcall SetAdapterMode ( HANDLE hOpen, PADAPTER_MODE pMode )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->SetAdapterMode ( pMode );
}

BOOL __stdcall GetAdapterMode ( HANDLE hOpen, PADAPTER_MODE pMode )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetAdapterMode ( pMode );
}

BOOL __stdcall FlushAdapterPacketQueue ( HANDLE hOpen, HANDLE hAdapter )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);
	
	return pApi->FlushAdapterPacketQueue ( hAdapter );
}

BOOL __stdcall GetAdapterPacketQueueSize ( HANDLE hOpen, HANDLE hAdapter , PDWORD pdwSize)

{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->GetAdapterPacketQueueSize ( hAdapter, pdwSize ); 
}

BOOL __stdcall SetPacketEvent ( HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);
	
	return pApi->SetPacketEvent ( hAdapter, hWin32Event );
}

BOOL __stdcall SetWANEvent ( HANDLE hOpen, HANDLE hWin32Event )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);
	
	return pApi->SetWANEvent ( hWin32Event );
}

BOOL __stdcall SetAdapterListChangeEvent ( HANDLE hOpen, HANDLE hWin32Event )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);
	
	return pApi->SetAdapterListChangeEvent ( hWin32Event );
}

BOOL __stdcall NdisrdRequest ( HANDLE hOpen, PPACKET_OID_DATA OidData, BOOL Set )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->NdisrdRequest ( OidData, Set );
}

BOOL __stdcall GetRasLinks ( HANDLE hOpen, HANDLE hAdapter, PRAS_LINKS pLinks )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetRasLinks ( hAdapter, pLinks );
}

BOOL __stdcall SetHwPacketFilter ( HANDLE hOpen, HANDLE hAdapter, DWORD Filter )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->SetHwPacketFilter ( hAdapter, Filter );
}

BOOL __stdcall GetHwPacketFilter ( HANDLE hOpen, HANDLE hAdapter, PDWORD pFilter )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetHwPacketFilter ( hAdapter, pFilter );
}

BOOL __stdcall SetHwPacketFilterEvent ( HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->SetHwPacketFilterEvent ( hAdapter, hWin32Event );
}

BOOL __stdcall SetPacketFilterTable ( HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->SetPacketFilterTable (pFilterList);
}

BOOL __stdcall ResetPacketFilterTable ( HANDLE hOpen )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->ResetPacketFilterTable ();
}

BOOL __stdcall GetPacketFilterTableSize ( HANDLE hOpen, PDWORD pdwTableSize )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetPacketFilterTableSize (pdwTableSize);
}

BOOL __stdcall GetPacketFilterTable ( HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetPacketFilterTable (pFilterList);
}

BOOL __stdcall GetPacketFilterTableResetStats ( HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetPacketFilterTableResetStats (pFilterList);
}

BOOL __stdcall SetMTUDecrement ( DWORD dwMTUDecrement )
{
	return CNdisApi::SetMTUDecrement ( dwMTUDecrement );
}

DWORD __stdcall GetMTUDecrement ()
{
	return CNdisApi::GetMTUDecrement();	
}

BOOL __stdcall SetAdaptersStartupMode ( DWORD dwStartupMode )
{
	return CNdisApi::SetAdaptersStartupMode ( dwStartupMode );
}

DWORD __stdcall GetAdaptersStartupMode ()
{
	return CNdisApi::GetAdaptersStartupMode();	
}

BOOL __stdcall IsDriverLoaded ( HANDLE hOpen )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->IsDriverLoaded();
}

BOOL __stdcall InitializeFastIo(HANDLE hOpen, PFAST_IO_SECTION pFastIo, DWORD dwSize)
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->InitializeFastIo(pFastIo, dwSize);
}

BOOL __stdcall ReadPacketsUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketsSuccess)
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->ReadPacketsUnsorted(Packets, dwPacketsNum, pdwPacketsSuccess);
}

BOOL __stdcall SendPacketsToAdaptersUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess)
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->SendPacketsToAdaptersUnsorted(Packets, dwPacketsNum, pdwPacketSuccess);
}

BOOL __stdcall SendPacketsToMstcpUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess)
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen);

	return pApi->SendPacketsToMstcpUnsorted(Packets, dwPacketsNum, pdwPacketSuccess);
}

DWORD __stdcall GetBytesReturned ( HANDLE hOpen )
{
	if (!hOpen)
		return FALSE;

	CNdisApi* pApi = (CNdisApi*)(hOpen); 

	return pApi->GetBytesReturned ();
}

BOOL __stdcall IsNdiswanIp ( LPCSTR adapterName )
{
	return CNdisApi::IsNdiswanIp (adapterName);
}

BOOL __stdcall IsNdiswanIpv6 ( LPCSTR adapterName )
{
	return CNdisApi::IsNdiswanIpv6 (adapterName);
}

BOOL __stdcall IsNdiswanBh ( LPCSTR adapterName )
{
	return CNdisApi::IsNdiswanBh (adapterName);
}

BOOL
	__stdcall
		ConvertWindowsNTAdapterName (
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
			)
{
	return CNdisApi::ConvertWindowsNTAdapterName (
						szAdapterName,
						szUserFriendlyName,
						dwUserFriendlyNameLength
						);
}


BOOL
	__stdcall 
		ConvertWindows2000AdapterName (
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
			)
{
	return CNdisApi::ConvertWindows2000AdapterName (
						szAdapterName,
						szUserFriendlyName,
						dwUserFriendlyNameLength
						);
}

BOOL
	__stdcall 
		ConvertWindows9xAdapterName (
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
			)
{
	return CNdisApi::ConvertWindows9xAdapterName (
						szAdapterName,
						szUserFriendlyName,
						dwUserFriendlyNameLength
						);
}

void
	__stdcall
	RecalculateIPChecksum(
		PINTERMEDIATE_BUFFER pPacket
	)
{
	CNdisApi::RecalculateIPChecksum (pPacket);
}

void
	__stdcall
	RecalculateICMPChecksum(
		PINTERMEDIATE_BUFFER pPacket
	)
{
	CNdisApi::RecalculateICMPChecksum (pPacket);
}

void
	__stdcall
	RecalculateTCPChecksum(
		PINTERMEDIATE_BUFFER pPacket
	)
{
	CNdisApi::RecalculateTCPChecksum (pPacket);
}

void
	__stdcall
	RecalculateUDPChecksum(
		PINTERMEDIATE_BUFFER pPacket
)
{
	CNdisApi::RecalculateUDPChecksum (pPacket);
}

