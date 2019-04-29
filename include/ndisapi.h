/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisapi.h                                               */
/*                                                                       */
/* Description: API exported C++ class and C API declarations            */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#ifdef _LIB // must be defined when linking static library version of ndisapi.dll
#define NDISAPI_API 
#else
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the NDISAPI_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// NDISAPI_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef NDISAPI_EXPORTS
#define NDISAPI_API __declspec(dllexport)
#else
#define NDISAPI_API __declspec(dllimport)
#endif //NDISAPI_EXPORTS
#endif //_LIB

#if _MSC_VER >= 1700 
#ifdef _USING_V110_SDK71_
#define _USE_LEGACY_VERSION_INFO
#endif //_USING_V110_SDK71_
#endif // _MSC_VER

#if _MSC_VER < 1700
#define _USE_LEGACY_VERSION_INFO
#endif //_MSC_VER

#ifndef _USE_LEGACY_VERSION_INFO // Use VersionHelpers for 2012 and later toolsets only
#include <VersionHelpers.h>
#endif // _USE_LEGACY_VERSION_INFO

enum
{
	FILE_NAME_SIZE = 1000
};

typedef BOOL (__stdcall *IsWow64ProcessPtr)(HANDLE hProcess, PBOOL Wow64Process);

// Simple OSVERSIONINFO extension
struct NDISAPI_API CVersionInfo : private OSVERSIONINFO
{
#ifdef _USE_LEGACY_VERSION_INFO
	CVersionInfo() {
		dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		::GetVersionEx(this);
	}

	BOOL IsWindowsVistaOrGreater() { return (dwMajorVersion >= 6); }
	BOOL IsWindows7OrGreater() { return (dwMajorVersion > 6) || ((dwMajorVersion == 6) && (dwMinorVersion > 0)); }
	BOOL IsWindowsXPOrGreater() { return ((dwMajorVersion == 5) && (dwMinorVersion >= 1))/*Windows XP/2003*/ || (dwMajorVersion > 5)/*Windows Vista or later*/; }
	BOOL IsWindows10OrGreater() { return (dwMajorVersion >= 10); }
	BOOL IsWindowsNTPlatform() { return (dwPlatformId == VER_PLATFORM_WIN32_NT); }
#else
	BOOL IsWindowsVistaOrGreater() { return ::IsWindowsVistaOrGreater(); }
	BOOL IsWindowsXPOrGreater() { return ::IsWindowsXPOrGreater(); }
	BOOL IsWindows7OrGreater() { return ::IsWindows7OrGreater(); }
	BOOL IsWindows10OrGreater() { return ::IsWindowsVersionOrGreater(10, 0, 0); }
	BOOL IsWindowsNTPlatform() { return IsWindowsXPOrGreater(); }
#endif //  _MSC_VER >= 1700
};

class NDISAPI_API CNdisApi 
{

	class CWow64Helper;

public:
	CNdisApi (const TCHAR* pszFileName = _T(DRIVER_NAME_A));
	virtual ~CNdisApi ();

private:
	// Private member functions
	BOOL DeviceIoControl (DWORD dwService, void *BuffIn, int SizeIn, void *BuffOut, int SizeOut, unsigned long *SizeRet = NULL, LPOVERLAPPED povlp = NULL) const;

	// Private static functions
	static BOOL	IsNdiswanInterface (LPCSTR adapterName, LPCSTR ndiswanName);

public:
	// Driver services
	ULONG	GetVersion () const;
	BOOL	GetTcpipBoundAdaptersInfo ( PTCP_AdapterList pAdapters ) const;
	BOOL	SendPacketToMstcp ( PETH_REQUEST pPacket ) const;
	BOOL	SendPacketToAdapter ( PETH_REQUEST pPacket ) const;
	BOOL	ReadPacket ( PETH_REQUEST pPacket ) const;
	BOOL	SendPacketsToMstcp (PETH_M_REQUEST pPackets) const;
	BOOL	SendPacketsToAdapter(PETH_M_REQUEST pPackets) const;
	BOOL	ReadPackets(PETH_M_REQUEST pPackets) const;
	BOOL	SetAdapterMode ( PADAPTER_MODE pMode ) const;
	BOOL	GetAdapterMode ( PADAPTER_MODE pMode ) const;
	BOOL	FlushAdapterPacketQueue ( HANDLE hAdapter ) const;
	BOOL	GetAdapterPacketQueueSize ( HANDLE hAdapter, PDWORD pdwSize ) const;
	BOOL	SetPacketEvent ( HANDLE hAdapter, HANDLE hWin32Event ) const;
	BOOL	SetWANEvent ( HANDLE hWin32Event ) const;
	BOOL	SetAdapterListChangeEvent ( HANDLE hWin32Event ) const;
	BOOL	NdisrdRequest ( PPACKET_OID_DATA OidData, BOOL Set ) const;
	BOOL	GetRasLinks (HANDLE hAdapter, PRAS_LINKS pLinks) const;
	BOOL	SetHwPacketFilter ( HANDLE hAdapter, DWORD Filter ) const;
	BOOL	GetHwPacketFilter ( HANDLE hAdapter, PDWORD pFilter ) const;
	BOOL	SetHwPacketFilterEvent(HANDLE hAdapter, HANDLE hWin32Event) const;
	BOOL	SetPacketFilterTable (PSTATIC_FILTER_TABLE pFilterList ) const;
	BOOL	ResetPacketFilterTable () const;
	BOOL	GetPacketFilterTableSize ( PDWORD pdwTableSize ) const;
	BOOL	GetPacketFilterTable ( PSTATIC_FILTER_TABLE pFilterList ) const;
	BOOL	GetPacketFilterTableResetStats ( PSTATIC_FILTER_TABLE pFilterList ) const;
	BOOL	IsDriverLoaded () const;
	BOOL	InitializeFastIo(PFAST_IO_SECTION pFastIo, DWORD dwSize) const;
	BOOL	ReadPacketsUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketsSuccess) const;
	BOOL	SendPacketsToAdaptersUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) const;
	BOOL	SendPacketsToMstcpUnsorted(PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess) const;
	DWORD	GetBytesReturned () const;
	
	// Static helper routines

	static BOOL		SetMTUDecrement ( DWORD dwMTUDecrement );
	static DWORD	GetMTUDecrement ();

	static BOOL		SetAdaptersStartupMode ( DWORD dwStartupMode );
	static DWORD	GetAdaptersStartupMode ();

	static BOOL		IsNdiswanIp ( LPCSTR adapterName );
	static BOOL		IsNdiswanIpv6 ( LPCSTR adapterName );
	static BOOL		IsNdiswanBh ( LPCSTR adapterName );

	static BOOL
		ConvertWindowsNTAdapterName (
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
			);

	static BOOL
		ConvertWindows2000AdapterName (
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
			);

	static BOOL
		ConvertWindows9xAdapterName (
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
			);

	static void
		RecalculateIPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	static void
		RecalculateICMPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	static void
		RecalculateTCPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	static void
		RecalculateUDPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	static BOOL IsWindowsVistaOrLater()
	{
		return ms_Version.IsWindowsVistaOrGreater();
	}

	static BOOL IsWindows7OrLater()
	{
		return ms_Version.IsWindows7OrGreater();
	}

private:
	// Private member variables
	mutable OVERLAPPED		m_ovlp;
	mutable DWORD			m_BytesReturned;

	HANDLE					m_hFileHandle;
	BOOL					m_bIsLoadSuccessfully;

	IsWow64ProcessPtr		m_pfnIsWow64Process;
	BOOL					m_bIsWow64Process;
	CWow64Helper&			m_Wow64Helper;

	static	CVersionInfo	ms_Version;
};

extern "C"
{
	HANDLE	__stdcall		OpenFilterDriver(const TCHAR* pszFileName = _T(DRIVER_NAME_A));
	VOID	__stdcall		CloseFilterDriver(HANDLE hOpen);
	DWORD	__stdcall		GetDriverVersion(HANDLE hOpen);
	BOOL	__stdcall		GetTcpipBoundAdaptersInfo(HANDLE hOpen, PTCP_AdapterList pAdapters);
	BOOL	__stdcall		SendPacketToMstcp(HANDLE hOpen, PETH_REQUEST pPacket);
	BOOL	__stdcall		SendPacketToAdapter(HANDLE hOpen, PETH_REQUEST pPacket);
	BOOL	__stdcall		ReadPacket(HANDLE hOpen, PETH_REQUEST pPacket);
	BOOL	__stdcall		SendPacketsToMstcp(HANDLE hOpen, PETH_M_REQUEST pPackets);
	BOOL	__stdcall		SendPacketsToAdapter(HANDLE hOpen, PETH_M_REQUEST pPackets);
	BOOL	__stdcall		ReadPackets(HANDLE hOpen, PETH_M_REQUEST pPackets);
	BOOL	__stdcall		SetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode);
	BOOL	__stdcall		GetAdapterMode(HANDLE hOpen, PADAPTER_MODE pMode);
	BOOL	__stdcall		FlushAdapterPacketQueue(HANDLE hOpen, HANDLE hAdapter);
	BOOL	__stdcall 		GetAdapterPacketQueueSize(HANDLE hOpen, HANDLE hAdapter, PDWORD pdwSize);
	BOOL	__stdcall		SetPacketEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event);
	BOOL	__stdcall		SetWANEvent(HANDLE hOpen, HANDLE hWin32Event);
	BOOL	__stdcall		SetAdapterListChangeEvent(HANDLE hOpen, HANDLE hWin32Event);
	BOOL	__stdcall		NdisrdRequest(HANDLE hOpen, PPACKET_OID_DATA OidData, BOOL Set);
	BOOL	__stdcall		GetRasLinks(HANDLE hOpen, HANDLE hAdapter, PRAS_LINKS pLinks);
	BOOL	__stdcall		SetHwPacketFilter(HANDLE hOpen, HANDLE hAdapter, DWORD Filter);
	BOOL	__stdcall		GetHwPacketFilter(HANDLE hOpen, HANDLE hAdapter, PDWORD pFilter);
	BOOL	__stdcall		SetHwPacketFilterEvent(HANDLE hOpen, HANDLE hAdapter, HANDLE hWin32Event);
	BOOL	__stdcall		SetPacketFilterTable ( HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList );
	BOOL	__stdcall		ResetPacketFilterTable(HANDLE hOpen);
	BOOL	__stdcall		GetPacketFilterTableSize(HANDLE hOpen, PDWORD pdwTableSize);
	BOOL	__stdcall		GetPacketFilterTable(HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList);
	BOOL	__stdcall		GetPacketFilterTableResetStats(HANDLE hOpen, PSTATIC_FILTER_TABLE pFilterList);
	BOOL	__stdcall		SetMTUDecrement(DWORD dwMTUDecrement);
	DWORD	__stdcall		GetMTUDecrement();
	BOOL	__stdcall		SetAdaptersStartupMode(DWORD dwStartupMode);
	DWORD	__stdcall		GetAdaptersStartupMode();
	BOOL	__stdcall		IsDriverLoaded(HANDLE hOpen);
	BOOL	__stdcall		InitializeFastIo(HANDLE hOpen, PFAST_IO_SECTION pFastIo, DWORD dwSize);
	BOOL	__stdcall		ReadPacketsUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketsSuccess);
	BOOL	__stdcall		SendPacketsToAdaptersUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess);
	BOOL	__stdcall		SendPacketsToMstcpUnsorted(HANDLE hOpen, PINTERMEDIATE_BUFFER* Packets, DWORD dwPacketsNum, PDWORD pdwPacketSuccess);
	DWORD	__stdcall		GetBytesReturned(HANDLE hOpen);

	BOOL __stdcall			IsNdiswanIp ( LPCSTR adapterName );
	BOOL __stdcall			IsNdiswanIpv6 ( LPCSTR adapterName );
	BOOL __stdcall			IsNdiswanBh ( LPCSTR adapterName );

	BOOL __stdcall
		ConvertWindowsNTAdapterName(
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
		);

	BOOL __stdcall
		ConvertWindows2000AdapterName(
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
		);

	BOOL __stdcall
		ConvertWindows9xAdapterName(
			LPCSTR szAdapterName,
			LPSTR szUserFriendlyName,
			DWORD dwUserFriendlyNameLength
		);

	void __stdcall
		RecalculateIPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	void __stdcall
		RecalculateICMPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	void __stdcall
		RecalculateTCPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);

	void __stdcall
		RecalculateUDPChecksum(
			PINTERMEDIATE_BUFFER pPacket
		);
}