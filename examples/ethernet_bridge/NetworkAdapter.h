/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  NetworkAdapter.h                                        */
/*                                                                       */
/* Abstract: Network interface wrapper class declaration                 */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/
#pragma once

//
// Simple wrapper class for Windows handle
//
class SafeObjectHandle : public std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)>
{
public:
	SafeObjectHandle(HANDLE handle) : unique_ptr(handle, &SafeObjectHandle::close)
	{
	}
	operator HANDLE() const
	{
		return get();
	}
	const bool valid() const
	{
		return (get() != INVALID_HANDLE_VALUE);
	}

private:
	static void close(HANDLE handle)
	{
		if (handle != INVALID_HANDLE_VALUE)
			CloseHandle(handle);
	}
};

//
// Simple Wrapper for Windows event object
//
class SafeEvent : public SafeObjectHandle
{
public:
	SafeEvent(HANDLE handle) : SafeObjectHandle(handle)
	{
	}
	
	unsigned wait(unsigned dwMilliseconds) const
	{
		return WaitForSingleObject(get(), dwMilliseconds);
	}

	bool signal() const
	{
		return SetEvent(get()) ? true : false;
	}

	bool reset_event() const
	{
		return ResetEvent(get()) ? true : false;
	}

};

//
// Required to use IPv4 in_addr as a key in unordered map
//
inline bool operator <(const in_addr& lh, const in_addr& rh) { return lh.S_un.S_addr < rh.S_un.S_addr; }
inline bool operator ==(const in_addr& lh, const in_addr& rh) { return lh.S_un.S_addr == rh.S_un.S_addr; }

namespace std
{
	template<> struct hash<in_addr>
	{
		typedef in_addr argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& ip) const
		{
			result_type const h1(std::hash<unsigned long>{}(ip.S_un.S_addr));
			
			return h1; 
		}
	};
}

//
// Simple wrapper for MAC address
//
struct mac_address {
	mac_address() noexcept { memset(data, 0, ETH_ALEN); }
	mac_address(const mac_address& rhs) { memmove(data, rhs.data, ETH_ALEN); }
	mac_address(const unsigned char* ptr) { memmove(data, ptr, ETH_ALEN); }
	
	const mac_address& operator = (const mac_address& rhs){
		memmove(data, rhs.data, ETH_ALEN); 
		return *this;
	}

	unsigned char& operator[](std::size_t index) { return data[index]; }
	const unsigned char& operator[](std::size_t index)const { return data[index]; }

	bool operator ==(const mac_address& rhs) {
		return (memcmp(data, rhs.data, ETH_ALEN) == 0)?true:false;
	}

	bool operator !=(const mac_address& rhs) {
		return !(*this == rhs);
	}

	static const mac_address empty;
	unsigned char data[ETH_ALEN];
};

//
// Class representing network interface
//
class CNetworkAdapter {
public:
	CNetworkAdapter(
		CNdisApi& api,
		HANDLE hAdapter,
		unsigned char* mac_addr,
		std::string const& InternalName,
		std::string const& FriendlyName,
		unsigned dwFilter = 0
	) :	m_api(api),
		m_hAdapter(hAdapter),
		m_HwAddress(mac_addr),
		m_dwNetworkFilter(dwFilter),
		m_Event(CreateEvent(NULL, TRUE, FALSE, NULL)),
		m_InternalName(InternalName),
		m_FriendlyName(FriendlyName),
		m_CurrentMode({ 0 })
	{
		InitializeInterface();
	}

	~CNetworkAdapter() {}

	void						InitializeInterface() noexcept; // Initialize additional network interface parameters 
	HANDLE						GetAdapter() const { return m_hAdapter; } // Returnes network interface handle value
	bool						SetHwFilter(unsigned dwFilter) { return m_api.SetHwPacketFilter(m_hAdapter, dwFilter)?true:false; } // Set network filter for the interface
	unsigned long				GetHwFilter(); // Get current network filter
	void						Release(); // Stops filtering the network interface and tries tor restore its original state
	void						SetMode(unsigned dwFlags); // Set filtering mode for the network interface
	bool						IsLocal(unsigned char* ptr) const { return (mac_address(ptr) == m_HwAddress); } // Check is provided MAC address belongs to this adapter
	unsigned					WaitEvent(unsigned dwMilliseconds) const {return m_Event.wait(dwMilliseconds);} // Waits for network interface event to be signalled
	bool						ResetEvent() const { return m_Event.reset_event(); }
	bool						SetPacketEvent() const { return m_api.SetPacketEvent(m_hAdapter, m_Event)?true:false; }
	const std::string&			GetInternalName() const { return m_InternalName; }
	const std::string&			GetFriendlyName() const { return m_FriendlyName; }
	bool						IsWLAN() const { return m_bIsWLAN; }
	mac_address					GetHwAddress() const { return m_HwAddress; }
	mac_address					GetMacByIp (in_addr& ip);
	void						SetMacForIp(in_addr& ip, unsigned char* mac);
private:

	CNdisApi&											m_api;				// Driver interface reference
	HANDLE												m_hAdapter;			// Network interface handle value
	mac_address											m_HwAddress;		// Network interface current MAC address
	unsigned long										m_dwNetworkFilter;	// Network interface original filter value
	SafeEvent											m_Event;			// Packet in the adapter queue event
	std::string											m_InternalName;		// Internal network interface name
	std::string											m_FriendlyName;		// User-friendly name

	ADAPTER_MODE										m_CurrentMode;		// Used to manipulate network interface mode
	bool												m_bIsWLAN = false;	// True for WLAN media type
	std::unordered_map<in_addr, mac_address>			m_Ip2Mac;			// ARP table
	std::mutex											m_Ip2MacMutex;		// Synchronization object to control access to ARP table
};
