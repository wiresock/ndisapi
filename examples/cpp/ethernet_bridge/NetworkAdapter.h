// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  NetworkAdapter.h
/// Network interface wrapper class declaration
/// </summary>
// --------------------------------------------------------------------------------

#pragma once
#include <iomanip>

// --------------------------------------------------------------------------------
/// <summary>
/// Simple wrapper class for Windows handle
/// </summary>
// --------------------------------------------------------------------------------
class safe_object_handle : public std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)>
{
public:
	explicit safe_object_handle(HANDLE handle) : unique_ptr(handle, &safe_object_handle::close)
	{
	}

	explicit operator HANDLE() const
	{
		return get();
	}

	bool valid() const
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

// --------------------------------------------------------------------------------
/// <summary>
/// Simple Wrapper for Windows event object
/// </summary>
// --------------------------------------------------------------------------------
class safe_event : public safe_object_handle
{
public:
	explicit safe_event(HANDLE handle) : safe_object_handle(handle)
	{
	}
	
	unsigned wait(unsigned milliseconds) const
	{
		return WaitForSingleObject(get(), milliseconds);
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

/// <summary>Required to use IPv4 in_addr as a key in unordered map</summary>
inline bool operator <(const in_addr& lh, const in_addr& rh) { return lh.S_un.S_addr < rh.S_un.S_addr; }
inline bool operator ==(const in_addr& lh, const in_addr& rh) { return lh.S_un.S_addr == rh.S_un.S_addr; }

namespace std
{
	template<> struct hash<in_addr>
	{
		typedef in_addr argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& ip) const noexcept
		{
			auto const h1(std::hash<unsigned long>{}(ip.S_un.S_addr));
			
			return h1; 
		}
	};
}

// --------------------------------------------------------------------------------
/// <summary>
/// Simple wrapper for MAC address
/// </summary>
// --------------------------------------------------------------------------------
struct mac_address {
	mac_address() { memset(&data[0], 0, ETH_ALEN); }
	explicit mac_address(const unsigned char* ptr) { memmove(&data[0], ptr, ETH_ALEN); }

	unsigned char& operator[](size_t index) { return data[index]; }
	const unsigned char& operator[](size_t index)const { return data[index]; }

	bool operator ==(const mac_address& rhs) const {
		return data == rhs.data;
	}

	bool operator !=(const mac_address& rhs) const {
		return !(*this == rhs);
	}

	bool operator <(const mac_address& rhs) const {
		return (memcmp(&data[0], &rhs.data[0], ETH_ALEN) < 0);
	}

	explicit operator bool () const{
		return (*this != mac_address());
	}

	explicit operator std::array<unsigned char, ETH_ALEN>() const { return data; }

	template<typename T>
	explicit operator std::basic_string<T>() const {
		std::basic_ostringstream<T> oss;
		oss << std::hex
			<< std::uppercase
			<< std::setfill(T('0')) << std::setw(2)
			<< static_cast<unsigned> (data[0]) //<< ":"
			<< std::setfill(T('0')) << std::setw(2)
			<< static_cast<unsigned> (data[1]) //<< ":"
			<< std::setfill(T('0')) << std::setw(2)
			<< static_cast<unsigned> (data[2]) //<< ":"
			<< std::setfill(T('0')) << std::setw(2)
			<< static_cast<unsigned> (data[3]) //<< ":"
			<< std::setfill(T('0')) << std::setw(2)
			<< static_cast<unsigned> (data[4]) //<< ":"
			<< std::setfill(T('0')) << std::setw(2)
			<< static_cast<unsigned> (data[5]);
		return oss.str();
	}

	const mac_address& reverse() { std::reverse(data.begin(), data.end()); return *this; }
	std::array<unsigned char, ETH_ALEN> data;
};

namespace std
{
	template<> struct hash<mac_address>
	{
		typedef mac_address argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& mac) const noexcept
		{
			const auto arg = (static_cast<uint64_t>(mac[0]) << 40) +
				(static_cast<uint64_t>(mac[1]) << 32) +
				(static_cast<uint64_t>(mac[2]) << 24) +
				(static_cast<uint64_t>(mac[3]) << 16) +
				(static_cast<uint64_t>(mac[4]) << 8) +
				mac[5];

			auto const h1(
				std::hash<uint64_t>{}(arg)
			);

			return h1;
		}
	};
}

// --------------------------------------------------------------------------------
/// <summary>
/// Class representing network interface
/// </summary>
// --------------------------------------------------------------------------------
class network_adapter {
public:
	network_adapter(
		CNdisApi& api,
		HANDLE adapter,
		unsigned char* mac_addr,
		std::string const& internal_name,
		std::string const& friendly_name,
		const unsigned filter = 0
	) :	api_(api),
		hardware_address_(mac_addr),
		network_filter_(filter),
		event_(::CreateEvent(nullptr, TRUE, FALSE, nullptr)),
		internal_name_(internal_name),
		friendly_name_(friendly_name),
		current_mode_({ adapter, 0})
	{
		initialize_interface();
	}

	~network_adapter() {}
	// ********************************************************************************
	/// <summary>
	/// Initialize additional network interface parameters
	/// </summary>
	// ********************************************************************************
	void initialize_interface() noexcept;

	// ********************************************************************************
	/// <summary>
	/// Returns network interface handle value
	/// </summary>
	/// <returns>network interface driver handle</returns>
	// ********************************************************************************
	HANDLE get_adapter() const { return current_mode_.hAdapterHandle; }

	// ********************************************************************************
	/// <summary>
	/// Set network filter for the interface
	/// </summary>
	/// <param name="filter">hardware filter to set</param>
	/// <returns>boolean status of the operation</returns>
	// ********************************************************************************
	bool set_hw_filter(const unsigned filter) const { return api_.SetHwPacketFilter(current_mode_.hAdapterHandle, filter)?true:false; }

	// ********************************************************************************
	/// <summary>
	/// Get current network filter
	/// </summary>
	/// <returns>current hardware filter value</returns>
	// ********************************************************************************
	unsigned long get_hw_filter() const;

	// ********************************************************************************
	/// <summary>
	/// Stops filtering the network interface and tries tor restore its original state
	/// </summary>
	// ********************************************************************************
	void release();

	// ********************************************************************************
	/// <summary>
	/// Set filtering mode for the network interface
	/// </summary>
	/// <param name="flags">filter mode to set</param>
	// ********************************************************************************
	void set_mode(unsigned flags);

	// ********************************************************************************
	/// <summary>
	/// Check is provided MAC address belongs to this adapter
	/// </summary>
	/// <param name="ptr">pointer to 6 bytes of MAC address</param>
	/// <returns>true if MAC address belongs to this network adapter</returns>
	// ********************************************************************************
	bool is_local(unsigned char* ptr) const { return (mac_address(ptr) == hardware_address_); }

	// ********************************************************************************
	/// <summary>
	/// Waits for network interface event to be signaled
	/// </summary>
	/// <param name="milliseconds">timeout value in milliseconds</param>
	/// <returns>wait status</returns>
	// ********************************************************************************
	unsigned wait_event(const unsigned milliseconds) const {return event_.wait(milliseconds);}

	// ********************************************************************************
	/// <summary>
	/// Resets packet event to non-signaled state
	/// </summary>
	/// <returns>boolean status of the operation</returns>
	// ********************************************************************************
	bool reset_event() const { return event_.reset_event(); }

	// ********************************************************************************
	/// <summary>
	/// Loads packet event into the driver
	/// </summary>
	/// <returns>boolean status of the operation</returns>
	// ********************************************************************************
	bool set_packet_event() const { return api_.SetPacketEvent(current_mode_.hAdapterHandle, static_cast<HANDLE>(event_))?true:false; }

	// ********************************************************************************
	/// <summary>
	/// Network interface internal name getter
	/// </summary>
	/// <returns>string reference to the internal name</returns>
	// ********************************************************************************
	const std::string& get_internal_name() const { return internal_name_; }

	// ********************************************************************************
	/// <summary>
	/// Network interface friendly name getter
	/// </summary>
	/// <returns>string reference to the user friendly name</returns>
	// ********************************************************************************
	const std::string& get_friendly_name() const { return friendly_name_; }

	// ********************************************************************************
	/// <summary>
	/// Checks if this network adapter is Wi-Fi
	/// </summary>
	/// <returns>true for Wi-Fi adapter, false otherwise</returns>
	// ********************************************************************************
	bool is_wlan() const { return is_wlan_; }

	// ********************************************************************************
	/// <summary>
	/// Network adapter hardware address getter
	/// </summary>
	/// <returns>network interface hardware address</returns>
	// ********************************************************************************
	const mac_address& get_hw_address() const { return hardware_address_; }

	// ********************************************************************************
	/// <summary>
	/// Returns MAC address by the supplied IP address
	/// </summary>
	/// <param name="ip">IP address</param>
	/// <returns>MAC address associated with IP above if available, zero initialized
	/// otherwise</returns>
	// ********************************************************************************
	mac_address get_mac_by_ip (in_addr& ip);

	// ********************************************************************************
	/// <summary>
	/// Stores IP to MAC address association
	/// </summary>
	/// <param name="ip">IP address</param>
	/// <param name="mac">pointer to 6 bytes of MAC address</param>
	// ********************************************************************************
	void set_mac_for_ip(in_addr& ip, unsigned char* mac);

private:
	/// <summary>Driver interface reference</summary>
	CNdisApi& api_;
	/// <summary>Network interface current MAC address</summary>
	mac_address hardware_address_;	
	/// <summary>Network interface original filter value</summary>
	unsigned long network_filter_;	
	/// <summary>Packet in the adapter queue event</summary>
	safe_event event_;			
	/// <summary>Internal network interface name</summary>
	std::string internal_name_;		
	/// <summary>User-friendly name</summary>
	std::string friendly_name_;		
	/// <summary>Used to manipulate network interface mode</summary>
	ADAPTER_MODE current_mode_;		
	/// <summary>True for WLAN media type</summary>
	bool is_wlan_ = false;	
	/// <summary>ARP table</summary>
	std::unordered_map<in_addr, mac_address> ip_to_mac_;			
	/// <summary>Synchronization object to control access to ARP table</summary>
	std::mutex ip_to_mac_mutex_;		
};
