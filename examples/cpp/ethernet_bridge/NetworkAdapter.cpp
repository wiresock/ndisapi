// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  NetworkAdapter.cpp
/// Abstract: Network interface wrapper class definitions 
/// </summary>
// --------------------------------------------------------------------------------

#include "stdafx.h"

// Set network filter for the interface
inline unsigned long network_adapter::get_hw_filter() const
{ 
	unsigned long result = 0;

	api_.GetHwPacketFilter(current_mode_.hAdapterHandle, &result);

	return result;
}

void network_adapter::release()
{
	// This function releases packets in the adapter queue and stops listening the interface
	[[maybe_unused]] auto event_result = event_.signal();

	// Restore old packet filter (not for WLAN as we don't modify it)
	if (!is_wlan() && network_filter_)
	{
		[[maybe_unused]] auto hw_result = set_hw_filter(network_filter_);
	}

	// Reset adapter mode and flush the packet queue
	current_mode_.dwFlags = 0;

	api_.SetAdapterMode(&current_mode_);
	api_.FlushAdapterPacketQueue(current_mode_.hAdapterHandle);
}

void network_adapter::set_mode(const unsigned flags)
{
	current_mode_.dwFlags = flags;

	api_.SetAdapterMode(&current_mode_);
}

void network_adapter::set_mac_for_ip(in_addr & ip, unsigned char* mac)
{
	std::lock_guard<std::mutex> guard(ip_to_mac_mutex_);
	
	ip_to_mac_[ip] = mac_address(mac);
}

mac_address network_adapter::get_mac_by_ip(in_addr & ip)
{
	std::lock_guard<std::mutex> guard(ip_to_mac_mutex_);

	const auto search = ip_to_mac_.find(ip);

	if (search != ip_to_mac_.end())
	{
		return search->second;
	}

	return mac_address();
}

void network_adapter::initialize_interface() noexcept
{
	//
	// Saves original packet filter
	//
	network_filter_ = get_hw_filter();

	//
	// Query physical media for the network interface to check is this is WLAN network adapter
	//
	const auto phys_medium_request = reinterpret_cast<PPACKET_OID_DATA>(new char[sizeof(PACKET_OID_DATA) + sizeof(DWORD) - 1]);
	phys_medium_request->Length = sizeof(DWORD);
	phys_medium_request->Oid = OID_GEN_PHYSICAL_MEDIUM;

	phys_medium_request->hAdapterHandle = current_mode_.hAdapterHandle;
	if (api_.NdisrdRequest(phys_medium_request, FALSE))
	{
		if (static_cast<NdisPhysicalMedium>(*reinterpret_cast<PDWORD>(phys_medium_request->Data)) ==
			NdisPhysicalMedium::NdisPhysicalMediumNative802_11)
		{
			is_wlan_ = true;
		}
	}
}