/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  network_adapter.h                                       */
/*                                                                       */
/* Abstract: Network interface wrapper class declaration                 */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#pragma once

namespace ndisapi
{
	//
	// Class representing network interface
	//

	class network_adapter {
	public:
		network_adapter(
			CNdisApi* api,
			HANDLE hAdapter,
			unsigned char* mac_addr,
			const std::string& InternalName,
			const std::string& FriendlyName,
			unsigned dwFilter = 0
		) : m_pApi(api),
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

		~network_adapter() {}

		void						InitializeInterface() noexcept {}; // Initialize additional network interface parameters 
		HANDLE						GetAdapter() const { return m_hAdapter; } // Returnes network interface handle value
		void						Release(); // Stops filtering the network interface and tries tor restore its original state
		void						SetMode(unsigned dwFlags); // Set filtering mode for the network interface
		unsigned					WaitEvent(unsigned dwMilliseconds) const { return m_Event.wait(dwMilliseconds); } // Waits for network interface event to be signalled
		bool						ResetEvent() const { return m_Event.reset_event(); }
		bool						SetPacketEvent() const { return m_pApi->SetPacketEvent(m_hAdapter, m_Event) ? true : false; }
		const std::string&			GetInternalName() const { return m_InternalName; }
		const std::string&			GetFriendlyName() const { return m_FriendlyName; }
		mac_address					GetHwAddress() const { return m_HwAddress; }

	private:

		CNdisApi*					m_pApi;				// Driver interface pointer
		HANDLE						m_hAdapter;			// Network interface handle value
		mac_address					m_HwAddress;		// Network interface current MAC address
		unsigned long				m_dwNetworkFilter;	// Network interface original filter value
		safe_event					m_Event;			// Packet in the adapter queue event
		std::string					m_InternalName;		// Internal network interface name
		std::string					m_FriendlyName;		// User-friendly name
		ADAPTER_MODE				m_CurrentMode;		// Used to manipulate network interface mode
	};

	inline void network_adapter::Release()
	{
		// This function releases packets in the adapter queue and stops listening the interface
		m_Event.signal();

		// Reset adapter mode and flush the packet queue
		m_CurrentMode.dwFlags = 0;
		m_CurrentMode.hAdapterHandle = m_hAdapter;

		m_pApi->SetAdapterMode(&m_CurrentMode);
		m_pApi->FlushAdapterPacketQueue(m_hAdapter);
	}

	inline void network_adapter::SetMode(unsigned dwFlags)
	{
		m_CurrentMode.dwFlags = dwFlags;
		m_CurrentMode.hAdapterHandle = m_hAdapter;

		m_pApi->SetAdapterMode(&m_CurrentMode);
	}
}

