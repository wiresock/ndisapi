/// <summary>
/// Module Name:  network_adapter.h 
/// Abstract: Network interface wrapper class declaration 
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

namespace ndisapi
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Class representing network interface
	/// </summary>
	// --------------------------------------------------------------------------------
	class network_adapter {
	public:
		network_adapter(
			CNdisApi* api,
			HANDLE adapter_handle,
			unsigned char* mac_addr,
			std::string internal_name,
			std::string friendly_name
		) : api_(api),
			hardware_address_{ mac_addr },
			packet_event_(CreateEvent(nullptr, TRUE, FALSE, nullptr)),
			internal_name_(std::move(internal_name)),
			friendly_name_(std::move(friendly_name)),
			current_mode_({ adapter_handle, 0}) {}

		~network_adapter() = default;

		network_adapter(const network_adapter& other) = delete;

		network_adapter(network_adapter&& other) noexcept
			: api_{other.api_},
			  hardware_address_{other.hardware_address_},
			  packet_event_{std::move(other.packet_event_)},
			  internal_name_{std::move(other.internal_name_)},
			  friendly_name_{std::move(other.friendly_name_)},
			  current_mode_{other.current_mode_}
		{
		}

		network_adapter& operator=(const network_adapter& other) = delete;

		network_adapter& operator=(network_adapter&& other) noexcept
		{
			if (this == &other)
				return *this;
			api_ = other.api_;
			hardware_address_ = other.hardware_address_;
			packet_event_ = std::move(other.packet_event_);
			internal_name_ = std::move(other.internal_name_);
			friendly_name_ = std::move(other.friendly_name_);
			current_mode_ = other.current_mode_;
			return *this;
		}

		// ********************************************************************************
		/// <summary>
		/// Returns network interface handle value
		/// </summary>
		/// <returns>network adapter handle</returns>
		// ********************************************************************************
		HANDLE get_adapter() const { return current_mode_.hAdapterHandle; }
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
		/// <param name="flags">filter mode flags value</param>
		// ********************************************************************************
		void set_mode(unsigned flags);
		// ********************************************************************************
		/// <summary>
		/// Waits for network interface event to be signaled
		/// </summary>
		/// <param name="milliseconds"></param>
		/// <returns>wait status</returns>
		// ********************************************************************************
		unsigned wait_event(const unsigned milliseconds) const { return packet_event_.wait(milliseconds); }
		// ********************************************************************************
		/// <summary>
		/// Signals packet event
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool signal_event() const { return packet_event_.signal(); }
		// ********************************************************************************
		/// <summary>
		/// resets packet event
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool reset_event() const { return packet_event_.reset_event(); }
		// ********************************************************************************
		/// <summary>
		/// submits packet event into the driver
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool set_packet_event() const { return api_->SetPacketEvent(current_mode_.hAdapterHandle, static_cast<HANDLE>(packet_event_)) ? true : false; }
		// ********************************************************************************
		/// <summary>
		/// Network adapter internal name getter
		/// </summary>
		/// <returns>internal name string reference</returns>
		// ********************************************************************************
		const std::string& get_internal_name() const { return internal_name_; }
		// ********************************************************************************
		/// <summary>
		/// Network adapter user friendly name getter
		/// </summary>
		/// <returns>user friendly name string reference</returns>
		// ********************************************************************************
		const std::string& get_friendly_name() const { return friendly_name_; }
		// ********************************************************************************
		/// <summary>
		/// Queries network adapter hardware address
		/// </summary>
		/// <returns>network adapter MAC address</returns>
		// ********************************************************************************
		net::mac_address	get_hw_address() const { return hardware_address_; }

	private:

		/// <summary>Driver interface pointer</summary>
		CNdisApi* 	api_;
		/// <summary>Network interface current MAC address</summary>
		net::mac_address hardware_address_;
		/// <summary>Packet in the adapter queue event</summary>
		winsys::safe_event packet_event_;
		/// <summary>Internal network interface name</summary>
		std::string internal_name_;	
		/// <summary>User-friendly name</summary>
		std::string friendly_name_;	
		/// <summary>Used to manipulate network interface mode</summary>
		ADAPTER_MODE current_mode_;		
	};

	inline void network_adapter::release()
	{
		// This function releases packets in the adapter queue and stops listening the interface
		[[maybe_unused]] auto result = packet_event_.signal();

		// Reset adapter mode and flush the packet queue
		current_mode_.dwFlags = 0;

		api_->SetAdapterMode(&current_mode_);
		api_->FlushAdapterPacketQueue(current_mode_.hAdapterHandle);
	}

	inline void network_adapter::set_mode(unsigned flags)
	{
		current_mode_.dwFlags = flags;

		api_->SetAdapterMode(&current_mode_);
	}
}

