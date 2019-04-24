// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  simple_packet_filter.h 
/// Abstract: Simple packet filter class declaration
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

//#ifndef  _ENABLE_EXTENDED_ALIGNED_STORAGE
//// ReSharper disable once CppInconsistentNaming
//#define  _ENABLE_EXTENDED_ALIGNED_STORAGE
//#endif //  _ENABLE_EXTENDED_ALIGNED_STORAGE

namespace ndisapi
{
	inline const size_t maximum_packet_block = 510;

	enum class packet_action
	{
		pass,
		drop
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// simple winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class simple_packet_filter final : public CNdisApi
	{	
		simple_packet_filter() noexcept
		{
			initialize_network_interfaces();
		}
	
	public:
		~simple_packet_filter() { stop_filter(); }

		simple_packet_filter(const simple_packet_filter& other) = delete;
		simple_packet_filter(simple_packet_filter&& other) noexcept = delete;
		simple_packet_filter& operator=(const simple_packet_filter& other) = delete;
		simple_packet_filter& operator=(simple_packet_filter&& other) noexcept = delete;

		// ********************************************************************************
		/// <summary>
		/// Constructs simple_packet_filter
		/// </summary>
		/// <param name="in">incoming packets handling routine</param>
		/// <param name="out">outgoing packet handling routine</param>
		/// <returns></returns>
		// ********************************************************************************
		template<typename F1, typename F2>
		simple_packet_filter(F1 in, F2 out) : simple_packet_filter()
		{
			filter_incoming_packet_ = in;
			filter_outgoing_packet_ = out;
		}

		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering
		/// </summary>
		/// <param name="adapter">network interface index to filter</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filter(size_t adapter);
		// ********************************************************************************
		/// <summary>
		/// Stops packet filtering
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool stop_filter();
		// ********************************************************************************
		/// <summary>
		/// Queries the list of available network interfaces
		/// </summary>
		/// <returns>list of network adapters friendly names</returns>
		// ********************************************************************************
		std::vector<std::string> get_interface_list();

	private:
		// ********************************************************************************
		/// <summary>
		/// Working thread routine
		/// </summary>
		// ********************************************************************************
		void filter_working_thread();
		// ********************************************************************************
		/// <summary>
		/// Initializes available network interface list
		/// </summary>
		// ********************************************************************************
		void initialize_network_interfaces();

		/// <summary>outgoing packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_outgoing_packet_ = nullptr;
		/// <summary>incoming packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_incoming_packet_ = nullptr;

		/// <summary>working thread running status</summary>
		std::atomic_bool is_running_ = false;
		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;
		/// <summary>working thread object</summary>
		std::thread working_thread_;
		/// <summary>filtered adapter index</summary>
		size_t adapter_{ 0 };
	};

	inline bool simple_packet_filter::start_filter(const size_t adapter)
	{
		if (is_running_)
			return false;
		else
			is_running_ = true;

		adapter_ = adapter;
		working_thread_ = std::thread(&simple_packet_filter::filter_working_thread, this);

		return true;
	}

	inline bool simple_packet_filter::stop_filter()
	{
		if (!is_running_)
		{
			return false;
		}
		else
		{
			is_running_ = false;
		}

		network_interfaces_[adapter_]->release();

		// Wait for working thread to exit
		if (working_thread_.joinable())
			working_thread_.join();

		return true;
	}

	inline std::vector<std::string> simple_packet_filter::get_interface_list()
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline void simple_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList			ad_list;
		std::vector<char>		friendly_name(MAX_PATH * 4);

		GetTcpipBoundAdaptersInfo(&ad_list);

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			CNdisApi::ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]), friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_unique<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data())));
		}
	}

	inline void simple_packet_filter::filter_working_thread()
	{
		auto packet_buffer =
			std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

		//
		// Initialize Requests
		//

		using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
			sizeof(NDISRD_ETH_Packet)*(maximum_packet_block - 1), 0x1000>;

		// 1. Allocate memory using unique_ptr for auto-delete on thread exit
		auto read_request_ptr = std::make_unique<request_storage_type_t>();
		auto write_adapter_request_ptr = std::make_unique<request_storage_type_t>();
		auto write_mstcp_request_ptr = std::make_unique<request_storage_type_t>();

		// 2. Get raw pointers for convenience
		auto read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr.get());
		auto write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr.get());
		auto write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr.get());

		read_request->hAdapterHandle = network_interfaces_[adapter_]->get_adapter();
		write_adapter_request->hAdapterHandle = network_interfaces_[adapter_]->get_adapter();
		write_mstcp_request->hAdapterHandle = network_interfaces_[adapter_]->get_adapter();

		read_request->dwPacketsNumber = maximum_packet_block;

		//
		// Initialize packet buffers
		//
		ZeroMemory(packet_buffer.get(), sizeof(INTERMEDIATE_BUFFER)*maximum_packet_block);

		for (unsigned i = 0; i < maximum_packet_block; ++i)
		{
			read_request->EthPacket[i].Buffer = &packet_buffer[i];
		}

		//
		// Set events for helper driver
		//
		if (!network_interfaces_[adapter_]->set_packet_event())
		{
			return;
		}

		network_interfaces_[adapter_]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

		while (is_running_)
		{
			[[maybe_unused]] auto wait_result = network_interfaces_[adapter_]->wait_event(INFINITE);

			[[maybe_unused]] auto reset_result = network_interfaces_[adapter_]->reset_event();

			while (is_running_ && ReadPackets(read_request))
			{
				for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
				{
					auto packet_action = packet_action::pass;

					if ((filter_outgoing_packet_ != nullptr) && (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
						packet_action = filter_outgoing_packet_(read_request->hAdapterHandle, packet_buffer[i]);

					if ((filter_incoming_packet_ != nullptr) && (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						packet_action = filter_incoming_packet_(read_request->hAdapterHandle, packet_buffer[i]);

					// Place packet back into the flow if was allowed to
					if (packet_action == packet_action::pass)
					{
						if (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &packet_buffer[i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &packet_buffer[i];
							++write_mstcp_request->dwPacketsNumber;
						}
					}
				}

				if (write_adapter_request->dwPacketsNumber)
				{
					SendPacketsToAdapter(write_adapter_request);
					write_adapter_request->dwPacketsNumber = 0;
				}

				if (write_mstcp_request->dwPacketsNumber)
				{
					SendPacketsToMstcp(write_mstcp_request);
					write_mstcp_request->dwPacketsNumber = 0;
				}

				read_request->dwPacketsSuccess = 0;
			}
		}
	}
}