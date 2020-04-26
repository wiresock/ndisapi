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
		drop,
		revert
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// simple winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class simple_packet_filter final : public CNdisApi
	{
		using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
			sizeof(NDISRD_ETH_Packet) * (maximum_packet_block - 1), 0x1000>;

		enum class filter_state
		{
			stopped,
			starting,
			running,
			stopping
		};
		
		simple_packet_filter()
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
		/// Updates available network interfaces. Should be called when the filter is inactive. 
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool reconfigure();
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
		/// Queries the list of the names for the available network interfaces
		/// </summary>
		/// <returns>list of network adapters friendly names</returns>
		// ********************************************************************************
		std::vector<std::string> get_interface_names_list() const;

		// ********************************************************************************
		/// <summary>
		/// Queries the list of the available network interfaces
		/// </summary>
		/// <returns>vector of available network adapters</returns>
		// ********************************************************************************
		const std::vector<std::unique_ptr<network_adapter>>& get_interface_list() const;

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
		// ********************************************************************************
		/// <summary>
		/// Initialize interface and associated data structures required for packet filtering
		/// </summary>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool init_filter();
		// ********************************************************************************
		/// <summary>
		/// Release interface and associated data structures required for packet filtering
		/// </summary>
		// ********************************************************************************
		void release_filter();

		/// <summary>outgoing packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_outgoing_packet_ = nullptr;
		/// <summary>incoming packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_incoming_packet_ = nullptr;
		/// <summary>working thread running status</summary>
		std::atomic<filter_state> filter_state_ = filter_state::stopped;
		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;
		/// <summary>working thread object</summary>
		std::thread working_thread_;
		/// <summary>filtered adapter index</summary>
		size_t adapter_{ 0 };
		/// <summary>array of INTERMEDIATE_BUFFER structures</summary>
		std::unique_ptr<INTERMEDIATE_BUFFER[]> packet_buffer_;
		/// <summary>driver request for reading packets</summary>
		std::unique_ptr<request_storage_type_t> read_request_ptr_;
		/// <summary>driver request for writing packets to adapter</summary>
		std::unique_ptr<request_storage_type_t> write_adapter_request_ptr_;
		/// <summary>driver request for writing packets up to protocol stack</summary>
		std::unique_ptr<request_storage_type_t> write_mstcp_request_ptr_;
	};

	inline bool simple_packet_filter::init_filter()
	{
		try
		{
			packet_buffer_ = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

			read_request_ptr_ = std::make_unique<request_storage_type_t>();
			write_adapter_request_ptr_ = std::make_unique<request_storage_type_t>();
			write_mstcp_request_ptr_ = std::make_unique<request_storage_type_t>();
		}
		catch (const std::bad_alloc&)
		{
			return false;
		}

		auto read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr_.get());
		auto write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr_.get());
		auto write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr_.get());

		read_request->hAdapterHandle = network_interfaces_[adapter_]->get_adapter();
		write_adapter_request->hAdapterHandle = network_interfaces_[adapter_]->get_adapter();
		write_mstcp_request->hAdapterHandle = network_interfaces_[adapter_]->get_adapter();

		read_request->dwPacketsNumber = maximum_packet_block;

		//
		// Initialize packet buffers
		//
		ZeroMemory(packet_buffer_.get(), sizeof(INTERMEDIATE_BUFFER) * maximum_packet_block);

		for (unsigned i = 0; i < maximum_packet_block; ++i)
		{
			read_request->EthPacket[i].Buffer = &packet_buffer_[i];
		}

		//
		// Set events for helper driver
		//
		if (!network_interfaces_[adapter_]->set_packet_event())
		{
			packet_buffer_.reset();
			read_request_ptr_.reset();
			write_adapter_request_ptr_.reset();
			write_mstcp_request_ptr_.reset();

			return false;
		}

		network_interfaces_[adapter_]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

		return true;
	}

	inline void simple_packet_filter::release_filter()
	{
		network_interfaces_[adapter_]->release();

		// Wait for working thread to exit
		if (working_thread_.joinable())
			working_thread_.join();

		packet_buffer_.reset();
		read_request_ptr_.reset();
		write_adapter_request_ptr_.reset();
		write_mstcp_request_ptr_.reset();
	}

	inline bool simple_packet_filter::reconfigure()
	{
		if (filter_state_ != filter_state::stopped)
			return false;

		network_interfaces_.clear();

		initialize_network_interfaces();

		return true;
	}

	inline bool simple_packet_filter::start_filter(const size_t adapter)
	{
		if (filter_state_ != filter_state::stopped)
			return false;
		
		filter_state_ = filter_state::starting;

		adapter_ = adapter;

		if (init_filter())
			working_thread_ = std::thread(&simple_packet_filter::filter_working_thread, this);
		else
			return false;

		return true;
	}

	inline bool simple_packet_filter::stop_filter()
	{
		if (filter_state_ != filter_state::running)
			return false;

		filter_state_ = filter_state::stopping;

		release_filter();

		filter_state_ = filter_state::stopped;

		return true;
	}

	inline std::vector<std::string> simple_packet_filter::get_interface_names_list() const
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline const std::vector<std::unique_ptr<network_adapter>>& simple_packet_filter::get_interface_list() const
	{
		return network_interfaces_;
	}

	inline void simple_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList			ad_list;
		std::vector<char>		friendly_name(MAX_PATH * 4);

		GetTcpipBoundAdaptersInfo(&ad_list);

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]), friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

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
		filter_state_ = filter_state::running;
		
		auto read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr_.get());
		auto write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr_.get());
		auto write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr_.get());

		while (filter_state_ == filter_state::running)
		{
			[[maybe_unused]] auto wait_result = network_interfaces_[adapter_]->wait_event(INFINITE);

			[[maybe_unused]] auto reset_result = network_interfaces_[adapter_]->reset_event();

			while (filter_state_ == filter_state::running && ReadPackets(read_request))
			{
				for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
				{
					auto packet_action = packet_action::pass;

					if (packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						if (filter_outgoing_packet_ != nullptr)
							packet_action = filter_outgoing_packet_(read_request->hAdapterHandle, packet_buffer_[i]);
					}
					else
					{
						if (filter_incoming_packet_ != nullptr)
							packet_action = filter_incoming_packet_(read_request->hAdapterHandle, packet_buffer_[i]);
					}

					// Place packet back into the flow if was allowed to
					if (packet_action == packet_action::pass)
					{
						if (packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &packet_buffer_[i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &packet_buffer_[i];
							++write_mstcp_request->dwPacketsNumber;
						}
					}
					else if(packet_action == packet_action::revert)
					{
						if (packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &packet_buffer_[i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &packet_buffer_[i];
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