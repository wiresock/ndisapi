// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  dual_packet_filter.h 
/// Abstract: Dual interface packet filter class
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

namespace ndisapi
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Dual interface winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class dual_packet_filter final : public CNdisApi
	{
	public:
		/// <summary>
		/// Defines packet action
		/// </summary>
		enum class packet_action
		{
			/// <summary>
			/// pass the packet over
			/// </summary>
			pass,
			/// <summary>
			/// drop the packet
			/// </summary>
			drop,
			/// <summary>
			/// change packet direction (e.g. forward incoming packet out)
			/// </summary>
			revert,
			/// <summary>
			/// forward packet via another network interface
			/// </summary>
			route,
			/// <summary>
			/// forward packet via another network interface and change its direction
			/// </summary>
			route_revert
		};

	private:
		/// <summary>
		/// Defines maximum number of network packets to read via one I/O operation
		/// </summary>
		static constexpr size_t maximum_packet_block = 510;

		/// <summary>
		/// Storage type for the I/O operations
		/// </summary>
		using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
		                                                      sizeof(NDISRD_ETH_Packet) * (maximum_packet_block - 1),
		                                                      0x1000>;

		/// <summary>
		/// Defines current NDIS filtering state
		/// </summary>
		enum class filter_state
		{
			stopped,
			starting,
			running,
			stopping
		};

		/// <summary>
		/// Constructor
		/// </summary>
		dual_packet_filter():
			adapter_event_(CreateEvent(nullptr, TRUE, FALSE, nullptr))
		{
			SetAdapterListChangeEvent(static_cast<HANDLE>(adapter_event_));
			allocate_storage();
			initialize_network_interfaces();

			adapter_watch_thread_ = std::thread([this]()
			{
				while (!adapter_watch_exit_.load())
				{
					[[maybe_unused]] auto wait_result = adapter_event_.wait(INFINITE);
					[[maybe_unused]] auto reset_result = adapter_event_.reset_event();

					if (adapter_watch_exit_.load())
						return;

					TCP_AdapterList ad_list;

					GetTcpipBoundAdaptersInfo(&ad_list);

					std::pair adapter_flags{false, false};

					for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
					{
						if (adapter_[0].load() == ad_list.m_nAdapterHandle[i])
						{
							adapter_flags.first = true;
						}
						else if (adapter_[1].load() == ad_list.m_nAdapterHandle[i])
						{
							adapter_flags.second = true;
						}
					}

					if (const auto adapter_handle = adapter_[0].load(); adapter_handle && !adapter_flags.first)
					{
						if (auto adapter_idx = get_adapter_by_handle(adapter_handle); adapter_idx.has_value())
						{
							std::cout << "[dual_packet_filter] : " << network_interfaces_[adapter_idx.value()]->
								get_friendly_name() << " : removed. Stopping filter!\n";
						}
						stop_filter(0);
					}

					if (const auto adapter_handle = adapter_[1].load(); adapter_handle && !adapter_flags.second)
					{
						if (auto adapter_idx = get_adapter_by_handle(adapter_handle); adapter_idx.has_value())
						{
							std::cout << "[dual_packet_filter] : " << network_interfaces_[adapter_idx.value()]->
								get_friendly_name() << " : removed. Stopping filter!\n";
						}
						stop_filter(1);
					}

					if (!adapter_flags.second || !adapter_flags.first)
						update_network_interfaces();

					std::shared_lock lock(lock_);
					for (auto& callback : adapters_change_callback_)
					{
						if (callback != nullptr)
						{
							callback();
						}
					}
				}
			});
		}

	public:
		// ********************************************************************************
		/// <summary>
		/// Destructor: stops filtering and releases resources
		/// </summary>
		~dual_packet_filter() override
		{
			adapter_watch_exit_.store(true);
			[[maybe_unused]] auto signal_result = adapter_event_.signal();

			stop_filter(0);
			stop_filter(1);

			if (adapter_watch_thread_.joinable())
				adapter_watch_thread_.join();
		}

		/// <summary>
		/// Deleted copy constructor
		/// </summary>
		dual_packet_filter(const dual_packet_filter& other) = delete;
		/// <summary>
		/// Deleted move constructor
		/// </summary>
		dual_packet_filter(dual_packet_filter&& other) noexcept = delete;
		/// <summary>
		/// Deleted copy assignment
		/// </summary>
		dual_packet_filter& operator=(const dual_packet_filter& other) = delete;
		/// <summary>
		/// Deleted move assignment
		/// </summary>
		dual_packet_filter& operator=(dual_packet_filter&& other) noexcept = delete;

		// ********************************************************************************
		/// <summary>
		/// Constructs dual_packet_filter
		/// </summary>
		/// <param name="first_in">primary incoming packets handling routine</param>
		/// <param name="first_out">primary outgoing packet handling routine</param>
		/// <param name="second_in">secondary incoming packets handling routine</param>
		/// <param name="second_out">secondary outgoing packet handling routine</param>
		/// <returns></returns>
		// ********************************************************************************
		template <typename F1, typename F2, typename F3, typename F4>
		dual_packet_filter(F1 first_in, F2 first_out, F3 second_in, F4 second_out) : dual_packet_filter()
		{
			filter_incoming_packet_[0] = first_in;
			filter_outgoing_packet_[0] = first_out;
			filter_incoming_packet_[1] = second_in;
			filter_outgoing_packet_[1] = second_out;
		}

		// ********************************************************************************
		/// <summary>
		/// Updates available network interfaces.
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool reconfigure();

		// ********************************************************************************
		/// <summary>
		/// Starts packet filtering
		/// </summary>
		/// <param name="adapter">network interface handle to filter</param>
		/// <param name="index">0 for primary adapter, 1 for secondary</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_filter(HANDLE adapter, size_t index);

		// ********************************************************************************
		/// <summary>
		/// Stops packet filtering
		/// </summary>
		/// <param name="index">0 for primary adapter, 1 for secondary</param>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool stop_filter(size_t index);

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
		const std::vector<std::shared_ptr<network_adapter>>& get_interface_list() const;

		// ********************************************************************************
		/// <summary>
		/// Resets adapter filter mode for the specified network interface
		/// </summary>
		/// <param name="adapter">adapter handle to reset</param>
		/// <returns>boolean result of the operation</returns>
		// ********************************************************************************
		bool reset_adapter_mode(HANDLE adapter) const
		{
			ADAPTER_MODE mode = {adapter, 0};
			return SetAdapterMode(&mode);
		}

		// ********************************************************************************
		/// <summary>
		/// Checks if adapter is in non-default filter mode for the specified network interface
		/// </summary>
		/// <param name="adapter">adapter handle </param>
		/// <returns>false if adapter is in filter mode, true otherwise</returns>
		// ********************************************************************************
		bool is_default_adapter_mode(HANDLE adapter) const
		{
			ADAPTER_MODE mode = {adapter, 0};
			if (GetAdapterMode(&mode))
			{
				return (mode.dwFlags == 0);
			}

			return true;
		}

		// ********************************************************************************
		/// <summary>
		/// Registers adapter change callback
		/// </summary>
		/// <param name="callback">callback function</param>
		/// <returns>true if successful, false otherwise</returns>
		// ********************************************************************************
		bool register_adapters_callback(std::function<void()> callback)
		{
			try
			{
				std::lock_guard lock(lock_);
				adapters_change_callback_.emplace_back(std::move(callback));
			}
			catch (...)
			{
				return false;
			}

			return true;
		}

		// ********************************************************************************
		/// <summary>
		/// Updates available network interface list
		/// </summary>
		// ********************************************************************************
		bool update_network_interfaces();

	private:
		// ********************************************************************************
		/// <summary>
		/// Working thread routine
		/// </summary>
		/// <param name="index">0 for primary adapter, 1 for secondary</param>
		/// <param name="adapter">network_adapter class instance</param>
		// ********************************************************************************
		void filter_working_thread(size_t index, std::shared_ptr<network_adapter> adapter);

		// ********************************************************************************
		/// <summary>
		/// Initializes available network interface list
		/// </summary>
		// ********************************************************************************
		void initialize_network_interfaces();

		// ********************************************************************************
		/// <summary>
		/// Allocates memory for packets storage
		/// </summary>
		// ********************************************************************************
		void allocate_storage();

		// ********************************************************************************
		/// <summary>
		/// Initialize interface and associated data structures required for packet filtering
		/// </summary>
		/// <param name="index">0 for primary adapter, 1 for secondary</param>
		/// <returns>true is success, false otherwise</returns>
		// ********************************************************************************
		bool init_filter(size_t index);

		// ********************************************************************************
		/// <summary>
		/// Release interface and associated data structures required for packet filtering
		/// </summary>
		/// <param name="index">0 for primary adapter, 1 for secondary</param>
		// ********************************************************************************
		void release_filter(size_t index);

		// ********************************************************************************
		/// <summary>
		/// Returns network_adapter object pointer by provided adapter handle
		/// </summary>
		/// <param name="adapter_handle"></param>
		/// <returns>network_adapter handle index in network_interfaces</returns>
		// ********************************************************************************
		std::optional<size_t> get_adapter_by_handle(HANDLE adapter_handle);

		/// <summary>adapter list monitoring event</summary>
		std::thread adapter_watch_thread_;
		/// <summary>adapter list exit flag</summary>
		std::atomic_bool adapter_watch_exit_{false};
		/// <summary>adapter list monitoring event</summary>
		winsys::safe_event adapter_event_;
		/// <summary>outgoing packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_outgoing_packet_[2] = {nullptr, nullptr};
		/// <summary>incoming packet processing functor</summary>
		std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)> filter_incoming_packet_[2] = {nullptr, nullptr};
		/// <summary>working thread running status</summary>
		std::atomic<filter_state> filter_state_[2] = {filter_state::stopped, filter_state::stopped};
		/// <summary>list of available network interfaces</summary>
		std::vector<std::shared_ptr<network_adapter>> network_interfaces_{};
		/// <summary>object state lock</summary>
		mutable std::shared_mutex lock_;
		/// <summary>working thread object</summary>
		std::thread working_thread_[2];
		/// <summary>filtered adapter handle</summary>
		std::atomic<HANDLE> adapter_[2]{nullptr, nullptr};
		/// <summary>array of INTERMEDIATE_BUFFER structures</summary>
		std::unique_ptr<INTERMEDIATE_BUFFER[]> packet_buffer_[2]{};
		/// <summary>driver request for reading packets</summary>
		std::unique_ptr<request_storage_type_t> read_request_ptr_[2]{};
		/// <summary>driver request for writing packets to adapter</summary>
		std::unique_ptr<request_storage_type_t> write_adapter_request_ptr_[2]{};
		/// <summary>driver request for writing packets up to protocol stack</summary>
		std::unique_ptr<request_storage_type_t> write_mstcp_request_ptr_[2]{};
		/// <summary>driver request for writing routed packets to adapter</summary>
		std::unique_ptr<request_storage_type_t> routed_write_adapter_request_ptr_[2]{};
		/// <summary>driver request for writing routed packets up to protocol stack</summary>
		std::unique_ptr<request_storage_type_t> routed_write_mstcp_request_ptr_[2]{};
		/// <summary>callback to notify for adapters changes</summary>
		std::vector<std::function<void()>> adapters_change_callback_{};
	};

	inline bool dual_packet_filter::init_filter(const size_t index)
	{
		auto* read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr_[index].get());
		auto* const write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr_[index].get());
		auto* const write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr_[index].get());
		auto* const routed_write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(routed_write_adapter_request_ptr_[
			index].get());
		auto* const routed_write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(routed_write_mstcp_request_ptr_[index]
			.get());

		read_request->hAdapterHandle = adapter_[index];
		write_adapter_request->hAdapterHandle = adapter_[index];
		write_mstcp_request->hAdapterHandle = adapter_[index];

		read_request->dwPacketsNumber = maximum_packet_block;
		write_adapter_request->dwPacketsNumber = 0;
		write_mstcp_request->dwPacketsNumber = 0;
		routed_write_adapter_request->dwPacketsNumber = 0;
		routed_write_mstcp_request->dwPacketsNumber = 0;

		//
		// Initialize packet buffers
		//
		ZeroMemory(packet_buffer_[index].get(), sizeof(INTERMEDIATE_BUFFER) * maximum_packet_block);

		for (unsigned i = 0; i < maximum_packet_block; ++i)
		{
			read_request->EthPacket[i].Buffer = &packet_buffer_[index][i];
		}

		if (const auto adapter_idx = get_adapter_by_handle(adapter_[index]); adapter_idx.has_value())
		{
			//
			// Set events for helper driver
			//
			if (!network_interfaces_[adapter_idx.value()]->set_packet_event())
			{
				return false;
			}

			network_interfaces_[adapter_idx.value()]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

			return true;
		}

		return false;
	}

	inline void dual_packet_filter::release_filter(const size_t index)
	{
		if (const auto adapter_idx = get_adapter_by_handle(adapter_[index]); adapter_idx.has_value())
		{
			network_interfaces_[adapter_idx.value()]->release();
		}

		// Wait for working thread to exit
		if (working_thread_[index].joinable())
			working_thread_[index].join();
	}

	inline std::optional<size_t> dual_packet_filter::get_adapter_by_handle(HANDLE adapter_handle)
	{
		const auto it = std::find_if(network_interfaces_.cbegin(), network_interfaces_.cend(),
		                             [adapter_handle](auto&& a)
		                             {
			                             if (a->get_adapter() == adapter_handle)
				                             return true;
			                             return false;
		                             });

		if (it == network_interfaces_.end())
			return {};

		return std::distance(network_interfaces_.cbegin(), it);
	}

	inline bool dual_packet_filter::reconfigure()
	{
		return update_network_interfaces();
	}

	inline bool dual_packet_filter::start_filter(HANDLE adapter_handle, const size_t index)
	{
		std::unique_lock lock(lock_);

		if (filter_state_[index] == filter_state::running)
			return true;

		adapter_[index] = adapter_handle;

		if (init_filter(index))
		{
			std::shared_ptr<network_adapter> adapter;
			if (const auto adapter_idx = get_adapter_by_handle(adapter_[index]); !adapter_idx.has_value())
				return false;
			else
				adapter = network_interfaces_[adapter_idx.value()];

			try
			{
				working_thread_[index] = std::thread(&dual_packet_filter::filter_working_thread, this, index,
				                                     std::move(adapter));
			}
			catch (...)
			{
				return false;
			}
		}
		else
		{
			return false;
		}
		filter_state_[index] = filter_state::running;
		return true;
	}

	inline bool dual_packet_filter::stop_filter(const size_t index)
	{
		std::unique_lock lock(lock_);

		if (filter_state_[index] == filter_state::stopped)
			return true;

		filter_state_[index] = filter_state::stopped;

		release_filter(index);

		adapter_[index].store(nullptr);

		return true;
	}

	inline std::vector<std::string> dual_packet_filter::get_interface_names_list() const
	{
		std::shared_lock lock(lock_);

		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline const std::vector<std::shared_ptr<network_adapter>>& dual_packet_filter::get_interface_list() const
	{
		return network_interfaces_;
	}

	inline void dual_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		GetTcpipBoundAdaptersInfo(&ad_list);

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_shared<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data()),
					ad_list.m_nAdapterMediumList[i],
					ad_list.m_usMTU[i]));
		}
	}

	inline bool dual_packet_filter::update_network_interfaces()
	{
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		if (!GetTcpipBoundAdaptersInfo(&ad_list))
			return false;

		std::unique_lock lock(lock_);

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			if (const auto it = std::find_if(network_interfaces_.cbegin(), network_interfaces_.cend(),
			                                 [handle = ad_list.m_nAdapterHandle[i]](auto&& a)
			                                 {
				                                 return (a->get_adapter() == handle);
			                                 }); it == network_interfaces_.cend())
			{
				// we have not seen this adapter, add it
				network_interfaces_.push_back(
					std::make_shared<network_adapter>(
						this,
						ad_list.m_nAdapterHandle[i],
						ad_list.m_czCurrentAddress[i],
						std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
						std::string(friendly_name.data()),
						ad_list.m_nAdapterMediumList[i],
						ad_list.m_usMTU[i]));
			}
			else if (it->operator->()->get_internal_name() != std::string(
					reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])) ||
				it->operator->()->get_friendly_name() != std::string(friendly_name.data()))
			{
				// handle case when adapter with existing handle has different name (internal driver level substitution has happened)
				// or friendly name has changed (dynamic change)
				// erase old adapter entry and add a new one
				network_interfaces_.erase(it);

				network_interfaces_.push_back(
					std::make_shared<network_adapter>(
						this,
						ad_list.m_nAdapterHandle[i],
						ad_list.m_czCurrentAddress[i],
						std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
						std::string(friendly_name.data()),
						ad_list.m_nAdapterMediumList[i],
						ad_list.m_usMTU[i]));
			}
		}

		// erase all adapters with unknown handles
		network_interfaces_.erase(std::remove_if(network_interfaces_.begin(), network_interfaces_.end(),
		                                         [&ad_list](auto&& a)
		                                         {
			                                         for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
			                                         {
				                                         if (ad_list.m_nAdapterHandle[i] == a->get_adapter())
					                                         return false;
			                                         }

			                                         return true;
		                                         }), network_interfaces_.end());

		return true;
	}

	inline void dual_packet_filter::allocate_storage()
	{
		for (size_t index = 0; index < 2; ++index)
		{
			packet_buffer_[index] = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);
			read_request_ptr_[index] = std::make_unique<request_storage_type_t>();
			write_adapter_request_ptr_[index] = std::make_unique<request_storage_type_t>();
			write_mstcp_request_ptr_[index] = std::make_unique<request_storage_type_t>();
			routed_write_adapter_request_ptr_[index] = std::make_unique<request_storage_type_t>();
			routed_write_mstcp_request_ptr_[index] = std::make_unique<request_storage_type_t>();
		}
	}

	inline void dual_packet_filter::filter_working_thread(const size_t index, std::shared_ptr<network_adapter> adapter)
	{
		auto* read_request = reinterpret_cast<PETH_M_REQUEST>(read_request_ptr_[index].get());
		auto* write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(write_adapter_request_ptr_[index].get());
		auto* write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(write_mstcp_request_ptr_[index].get());
		auto* routed_write_adapter_request = reinterpret_cast<PETH_M_REQUEST>(routed_write_adapter_request_ptr_[index].
			get());
		auto* routed_write_mstcp_request = reinterpret_cast<PETH_M_REQUEST>(routed_write_mstcp_request_ptr_[index].
			get());

		while (filter_state_[index] == filter_state::running)
		{
			[[maybe_unused]] auto wait_result = adapter->wait_event(INFINITE);

			[[maybe_unused]] auto reset_result = adapter->reset_event();

			while (filter_state_[index] == filter_state::running && ReadPackets(read_request))
			{
				for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
				{
					auto packet_action = packet_action::pass;

					if (packet_buffer_[index][i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						if (filter_outgoing_packet_[index] != nullptr)
							packet_action = filter_outgoing_packet_[index](
								read_request->hAdapterHandle, packet_buffer_[index][i]);
					}
					else
					{
						if (filter_incoming_packet_[index] != nullptr)
							packet_action = filter_incoming_packet_[index](
								read_request->hAdapterHandle, packet_buffer_[index][i]);
					}

					// Place packet back into the flow if was allowed to
					switch (packet_action)
					{
					case packet_action::pass:
						if (packet_buffer_[index][i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &
								packet_buffer_[index][i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &
								packet_buffer_[index][i];
							++write_mstcp_request->dwPacketsNumber;
						}
						break;
					case packet_action::revert:
						if (packet_buffer_[index][i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
						{
							write_adapter_request->EthPacket[write_adapter_request->dwPacketsNumber].Buffer = &
								packet_buffer_[index][i];
							++write_adapter_request->dwPacketsNumber;
						}
						else
						{
							write_mstcp_request->EthPacket[write_mstcp_request->dwPacketsNumber].Buffer = &
								packet_buffer_[index][i];
							++write_mstcp_request->dwPacketsNumber;
						}
						break;
					case packet_action::route:
						if (packet_buffer_[index][i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							routed_write_adapter_request->EthPacket[routed_write_adapter_request->dwPacketsNumber].
								Buffer = &packet_buffer_[index][i];
							++routed_write_adapter_request->dwPacketsNumber;
						}
						else
						{
							routed_write_mstcp_request->EthPacket[routed_write_mstcp_request->dwPacketsNumber].Buffer =
								&packet_buffer_[index][i];
							++routed_write_mstcp_request->dwPacketsNumber;
						}
						break;
					case packet_action::route_revert:
						if (packet_buffer_[index][i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
						{
							routed_write_adapter_request->EthPacket[routed_write_adapter_request->dwPacketsNumber].
								Buffer = &packet_buffer_[index][i];
							++routed_write_adapter_request->dwPacketsNumber;
						}
						else
						{
							routed_write_mstcp_request->EthPacket[routed_write_mstcp_request->dwPacketsNumber].Buffer =
								&packet_buffer_[index][i];
							++routed_write_mstcp_request->dwPacketsNumber;
						}
						break;
					case packet_action::drop:
						break;
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

				if (routed_write_adapter_request->dwPacketsNumber && filter_state_[(index + 1) % 2] ==
					filter_state::running)
				{
					routed_write_adapter_request->hAdapterHandle = adapter_[(index + 1) % 2];
					SendPacketsToAdapter(routed_write_adapter_request);
					routed_write_adapter_request->dwPacketsNumber = 0;
				}

				if (routed_write_mstcp_request->dwPacketsNumber && filter_state_[(index + 1) % 2] ==
					filter_state::running)
				{
					routed_write_mstcp_request->hAdapterHandle = adapter_[(index + 1) % 2];
					SendPacketsToMstcp(routed_write_mstcp_request);
					routed_write_mstcp_request->dwPacketsNumber = 0;
				}

				read_request->dwPacketsSuccess = 0;
			}
		}
	}
}
