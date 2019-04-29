// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  fastio_packet_filter.h 
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
	inline constexpr size_t maximum_packet_block = 512;
	inline constexpr size_t fast_io_size = 0x20000;
	inline constexpr uint32_t fast_io_packets_num = (fast_io_size - sizeof(FAST_IO_SECTION_HEADER)) / sizeof(INTERMEDIATE_BUFFER);

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
	class fastio_packet_filter final : public CNdisApi
	{	
		fastio_packet_filter() noexcept
		{
			initialize_network_interfaces();
		}
	
	public:
		~fastio_packet_filter() { stop_filter(); }

		fastio_packet_filter(const fastio_packet_filter& other) = delete;
		fastio_packet_filter(fastio_packet_filter&& other) noexcept = delete;
		fastio_packet_filter& operator=(const fastio_packet_filter& other) = delete;
		fastio_packet_filter& operator=(fastio_packet_filter&& other) noexcept = delete;

		// ********************************************************************************
		/// <summary>
		/// Constructs fastio_packet_filter
		/// </summary>
		/// <param name="in">incoming packets handling routine</param>
		/// <param name="out">outgoing packet handling routine</param>
		/// <returns></returns>
		// ********************************************************************************
		template<typename F1, typename F2>
		fastio_packet_filter(F1 in, F2 out) : fastio_packet_filter()
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

	inline bool fastio_packet_filter::start_filter(const size_t adapter)
	{
		if (is_running_)
			return false;
		else
			is_running_ = true;

		adapter_ = adapter;
		working_thread_ = std::thread(&fastio_packet_filter::filter_working_thread, this);

		return true;
	}

	inline bool fastio_packet_filter::stop_filter()
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

	inline std::vector<std::string> fastio_packet_filter::get_interface_list()
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline void fastio_packet_filter::initialize_network_interfaces()
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

	inline void fastio_packet_filter::filter_working_thread()
	{
		DWORD sent_success = 0;

		const auto packet_buffer =
			std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

		//
		// Initialize Requests
		//

		using request_storage_type_t = std::aligned_storage_t<sizeof(PINTERMEDIATE_BUFFER)*maximum_packet_block, 0x1000>;

		// 1. Allocate memory using unique_ptr for auto-delete on thread exit
		const auto read_request_ptr = std::make_unique<request_storage_type_t>();
		const auto write_adapter_request_ptr = std::make_unique<request_storage_type_t>();
		const auto write_mstcp_request_ptr = std::make_unique<request_storage_type_t>();

		// 2. Get raw pointers for convenience
		const auto read_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(read_request_ptr.get());
		const auto write_adapter_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_adapter_request_ptr.get());
		const auto write_mstcp_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_mstcp_request_ptr.get());

		// Initialize read request
		for (size_t i = 0; i < maximum_packet_block; ++i)
		{
			read_request[i] = &packet_buffer[i];
		}

		//
		// Set events for helper driver
		//
		if (!network_interfaces_[adapter_]->set_packet_event())
		{
			return;
		}

		using fast_io_storage_type_t = std::aligned_storage_t<fast_io_size, 0x1000>;
		const auto fast_io_ptr = std::make_unique<fast_io_storage_type_t>();
		const auto fast_io_section = reinterpret_cast<PFAST_IO_SECTION>(fast_io_ptr.get());
		
		if (InitializeFastIo(fast_io_section, fast_io_size))
		{
			std::cout << std::endl << "Successfully initialized fast I/O functionality" << std::endl;
		}
		else
		{
			std::cout << std::endl << "Failed tp initialize fast I/O functionality" << std::endl;
		}

		network_interfaces_[adapter_]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

		while (is_running_)
		{	
			//
			// Fast I/O processing section
			//
			if(fast_io_section->fast_io_header.fast_io_write_union.union_.split.number_of_packets)
			{
				fast_io_section->fast_io_header.read_in_progress_flag = 1;

				std::cout << "Fast I/O: " << 
					fast_io_section->fast_io_header.fast_io_write_union.union_.split.number_of_packets <<
					" packet(s)" << std::endl;

				/*std::cout << "number_of_packets = " << fast_io_section->fast_io_header.fast_io_write_union.union_.split.number_of_packets << std::endl;
				std::cout << "write_in_progress_flag = " << fast_io_section->fast_io_header.fast_io_write_union.union_.split.write_in_progress_flag << std::endl;
				std::cout << "read_in_progress_flag = " << fast_io_section->fast_io_header.read_in_progress_flag << std::endl;*/
				
				auto send_to_adapter_num = 0;
				auto send_to_mstcp_num = 0;

				for (size_t i = 0; i < fast_io_section->fast_io_header.fast_io_write_union.union_.split.number_of_packets; ++i)
				{
					// For the last packet wait the write completion
					while ((i == (fast_io_section->fast_io_header.fast_io_write_union.union_.split.number_of_packets - 1)) &&
						(fast_io_section->fast_io_header.fast_io_write_union.union_.split.write_in_progress_flag))
					{
						std::this_thread::yield();
					}

					auto packet_action = packet_action::pass;

					if ((filter_outgoing_packet_ != nullptr) && (fast_io_section->fast_io_packets[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
						packet_action = filter_outgoing_packet_(fast_io_section->fast_io_packets[i].m_qLink.Flink, fast_io_section->fast_io_packets[i]);

					if ((filter_incoming_packet_ != nullptr) && (fast_io_section->fast_io_packets[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						packet_action = filter_incoming_packet_(fast_io_section->fast_io_packets[i].m_qLink.Flink, fast_io_section->fast_io_packets[i]);

					// Place packet back into the flow if was allowed to
					if (packet_action == packet_action::pass)
					{
						if (fast_io_section->fast_io_packets[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							write_adapter_request[send_to_adapter_num] = &fast_io_section->fast_io_packets[i];
							++send_to_adapter_num;
						}
						else
						{
							write_mstcp_request[send_to_mstcp_num] = &fast_io_section->fast_io_packets[i];
							++send_to_mstcp_num;
						}
					}
				}

				if (send_to_adapter_num > 0)
				{
					/*std::cout << "Fast I/O " << send_to_adapter_num << " -> adapter" << std::endl;*/
					SendPacketsToAdaptersUnsorted(write_adapter_request, send_to_adapter_num, &sent_success);
					send_to_adapter_num = 0;
				}

				if (send_to_mstcp_num > 0)
				{
					/*std::cout << "Fast I/O " << send_to_mstcp_num << " -> MSTCP" << std::endl;*/
					SendPacketsToMstcpUnsorted(write_mstcp_request, send_to_mstcp_num, &sent_success);
					send_to_mstcp_num = 0;
				}

				fast_io_section->fast_io_header.fast_io_write_union.union_.join = 0;
				fast_io_section->fast_io_header.read_in_progress_flag = 0;
			}

			//
			// Retrieve packets from the queue if have any
			//
			[[maybe_unused]] auto wait_result = network_interfaces_[adapter_]->wait_event(INFINITE);

			[[maybe_unused]] auto reset_result = network_interfaces_[adapter_]->reset_event();

			DWORD packets_success = 0;

			if (is_running_ && ReadPacketsUnsorted(read_request, maximum_packet_block, &packets_success))
			{
				auto send_to_adapter_num = 0;
				auto send_to_mstcp_num = 0;

				std::cout << "Queue I/O " <<
					packets_success <<
					" packet(s)" << std::endl;

				for (size_t i = 0; i < packets_success; ++i)
				{
					auto packet_action = packet_action::pass;

					if ((filter_outgoing_packet_ != nullptr) && (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
						packet_action = filter_outgoing_packet_(packet_buffer[i].m_hAdapter, packet_buffer[i]);

					if ((filter_incoming_packet_ != nullptr) && (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE))
						packet_action = filter_incoming_packet_(packet_buffer[i].m_hAdapter, packet_buffer[i]);

					// Place packet back into the flow if was allowed to
					if (packet_action == packet_action::pass)
					{
						if (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
						{
							write_adapter_request[send_to_adapter_num] = &packet_buffer[i];
							++send_to_adapter_num;
						}
						else
						{
							write_mstcp_request[send_to_mstcp_num] = &packet_buffer[i];
							++send_to_mstcp_num;
						}
					}
				}

				if (send_to_adapter_num > 0)
				{
					/*std::cout << "Queue I/O " << send_to_adapter_num << " -> adapter" << std::endl;*/
					SendPacketsToAdaptersUnsorted(write_adapter_request, send_to_adapter_num, &sent_success);
					send_to_adapter_num = 0;
				}

				if (send_to_mstcp_num > 0)
				{
					/*std::cout << "Queue I/O " << send_to_mstcp_num << " -> MSTCP" << std::endl;*/
					SendPacketsToMstcpUnsorted(write_mstcp_request, send_to_mstcp_num, &sent_success);
					send_to_mstcp_num = 0;
				}
			}
		}
	}
}