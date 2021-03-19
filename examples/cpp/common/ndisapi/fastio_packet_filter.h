// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  fastio_packet_filter.h 
/// Abstract: Simple packet filter class declaration
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

namespace ndisapi
{
	inline constexpr size_t fast_io_size = 0x300000;
	inline constexpr uint32_t fast_io_packets_num = (fast_io_size - sizeof(FAST_IO_SECTION_HEADER)) / sizeof(INTERMEDIATE_BUFFER);
	inline constexpr size_t maximum_packet_block = 2048 * 3;

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
	class fastio_packet_filter final : public CNdisApi
	{
		using request_storage_type_t = std::aligned_storage_t<sizeof(PINTERMEDIATE_BUFFER)* maximum_packet_block, 0x1000>;
		using fast_io_storage_type_t = std::aligned_storage_t<fast_io_size, 0x1000>;

		enum class filter_state
		{
			stopped,
			starting,
			running,
			stopping
		};
		
		explicit fastio_packet_filter(const bool wait_on_poll = false) :
		wait_on_poll_(wait_on_poll) 
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
		fastio_packet_filter(F1 in, F2 out, const bool sleep_on_poll = false): 
		fastio_packet_filter(sleep_on_poll)
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
		/// <summary>specifies if sleep should be used on polling fas I/O</summary>
		bool wait_on_poll_{ false };
		/// <summary>array of INTERMEDIATE_BUFFER structures</summary>
		std::unique_ptr<INTERMEDIATE_BUFFER[]> packet_buffer_;
		/// <summary>driver request for writing packets to adapter</summary>
		std::unique_ptr<request_storage_type_t> write_adapter_request_ptr_;
		/// <summary>driver request for writing packets up to protocol stack</summary>
		std::unique_ptr<request_storage_type_t> write_mstcp_request_ptr_;
		/// <summary>shared fast i/o memory</summary>
		std::unique_ptr<fast_io_storage_type_t[]> fast_io_ptr_;
	};

	inline bool fastio_packet_filter::init_filter()
	{
		try
		{
			packet_buffer_ = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

			write_adapter_request_ptr_ = std::make_unique<request_storage_type_t>();
			write_mstcp_request_ptr_ = std::make_unique<request_storage_type_t>();
			fast_io_ptr_ = std::make_unique<fast_io_storage_type_t[]>(4);
		}
		catch (const std::bad_alloc&)
		{
			return false;
		}

		//
		// Set events for helper driver
		//
		if (!network_interfaces_[adapter_]->set_packet_event())
		{
			packet_buffer_.reset();
			write_adapter_request_ptr_.reset();
			write_mstcp_request_ptr_.reset();
			fast_io_ptr_.reset();
			
			return false;
		}
		
		auto fast_io_section = reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[0]);

		if (!InitializeFastIo(fast_io_section, fast_io_size))
		{
			packet_buffer_.reset();
			write_adapter_request_ptr_.reset();
			write_mstcp_request_ptr_.reset();
			fast_io_ptr_.reset();
			
			return false;
		}

		for (auto i = 1; i < 4; ++i)
		{
			fast_io_section = reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[i]);

			if (!AddSecondaryFastIo(fast_io_section, fast_io_size))
			{
				packet_buffer_.reset();
				write_adapter_request_ptr_.reset();
				write_mstcp_request_ptr_.reset();
				fast_io_ptr_.reset();

				return false;
			}
		}
		
		network_interfaces_[adapter_]->set_mode(MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL);

		return true;
	}

	inline void fastio_packet_filter::release_filter()
	{
		network_interfaces_[adapter_]->release();

		// Wait for working thread to exit
		if (working_thread_.joinable())
			working_thread_.join();

		packet_buffer_.reset();
		write_adapter_request_ptr_.reset();
		write_mstcp_request_ptr_.reset();
		fast_io_ptr_.reset();
	}

	inline bool fastio_packet_filter::reconfigure()
	{
		if (filter_state_ != filter_state::stopped)
			return false;

		network_interfaces_.clear();

		initialize_network_interfaces();

		return true;
	}

	inline bool fastio_packet_filter::start_filter(const size_t adapter)
	{
		if (filter_state_ != filter_state::stopped)
			return false;

		filter_state_ = filter_state::starting;

		adapter_ = adapter;

		if (init_filter())
			working_thread_ = std::thread(&fastio_packet_filter::filter_working_thread, this);
		else
			return false;

		return true;
	}

	inline bool fastio_packet_filter::stop_filter()
	{
		if (filter_state_ != filter_state::running)
			return false;

		filter_state_ = filter_state::stopping;

		release_filter();

		filter_state_ = filter_state::stopped;

		return true;
	}

	inline std::vector<std::string> fastio_packet_filter::get_interface_names_list() const
	{
		std::vector<std::string> result;
		result.reserve(network_interfaces_.size());

		for (auto&& e : network_interfaces_)
		{
			result.push_back(e->get_friendly_name());
		}

		return result;
	}

	inline const std::vector<std::unique_ptr<network_adapter>>& fastio_packet_filter::get_interface_list() const
	{
		return network_interfaces_;
	}

	inline void fastio_packet_filter::initialize_network_interfaces()
	{
		TCP_AdapterList			ad_list;
		std::vector<char>		friendly_name(MAX_PATH * 4);

		if (!GetTcpipBoundAdaptersInfo(&ad_list))
			return;

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]), friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

			network_interfaces_.push_back(
				std::make_unique<network_adapter>(
					this,
					ad_list.m_nAdapterHandle[i],
					ad_list.m_czCurrentAddress[i],
					std::string(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i])),
					std::string(friendly_name.data()),
					ad_list.m_nAdapterMediumList[i],
					ad_list.m_usMTU[i]));
		}
	}

	inline void fastio_packet_filter::filter_working_thread()
	{		
		using namespace std::chrono_literals;

		filter_state_ = filter_state::running;
		
		DWORD sent_success = 0;
		DWORD fast_io_packets_success = 0;

		auto* const write_adapter_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_adapter_request_ptr_.get());
		auto* const write_mstcp_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_mstcp_request_ptr_.get());

		const PFAST_IO_SECTION fast_io_section[] = {
			reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[0]),
			reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[1]),
			reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[2]),
			reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[3]),
		};

#ifdef FAST_IO_MEASURE_STATS
		uint64_t fast_io_packets_total = 0;
		uint64_t queued_io_packets_total = 0;
		uint64_t fast_io_reads_total = 0;
		uint64_t queued_io_reads_total = 0;
#endif //FAST_IO_MEASURE_STATS
		
		while (filter_state_ == filter_state::running)
		{
			//
			// Fast I/O processing section
			//
						
			for (auto i : fast_io_section)
			{
				if (InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0, 0))
				{
					InterlockedExchange(&i->fast_io_header.read_in_progress_flag, 1);

					auto write_union = InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0, 0);

					auto current_packets_success = reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.number_of_packets;

					//
					// Copy packets and reset section
					//

					memmove(&packet_buffer_[fast_io_packets_success], &i->fast_io_packets[0], sizeof(INTERMEDIATE_BUFFER) * (current_packets_success - 1));

					// For the last packet(s) wait the write completion if in progress
					write_union = InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0, 0);

					while (reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.write_in_progress_flag)
					{
						write_union = InterlockedCompareExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0, 0);
					}

					// Copy the last packet(s)
					memmove(&packet_buffer_[static_cast<uint64_t>(fast_io_packets_success) + current_packets_success - 1], &
					        i->fast_io_packets[current_packets_success - 1], sizeof(INTERMEDIATE_BUFFER));
					if (current_packets_success < reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.number_of_packets)
					{
						current_packets_success = reinterpret_cast<PFAST_IO_WRITE_UNION>(&write_union)->union_.split.number_of_packets;
						memmove(&packet_buffer_[static_cast<uint64_t>(fast_io_packets_success) + current_packets_success - 1], &
						        i->fast_io_packets[current_packets_success - 1], sizeof(INTERMEDIATE_BUFFER));
					}

					InterlockedExchange(&i->fast_io_header.fast_io_write_union.union_.join, 0);
					InterlockedExchange(&i->fast_io_header.read_in_progress_flag, 0);

					fast_io_packets_success += current_packets_success;
				}
			}

			auto send_to_adapter_num = 0;
			auto send_to_mstcp_num = 0;

#ifdef FAST_IO_MEASURE_STATS
			fast_io_packets_total += static_cast<uint64_t>(fast_io_packets_success);
			++fast_io_reads_total;
#endif //FAST_IO_MEASURE_STATS

			for (uint32_t i = 0; i < fast_io_packets_success; ++i)
			{
				auto packet_action = packet_action::pass;

				if(packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				{
					if (filter_outgoing_packet_ != nullptr)
						packet_action = filter_outgoing_packet_(packet_buffer_[i].m_hAdapter, packet_buffer_[i]);
				}
				else
				{
					if (filter_incoming_packet_ != nullptr)
						packet_action = filter_incoming_packet_(packet_buffer_[i].m_hAdapter, packet_buffer_[i]);
				}

				// Place packet back into the flow if was allowed to
				if (packet_action == packet_action::pass)
				{
					if (packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
					{
						write_adapter_request[send_to_adapter_num] = &packet_buffer_[i];
						++send_to_adapter_num;
					}
					else
					{
						write_mstcp_request[send_to_mstcp_num] = &packet_buffer_[i];
						++send_to_mstcp_num;
					}
				}
				else if (packet_action == packet_action::revert)
				{
					if (packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
					{
						write_adapter_request[send_to_adapter_num] = &packet_buffer_[i];
						++send_to_adapter_num;
					}
					else
					{
						write_mstcp_request[send_to_mstcp_num] = &packet_buffer_[i];
						++send_to_mstcp_num;
					}
				}
			}

			if (send_to_adapter_num > 0)
			{
				SendPacketsToAdaptersUnsorted(write_adapter_request, send_to_adapter_num, &sent_success);
			}

			if (send_to_mstcp_num > 0)
			{
				SendPacketsToMstcpUnsorted(write_mstcp_request, send_to_mstcp_num, &sent_success);
			}

			if (fast_io_packets_success == 0 && wait_on_poll_)
			{
				auto [[maybe_unused]] result = network_interfaces_[adapter_]->wait_event(INFINITE);
				result = network_interfaces_[adapter_]->reset_event();
			}

			fast_io_packets_success = 0;
		}

#ifdef FAST_IO_MEASURE_STATS
		std::cout << "fast_io_packets_total = " << fast_io_packets_total << std::endl;
		std::cout << "fast_io_reads_total = " << fast_io_reads_total << std::endl;
		std::cout << "queued_io_packets_total = " << queued_io_packets_total << std::endl;
		std::cout << "queued_io_reads_total = " << queued_io_reads_total << std::endl;
		std::cout << "queued_io_reads_total/reads_total = " << static_cast<double>(queued_io_reads_total) / (fast_io_reads_total + queued_io_reads_total) * 100 << "%" << std::endl;
		std::cout << "queued_io_packets_total/packets_total = " << static_cast<double>(queued_io_packets_total) / (fast_io_packets_total + queued_io_packets_total) * 100 << "%" << std::endl;
#endif //FAST_IO_MEASURE_STATS
	}
}