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
	inline constexpr size_t fast_io_section_count = 4;
	inline constexpr size_t fast_io_physical_packets =
		(fast_io_size - sizeof(FAST_IO_SECTION_HEADER)) / sizeof(INTERMEDIATE_BUFFER);
	inline constexpr uint32_t fast_io_packets_num = static_cast<uint32_t>(
		fast_io_physical_packets < 65535 ? fast_io_physical_packets : 65535);
	// The worker can consume every section before routing the collected packets.
	// Packet storage and both send-pointer arrays must use this same bound.
	inline constexpr size_t maximum_packet_block = fast_io_section_count * fast_io_packets_num;

	// --------------------------------------------------------------------------------
	/// <summary>
	/// simple winpkfilter based filter class for quick prototyping 
	/// </summary>
	// --------------------------------------------------------------------------------
	class fastio_packet_filter final : public CNdisApi
	{
	public:
		enum class packet_action
		{
			pass,
			drop,
			revert
		};

	private:
		using request_storage_type_t = std::aligned_storage_t<
			sizeof(PINTERMEDIATE_BUFFER) * maximum_packet_block, 0x1000>;
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
		~fastio_packet_filter() override { stop_filter(); }

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
		template <typename F1, typename F2>
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

		// ********************************************************************************
		/// <summary>
		/// Returns current filter state
		/// </summary>
		/// <returns>current filter state</returns>
		// ********************************************************************************
		[[nodiscard]] filter_state get_filter_state() const
		{
			return filter_state_.load();
		}

	private:
		// ********************************************************************************
		/// <summary>
		/// Working thread routine
		/// </summary>
		// ********************************************************************************
		void filter_working_thread();
		// Consume one section only after copying a complete, bounded snapshot.
		// A zero result leaves any unconsumed write state intact.
		DWORD read_fast_io_section(PFAST_IO_SECTION section, PINTERMEDIATE_BUFFER packets, size_t capacity);
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
		size_t adapter_{0};
		/// <summary>specifies if sleep should be used on polling fas I/O</summary>
		bool wait_on_poll_{false};
		/// <summary>array of INTERMEDIATE_BUFFER structures</summary>
		std::unique_ptr<INTERMEDIATE_BUFFER[]> packet_buffer_;
		/// <summary>driver request for writing packets to adapter</summary>
		std::unique_ptr<request_storage_type_t> write_adapter_request_ptr_;
		/// <summary>driver request for writing packets up to protocol stack</summary>
		std::unique_ptr<request_storage_type_t> write_mstcp_request_ptr_;
		/// <summary>shared fast i/o memory</summary>
		std::unique_ptr<fast_io_storage_type_t[]> fast_io_ptr_;
		// Close the registration handle before backing storage, including member destruction.
		std::unique_ptr<CNdisApi> registration_owner_;
		bool packet_event_registered_{false};
		bool adapter_mode_set_{false};
	};

	inline bool fastio_packet_filter::init_filter()
	{
		// A fresh file object owns only this start's shared-memory registrations.
		registration_owner_ = std::make_unique<CNdisApi>();
		if (!registration_owner_->IsDriverLoaded())
			return false;

		packet_buffer_ = std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);
		write_adapter_request_ptr_ = std::make_unique<request_storage_type_t>();
		write_mstcp_request_ptr_ = std::make_unique<request_storage_type_t>();
		fast_io_ptr_ = std::make_unique<fast_io_storage_type_t[]>(fast_io_section_count);

		if (wait_on_poll_)
		{
			if (!network_interfaces_[adapter_]->set_packet_event())
				return false;
			packet_event_registered_ = true;
		}

		auto fast_io_section = reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[0]);
		if (!registration_owner_->InitializeFastIo(fast_io_section, fast_io_size))
			return false;

		for (size_t i = 1; i < fast_io_section_count; ++i)
		{
			fast_io_section = reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[i]);
			if (!registration_owner_->AddSecondaryFastIo(fast_io_section, fast_io_size))
				return false;
		}

		ADAPTER_MODE mode{network_interfaces_[adapter_]->get_adapter(),
			MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL};
		if (!SetAdapterMode(&mode))
			return false;
		adapter_mode_set_ = true;
		return true;
	}

	inline void fastio_packet_filter::release_filter()
	{
		// Only undo adapter setup acquired by this start. release() also wakes the worker.
		if (adapter_mode_set_)
		{
			network_interfaces_[adapter_]->release();
			adapter_mode_set_ = false;
		}

		if (working_thread_.joinable())
			working_thread_.join();

		if (packet_event_registered_)
		{
			SetPacketEvent(network_interfaces_[adapter_]->get_adapter(), nullptr);
			packet_event_registered_ = false;
		}

		// Driver close removes the owned mappings before their backing storage is freed.
		registration_owner_.reset();
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

		try
		{
			if (init_filter())
			{
				// Publish before the worker can execute; the worker never changes lifecycle state.
				filter_state_ = filter_state::running;
				working_thread_ = std::thread(&fastio_packet_filter::filter_working_thread, this);
				return true;
			}
		}
		catch (const std::bad_alloc&)
		{
		}
		catch (const std::system_error&)
		{
		}

		filter_state_ = filter_state::stopping;
		release_filter();
		filter_state_ = filter_state::stopped;
		return false;
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
		TCP_AdapterList ad_list;
		std::vector<char> friendly_name(MAX_PATH * 4);

		if (!GetTcpipBoundAdaptersInfo(&ad_list))
			return;

		for (size_t i = 0; i < ad_list.m_nAdapterCount; ++i)
		{
			ConvertWindows2000AdapterName(reinterpret_cast<const char*>(ad_list.m_szAdapterNameList[i]),
			                              friendly_name.data(), static_cast<DWORD>(friendly_name.size()));

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

	inline DWORD fastio_packet_filter::read_fast_io_section(
		PFAST_IO_SECTION section, PINTERMEDIATE_BUFFER packets, const size_t capacity)
	{
		auto& header = section->fast_io_header;
		if (filter_state_ != filter_state::running ||
			!InterlockedCompareExchange(&header.fast_io_write_union.union_.join, 0, 0))
			return 0;

		InterlockedExchange(&header.read_in_progress_flag, 1);
		struct reader_claim_guard
		{
			volatile DWORD& flag;
			~reader_claim_guard() { InterlockedExchange(&flag, 0); }
		} claim{header.read_in_progress_flag};

		size_t copied = 0;
		while (filter_state_ == filter_state::running)
		{
			FAST_IO_WRITE_UNION snapshot{};
			snapshot.union_.join = InterlockedCompareExchange(&header.fast_io_write_union.union_.join, 0, 0);
			const size_t count = snapshot.union_.split.number_of_packets;
			// Repeat all bounds after a failed reset CAS: its successor may have grown.
			if (count > fast_io_packets_num || count > capacity || count < copied)
				return 0;
			if (snapshot.union_.split.write_in_progress_flag)
				continue;

			if (count > copied)
			{
				memmove(packets + copied, &section->fast_io_packets[copied],
					sizeof(INTERMEDIATE_BUFFER) * (count - copied));
				copied = count;
			}
			if (filter_state_ != filter_state::running)
				return 0;

			// A writer may have passed its reader-flag check before our claim.
			// On contention, wait for completion and copy its entire new tail.
			if (InterlockedCompareExchange(&header.fast_io_write_union.union_.join, 0,
				snapshot.union_.join) == snapshot.union_.join)
				return static_cast<DWORD>(copied);
		}
		return 0;
	}

	inline void fastio_packet_filter::filter_working_thread()
	{
		using namespace std::chrono_literals;


		DWORD sent_success = 0;
		DWORD fast_io_packets_success = 0;

		auto* const write_adapter_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_adapter_request_ptr_.get());
		auto* const write_mstcp_request = reinterpret_cast<PINTERMEDIATE_BUFFER*>(write_mstcp_request_ptr_.get());


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

			for (size_t i = 0; i < fast_io_section_count; ++i)
			{
				auto* section = reinterpret_cast<PFAST_IO_SECTION>(&fast_io_ptr_.get()[i]);
				fast_io_packets_success += read_fast_io_section(section,
					&packet_buffer_[fast_io_packets_success], maximum_packet_block - fast_io_packets_success);
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

				if (packet_buffer_[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
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
