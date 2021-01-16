#pragma once

namespace ndisapi
{
	// ********************************************************************************
	/// <summary>
	/// erase_if template for associative containers
	/// </summary>
	// ********************************************************************************
	template< typename ContainerT, class FwdIt, class Pr >
	void erase_if(ContainerT& items, FwdIt it, FwdIt last, Pr predicate)
	{
		for (; it != last; )
		{
			if (predicate(*it)) it = items.erase(it);
			else ++it;
		}
	}

	enum class log_level
	{
		none = 0,
		info = 1,
		debug = 2,
		all = 3,
	};

	enum class proxy_status
	{
		starting,
		started,
		stopping,
		stopped
	};
	
	template <typename T> class udp_proxy_server;

	template<typename T>
	class udp_proxy_socket
	{
		friend udp_proxy_server;
		
	public:
		using address_type_t = T;
		using negotiate_context_t = proxy::negotiate_context<T>;

		udp_proxy_socket(
			CNdisApi* ndis_api,
			const uint16_t local_port,
			address_type_t remote_peer_address,
			const uint16_t remote_peer_port,
			address_type_t original_peer_address,
			const uint16_t original_peer_port,
			std::unique_ptr<negotiate_context_t> negotiate_ctx)
			: ndis_api_(ndis_api),
		    local_port_(local_port),
			remote_peer_address_(remote_peer_address),
			remote_peer_port_(remote_peer_port),
			original_peer_address_(original_peer_address),
			original_peer_port_(original_peer_port),
			negotiate_ctx_(std::move(negotiate_ctx))
		{
			lock_ = std::make_unique<std::mutex>();
			
			using namespace std::chrono_literals;
			timeout_ = 300s;
		}

		udp_proxy_socket(const udp_proxy_socket& other) = delete;

		udp_proxy_socket(udp_proxy_socket&& other) noexcept
			: ndis_api_(other.ndis_api_),
		      local_port_(other.local_port_),
			  remote_peer_address_(std::move(other.remote_peer_address_)),
			  remote_peer_port_(other.remote_peer_port_),
			  original_peer_address_(std::move(other.original_peer_address_)),
			  original_peer_port_(other.original_peer_port_),
			  negotiate_ctx_(std::move(other.negotiate_ctx_)),
			  relay_started_(std::move(other.relay_started_)), timeout_(std::move(other.timeout_)),
			  lock_(std::move(other.lock_)),
			  to_remote_queue_(std::move(other.to_remote_queue_))
		{
		}

		udp_proxy_socket& operator=(const udp_proxy_socket& other) = delete;

		udp_proxy_socket& operator=(udp_proxy_socket&& other) noexcept
		{
			if (this == &other)
				return *this;
			ndis_api_ = other.ndis_api_;
			local_port_ = other.local_port_;
			remote_peer_address_ = std::move(other.remote_peer_address_);
			remote_peer_port_ = other.remote_peer_port_;
			original_peer_address_ = std::move(other.original_peer_address_);
			original_peer_port_ = other.original_peer_port_;
			negotiate_ctx_ = std::move(other.negotiate_ctx_);
			relay_started_ = std::move(other.relay_started_);
			timeout_ = std::move(other.timeout_);
			lock_ = std::move(other.lock_);
			to_remote_queue_ = std::move(other.to_remote_queue_);
			return *this;
		}

		virtual ~udp_proxy_socket() = default;

		size_t get_maximum_queue_size() const
		{
			return maximum_queue_size_;
		}

		void set_maximum_queue_size(const size_t maximum_queue_size)
		{
			maximum_queue_size_ = maximum_queue_size;
		}


		std::chrono::steady_clock::duration get_timeout() const
		{
			return timeout_;
		}

		void set_timeout(const std::chrono::steady_clock::duration timeout)
		{
			timeout_ = timeout;
		}


		T get_original_peer_address() const
		{
			return original_peer_address_;
		}

		uint16_t get_original_peer_port() const
		{
			return original_peer_port_;
		}

		// ********************************************************************************
		/// <summary>
		/// Attempts to negotiate credentials with remote peer and starts data relay
		/// </summary>
		/// <param name="adapter_handle">Associated ndisapi adapter handle </param>
		/// <param name="packet">First outgoing UDP packet on the wire</param>
		/// <returns>true is relay was started, false otherwise</returns>
		// ********************************************************************************
		bool start(HANDLE adapter_handle, INTERMEDIATE_BUFFER& packet)
		{
			const auto ether_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);

			timestamp_ = std::chrono::steady_clock::now();
			adapter_handle_ = adapter_handle;
			local_mac_address_ = net::mac_address (ether_header->h_source);
			remote_mac_address_ = net::mac_address(ether_header->h_dest);

			if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
			{
				if (ntohs(ether_header->h_proto) == ETH_P_IP)
				{
					const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

					if (ip_header->ip_p == IPPROTO_UDP)
					{
						const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);
						local_ip_address_ = ip_header->ip_src;
						local_udp_port_ = ntohs(udp_header->th_sport);
					}
				}
			}
			else if constexpr (std::is_same_v<address_type_t, net::ip_address_v6>)
			{
				if (ntohs(ether_header->h_proto) == ETH_P_IPV6)
				{
					const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_header + 1);
					auto [header, protocol] = net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

					if (protocol == IPPROTO_UDP)
					{
						const auto udp_header = reinterpret_cast<udphdr_ptr>(header);
						local_ip_address_ = ip_header->ip6_src;
						local_udp_port_ = ntohs(udp_header->th_sport);
					}
				}
			}
			
			if (remote_negotiate())
			{
				// if negotiate phase can be complete immediately (or not needed at all)
				// start data relay here
				return start_data_relay();
			}
			
			// otherwise start_data_relay should be called from process_in_packet
			return false;
		}

		// ********************************************************************************
		/// <summary>
		/// Called for incoming packets
		/// </summary>
		/// <param name="packet">network packet to process</param>
		/// <returns>action to be taken for the packet</returns>
		// ********************************************************************************
		packet_action process_in_packet(INTERMEDIATE_BUFFER& packet)
		{
			if (!relay_started_.load(std::memory_order_acquire))
			{
				return process_in_packet_internal(packet);
			}
			
			const auto ether_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);
			auto result = packet_action::pass;

			if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
			{
				if (ntohs(ether_header->h_proto) == ETH_P_IP)
				{
					const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

					if (ip_header->ip_p == IPPROTO_UDP)
					{
						const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);

						ip_header->ip_src = original_peer_address_;
						udp_header->th_sport = htons(original_peer_port_);

						result = process_in_packet_internal(packet);

						CNdisApi::RecalculateUDPChecksum(&packet);
						CNdisApi::RecalculateIPChecksum(&packet);
					}
				}
			}
			else if constexpr (std::is_same_v<address_type_t, net::ip_address_v6>)
			{
				if (ntohs(ether_header->h_proto) == ETH_P_IPV6)
				{
					const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_header + 1);
					auto [header, protocol] = net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

					if (protocol == IPPROTO_UDP)
					{
						const auto udp_header = reinterpret_cast<udphdr_ptr>(header);

						ip_header->ip6_src = original_peer_address_;
						udp_header->th_sport = htons(original_peer_port_);

						result = process_in_packet_internal(packet);

						net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);
					}
				}
			}

			timestamp_ = std::chrono::steady_clock::now();
			
			return result;
		}

		// ********************************************************************************
		/// <summary>
		/// Called for outgoing packets
		/// </summary>
		/// <param name="packet">network packet to process</param>
		/// <returns>action to be taken for the packet</returns>
		// ********************************************************************************
		packet_action process_out_packet(INTERMEDIATE_BUFFER& packet)
		{
			if(!relay_started_.load(std::memory_order_acquire))
			{
				std::lock_guard<std::mutex> lock(*lock_);
				if (maximum_queue_size_ > to_remote_queue_.size())
					to_remote_queue_.emplace_back(std::make_unique<INTERMEDIATE_BUFFER>(packet));

				// call packet processing but don't re-inject because packet is already queued
				process_out_packet_internal(packet);
				
				return packet_action::drop;
			}
			
			const auto ether_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);
			auto result = packet_action::pass;

			if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
			{
				if (ntohs(ether_header->h_proto) == ETH_P_IP)
				{
					const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

					if (ip_header->ip_p == IPPROTO_UDP)
					{
						const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);

						ip_header->ip_dst = remote_peer_address_;
						udp_header->th_dport = htons(remote_peer_port_);

						result = process_out_packet_internal(packet);

						CNdisApi::RecalculateUDPChecksum(&packet);
						CNdisApi::RecalculateIPChecksum(&packet);
					}
				}
			}
			else if constexpr (std::is_same_v<address_type_t, net::ip_address_v6>)
			{
				if (ntohs(ether_header->h_proto) == ETH_P_IPV6)
				{
					const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_header + 1);
					auto [header, protocol] = net::ipv6_helper::find_transport_header(ip_header, packet.m_Length - ETHER_HEADER_LENGTH);

					if (protocol == IPPROTO_UDP)
					{
						const auto udp_header = reinterpret_cast<udphdr_ptr>(header);

						ip_header->ip6_dst = remote_peer_address_;
						udp_header->th_dport = htons(remote_peer_port_);

						result = process_out_packet_internal(packet);

						net::ipv6_helper::recalculate_tcp_udp_checksum(&packet);
					}
				}
			}
			
			timestamp_ = std::chrono::steady_clock::now();
			
			return result;
		}

		virtual bool keep_alive(const std::chrono::steady_clock::time_point now)
		{
			if ((now - timestamp_) > timeout_)
				return false;
			
			return true;
		}

	protected:

		// ********************************************************************************
		/// <summary>
		/// Switches on the relay flag and processes all queued packets
		/// </summary>
		/// <returns>status of the operation</returns>
		// ********************************************************************************
		bool start_data_relay()
		{
			auto expected = false;
			
			if(relay_started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
			{
				std::lock_guard<std::mutex> lock(*lock_);
				
				std::for_each(to_remote_queue_.begin(), to_remote_queue_.end(), [this](auto&& packet)
				{
					ETH_REQUEST request = { adapter_handle_, packet.get() };
					if(packet_action::pass == process_out_packet(*packet.get()))
						ndis_api_->SendPacketToAdapter(&request);
				});

				// Clear the queues
				to_remote_queue_.clear();

				// Release memory from the queues
				to_remote_queue_.shrink_to_fit();
				
				return true;
			}

			return false;
		}
		
		// ********************************************************************************
		/// <summary>
		/// Generates an outgoing UDP packet associated with proxy session
		/// </summary>
		/// <param name="data">UDP payload adata pointer</param>
		/// <param name="length">length of the data</param>
		/// <returns>pointer to the generated INTERMEDIATE_BUFFER</returns>
		// ********************************************************************************
		std::unique_ptr<INTERMEDIATE_BUFFER> forge_outgoing_udp_packet(uint8_t* data, const size_t length) const
		{
			auto packet = std::make_unique<INTERMEDIATE_BUFFER>();

			const auto ether_hdr = reinterpret_cast<ether_header_ptr>(packet->m_IBuffer);
			memcpy_s(ether_hdr->h_dest, ETHER_ADDR_LENGTH, &remote_mac_address_[0], ETHER_ADDR_LENGTH);
			memcpy_s(ether_hdr->h_source, ETHER_ADDR_LENGTH, &local_mac_address_[0], ETHER_ADDR_LENGTH);

			if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
			{
				if (length > (MAX_ETHER_FRAME - sizeof(ether_header) - sizeof(iphdr) - sizeof(udphdr)))
					return nullptr;
				
				ether_hdr->h_proto = ETH_P_IP_NET;
				
				const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_hdr + 1);
				const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(uint32_t) * 5);

				// Copy data payload
				memcpy_s(reinterpret_cast<void*>(udp_header + 1),
					MAX_ETHER_FRAME - (sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr)),
					data,
					length
				);

				// Set new packet buffer length
				packet->m_Length =
					static_cast<unsigned long>(sizeof(ether_header) + // NOLINT(bugprone-misplaced-widening-cast)
						sizeof(uint32_t) * 5 + sizeof(udphdr) + length);

				ip_header->ip_v = 4;
				ip_header->ip_hl = 5;
				ip_header->ip_id = static_cast<uint16_t>(std::rand());
				ip_header->ip_p = IPPROTO_UDP;
				ip_header->ip_src = local_ip_address_;
				ip_header->ip_dst = remote_peer_address_;
				ip_header->ip_len = htons(static_cast<short>(packet->m_Length - sizeof(ether_header)));
				ip_header->ip_ttl = 128;
				
				udp_header->th_sport = htons(local_port_);
				udp_header->th_dport = htons(remote_peer_port_);
				udp_header->length = htons(
					static_cast<short>(packet->m_Length - sizeof(ether_header) - 4 * ip_header->ip_hl));
				
				// Recalculate checksum
				CNdisApi::RecalculateUDPChecksum(packet.get());
				CNdisApi::RecalculateIPChecksum(packet.get());
			}
			else if constexpr (std::is_same_v<address_type_t, net::ip_address_v6>)
			{
				if (length > (MAX_ETHER_FRAME - sizeof(ether_header) - sizeof(ipv6hdr) - sizeof(udphdr)))
					return nullptr;
				
				ether_hdr->h_proto = ETH_P_IPV6_NET;
				
				const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_hdr + 1);
				const auto udp_header = reinterpret_cast<udphdr_ptr>(ip_header + 1);

				// Copy data payload
				memcpy_s(reinterpret_cast<void*>(udp_header + 1),
					MAX_ETHER_FRAME - (sizeof(ether_header) + sizeof(ipv6hdr) + sizeof(udphdr)),
					data,
					length
				);

				// Set new packet buffer length
				packet->m_Length =
					static_cast<unsigned long>(sizeof(ether_header) + // NOLINT(bugprone-misplaced-widening-cast)
						sizeof(ipv6hdr) + sizeof(udphdr) + length);

				ip_header->ip6_v = 6;
				ip_header->ip6_len = htons(static_cast<short>(packet->m_Length - sizeof(ether_header) - sizeof(ipv6hdr)));
				ip_header->ip6_next = IPPROTO_UDP;
				ip_header->ip6_src = local_ip_address_;
				ip_header->ip6_dst = remote_peer_address_;
				ip_header->ip6_hops = 128;

				udp_header->th_sport = htons(local_port_);
				udp_header->th_dport = htons(remote_peer_port_);
				udp_header->length = htons(
					static_cast<short>(packet->m_Length - sizeof(ether_header) - sizeof(ipv6hdr)));

				// Recalculate checksum
				net::ipv6_helper::recalculate_tcp_udp_checksum(packet.get());
			}
			else
			{
				return nullptr;
			}

			return packet;
		}
		
		// ********************************************************************************
		/// <summary>
		/// Called for proxy specific negotiate/authenticate with remote proxy/host
		/// </summary>
		/// <returns>true is successful</returns>
		// ********************************************************************************
		virtual bool remote_negotiate()
		{
			return true;
		}

		// ********************************************************************************
		/// <summary>
		/// Called for proxy specific incoming packet processing
		/// </summary>
		/// <param name="packet">packet to process</param>
		/// <returns>action to be taken for the packet</returns>
		// ********************************************************************************
		virtual packet_action process_in_packet_internal(INTERMEDIATE_BUFFER& packet)
		{
			return packet_action::pass;
		}

		// ********************************************************************************
		/// <summary>
		/// Called for proxy specific outgoing packets processing
		/// </summary>
		/// <param name="packet">packet to process</param>
		/// <returns>action to be taken for the packet</returns>
		// ********************************************************************************
		virtual packet_action process_out_packet_internal(INTERMEDIATE_BUFFER& packet)
		{
			return packet_action::pass;
		}

		// ********************************************************************************
		/// <summary>
		/// Queries a pointer to the negotiate_context
		/// </summary>
		/// <returns> raw pointer to the negotiate_context</returns>
		// ********************************************************************************
		negotiate_context_t* get_negotiate_ctx() const
		{
			return negotiate_ctx_.get();
		}

		CNdisApi* ndis_api_;
		uint16_t local_port_;
		address_type_t remote_peer_address_;
		uint16_t remote_peer_port_;
		address_type_t original_peer_address_;
		uint16_t original_peer_port_;
		std::unique_ptr<negotiate_context_t> negotiate_ctx_;
		std::atomic_bool relay_started_{ false };

		std::chrono::steady_clock::time_point timestamp_{};
		HANDLE adapter_handle_{ nullptr };
		net::mac_address local_mac_address_{};
		net::mac_address remote_mac_address_{};
		address_type_t local_ip_address_{};
		uint16_t local_udp_port_{};

		size_t maximum_queue_size_{ 510 };
		std::chrono::steady_clock::duration timeout_;

		/// <summary>provides synchronization for the I/O operations</summary>
		std::unique_ptr<std::mutex> lock_;

		std::vector<std::unique_ptr<INTERMEDIATE_BUFFER>> to_remote_queue_;
	};

	template <typename T>
	class udp_proxy_server: public iphelper::network_config_info<udp_proxy_server<T>>
	{
		friend iphelper::network_config_info<udp_proxy_server<T>>;
		
	public:
		using negotiate_context_t = typename T::negotiate_context_t;
		using address_type_t = typename T::address_type_t;

		using query_remote_peer_t = std::tuple <address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>>(address_type_t, uint16_t, address_type_t, uint16_t);

		udp_proxy_server(const std::function<query_remote_peer_t> query_remote_peer_fn, address_type_t const& server_address,  void (*log_printer)(const char*), const log_level level)
			: query_remote_peer_{ query_remote_peer_fn }, command_server_address_{server_address}, log_printer_{ log_printer }, log_level_{ level }
			
		{
			lock_ = std::make_unique<std::shared_mutex>();
			set_packet_filter();
		}

		~udp_proxy_server()
		{
			stop();
		}


		udp_proxy_server(const udp_proxy_server& other) = delete;

		udp_proxy_server(udp_proxy_server&& other) noexcept
			: iphelper::network_config_info<udp_proxy_server<T>>(std::move(other)),
			  lock_(std::move(other.lock_)),
			  keep_alive_thread_(std::move(other.keep_alive_thread_)),
			  proxy_sockets_(std::move(other.proxy_sockets_)),
			  query_remote_peer_(std::move(other.query_remote_peer_)),
			  packet_filter_(std::move(other.packet_filter_)),
			  network_interfaces_(std::move(other.network_interfaces_)),
			  default_adapter_(std::move(other.default_adapter_)),
			  mtu_(other.mtu_),
			  if_index_(other.if_index_),
			  if_handle_(other.if_handle_),
			  command_server_address_(std::move(other.command_server_address_)),
			  log_printer_(std::move(other.log_printer_)),
			  log_level_(other.log_level_),
			  status_(other.status_.load()),
			  remote_address_(std::move(other.remote_address_))
		{
		}

		udp_proxy_server& operator=(const udp_proxy_server& other) = delete;

		udp_proxy_server& operator=(udp_proxy_server&& other) noexcept
		{
			if (this == &other)
				return *this;
			iphelper::network_config_info<udp_proxy_server<T>>::operator =(std::move(other));
			lock_ = std::move(other.lock_);
			keep_alive_thread_ = std::move(other.keep_alive_thread_);
			proxy_sockets_ = std::move(other.proxy_sockets_);
			query_remote_peer_ = std::move(other.query_remote_peer_);
			packet_filter_ = std::move(other.packet_filter_);
			network_interfaces_ = std::move(other.network_interfaces_);
			default_adapter_ = std::move(other.default_adapter_);
			mtu_ = other.mtu_;
			if_index_ = other.if_index_;
			if_handle_ = other.if_handle_;
			command_server_address_ = std::move(other.command_server_address_);
			log_printer_ = std::move(other.log_printer_);
			log_level_ = other.log_level_;
			status_ = other.status_.load();
			remote_address_ = std::move(other.remote_address_);
			return *this;
		}

		std::optional<proxy_status> start()
		{
			if (!this->iphelper::network_config_info<udp_proxy_server<T>>::set_notify_ip_interface_change())
			{
				print_log(log_level::info, "udp_proxy_server::start: set_notify_ip_interface_change has failed!");
			}
			
			return start_internal();
		}

		void stop()
		{
			if (!this->iphelper::network_config_info<udp_proxy_server<T>>::cancel_notify_ip_interface_change())
			{
				print_log(log_level::info, "udp_proxy_server::start: cancel_notify_ip_interface_change has failed!");
			}
			
			using namespace std::chrono_literals;

			while (status_ != proxy_status::stopped)
			{
				stop_internal();
				std::this_thread::sleep_for(1ms);
			}
		}

		std::vector<negotiate_context_t> query_current_sessions_ctx()
		{
			std::shared_lock<std::shared_mutex> lock(*lock_);
			std::vector<negotiate_context_t> result;
			result.reserve(proxy_sockets_.size());

			std::transform(proxy_sockets_.cbegin(), proxy_sockets_.cend(), std::back_inserter(result), [](auto&& e)
			{
				return *reinterpret_cast<negotiate_context_t*>(e.second->get_negotiate_ctx());
			});

			return result;
		}

	private:

		std::optional<proxy_status> start_internal()
		{
			auto expected = proxy_status::stopped;
			if (!status_.compare_exchange_strong(expected, proxy_status::starting))
				return {};

			if (!update_network_configuration())
			{
				status_ = proxy_status::stopped;
				return status_;
			}

			// start_internal keep-alive thread here
			keep_alive_thread_ = std::thread(&udp_proxy_server::keep_alive_thread, this);

			if (packet_filter_->start_filter(if_index_))
			{
				status_ = proxy_status::started;
			}
			else
			{
				status_ = proxy_status::stopped;
				
				if (keep_alive_thread_.joinable())
					keep_alive_thread_.join();
			}

			return status_;
		}

		std::optional<proxy_status> stop_internal()
		{
			auto expected = proxy_status::started;
			if (!status_.compare_exchange_strong(expected, proxy_status::stopping))
				return {};

			if (packet_filter_)
				packet_filter_->stop_filter();

			if (keep_alive_thread_.joinable())
				keep_alive_thread_.join();

			proxy_sockets_.clear();

			status_ = proxy_status::stopped;

			return status_;
		}

		void keep_alive_thread()
		{
			while (status_ == proxy_status::started)
			{
				{
					std::lock_guard<std::shared_mutex> lock(*lock_);
					erase_if(proxy_sockets_, proxy_sockets_.begin(), proxy_sockets_.end(), [now = std::chrono::steady_clock::now() ](auto&& socket)
					{
						return !socket.second->keep_alive(now);
					});
				}

				using namespace std::chrono_literals;
				std::this_thread::sleep_for(1000ms);
			}
		}

		void set_packet_filter()
		{
			packet_filter_ = std::make_unique<ndisapi::simple_packet_filter>(
				[this](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
				{
					auto packet_action = packet_action::pass;

					const auto ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

					if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
					{
						if (ntohs(ether_header->h_proto) == ETH_P_IP)
						{
							const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

							if (ip_header->ip_p == IPPROTO_UDP)
							{
								const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);

								std::shared_lock<std::shared_mutex> lock(*lock_);
								auto it = proxy_sockets_.find(ntohs(udp_header->th_dport));

								if (it != proxy_sockets_.end())
								{
									packet_action = it->second->process_in_packet(buffer);
								}
							}
						}
					}
					else if constexpr (std::is_same_v<address_type_t, net::ip_address_v6>)
					{
						if (ntohs(ether_header->h_proto) == ETH_P_IPV6)
						{
							const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_header + 1);
							auto [header, protocol] = net::ipv6_helper::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

							if (protocol == IPPROTO_UDP)
							{
								const auto udp_header = reinterpret_cast<udphdr_ptr>(header);

								std::shared_lock<std::shared_mutex> lock(*lock_);
								auto it = proxy_sockets_.find(ntohs(udp_header->th_dport));

								if (it != proxy_sockets_.end())
								{
									packet_action = it->second->process_in_packet(buffer);
								}
							}
						}
					}
					return packet_action;
				},
				[this](HANDLE adapter_handle, INTERMEDIATE_BUFFER& buffer)
				{
					auto packet_action = packet_action::pass;

					const auto ether_header = reinterpret_cast<ether_header_ptr>(buffer.m_IBuffer);

					if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
					{
						if (ntohs(ether_header->h_proto) == ETH_P_IP)
						{
							const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

							if (ip_header->ip_p == IPPROTO_UDP)
							{
								const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);

								std::shared_lock<std::shared_mutex> lock(*lock_);
								auto it = proxy_sockets_.find(ntohs(udp_header->th_sport));

								if ((it != proxy_sockets_.end()) &&
									(it->second->get_original_peer_address() == address_type_t(ip_header->ip_dst)) &&
									(it->second->get_original_peer_port() == ntohs(udp_header->th_dport)))
								{
									packet_action = it->second->process_out_packet(buffer);
								}
								else
								{
									lock.unlock();
									if (query_remote_peer_ != nullptr)
									{
										auto [address, port, context] = query_remote_peer_(ip_header->ip_src, ntohs(udp_header->th_sport), ip_header->ip_dst, ntohs(udp_header->th_dport));

										if (port != 0)
										{

											std::lock_guard<std::shared_mutex> guard_lock(*lock_);
											proxy_sockets_[ntohs(udp_header->th_sport)] =
												std::make_unique<T>(
													packet_filter_.get(),
													ntohs(udp_header->th_sport),
													address,
													port,
													ip_header->ip_dst,
													ntohs(udp_header->th_dport),
													std::move(context));

											proxy_sockets_[ntohs(udp_header->th_sport)]->start(if_handle_, buffer);
											packet_action = proxy_sockets_[ntohs(udp_header->th_sport)]->process_out_packet(buffer);
										}
									}
								}
							}
						}
					}
					else if constexpr (std::is_same_v<address_type_t, net::ip_address_v6>)
					{
						if (ntohs(ether_header->h_proto) == ETH_P_IPV6)
						{
							const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_header + 1);
							auto [header, protocol] = net::ipv6_helper::find_transport_header(ip_header, buffer.m_Length - ETHER_HEADER_LENGTH);

							if (protocol == IPPROTO_UDP)
							{
								const auto udp_header = reinterpret_cast<udphdr_ptr>(header);

								std::shared_lock<std::shared_mutex> lock(*lock_);
								auto it = proxy_sockets_.find(ntohs(udp_header->th_sport));

								if ((it != proxy_sockets_.end()) &&
									(it->second->get_original_peer_address() == address_type_t(ip_header->ip6_dst)) &&
									(it->second->get_original_peer_port() == ntohs(udp_header->th_dport)))
								{
									packet_action = it->second->process_out_packet(buffer);
								}
								else
								{
									lock.unlock();
									if (query_remote_peer_ != nullptr)
									{
										auto [address, port, context] = query_remote_peer_(ip_header->ip6_src, ntohs(udp_header->th_sport), ip_header->ip6_dst, ntohs(udp_header->th_dport));

										if (port != 0)
										{
											std::lock_guard<std::shared_mutex> guard_lock(*lock_);
											proxy_sockets_[ntohs(udp_header->th_sport)] =
												std::make_unique<T>(
													packet_filter_.get(),
													ntohs(udp_header->th_sport),
													address,
													port,
													ip_header->ip6_dst,
													ntohs(udp_header->th_dport),
													std::move(context));

											proxy_sockets_[ntohs(udp_header->th_sport)]->start(if_handle_, buffer);
											packet_action = proxy_sockets_[ntohs(udp_header->th_sport)]->process_out_packet(buffer);
										}
									}
								}
							}
						}
					}
					return packet_action;
				});
		}

		bool update_network_configuration()
		{
			if (!packet_filter_->reconfigure())
			{
				print_log(log_level::info, "udp_proxy_server::update_network_configuration: Failed to update WinpkFilter network interfaces");
			}

			auto& ndis_adapters = packet_filter_->get_interface_list();
			default_adapter_ = iphelper::network_config_info<udp_proxy_server>::get_best_interface(command_server_address_);

			if (!default_adapter_)
			{
				//log_printer_("wg_tunnel: Failed to figure out the route to the server \n");
				return false;
			}

			{
				std::ostringstream oss;
				oss << "udp_proxy_server::update_network_configuration: detected default interface " << default_adapter_->get_adapter_name() << std::endl;
				print_log(log_level::info, oss.str());
			}

			if (default_adapter_->get_if_type() != IF_TYPE_PPP)
			{
				// For non NDISWAN adapters we simply match the name
				auto it = std::find_if(ndis_adapters.cbegin(), ndis_adapters.cend(), [this](auto& ndis_adapter)
					{
						return (std::string::npos != ndis_adapter->get_internal_name().find(default_adapter_->get_adapter_name()));
					});

				if (it != ndis_adapters.cend())
				{
					if_index_ = it - ndis_adapters.begin();
					if_handle_ = (*it)->get_adapter();
					mtu_ = default_adapter_->get_mtu();
					return true;
				}
			}
			else
			{
				// For NDISWAN adapters we have to match by IP address information
				auto it = std::find_if(ndis_adapters.cbegin(), ndis_adapters.cend(), [this](auto& ndis_adapter)
					{
						if (auto wan_info = ndis_adapter->get_ras_links(); wan_info)
						{
							auto ras_it = std::find_if(wan_info->cbegin(), wan_info->cend(), [this](auto& ras_link)
								{
									return default_adapter_->has_address(ras_link.ip_address);
								});

							if (ras_it != wan_info->cend())
							{
								// Store the remote MAC address (as may have multiply RAS connections)
								remote_address_ = ras_it->remote_hw_address;
								return true;
							}
						}

						return false;
					});

				if (it != ndis_adapters.cend())
				{
					if_index_ = it - ndis_adapters.begin();
					if_handle_ = (*it)->get_adapter();
					mtu_ = default_adapter_->get_mtu();
					return true;
				}
			}

			{
				std::ostringstream oss;
				oss << "udp_proxy_server::update_network_configuration: Failed to find a matching WinpkFilter interface for the " << default_adapter_->get_adapter_name() << std::endl;
				print_log(log_level::info, oss.str());
			}
			
			return false;
		}
		
		void ip_interface_changed_callback(PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE notification_type)
		{
			auto adapter = iphelper::network_config_info<udp_proxy_server>::get_best_interface(command_server_address_);

			if (!adapter && (status_ != proxy_status::stopping) && (status_ != proxy_status::stopped))
			{
				if (stop_internal())
				{
					default_adapter_ = adapter;
					print_log(log_level::info, "udp_proxy_server::ip_interface_changed_callback: Internet is unreachable. Proxy is stopped.");
				}
				return;
			}

			if (*adapter == *default_adapter_ && adapter->is_same_address_info<false>(*default_adapter_))
			{
				// nothing has changed, no reaction needed
				return;
			}

			if (auto result = stop_internal(); result && (result.value() == proxy_status::stopped))
			{
				print_log(log_level::info, "udp_proxy_server::ip_interface_changed_callback: UDP proxy was stopped successfully.");
			}

			if (auto result = start_internal(); result && (result.value() == proxy_status::started))
			{
				print_log(log_level::info, "udp_proxy_server::ip_interface_changed_callback: UDP proxy was started successfully.");
			}
		}

		void print_log(const log_level level, std::string const& message) const
		{
			if((level < log_level_) && log_printer_)
			{
				log_printer_(message.c_str());
			}
		}
		
		/// <summary>guards proxy_sockets_ access</summary>
		std::unique_ptr<std::shared_mutex> lock_;

		/// <summary>keep alive thread object</summary>
		std::thread	keep_alive_thread_;

		/// <summary>maps local UDP port to proxy socket object</summary>
		std::unordered_map<uint16_t, std::unique_ptr<T>> proxy_sockets_;
		
		/// <summary>routine provided by the client to supply the information for proxy socket creation</summary>
		std::function<query_remote_peer_t> query_remote_peer_;

		/// <summary>packet filter object</summary>
		std::unique_ptr<ndisapi::simple_packet_filter> packet_filter_;

		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;

		/// <summary>filtered adapter</summary>
		std::optional<iphelper::network_adapter_info> default_adapter_{};

		/// <summary>default network interface MTU</summary>
		uint16_t mtu_{ MAX_ETHER_FRAME };
		
		/// <summary>default network interface adapter index</summary>
		size_t if_index_{};
		
		/// <summary>default network interface adapter handle</summary>
		HANDLE if_handle_{ nullptr };
		
		/// <summary>this address is used to figure out the default interface</summary>
		address_type_t command_server_address_;
		
		/// <summary>log printer</summary>
		std::function<void(const char*)> log_printer_{};
		
		/// <summary>logging level for the log printer</summary>
		log_level log_level_{ log_level::all };
		
		/// <summary>Current status of the proxy</summary>
		std::atomic<proxy_status> status_{ proxy_status::stopped };
		
		/// <summary>remote hardware address for the RAS connection</summary>
		std::optional<net::mac_address> remote_address_{};
	};
}


