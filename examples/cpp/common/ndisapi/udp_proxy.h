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
	
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Used to pass data required to negotiate connection to the remote proxy
	/// </summary>
	// --------------------------------------------------------------------------------
	template<typename T>
	struct negotiate_context
	{
		negotiate_context(const T& remote_address, const uint16_t remote_port)
			: remote_address(remote_address),
			remote_port(remote_port)
		{
		}

		virtual ~negotiate_context() = default;

		T remote_address;
		uint16_t remote_port;
	};

	template<typename T>
	class udp_proxy_socket
	{
	public:
		using address_type_t = T;
		using negotiate_context_t = negotiate_context<T>;

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
		/// <returns>true is packet was queued, false if packet was processed in place</returns>
		// ********************************************************************************
		bool process_in_packet(INTERMEDIATE_BUFFER& packet)
		{
			if (!relay_started_.load(std::memory_order_acquire))
			{
				return process_in_packet_internal(packet);
			}
			
			const auto ether_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);
			auto result = false;

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
		/// <returns>true is packet was queued, false if packet was processed in place</returns>
		// ********************************************************************************
		bool process_out_packet(INTERMEDIATE_BUFFER& packet)
		{
			if(!relay_started_.load(std::memory_order_acquire))
			{
				std::lock_guard<std::mutex> lock(lock_);
				if (maximum_queue_size_ > to_remote_queue_.size())
					to_remote_queue_.emplace_back(std::make_unique<INTERMEDIATE_BUFFER>(packet));

				// call packet processing but don't re-inject because packet is already queued
				process_out_packet_internal(packet);
				
				return true;
			}
			
			const auto ether_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);
			auto result = false;

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
				std::lock_guard<std::mutex> lock(lock_);
				
				std::for_each(to_remote_queue_.begin(), to_remote_queue_.end(), [this](auto&& packet)
				{
					ETH_REQUEST request = { adapter_handle_, packet.get() };
					if(!process_out_packet(*packet.get()))
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
		/// <returns>true if packet is pending, false if it was processed in place</returns>
		// ********************************************************************************
		virtual bool process_in_packet_internal(INTERMEDIATE_BUFFER& packet)
		{
			return false;
		}

		// ********************************************************************************
		/// <summary>
		/// Called for proxy specific outgoing packets processing
		/// </summary>
		/// <param name="packet">packet to process</param>
		/// <returns>true if packet is pending, false if it was processed in place</returns>
		// ********************************************************************************
		virtual bool process_out_packet_internal(INTERMEDIATE_BUFFER& packet)
		{
			return false;
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
		std::mutex lock_;

		std::vector<std::unique_ptr<INTERMEDIATE_BUFFER>> to_remote_queue_;
	};

	template <typename T>
	class udp_proxy_server: public CNdisApi
	{
		static constexpr size_t maximum_packet_block = 510;

	public:
		using negotiate_context_t = typename T::negotiate_context_t;
		using address_type_t = typename T::address_type_t;

		using query_remote_peer_t = std::tuple <address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>>(address_type_t, uint16_t, address_type_t, uint16_t);

		udp_proxy_server(const std::function<query_remote_peer_t> query_remote_peer_fn)
			: query_remote_peer_(query_remote_peer_fn)
		{
			initialize_network_interfaces();
		}

		~udp_proxy_server()
		{
			if (server_stopped_ == false)
				stop();
		}

		bool start(const size_t adapter)
		{
			if (server_stopped_ == false)
			{
				// already running
				return true;
			}

			server_stopped_ = false;

			adapter_ = adapter;

			keep_alive_thread_ = std::thread(&udp_proxy_server::keep_alive_thread, this);
			proxy_thread_ = std::thread(&udp_proxy_server::server_thread, this);

			return true;
		}

		void stop()
		{
			if (server_stopped_ == true)
			{
				// already stopped
				return;
			}

			server_stopped_ = true;

			[[maybe_unused]] auto result = network_interfaces_[adapter_]->signal_event();

			if (proxy_thread_.joinable())
				proxy_thread_.join();

			if (keep_alive_thread_.joinable())
				keep_alive_thread_.join();

			proxy_sockets_.clear();
		}

		std::vector<std::string> get_interface_list()
		{
			std::vector<std::string> result;
			result.reserve(network_interfaces_.size());

			for (auto&& e : network_interfaces_)
			{
				result.push_back(e->get_friendly_name());
			}

			return result;
		}

	private:

		void initialize_network_interfaces()
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
						std::string(friendly_name.data())));
			}
		}

		void keep_alive_thread()
		{
			while (server_stopped_ == false)
			{
				{
					std::lock_guard<std::shared_mutex> lock(lock_);
					erase_if(proxy_sockets_, proxy_sockets_.begin(), proxy_sockets_.end(), [now = std::chrono::steady_clock::now() ](auto&& socket)
					{
						return !socket.second->keep_alive(now);
					});
				}

				using namespace std::chrono_literals;
				std::this_thread::sleep_for(1000ms);
			}
		}

		void server_thread()
		{
			const auto packet_buffer =
				std::make_unique<INTERMEDIATE_BUFFER[]>(maximum_packet_block);

			//
			// Initialize Requests
			//

			using request_storage_type_t = std::aligned_storage_t<sizeof(ETH_M_REQUEST) +
				sizeof(NDISRD_ETH_Packet) * (maximum_packet_block - 1), 0x1000>;

			// 1. Allocate memory using unique_ptr for auto-delete on thread exit
			const auto read_request_ptr = std::make_unique<request_storage_type_t>();
			const auto write_adapter_request_ptr = std::make_unique<request_storage_type_t>();
			const auto write_mstcp_request_ptr = std::make_unique<request_storage_type_t>();

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
			ZeroMemory(packet_buffer.get(), sizeof(INTERMEDIATE_BUFFER) * maximum_packet_block);

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

			while (!server_stopped_)
			{
				[[maybe_unused]] auto wait_result = network_interfaces_[adapter_]->wait_event(INFINITE);

				[[maybe_unused]] auto reset_result = network_interfaces_[adapter_]->reset_event();

				while (!server_stopped_ && ReadPackets(read_request))
				{
					for (size_t i = 0; i < read_request->dwPacketsSuccess; ++i)
					{
						auto packet_action = false;

						const auto ether_header = reinterpret_cast<ether_header_ptr>(packet_buffer[i].m_IBuffer);

						if constexpr (std::is_same_v<address_type_t, net::ip_address_v4>)
						{
							if (ntohs(ether_header->h_proto) == ETH_P_IP)
							{
								const auto ip_header = reinterpret_cast<iphdr_ptr>(ether_header + 1);

								if (ip_header->ip_p == IPPROTO_UDP)
								{
									const auto udp_header = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) * ip_header->ip_hl);

									if (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
									{
										std::shared_lock<std::shared_mutex> lock(lock_);
										auto it = proxy_sockets_.find(ntohs(udp_header->th_sport));

										if((it != proxy_sockets_.end()) &&
											(it->second->get_original_peer_address() == address_type_t(ip_header->ip_dst)) &&
											(it->second->get_original_peer_port() == ntohs(udp_header->th_dport)))
										{
											packet_action = it->second->process_out_packet(packet_buffer[i]);
										}
										else
										{
											lock.unlock();
											if(query_remote_peer_ != nullptr)
											{
												auto [address, port, context] = query_remote_peer_(ip_header->ip_src, ntohs(udp_header->th_sport), ip_header->ip_dst, ntohs(udp_header->th_dport));

												if(port != 0)
												{
													
													std::lock_guard<std::shared_mutex> guard_lock(lock_);
													proxy_sockets_[ntohs(udp_header->th_sport)] = 
														std::make_unique<T>(
															this, 
															ntohs(udp_header->th_sport),
															address,
															port,
															ip_header->ip_dst,
															ntohs(udp_header->th_dport),
															std::move(context));
													
													proxy_sockets_[ntohs(udp_header->th_sport)]->start(network_interfaces_[adapter_]->get_adapter(), packet_buffer[i]);
													packet_action = proxy_sockets_[ntohs(udp_header->th_sport)]->process_out_packet(packet_buffer[i]);
												}
											}
										}
									}
									else
									{
										std::shared_lock<std::shared_mutex> lock(lock_);
										auto it = proxy_sockets_.find(ntohs(udp_header->th_dport));

										if (it != proxy_sockets_.end())
										{
											packet_action = it->second->process_in_packet(packet_buffer[i]);
										}
									}
								}
							}
						}
						else if constexpr(std::is_same_v<address_type_t, net::ip_address_v6>)
						{
							if (ntohs(ether_header->h_proto) == ETH_P_IPV6)
							{
								const auto ip_header = reinterpret_cast<ipv6hdr_ptr>(ether_header + 1);
								auto [header, protocol] = net::ipv6_helper::find_transport_header(ip_header, packet_buffer[i].m_Length - ETHER_HEADER_LENGTH);

								if (protocol == IPPROTO_UDP)
								{
									const auto udp_header = reinterpret_cast<udphdr_ptr>(header);

									if (packet_buffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
									{
										std::shared_lock<std::shared_mutex> lock(lock_);
										auto it = proxy_sockets_.find(ntohs(udp_header->th_sport));

										if ((it != proxy_sockets_.end()) &&
											(it->second->get_original_peer_address() == address_type_t(ip_header->ip6_dst)) &&
											(it->second->get_original_peer_port() == ntohs(udp_header->th_dport)))
										{
											packet_action = it->second->process_out_packet(packet_buffer[i]);
										}
										else
										{
											lock.unlock();
											if (query_remote_peer_ != nullptr)
											{
												auto [address, port, context] = query_remote_peer_(ip_header->ip6_src, ntohs(udp_header->th_sport), ip_header->ip6_dst, ntohs(udp_header->th_dport));

												if (port != 0)
												{
													std::lock_guard<std::shared_mutex> guard_lock(lock_);
													proxy_sockets_[ntohs(udp_header->th_sport)] =
														std::make_unique<T>(
															this,
															ntohs(udp_header->th_sport),
															address,
															port,
															ip_header->ip6_dst,
															ntohs(udp_header->th_dport),
															std::move(context));

													proxy_sockets_[ntohs(udp_header->th_sport)]->start(network_interfaces_[adapter_]->get_adapter(), packet_buffer[i]);
													packet_action = proxy_sockets_[ntohs(udp_header->th_sport)]->process_out_packet(packet_buffer[i]);
												}
											}
										}
									}
									else
									{
										std::shared_lock<std::shared_mutex> lock(lock_);
										auto it = proxy_sockets_.find(ntohs(udp_header->th_dport));

										if (it != proxy_sockets_.end())
										{
											packet_action = it->second->process_in_packet(packet_buffer[i]);
										}
									}
								}
							}
						}

						// Place packet back into the flow if was allowed to
						if (packet_action == false)
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

		std::shared_mutex lock_;

		std::thread proxy_thread_;
		std::thread	keep_alive_thread_;

		std::unordered_map<uint16_t, std::unique_ptr<T>> proxy_sockets_;

		/// <summary>set to true on proxy termination</summary>
		std::atomic_bool server_stopped_{ true };			
		
		std::function<query_remote_peer_t> query_remote_peer_;

		/// <summary>list of available network interfaces</summary>
		std::vector<std::unique_ptr<network_adapter>> network_interfaces_;

		/// <summary>filtered adapter index</summary>
		size_t adapter_{ 0 };
	};
}


