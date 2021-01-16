#pragma once
namespace proxy
{
	template <typename T>
	class tcp_proxy_server
	{
		constexpr static size_t connections_array_size = 64;

	public:
		using negotiate_context_t = typename T::negotiate_context_t;
		using address_type_t = typename T::address_type_t;
		using per_io_context_t = typename T::per_io_context_t;

		using query_remote_peer_t = std::tuple <address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>> (address_type_t, uint16_t);

		tcp_proxy_server(const uint16_t proxy_port, winsys::io_completion_port& completion_port, const std::function<query_remote_peer_t> query_remote_peer_fn)
			: proxy_port_(proxy_port),
			  completion_port_(completion_port),
			  query_remote_peer_(query_remote_peer_fn)
		{
		}

		~tcp_proxy_server()
		{
			if (end_server_ == false)
				stop();
		}

		bool start()
		{
			if(end_server_ == false)
			{
				// already running
				return true;
			}

			if (!create_server_socket())
			{
				return false;
			}

			end_server_ = false;

			sock_array_events_.reserve(connections_array_size);

			sock_array_events_.push_back(std::make_tuple(WSACreateEvent(),
			                                             WSASocket(address_type_t::af_type, SOCK_STREAM,
			                                                       IPPROTO_TCP, nullptr, 0,
			                                                       WSA_FLAG_OVERLAPPED), INVALID_SOCKET, nullptr));

			if(std::get<1>(sock_array_events_[0]) != INVALID_SOCKET)
			{
				auto [status, io_key] = completion_port_.associate_socket(
					std::get<1>(sock_array_events_[0]),
					[this](const DWORD num_bytes, OVERLAPPED* povlp, const BOOL status)
				{
					if (end_server_)
						return false;

					auto io_context = static_cast<per_io_context_t*>(povlp);

					if (!status || (status && (num_bytes == 0)))
					{
						if ((io_context->io_operation == proxy_io_operation::relay_io_read) ||
							(io_context->io_operation == proxy_io_operation::negotiate_io_read))
						{
							io_context->proxy_socket_ptr->close_client<false>(true, io_context->is_local);
							return false;
						}

						if (!status)
						{
							io_context->proxy_socket_ptr->close_client<false>(false, io_context->is_local);
							return false;
						}
					}

					switch (io_context->io_operation)
					{
					case proxy_io_operation::relay_io_read:
						io_context->proxy_socket_ptr->process_receive_buffer_complete(num_bytes, io_context);
						break;

					case proxy_io_operation::relay_io_write:
						io_context->proxy_socket_ptr->process_send_buffer_complete(num_bytes, io_context);
						break;

					case proxy_io_operation::negotiate_io_read:
						io_context->proxy_socket_ptr->process_receive_negotiate_complete(num_bytes, io_context);
						break;

					case proxy_io_operation::negotiate_io_write:
						io_context->proxy_socket_ptr->process_send_negotiate_complete(num_bytes, io_context);
						break;

					case proxy_io_operation::inject_io_write:
						T::process_inject_buffer_complete(io_context);
						break;

					default: break;
					}

					return true;
				});

				if(status == true)
				{
					completion_key_ = io_key;
				}
				else
				{
					if (std::get<0>(sock_array_events_[0]) != INVALID_HANDLE_VALUE)
					{
						WSACloseEvent(std::get<0>(sock_array_events_[0]));
					}

					if (std::get<1>(sock_array_events_[0]) != INVALID_SOCKET)
					{
						closesocket(std::get<1>(sock_array_events_[0]));
					}

					sock_array_events_.clear();
					end_server_ = true;
					return false;
				}
			}

			proxy_server_ = std::thread(&tcp_proxy_server<T>::start_proxy_thread, this);
			check_clients_thread_ = std::thread(&tcp_proxy_server<T>::clear_thread, this);;
			connect_to_remote_host_thread_ = std::thread(&tcp_proxy_server<T>::connect_to_remote_host_thread, this);;

			return true;
		}

		void stop()
		{
			if (end_server_ == true)
			{
				// already stopped
				return;
			}

			end_server_ = true;

			if (listen_socket_ != INVALID_SOCKET)
			{
				shutdown(listen_socket_, SD_BOTH);
				closesocket(listen_socket_);
				listen_socket_ = INVALID_SOCKET;
			}

			{
				std::shared_lock<std::shared_mutex> lock(lock_);
				::WSASetEvent(std::get<0>(sock_array_events_[0]));
			}

			if(proxy_server_.joinable())
			{
				proxy_server_.join();
			}

			if(check_clients_thread_.joinable())
			{
				check_clients_thread_.join();
			}

			if(connect_to_remote_host_thread_.joinable())
			{
				connect_to_remote_host_thread_.join();
			}

			if(!sock_array_events_.empty())
			{
				sock_array_events_.clear();
			}

			if (!proxy_sockets_.empty())
			{
				proxy_sockets_.clear();
			}
		}

		std::vector<negotiate_context_t> query_current_sessions_ctx()
		{
			std::shared_lock<std::shared_mutex> lock(lock_);
			std::vector<negotiate_context_t> result;
			result.reserve(proxy_sockets_.size());

			std::transform(proxy_sockets_.cbegin(), proxy_sockets_.cend(), std::back_inserter(result), [](auto&& e)
				{
					return *reinterpret_cast<negotiate_context_t*>(e->get_negotiate_ctx());
				});

			return result;
		}

	private:
		// ********************************************************************************
		/// <summary>
		/// Queries remote host information for outgoing connection by locally accepted socket
		/// </summary>
		/// <param name="accepted">locally accepted TCP socket</param>
		/// <returns>tuple of information required to connect to the remote peer</returns>
		// ********************************************************************************
		std::tuple <address_type_t, uint16_t, std::unique_ptr<negotiate_context_t>> get_remote_peer(const SOCKET accepted) const
		{
			SOCKADDR_STORAGE name;
			int len = sizeof(SOCKADDR_STORAGE);

			if (!getpeername(accepted, reinterpret_cast<sockaddr*>(&name), &len))
			{
				uint16_t accepted_peer_port = 0;
				address_type_t accepted_peer_address{};

				if constexpr (address_type_t::af_type == AF_INET)
				{
					accepted_peer_port = ntohs(reinterpret_cast<sockaddr_in*>(&name)->sin_port);
					accepted_peer_address = address_type_t(reinterpret_cast<sockaddr_in*>(&name)->sin_addr);
				}
				else if constexpr(address_type_t::af_type == AF_INET6)
				{
					accepted_peer_port = ntohs(reinterpret_cast<sockaddr_in6*>(&name)->sin6_port);
					accepted_peer_address = address_type_t(reinterpret_cast<sockaddr_in6*>(&name)->sin6_addr);
				}
				else
				{
					static_assert(false_v<T>, "Unsupported address family used as a template parameter!");
				}

				if(query_remote_peer_)
				{
					return query_remote_peer_(accepted_peer_address, accepted_peer_port);
				}
			}
			else
			{
				return std::make_tuple(address_type_t{}, 0, nullptr);
			}

			return std::make_tuple(address_type_t{}, 0, nullptr);
		}

		bool create_server_socket()
		{
			listen_socket_ = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
			                           WSA_FLAG_OVERLAPPED);

			if (listen_socket_ == INVALID_SOCKET)
			{
				return false;
			}

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in service;
				service.sin_family = address_type_t::af_type;
				service.sin_addr.s_addr = INADDR_ANY;
				service.sin_port = htons(proxy_port_);

				const auto status = bind(listen_socket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));

				if (status == SOCKET_ERROR)
				{
					return false;
				}
			}
			else
			{
				sockaddr_in6 service;
				service.sin6_family = address_type_t::af_type;
				service.sin6_addr = in6addr_any;
				service.sin6_port = htons(proxy_port_);

				const auto status = bind(listen_socket_, reinterpret_cast<SOCKADDR*>(&service), sizeof(service));

				if (status == SOCKET_ERROR)
				{
					return false;
				}
			}

			const auto status = listen(listen_socket_, SOMAXCONN);

			if (status == SOCKET_ERROR)
			{
				return false;
			}

			return true;
		}

		bool connect_to_remote_host(SOCKET accepted)
		{
			auto[remote_ip, remote_port, negotiate_ctx] = get_remote_peer(accepted);

			if (!remote_port)
				return false;

			/*std::cout << "connect_to_remote_host: "
				<< "remote_ip: " << remote_ip << " "
				<< "remote_port: " << remote_port << "\n";*/

			auto remote_socket = WSASocket(address_type_t::af_type, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
			                               WSA_FLAG_OVERLAPPED);

			if (remote_socket == INVALID_SOCKET)
			{
				return false;
			}

			/*std::cout << "connect_to_remote_host: "
				<< "remote_socket: " << remote_socket << "\n";*/

			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_local = { 0 };
				sa_local.sin_family = address_type_t::af_type;
				sa_local.sin_port = htons(0);
				sa_local.sin_addr.s_addr = htonl(INADDR_ANY);

				// bind socket's name
				const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr));

				if (status == SOCKET_ERROR)
				{
					shutdown(remote_socket, SD_BOTH);
					closesocket(remote_socket);

					return false;
				}
			}
			else
			{
				sockaddr_in6 sa_local = {0};
				sa_local.sin6_family = address_type_t::af_type;
				sa_local.sin6_port = htons(0);
				sa_local.sin6_addr = in6addr_any;

				// bind socket's name
				const auto status = bind(remote_socket, reinterpret_cast<sockaddr*>(&sa_local), sizeof(sockaddr));

				if (status == SOCKET_ERROR)
				{
					shutdown(remote_socket, SD_BOTH);
					closesocket(remote_socket);

					return false;
				}
			}

			// enable non-blocking mode
			u_long mode = 1;
			auto ret = ioctlsocket(remote_socket, FIONBIO, reinterpret_cast<u_long FAR*>(&mode));

			// The client_service structure specifies the address family,
			// IP address, and port of the server to be connected to.
			{
				std::lock_guard<std::shared_mutex> lock(lock_);

				sock_array_events_.push_back(std::make_tuple(::WSACreateEvent(), accepted, remote_socket, std::move(negotiate_ctx)));
			
				WSAEventSelect(remote_socket, std::get<0>(sock_array_events_.back()), FD_CONNECT);
				
				WSASetEvent(std::get<0>(sock_array_events_[0]));
			}

			// connect to server
			if constexpr (address_type_t::af_type == AF_INET)
			{
				sockaddr_in sa_service = {0};
				sa_service.sin_family = address_type_t::af_type;
				sa_service.sin_addr = remote_ip;
				sa_service.sin_port = htons(remote_port);

				if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) == SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK)
					{
						shutdown(remote_socket, SD_BOTH);
						closesocket(remote_socket);

						return false;
					}
				}
			}
			else
			{
				sockaddr_in6 sa_service = {0};
				sa_service.sin6_family = address_type_t::af_type;
				sa_service.sin6_addr = remote_ip;
				sa_service.sin6_port = htons(remote_port);

				if (connect(remote_socket, reinterpret_cast<SOCKADDR*>(&sa_service), sizeof(sa_service)) == SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK)
					{
						shutdown(remote_socket, SD_BOTH);
						closesocket(remote_socket);

						return false;
					}
				}
			}

			return true;;
		}
		
		void start_proxy_thread()
		{
			while (end_server_ == false)
			{
				//
				// loop accepting connections from clients until proxy shuts down
				//
				const auto accepted = WSAAccept(listen_socket_, nullptr, nullptr, nullptr, 0);

				if ((accepted == SOCKET_ERROR) || end_server_)
				{
					break;
				}

				const auto connected = connect_to_remote_host(accepted);

				if (!connected)
				{
					closesocket(accepted);
				}
			}
		}

		void connect_to_remote_host_thread()
		{
			std::vector<WSAEVENT> wait_events;
			wait_events.reserve(connections_array_size);

			while (end_server_ == false)
			{
				{
					// initialize wait events array
					wait_events.clear();

					std::shared_lock<std::shared_mutex> lock(lock_);

					std::transform(sock_array_events_.cbegin(), sock_array_events_.cend(), std::back_inserter(wait_events), [](auto&& e)
					{
						return std::get<0>(e);
					});
				}

				const auto event_index = WSAWaitForMultipleEvents(static_cast<DWORD>(wait_events.size()),
				                                                  &wait_events[0], FALSE, INFINITE, FALSE);

				if (end_server_ == true)
					break;

				/*std::cout << "connect_to_remote_host_thread: "
					<< "event_index: " << event_index << "\n";*/

				if (event_index != 0)
				{
					std::lock_guard<std::shared_mutex> lock(lock_);

					/*std::cout << "connect_to_remote_host_thread: " 
					<< "event: " << wait_events[event_index] << " "
					<< "event: " << std::get<0>(sock_array_events_[event_index]) << " "
					<< "socket: " << std::get<2>(sock_array_events_[event_index]) << "\n";*/

					WSACloseEvent(wait_events[event_index]);

					proxy_sockets_.push_back(std::make_unique<T>(
						std::get<1>(sock_array_events_[event_index]),
						std::get<2>(sock_array_events_[event_index]),
						std::move(std::get<3>(sock_array_events_[event_index]))));

					proxy_sockets_.back()->associate_to_completion_port(completion_key_, completion_port_);
					proxy_sockets_.back()->start();

					sock_array_events_.erase(sock_array_events_.begin() + event_index);
				}
				else
				{
					WSAResetEvent(wait_events[event_index]);
				}
			}

			// cleanup on exit
			std::shared_lock<std::shared_mutex> lock(lock_);

			for (auto&& a: sock_array_events_)
			{
				if (std::get<0>(a) != INVALID_HANDLE_VALUE)
				{
					WSACloseEvent(std::get<0>(a));
				}

				if (std::get<1>(a) != INVALID_SOCKET)
				{
					shutdown(std::get<1>(a), SD_BOTH);
					closesocket(std::get<1>(a));
					std::get<1>(a) = INVALID_SOCKET;
				}

				if (std::get<2>(a) != INVALID_SOCKET)
				{
					shutdown(std::get<2>(a), SD_BOTH);
					closesocket(std::get<2>(a));
					std::get<2>(a) = INVALID_SOCKET;
				}
			}
		}

		void clear_thread()
		{
			while (end_server_ == false)
			{
				{
					std::lock_guard<std::shared_mutex> lock(lock_);

					proxy_sockets_.erase(std::remove_if(proxy_sockets_.begin(), proxy_sockets_.end(), [](auto&& a)
						{
							return a->is_ready_for_removal();
						}), proxy_sockets_.end());
				}

				using namespace std::chrono_literals;
				std::this_thread::sleep_for(1000ms);
			}
		}

		std::shared_mutex lock_;
	
		std::thread proxy_server_;
		std::thread	check_clients_thread_;
		std::thread connect_to_remote_host_thread_;
				
		std::vector<std::unique_ptr<T>> proxy_sockets_;
		std::vector<std::tuple<WSAEVENT, SOCKET, SOCKET, std::unique_ptr<negotiate_context_t>>> sock_array_events_;

		std::atomic_bool end_server_{true};			// set to true on proxy termination
		SOCKET listen_socket_{ INVALID_SOCKET };

		uint16_t proxy_port_;
		winsys::io_completion_port& completion_port_;
		ULONG_PTR completion_key_{0};
		std::function<query_remote_peer_t> query_remote_peer_;
	};
}
