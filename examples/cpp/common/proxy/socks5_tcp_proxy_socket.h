#pragma once

namespace proxy
{
	template <typename T>
	class socks5_tcp_proxy_socket final : public tcp_proxy_socket<T>
	{
		enum class socks5_state
		{
			pre_login,
			login_sent,
			login_responded,
			connect_sent
		};

	public:
		using address_type_t = T;
		using negotiate_context_t = negotiate_context<T>;
		using per_io_context_t = tcp_per_io_context<T>;

		socks5_tcp_proxy_socket(const SOCKET local_socket, const SOCKET remote_socket,
			std::unique_ptr<negotiate_context_t> negotiate_ctx,
			std::function<void(const char*)> log_printer, const netlib::log::log_level log_level)
			: tcp_proxy_socket<T>(local_socket, remote_socket, std::move(negotiate_ctx), std::move(log_printer), log_level)
		{
		}

		void process_receive_negotiate_complete(const uint32_t io_size, per_io_context_t* io_context) override
		{
			if (io_context->is_local == false)
			{
				if (current_state_ == socks5_state::login_sent)
				{
					current_state_ = socks5_state::login_responded;

					if ((ident_resp_.version != 5) ||
						(ident_resp_.method == 0xFF))
					{
						// SOCKS v5 identification or authentication failed
						tcp_proxy_socket<T>::close_client<false>(true, false);
					}
					else
					{
						connect_request_.version = 5;
						connect_request_.cmd = 1;
						connect_request_.reserved = 0;
						connect_request_.address_type = 1;
						connect_request_.dest_address.ip_v4 = tcp_proxy_socket<T>::negotiate_ctx_->remote_address;
						connect_request_.dest_port = htons(tcp_proxy_socket<T>::negotiate_ctx_->remote_port);

						io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_request_);
						io_context_send_negotiate_.wsa_buf.len = sizeof(socks5_req);
						io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&connect_response_);
						io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_resp);

						DWORD flags = 0;

						if ((::WSASend(
							tcp_proxy_socket<T>::remote_socket_,
							&io_context_send_negotiate_.wsa_buf,
							1,
							nullptr,
							0,
							&io_context_send_negotiate_,
							nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
						{
							tcp_proxy_socket<T>::close_client<false>(false, false);
						}

						current_state_ = socks5_state::connect_sent;

						if ((::WSARecv(
							tcp_proxy_socket<T>::remote_socket_,
							&io_context_recv_negotiate_.wsa_buf,
							1,
							nullptr,
							&flags,
							&io_context_recv_negotiate_,
							nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
						{
							tcp_proxy_socket<T>::close_client<false>(true, false);
						}
					}
				}
				else if (current_state_ == socks5_state::connect_sent)
				{
					if (connect_response_.reply != 0)
					{
						// SOCKS v5 connect failed
						tcp_proxy_socket<T>::close_client<false>(true, false);
					}
					else
					{
						tcp_proxy_socket<T>::start_data_relay();
					}
				}
			}
		}

	private:
		per_io_context_t io_context_recv_negotiate_{ proxy_io_operation::negotiate_io_read, this, false };
		per_io_context_t io_context_send_negotiate_{ proxy_io_operation::negotiate_io_write, this, false };

		socks5_state current_state_{ socks5_state::pre_login };
		socks5_ident_req ident_req_{};
		socks5_ident_resp ident_resp_{};
		socks5_req connect_request_{};
		socks5_resp connect_response_{};

	protected:
		bool local_negotiate() override
		{
			return true;
		}

		bool remote_negotiate() override
		{
			if (tcp_proxy_socket<T>::negotiate_ctx_)
			{
				if (current_state_ == socks5_state::pre_login)
				{
					ident_req_.version = 5;
					ident_req_.number_of_methods = 1;
					ident_req_.methods[0] = 0x00;
					io_context_send_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_req_);
					io_context_send_negotiate_.wsa_buf.len = sizeof(socks5_ident_req);
					io_context_recv_negotiate_.wsa_buf.buf = reinterpret_cast<char*>(&ident_resp_);
					io_context_recv_negotiate_.wsa_buf.len = sizeof(socks5_ident_resp);

					DWORD flags = 0;

					if ((::WSASend(
						tcp_proxy_socket<T>::remote_socket_,
						&io_context_send_negotiate_.wsa_buf,
						1,
						nullptr,
						0,
						&io_context_send_negotiate_,
						nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
					{
						tcp_proxy_socket<T>::close_client<false>(false, false);
					}

					current_state_ = socks5_state::login_sent;

					if ((::WSARecv(
						tcp_proxy_socket<T>::remote_socket_,
						&io_context_recv_negotiate_.wsa_buf,
						1,
						nullptr,
						&flags,
						&io_context_recv_negotiate_,
						nullptr) == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError()))
					{
						tcp_proxy_socket<T>::close_client<false>(true, false);
					}
				}

				return false;
			}

			return true;
		}
	};
}