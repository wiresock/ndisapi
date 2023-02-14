#pragma once

namespace ndisapi
{
	struct local_redirect_key
	{
		local_redirect_key() = default;

		local_redirect_key(const net::ip_address_v4& original_dest_ip, const u_short original_src_port)
			: original_dest_ip(original_dest_ip),
			  original_src_port(original_src_port)
		{
		}

		friend bool operator==(const local_redirect_key& lhs, const local_redirect_key& rhs)
		{
			return lhs.original_dest_ip == rhs.original_dest_ip
				&& lhs.original_src_port == rhs.original_src_port;
		}

		friend bool operator!=(const local_redirect_key& lhs, const local_redirect_key& rhs)
		{
			return !(lhs == rhs);
		}

		net::ip_address_v4 original_dest_ip{};
		u_short original_src_port = 0;
	};
}

namespace std
{
	template <>
	struct hash<ndisapi::local_redirect_key>
	{
		using argument_type = ndisapi::local_redirect_key;
		using result_type = size_t;

		result_type operator()(const argument_type& key) const noexcept
		{
			const auto h1(std::hash<net::ip_address_v4>{}(key.original_dest_ip) ^ key.original_src_port);

			return h1;
		}
	};
}

namespace ndisapi
{
	class local_redirector
	{
	public:
		explicit local_redirector(const u_short proxy_port)
			: proxy_port_(htons(proxy_port))
		{
		}

		[[nodiscard]] u_short get_proxy_port() const
		{
			return ntohs(proxy_port_);
		}

		bool process_client_to_server_packet(INTERMEDIATE_BUFFER& packet)
		{
			iphdr_ptr ip_header;
			tcphdr_ptr tcp_header;

			auto eth_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);

			if (ntohs(eth_header->h_proto) == ETH_P_IP)
			{
				ip_header = reinterpret_cast<iphdr_ptr>(packet.m_IBuffer + ETHER_HEADER_LENGTH);

				if (ip_header->ip_p == IPPROTO_TCP)
				{
					// This is TCP packet, get TCP header pointer
					tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) *
						ip_header->ip_hl);
				}
				else
				{
					return false;
				}
			}
			else
			{
				return false;
			}

			if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
			{
				if (const auto [it, result] = redirected_connections_.emplace(
					local_redirect_key{net::ip_address_v4{ip_header->ip_dst}, tcp_header->th_sport},
					tcp_header->th_dport); !result)
					return false;
			}
			else
			{
				if (const auto it = redirected_connections_.find(local_redirect_key{
					net::ip_address_v4{ip_header->ip_dst}, tcp_header->th_sport
				}); it == redirected_connections_.cend())
					return false;
			}

			// 1. Swap Ethernet addresses
			std::swap(eth_header->h_dest, eth_header->h_source);

			// 2. Swap IP addresses
			std::swap(ip_header->ip_dst.S_un.S_addr, ip_header->ip_src.S_un.S_addr);

			tcp_header->th_dport = proxy_port_;

			return true;
		}

		bool process_server_to_client_packet(INTERMEDIATE_BUFFER& packet)
		{
			iphdr_ptr ip_header;
			tcphdr_ptr tcp_header;

			auto eth_header = reinterpret_cast<ether_header_ptr>(packet.m_IBuffer);

			if (ntohs(eth_header->h_proto) == ETH_P_IP)
			{
				ip_header = reinterpret_cast<iphdr_ptr>(packet.m_IBuffer + ETHER_HEADER_LENGTH);

				if (ip_header->ip_p == IPPROTO_TCP)
				{
					// This is TCP packet, get TCP header pointer
					tcp_header = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(ip_header) + sizeof(DWORD) *
						ip_header->ip_hl);
				}
				else
				{
					return false;
				}
			}
			else
			{
				return false;
			}

			const auto it = redirected_connections_.find(local_redirect_key{
				net::ip_address_v4{ip_header->ip_dst}, tcp_header->th_dport
			});
			if (it == redirected_connections_.cend())
				return false;

			// Swap Ethernet addresses
			std::swap(eth_header->h_dest, eth_header->h_source);

			// Swap IP addresses
			std::swap(ip_header->ip_dst.S_un.S_addr, ip_header->ip_src.S_un.S_addr);

			tcp_header->th_sport = it->second;

			return true;
		}

	private:
		std::unordered_map<local_redirect_key, u_short> redirected_connections_;
		/// <summary>proxy port in network byte order</summary>
		u_short proxy_port_;
	};
}
