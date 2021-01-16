#pragma once

namespace net
{
    // --------------------------------------------------------------------------------
    /// <summary>
    /// Represents IPv4 TCP/UDP endpoint
    /// </summary>
    // --------------------------------------------------------------------------------
    template<typename T> struct ip_endpoint
    {
        ip_endpoint() = default;
        ip_endpoint(const T& ip, const unsigned short port) : ip(ip), port(port) {}

        [[nodiscard]] std::string ip_to_string() const noexcept { return std::string(ip); }
        [[nodiscard]] std::string port_to_string() const noexcept { return std::to_string(port); }

        bool operator ==(const ip_endpoint& rhs) const { return (ip == rhs.ip) && (port == rhs.port); }
        bool operator !=(const ip_endpoint& rhs) const { return (ip != rhs.ip) || (port != rhs.port); }

        T ip;
        uint16_t port{ 0 };
    };

    // --------------------------------------------------------------------------------
    /// <summary>
    /// Represents IPv4 TCP/UDP session
    /// </summary>
    // --------------------------------------------------------------------------------
    template<typename T> struct ip_session
    {
        ip_session(
            const T& local_ip,
            const T& remote_ip,
            const unsigned short local_port,
            const unsigned short remote_port) :
            local(local_ip, local_port),
            remote(remote_ip, remote_port) {}

        bool operator ==(const ip_session& rhs) const { return (local == rhs.local) && (remote == rhs.remote); }
        bool operator !=(const ip_session& rhs) const { return (local != rhs.local) || (remote != rhs.remote); }

        ip_endpoint<T> local;
        ip_endpoint<T> remote;
    };
}

namespace std
{
	template<typename T> struct hash<net::ip_endpoint<T>>
	{
        typedef net:: ip_endpoint<T> argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& endpoint) const noexcept
		{
			auto const h1(std::hash<std::size_t>{}(
				std::hash<T>{}(endpoint.ip) ^
				static_cast<unsigned long>(endpoint.port)
				));

			return h1;
		}
	};

	template<typename T> struct hash<net::ip_session<T>>
	{
		typedef net::ip_session<T> argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& endpoint) const noexcept
		{
			auto const h1(std::hash<std::size_t>{}(
				std::hash<net::ip_endpoint<T>>{}(endpoint.local) ^
				static_cast<unsigned long>(endpoint.local.port) ^
				std::hash<net::ip_endpoint<T>>{}(endpoint.remote) ^
				static_cast<unsigned long>(endpoint.remote.port)
				));

			return h1;
		}
	};
}