#pragma once

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

	T				ip;
	unsigned short	port{ 0 };
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

namespace std
{
	template<typename T> struct hash<ip_endpoint<T>>
	{
		typedef ip_endpoint<T> argument_type;
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

	template<typename T> struct hash<ip_session<T>>
	{
		typedef ip_session<T> argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& endpoint) const noexcept
		{
			auto const h1(std::hash<std::size_t>{}(
				std::hash<ip_endpoint<T>>{}(endpoint.local) ^
				static_cast<unsigned long>(endpoint.local.port) ^
				std::hash<ip_endpoint<T>>{}(endpoint.remote) ^
				static_cast<unsigned long>(endpoint.remote.port)
				));

			return h1;
		}
	};
}

// --------------------------------------------------------------------------------
/// <summary>
/// Represents a networking application
/// </summary>
// --------------------------------------------------------------------------------
struct network_process
{
	network_process() = default;

	network_process(const unsigned long id, std::wstring name, std::wstring path) :
		id(id), name(std::move(name)), path_name(std::move(path)) {}

	unsigned long		id{};
	std::wstring		name;
	std::wstring		path_name;
};

// --------------------------------------------------------------------------------
/// <summary>
/// process_lookup class utilizes IP Helper API to match TCP/UDP network packet to local process
/// </summary>
// --------------------------------------------------------------------------------
template <typename T> class process_lookup final
{
	process_lookup()
	{
		default_process_ = std::make_shared<network_process>(0, L"SYSTEM", L"SYSTEM");

		initialize_tcp_table();
		initialize_udp_table();
	}

public:

	process_lookup(const process_lookup& other) = delete;
	process_lookup(process_lookup&& other) noexcept = delete;
	process_lookup& operator=(const process_lookup& other) = delete;
	process_lookup& operator=(process_lookup&& other) noexcept = delete;

private:

	std::unordered_map<ip_session<T>, std::shared_ptr<network_process>>		tcp_to_app_; // TCP sessions hash
	std::unordered_map<ip_endpoint<T>, std::shared_ptr<network_process>>	udp_to_app_; // UDP sessions hash

	std::shared_mutex														tcp_to_app_lock_;
	std::shared_mutex														udp_to_app_lock_;

	std::shared_ptr<network_process>										default_process_;

public:
	static process_lookup& get_process_helper()
	{
		static process_lookup instance;
		return instance;
	}

	~process_lookup() = default;

	template <bool SetToDefault>
	std::shared_ptr<network_process> lookup_process_for_tcp(ip_session<T> const& session)
	{
		// Try to lookup in the current table
		std::shared_lock<std::shared_mutex> slock(tcp_to_app_lock_);

		auto it_first = tcp_to_app_.find(session);

		if (it_first != tcp_to_app_.end())
		{
			return it_first->second;
		}
		else
		{
			if constexpr (SetToDefault)
			{
				slock.unlock();

				std::unique_lock <std::shared_mutex> ulock(tcp_to_app_lock_);
				tcp_to_app_[session] = default_process_;
				return default_process_;
			}
			else
			{
				return nullptr;
			}
		}
	}

	template <bool SetToDefault>
	std::shared_ptr<network_process> lookup_process_for_udp(ip_endpoint<T> const& endpoint)
	{
		// UDP endpoints may have 0.0.0.0:137 form
		auto zero_ip_endpoint = endpoint;
		zero_ip_endpoint.ip = T{};

		// Try to lookup in the current table
		std::shared_lock<std::shared_mutex> slock(udp_to_app_lock_);

		auto it_first = udp_to_app_.find(endpoint);

		if (it_first != udp_to_app_.end())
		{
			return it_first->second;
		}
		else
		{
			// Search for 0.0.0.0:port
			it_first = udp_to_app_.find(zero_ip_endpoint);

			if (it_first != udp_to_app_.end())
			{
				return it_first->second;
			}
			else
			{
				if constexpr (SetToDefault)
				{
					slock.unlock();

					std::unique_lock <std::shared_mutex> ulock(udp_to_app_lock_);
					udp_to_app_[endpoint] = default_process_;
					return default_process_;
				}
				else
				{
					return nullptr;
				}
			}
		}
	}

	bool actualize(const bool tcp, const bool udp)
	{
		auto ret_tcp = true, ret_udp = true;

		if (tcp)
		{
			std::lock_guard<std::shared_mutex> lock(tcp_to_app_lock_);
			ret_tcp = initialize_tcp_table();
		}

		if (udp)
		{
			std::lock_guard<std::shared_mutex> lock(udp_to_app_lock_);
			ret_udp = initialize_udp_table();
		}

		return (ret_udp & ret_tcp);
	}

private:

	bool initialize_tcp_table()
	{
		DWORD table_size = 0;

		tcp_to_app_.clear();

		if (ERROR_INSUFFICIENT_BUFFER != GetExtendedTcpTable(nullptr, &table_size, FALSE, T::af_type,
		                                                     TCP_TABLE_OWNER_MODULE_CONNECTIONS, 0))
			return false;

		const auto table_ptr = std::make_unique<char[]>(static_cast<std::size_t>(table_size));

		if constexpr (std::is_same<T, net::ip_address_v4>::value)
		{
			auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(table_ptr.get());

			if (GetExtendedTcpTable(table, &table_size, FALSE, T::af_type, TCP_TABLE_OWNER_MODULE_CONNECTIONS, 0) != NO_ERROR)
				return false;

			for (size_t i = 0; i < table->dwNumEntries; i++)
			{
				DWORD size = 0;
				std::shared_ptr<network_process> process_ptr(nullptr);

				if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
				{
					auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

					auto info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());

					if (GetOwnerModuleFromTcpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR)
					{
						process_ptr = std::make_shared<network_process>(table->table[i].dwOwningPid, info->pModuleName, info->pModulePath);
					}
				}

				if (process_ptr)
					tcp_to_app_[ip_session<T>(
						T{ table->table[i].dwLocalAddr },
						T{ table->table[i].dwRemoteAddr },
						ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)),
						ntohs(static_cast<unsigned short>(table->table[i].dwRemotePort)))] = std::move(process_ptr);
			}
		}
		else
		{
			auto table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(table_ptr.get());

			if (GetExtendedTcpTable(table, &table_size, FALSE, T::af_type, TCP_TABLE_OWNER_MODULE_CONNECTIONS, 0) != NO_ERROR)
				return false;

			for (size_t i = 0; i < table->dwNumEntries; i++)
			{
				DWORD size = 0;
				std::shared_ptr<network_process> process_ptr(nullptr);

				if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcp6Entry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
				{
					auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

					auto info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());

					if (GetOwnerModuleFromTcp6Entry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR)
					{
						process_ptr = std::make_shared<network_process>(table->table[i].dwOwningPid, info->pModuleName, info->pModulePath);
					}
				}

				if (process_ptr)
					tcp_to_app_[ip_session<T>(
						T{ table->table[i].ucLocalAddr },
						T{ table->table[i].ucRemoteAddr },
						ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)),
						ntohs(static_cast<unsigned short>(table->table[i].dwRemotePort)))] = std::move(process_ptr);
			}
		}

		return true;
	}

	bool initialize_udp_table()
	{
		DWORD table_size = 0;

		udp_to_app_.clear();

		if (ERROR_INSUFFICIENT_BUFFER != GetExtendedUdpTable(nullptr, &table_size, FALSE, T::af_type, UDP_TABLE_OWNER_MODULE, 0))
			return false;

		const auto table_ptr = std::make_unique<char[]>(static_cast<std::size_t>(table_size));

		if constexpr (std::is_same<T, net::ip_address_v4>::value)
		{
			auto table = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(table_ptr.get());

			if (GetExtendedUdpTable(table, &table_size, FALSE, T::af_type, UDP_TABLE_OWNER_MODULE, 0) != NO_ERROR)
				return false;

			for (size_t i = 0; i < table->dwNumEntries; i++)
			{
				DWORD size = 0;
				std::shared_ptr<network_process> process_ptr(nullptr);

				if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
				{
					auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

					auto info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());

					if (GetOwnerModuleFromUdpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR)
					{
						process_ptr = std::make_shared<network_process>(table->table[i].dwOwningPid, info->pModuleName, info->pModulePath);
					}
				}

				if (process_ptr)
					udp_to_app_[ip_endpoint<T>(
						T{ table->table[i].dwLocalAddr },
						ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)))] = std::move(process_ptr);
			}
		}
		else
		{
			auto table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(table_ptr.get());

			if (GetExtendedUdpTable(table, &table_size, FALSE, T::af_type, UDP_TABLE_OWNER_MODULE, 0) != NO_ERROR)
				return false;

			for (size_t i = 0; i < table->dwNumEntries; i++)
			{
				DWORD size = 0;
				std::shared_ptr<network_process> process_ptr(nullptr);

				if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdp6Entry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
				{
					auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

					auto info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());

					if (GetOwnerModuleFromUdp6Entry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info, &size) == NO_ERROR)
					{
						process_ptr = std::make_shared<network_process>(table->table[i].dwOwningPid, info->pModuleName, info->pModulePath);
					}
				}

				if (process_ptr)
					udp_to_app_[ip_endpoint<T>(
						T{ table->table[i].ucLocalAddr },
						ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)))] = std::move(process_ptr);
			}
		}

		return true;
	}
};