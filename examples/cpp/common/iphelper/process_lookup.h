#pragma once

namespace iphelper
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Represents a networking application
	/// </summary>
	// --------------------------------------------------------------------------------
	struct network_process
	{
		/// <summary>
		/// Default constructor
		/// </summary>
		network_process() = default;

		/// <summary>
		/// Constructs object instance from provided process ID, name and path
		/// </summary>
		/// <param name="id">process ID</param>
		/// <param name="name">process name</param>
		/// <param name="path">path to the executable</param>
		network_process(const unsigned long id, std::wstring name, std::wstring path) :
			id(id), name(std::move(name)), path_name(std::move(path))
		{
		}

		unsigned long id{};
		std::wstring name;
		std::wstring path_name;
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// process_lookup class utilizes IP Helper API to match TCP/UDP network packet to local process
	/// Designed as a singleton
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	// --------------------------------------------------------------------------------
	template <typename T>
	class process_lookup final
	{
		/// <summary>
		/// Type to store TCP sessions
		/// </summary>
		using tcp_hashtable_t = std::unordered_map<net::ip_session<T>, std::shared_ptr<network_process>>;
		/// <summary>
		/// Type to store UDP sessions
		/// </summary>
		using udp_hashtable_t = std::unordered_map<net::ip_endpoint<T>, std::shared_ptr<network_process>>;

		/// <summary>
		/// Private constructor. Initializes current state of TCP/UDP connections.
		/// </summary>
		process_lookup()
		{
			default_process_ = std::make_shared<network_process>(0, L"SYSTEM", L"SYSTEM");

			initialize_tcp_table();
			initialize_udp_table();
		}

	public:
		/// <summary>
		/// Deleted copy constructor
		/// </summary>
		process_lookup(const process_lookup& other) = delete;
		/// <summary>
		/// deleted move constructor
		/// </summary>
		process_lookup(process_lookup&& other) noexcept = delete;
		/// <summary>
		/// Deleted copy assignment
		/// </summary>
		process_lookup& operator=(const process_lookup& other) = delete;
		/// <summary>
		/// Deleted move assignment
		/// </summary>
		process_lookup& operator=(process_lookup&& other) noexcept = delete;

	private:
		/// <summary>
		/// TCP sessions hashtable
		/// </summary>
		tcp_hashtable_t tcp_to_app_;
		/// <summary>
		/// UDP sessions hashtable
		/// </summary>
		udp_hashtable_t udp_to_app_;

		/// <summary>
		/// Lock to control access to TCP sessions hashtable
		/// </summary>
		std::shared_mutex tcp_to_app_lock_;
		/// <summary>
		/// Lock to control access to UDP sessions hashtable
		/// </summary>
		std::shared_mutex udp_to_app_lock_;
		/// <summary>
		/// Default process used when process lookup in not possible via IP Helper API
		/// Usually IP Helper API fails for system processes
		/// </summary>
		std::shared_ptr<network_process> default_process_;
		/// <summary>
		/// Memory buffer to query connection tables
		/// </summary>
		std::unique_ptr<char[]> table_buffer_{};
		/// <summary>
		/// Current size of the memory buffer to query connection tables
		/// </summary>
		DWORD table_buffer_size_{0};

	public:
		/// <summary>
		/// Constructs (only once) and returns process_lookup object reference
		/// </summary>
		/// <returns>process_lookup object reference</returns>
		static process_lookup& get_process_helper()
		{
			static process_lookup instance;
			return instance;
		}

		/// <summary>
		/// Default destructor
		/// </summary>
		~process_lookup() = default;

		/// <summary>
		/// Searches process by provided TCP session information
		/// </summary>
		/// <typeparam name="SetToDefault">when true and fail to lookup the process sets to default</typeparam>
		/// <param name="session">TCP session to lookup</param>
		/// <returns>shared pointer to network_process instance</returns>
		template <bool SetToDefault>
		std::shared_ptr<network_process> lookup_process_for_tcp(const net::ip_session<T>& session)
		{
			// Try to lookup in the current table
			std::shared_lock slock(tcp_to_app_lock_);

			if (auto it_first = tcp_to_app_.find(session); it_first != tcp_to_app_.end())
			{
				return it_first->second;
			}

			if constexpr (SetToDefault)
			{
				slock.unlock();

				std::unique_lock<std::shared_mutex> lock(tcp_to_app_lock_);
				tcp_to_app_[session] = default_process_;
				return default_process_;
			}
			else
			{
				return nullptr;
			}
		}

		/// <summary>
		/// Searches process by provided UDP endpoint information
		/// </summary>
		/// <typeparam name="SetToDefault">when true and fail to lookup the process sets to default</typeparam>
		/// <param name="endpoint">UDP endpoint to lookup</param>
		/// <returns>shared pointer to network_process instance</returns>
		template <bool SetToDefault>
		std::shared_ptr<network_process> lookup_process_for_udp(const net::ip_endpoint<T>& endpoint)
		{
			// UDP endpoints may have 0.0.0.0:137 form
			auto zero_ip_endpoint = endpoint;
			zero_ip_endpoint.ip = T{};

			// Try to lookup in the current table
			std::shared_lock<std::shared_mutex> slock(udp_to_app_lock_);

			if (auto it_first = udp_to_app_.find(endpoint); it_first != udp_to_app_.end())
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
				if constexpr (SetToDefault)
				{
					slock.unlock();

					std::unique_lock<std::shared_mutex> lock(udp_to_app_lock_);
					udp_to_app_[endpoint] = default_process_;
					return default_process_;
				}
				else
				{
					return nullptr;
				}
			}
		}

		/// <summary>
		/// Updates TCP/UDP hash tables
		/// </summary>
		/// <param name="tcp">set to true to update TCP table</param>
		/// <param name="udp">set to true to update UDP table</param>
		/// <returns>true if successful, false if error occurred</returns>
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

			return (ret_udp && ret_tcp);
		}

		/// <summary>
		/// Returns current TCP hash table string representation
		/// </summary>
		/// <returns>string with TCP hash table entries dumped</returns>
		std::string dump_tcp_table()
		{
			std::ostringstream oss;

			std::shared_lock<std::shared_mutex> lock(tcp_to_app_lock_);
			std::for_each(tcp_to_app_.begin(), tcp_to_app_.end(), [&oss](auto&& entry)
			{
				oss << std::string(entry.first.local.ip) << " : " << entry.first.local.port <<
					" <---> " << std::string(entry.first.remote.ip) << " : " << entry.first.remote.port <<
					" : " << entry.second->id << " : " << wstring_to_string(entry.second->name) << std::endl;
			});

			return oss.str();
		}

		/// <summary>
		/// Returns current UDP hash table string representation
		/// </summary>
		/// <returns>string with UDP hash table entries dumped</returns>
		std::string dump_udp_table()
		{
			std::ostringstream oss;

			std::shared_lock<std::shared_mutex> lock(udp_to_app_lock_);
			std::for_each(udp_to_app_.begin(), udp_to_app_.end(), [&oss](auto&& entry)
			{
				oss << std::string(entry.first.ip) << " : " << entry.first.port <<
					" : " << entry.second->id << " : " << wstring_to_string(entry.second->name) << std::endl;
			});

			return oss.str();
		}

	private:
		/// <summary>
		/// Convert wide char string to char string. Valid only for ASCII strings
		/// </summary>
		/// <param name="s">wide char string to convert</param>
		/// <returns></returns>
		static std::string wstring_to_string(const std::wstring& s)
		{
			std::string result;
			std::transform(s.begin(), s.end(), std::back_inserter(result),
			               [](auto&& e) { return static_cast<char>(e); });
			return result;
		}

		/// <summary>
		/// Initializes/updates TCP hashtable
		/// </summary>
		/// <returns>true is successful, false otherwise</returns>
		bool initialize_tcp_table()
		{
			try
			{
				auto table_size = table_buffer_size_;

				tcp_to_app_.clear();

				do
				{
					const uint32_t result = ::GetExtendedTcpTable(table_buffer_.get(), &table_size, FALSE, T::af_type,
					                                              TCP_TABLE_OWNER_MODULE_CONNECTIONS, 0);

					if (result == ERROR_INSUFFICIENT_BUFFER)
					{
						table_size *= 2;
						table_buffer_ = std::make_unique<char[]>(static_cast<std::size_t>(table_size));
						table_buffer_size_ = table_size;
						continue;
					}

					if (result == NO_ERROR)
					{
						break;
					}

					return false;
				}
				while (true);

				if constexpr (std::is_same<T, net::ip_address_v4>::value)
				{
					auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_MODULE>(table_buffer_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						DWORD size = 0;
						std::shared_ptr<network_process> process_ptr(nullptr);

						if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcpEntry(
							&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
						{
							auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

							if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
								GetOwnerModuleFromTcpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info, &size)
								== NO_ERROR)
							{
								process_ptr = std::make_shared<network_process>(
									table->table[i].dwOwningPid, info->pModuleName, info->pModulePath);
							}
						}

						if (process_ptr)
							tcp_to_app_[net::ip_session<T>(
								T{table->table[i].dwLocalAddr},
								T{table->table[i].dwRemoteAddr},
								ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)),
								ntohs(static_cast<unsigned short>(table->table[i].dwRemotePort)))] = std::move(
								process_ptr);
					}
				}
				else
				{
					auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_MODULE>(table_buffer_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						DWORD size = 0;
						std::shared_ptr<network_process> process_ptr(nullptr);

						if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromTcp6Entry(
							&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
						{
							auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

							if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
								GetOwnerModuleFromTcp6Entry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info,
								                            &size) == NO_ERROR)
							{
								process_ptr = std::make_shared<network_process>(
									table->table[i].dwOwningPid, info->pModuleName,
									info->pModulePath);
							}
						}

						if (process_ptr)
							tcp_to_app_[net::ip_session<T>(
								T{table->table[i].ucLocalAddr},
								T{table->table[i].ucRemoteAddr},
								ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)),
								ntohs(static_cast<unsigned short>(table->table[i].dwRemotePort)))] = std::move(
								process_ptr);
					}
				}
			}
			catch (...)
			{
				return false;
			}

			return true;
		}

		/// <summary>
		/// Initializes/updates UDP hashtable
		/// </summary>
		/// <returns>true is successful, false otherwise</returns>
		bool initialize_udp_table()
		{
			auto table_size = table_buffer_size_;

			udp_to_app_.clear();

			try
			{
				do
				{
					const uint32_t result = ::GetExtendedUdpTable(table_buffer_.get(), &table_size, FALSE, T::af_type,
					                                              UDP_TABLE_OWNER_MODULE, 0);

					if (result == ERROR_INSUFFICIENT_BUFFER)
					{
						table_size *= 2;
						table_buffer_ = std::make_unique<char[]>(static_cast<std::size_t>(table_size));
						table_buffer_size_ = table_size;
						continue;
					}

					if (result == NO_ERROR)
					{
						break;
					}

					return false;
				}
				while (true);

				if constexpr (std::is_same<T, net::ip_address_v4>::value)
				{
					auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_MODULE>(table_buffer_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						DWORD size = 0;
						std::shared_ptr<network_process> process_ptr(nullptr);

						if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdpEntry(
							&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
						{
							auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

							if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
								GetOwnerModuleFromUdpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info, &size)
								== NO_ERROR)
							{
								process_ptr = std::make_shared<network_process>(
									table->table[i].dwOwningPid, info->pModuleName,
									info->pModulePath);
							}
						}

						if (process_ptr)
							udp_to_app_[net::ip_endpoint<T>(
								T{table->table[i].dwLocalAddr},
								ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)))] = std::move(
								process_ptr);
					}
				}
				else
				{
					auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_MODULE>(table_buffer_.get());

					for (size_t i = 0; i < table->dwNumEntries; i++)
					{
						DWORD size = 0;
						std::shared_ptr<network_process> process_ptr(nullptr);

						if (ERROR_INSUFFICIENT_BUFFER == GetOwnerModuleFromUdp6Entry(
							&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, nullptr, &size))
						{
							auto module_ptr = std::make_unique<char[]>(static_cast<size_t>(size));

							if (auto* info = reinterpret_cast<PTCPIP_OWNER_MODULE_BASIC_INFO>(module_ptr.get());
								GetOwnerModuleFromUdp6Entry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC, info,
								                            &size) == NO_ERROR)
							{
								process_ptr = std::make_shared<network_process>(
									table->table[i].dwOwningPid, info->pModuleName,
									info->pModulePath);
							}
						}

						if (process_ptr)
							udp_to_app_[net::ip_endpoint<T>(
								T{table->table[i].ucLocalAddr},
								ntohs(static_cast<unsigned short>(table->table[i].dwLocalPort)))] = std::move(
								process_ptr);
					}
				}
			}
			catch (...)
			{
				return false;
			}

			return true;
		}
	};
}
