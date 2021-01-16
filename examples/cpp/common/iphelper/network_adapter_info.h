// ReSharper disable CppSpecialFunctionWithoutNoexceptSpecification
#pragma once

namespace iphelper {
	
	inline bool operator==(const IF_LUID& lhs, const IF_LUID& rhs) { return (lhs.Value == rhs.Value) && (lhs.Info.IfType == rhs.Info.IfType) && (lhs.Info.NetLuidIndex == rhs.Info.NetLuidIndex); }
	inline bool operator!=(const IF_LUID& lhs, const IF_LUID& rhs) { return !(lhs == rhs); }
	inline bool operator<(const IF_LUID& lhs, const IF_LUID& rhs) { return std::tie(lhs.Value, lhs.Info.IfType, lhs.Info.NetLuidIndex) < std::tie(rhs.Value, rhs.Info.IfType, rhs.Info.NetLuidIndex); }
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Simple wrapper for SOCKADDR
	/// </summary>
	// --------------------------------------------------------------------------------
	struct ip_address_info : SOCKADDR_STORAGE
	{
		ip_address_info() : SOCKADDR_STORAGE() {}
		explicit ip_address_info(const sockaddr& address) : SOCKADDR_STORAGE() { *reinterpret_cast<sockaddr*>(this) = address; }
		explicit ip_address_info(const sockaddr_in& address) : SOCKADDR_STORAGE() { *reinterpret_cast<sockaddr_in*>(this) = address; }
		explicit ip_address_info(const sockaddr_in6& address) : SOCKADDR_STORAGE() { *reinterpret_cast<sockaddr_in6*>(this) = address; }
		explicit ip_address_info(SOCKET_ADDRESS& address) : SOCKADDR_STORAGE() { memcpy(this, address.lpSockaddr, address.iSockaddrLength); }

		explicit operator sockaddr() const { return *reinterpret_cast<sockaddr*>(const_cast<ip_address_info*>(this)); }
		explicit operator sockaddr_in() const { return *reinterpret_cast<sockaddr_in*>(const_cast<ip_address_info*>(this)); }
		explicit operator sockaddr_in6() const { return *reinterpret_cast<sockaddr_in6*>(const_cast<ip_address_info*>(this)); }
		
		bool operator==(const ip_address_info& rhs) const
		{
			if (ss_family != rhs.ss_family)
				return false;

			switch (ss_family)
			{
			case AF_INET:
				return ((reinterpret_cast<sockaddr_in const*>(this))->sin_addr.S_un.S_addr == (reinterpret_cast<sockaddr_in const&>(rhs)).sin_addr.S_un.S_addr);
			case AF_INET6:
				return (0 == std::memcmp(reinterpret_cast<sockaddr_in6 const*>(this)->sin6_addr.u.Word, reinterpret_cast<sockaddr_in6 const&>(rhs).sin6_addr.u.Word, sizeof(sockaddr_in6::sin6_addr)));
			default:
				break;
			}

			return false;
		}

		explicit operator std::string() const
		{
			return (ss_family == AF_INET) ?
				std::string(net::ip_address_v4((reinterpret_cast<sockaddr_in const*>(this))->sin_addr)) :
				std::string(net::ip_address_v6((reinterpret_cast<sockaddr_in6 const*>(this)->sin6_addr)));
		}

		explicit operator std::wstring() const
		{
			return (ss_family == AF_INET) ?
				std::wstring(net::ip_address_v4((reinterpret_cast<sockaddr_in const*>(this))->sin_addr)) :
				std::wstring(net::ip_address_v6(reinterpret_cast<sockaddr_in6 const*>(this)->sin6_addr));
		}
	};

	struct ip_gateway_info : ip_address_info
	{
		ip_gateway_info(const sockaddr& address, const net::mac_address& hwaddr = net::mac_address()) : ip_address_info(address), m_HwAddress(hwaddr) {}
		ip_gateway_info(SOCKET_ADDRESS& address, const net::mac_address& hwaddr = net::mac_address()) : ip_address_info(address), m_HwAddress(hwaddr) {}

		net::mac_address m_HwAddress;
	};

	struct guid_wrapper : GUID
	{
		guid_wrapper() = default;
		explicit guid_wrapper(const GUID& guid) : GUID(guid) {}

		template<typename T>
		explicit operator std::basic_string<T>() const {
			std::basic_ostringstream<T> oss;
			oss << std::hex
				<< std::uppercase
				<< "{"
				<< std::setfill(T('0')) << std::setw(8)
				<< Data1 << "-"
				<< std::setfill(T('0')) << std::setw(4)
				<< Data2 << "-"
				<< std::setfill(T('0')) << std::setw(4)
				<< Data3 << "-"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[0])
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[1]) << "-"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[2])
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[3])
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[4])
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[5])
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[6])
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (Data4[7])
				<< "}";

			return oss.str();
		}
	};

	class network_adapter_info
	{
	public:
		
		network_adapter_info(PIP_ADAPTER_ADDRESSES address, PMIB_IF_TABLE2 if_table, const size_t index) :
			if_index_(address->IfIndex),
			ipv6_if_index_(address->Ipv6IfIndex),
			adapter_name_(address->AdapterName),
			description_(address->Description),
			friendly_name_(address->FriendlyName),
			physical_address_(address->PhysicalAddress),
			mtu_(static_cast<uint16_t>(address->Mtu)),
			if_type_(address->IfType),
			transmit_link_speed_(address->TransmitLinkSpeed),
			receive_link_speed_(address->ReceiveLinkSpeed),
			luid_(address->Luid),
			media_type_(if_table->Table[index].MediaType),
			physical_medium_type_(if_table->Table[index].PhysicalMediumType)
		{
			// Initialize from IP_ADAPTER_ADDRESSES
			auto unicast_address = address->FirstUnicastAddress;
			while (unicast_address)
			{
				unicast_address_list_.emplace_back(unicast_address->Address);
				unicast_address = unicast_address->Next;
			}

			auto dns_address = address->FirstDnsServerAddress;
			while (dns_address)
			{
				dns_server_address_list_.emplace_back(dns_address->Address);
				dns_address = dns_address->Next;
			}

			auto gateway_address = address->FirstGatewayAddress;
			while (gateway_address)
			{
				gateway_address_list_.emplace_back(gateway_address->Address);
				gateway_address = gateway_address->Next;
			}

			// Initialize MAC addresses for the network gateways
			if ((address->IfType == IF_TYPE_ETHERNET_CSMACD) ||
				(address->IfType == IF_TYPE_IEEE80211))
				initialize_gateway_hw_address_list();

			if (if_table->Table[index].PhysicalMediumType == NdisPhysicalMediumUnspecified)
			{
				// For unknown physical media interface (usually virtual interfaces) try to lookup the underlying media
				for (size_t i = 0; i < if_table->NumEntries; ++i)
				{
					if ((i != index) && // different entry from the current one
						(if_table->Table[i].MediaConnectState == MediaConnectStateConnected) && // in connected state
						(if_table->Table[i].PhysicalAddressLength == ETH_ALEN) && // has ethernet address
						(if_table->Table[i].PhysicalMediumType != NdisPhysicalMediumUnspecified) && // has real network media set
						(net::mac_address(if_table->Table[i].PhysicalAddress) == physical_address_) && // and equal MAC address
						(if_table->Table[i].InterfaceAndOperStatusFlags.HardwareInterface) // and real hardware interface
						)
					{
						true_medium_type_ = if_table->Table[i].PhysicalMediumType;
						true_adapter_name_ = guid_wrapper(if_table->Table[i].InterfaceGuid);
					}
				}
			}
		}

		network_adapter_info(const network_adapter_info& other) = default;
		network_adapter_info(network_adapter_info&& other) noexcept = default;
		network_adapter_info& operator=(const network_adapter_info& other) = default;
		network_adapter_info& operator=(network_adapter_info&& other) noexcept = default;
		
		[[nodiscard]] unsigned long get_if_index() const noexcept { return if_index_; }
		[[nodiscard]] unsigned long get_ipv6_if_index() const noexcept { return ipv6_if_index_; }

		[[nodiscard]] const std::string& get_adapter_name() const noexcept { return adapter_name_; }
		[[nodiscard]] std::string get_true_adapter_name() const { return std::string (true_adapter_name_); }
		[[nodiscard]] const std::wstring& get_description() const noexcept { return description_; }
		[[nodiscard]] const std::wstring& get_friendly_name() const noexcept { return friendly_name_; }

		[[nodiscard]] const std::vector<ip_address_info>& get_unicast_address_list() const noexcept { return unicast_address_list_; }
		[[nodiscard]] const std::vector<ip_address_info>& get_dns_server_address_list() const noexcept { return dns_server_address_list_; }
		[[nodiscard]] const std::vector<ip_gateway_info>& get_gateway_address_list() const noexcept { return gateway_address_list_; }

		[[nodiscard]] bool has_address(ip_address_info const& address) const
		{
			return unicast_address_list_.cend() != std::find(unicast_address_list_.cbegin(), unicast_address_list_.cend(), address);
		}

		[[nodiscard]] const net::mac_address& get_physical_address() const noexcept { return physical_address_; }
		[[nodiscard]] uint16_t get_mtu() const noexcept { return mtu_; }
		[[nodiscard]] unsigned get_if_type() const noexcept { return if_type_; }
		[[nodiscard]] IF_LUID get_luid() const noexcept { return luid_; }

		bool operator ==(const network_adapter_info& rhs) const { return luid_ == rhs.luid_; }
		bool operator !=(const network_adapter_info& rhs) const { return (luid_ != rhs.luid_); }
		bool operator <(const network_adapter_info& rhs) const { return (luid_ < rhs.luid_); }
		
		template<bool BCheckGateway = true>
		[[nodiscard]] bool is_same_address_info(const network_adapter_info& rhs) const
		{
			auto retval = true;

			if (unicast_address_list_.size() != rhs.unicast_address_list_.size())
				return false;

			if constexpr (BCheckGateway)
			{
				if (gateway_address_list_.size() != rhs.gateway_address_list_.size())
					return false;
			}

			// Check if any of the unicast addresses have changed
			std::for_each(rhs.unicast_address_list_.cbegin(), rhs.unicast_address_list_.cend(), [&retval, this](auto& address) {
				if (unicast_address_list_.cend() == std::find(unicast_address_list_.cbegin(), unicast_address_list_.cend(), address))
					retval = false;
			});

			if (retval == false)
				return retval;

			// Check if any of the gateways have changed
			if constexpr (BCheckGateway)
			{
				std::for_each(rhs.gateway_address_list_.cbegin(), rhs.gateway_address_list_.cend(), [&retval, this](auto& address) {
					if (gateway_address_list_.cend() == std::find(gateway_address_list_.cbegin(), gateway_address_list_.cend(), address))
						retval = false;
				});
			}

			return retval;
		}

		[[nodiscard]] NDIS_MEDIUM get_media_type() const { return media_type_; }
		[[nodiscard]] NDIS_PHYSICAL_MEDIUM get_physical_medium_type() const { return physical_medium_type_; }
		[[nodiscard]] NDIS_PHYSICAL_MEDIUM get_true_physical_medium_type() const { return true_medium_type_; }

		[[nodiscard]] ULONG64 transmit_link_speed() const
		{
			return transmit_link_speed_;
		}

		[[nodiscard]] ULONG64 receive_link_speed() const
		{
			return receive_link_speed_;
		}

		[[nodiscard]] std::unique_ptr<MIB_UNICASTIPADDRESS_ROW> add_unicast_address(const net::ip_address_v4 address, const uint8_t prefix_length) const
		{
			auto address_row = std::make_unique<MIB_UNICASTIPADDRESS_ROW>();
			
			::InitializeUnicastIpAddressEntry(address_row.get());
			
			address_row->Address.Ipv4.sin_family = AF_INET;
			address_row->Address.Ipv4.sin_addr = address;
			address_row->Address.si_family = AF_INET;
			
			address_row->InterfaceIndex = if_index_;
			address_row->InterfaceLuid = luid_;

			address_row->PrefixOrigin = IpPrefixOriginManual;
			address_row->SuffixOrigin = IpSuffixOriginManual;
			address_row->OnLinkPrefixLength = prefix_length;
			
			if (NO_ERROR == ::CreateUnicastIpAddressEntry(address_row.get()))
				return address_row;

			return nullptr;
		}

		[[nodiscard]] std::unique_ptr<MIB_UNICASTIPADDRESS_ROW> add_unicast_address(const net::ip_address_v6& address, const uint8_t prefix_length) const
		{
			auto address_row = std::make_unique<MIB_UNICASTIPADDRESS_ROW>();

			::InitializeUnicastIpAddressEntry(address_row.get());

			address_row->Address.Ipv6.sin6_family = AF_INET6;
			address_row->Address.Ipv6.sin6_addr = address;
			address_row->Address.si_family = AF_INET6;
			
			address_row->InterfaceIndex = ipv6_if_index_;
			address_row->InterfaceLuid = luid_;
			
			address_row->PrefixOrigin = IpPrefixOriginManual;
			address_row->SuffixOrigin = IpSuffixOriginManual;
			address_row->OnLinkPrefixLength = prefix_length;

			if (const auto status = ::CreateUnicastIpAddressEntry(address_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
				return address_row;

			return nullptr;
		}

		[[nodiscard]] static bool delete_unicast_address(const std::unique_ptr<MIB_UNICASTIPADDRESS_ROW> address)
		{
			return NO_ERROR == ::DeleteUnicastIpAddressEntry(address.get());
		}

		[[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> add_default_gateway(const net::ip_address_v4& address) const
		{
			auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
			::InitializeIpForwardEntry(forward_row.get());

			forward_row->InterfaceIndex = if_index_;
			forward_row->InterfaceLuid = luid_;
			forward_row->DestinationPrefix.Prefix.si_family = AF_INET;
			forward_row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
			forward_row->NextHop.si_family = AF_INET;
			forward_row->NextHop.Ipv4.sin_family = AF_INET;
			forward_row->NextHop.Ipv4.sin_addr = address;
			forward_row->SitePrefixLength = 0;
			forward_row->Metric = 1;
			forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
			forward_row->Origin = NlroManual;

			if (const auto status = ::CreateIpForwardEntry2(forward_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
				return forward_row;

			return nullptr;
		}

		[[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> add_default_gateway(const net::ip_address_v6& address) const
		{
			auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
			::InitializeIpForwardEntry(forward_row.get());

			forward_row->InterfaceIndex = ipv6_if_index_;
			forward_row->InterfaceLuid = luid_;
			forward_row->DestinationPrefix.Prefix.si_family = AF_INET6;
			forward_row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
			forward_row->NextHop.si_family = AF_INET6;
			forward_row->NextHop.Ipv6.sin6_family = AF_INET6;
			forward_row->NextHop.Ipv6.sin6_addr = address;
			forward_row->SitePrefixLength = 0;
			forward_row->Metric = 1;
			forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
			forward_row->Origin = NlroManual;

			if (const auto status = ::CreateIpForwardEntry2(forward_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
				return forward_row;

			return nullptr;
		}

		[[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> assign_default_gateway_v4(const uint32_t metric = 0) const
		{
			auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
			::InitializeIpForwardEntry(forward_row.get());

			forward_row->InterfaceIndex = if_index_;
			forward_row->InterfaceLuid = luid_;
			forward_row->DestinationPrefix.Prefix.si_family = AF_INET;
			forward_row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
			forward_row->NextHop.si_family = AF_INET;
			forward_row->NextHop.Ipv4.sin_family = AF_INET;
			forward_row->NextHop.Ipv4.sin_addr = net::ip_address_v4{};
			forward_row->SitePrefixLength = 0;
			forward_row->Metric = metric;
			forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
			forward_row->Origin = NlroManual;

			if (const auto status = ::CreateIpForwardEntry2(forward_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
				return forward_row;

			return nullptr;
		}

		[[nodiscard]] std::unique_ptr<MIB_IPFORWARD_ROW2> assign_default_gateway_v6(const uint32_t metric = 0) const
		{
			auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
			::InitializeIpForwardEntry(forward_row.get());

			forward_row->InterfaceIndex = ipv6_if_index_;
			forward_row->InterfaceLuid = luid_;
			forward_row->DestinationPrefix.Prefix.si_family = AF_INET6;
			forward_row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
			forward_row->NextHop.si_family = AF_INET6;
			forward_row->NextHop.Ipv6.sin6_family = AF_INET6;
			forward_row->NextHop.Ipv6.sin6_addr = net::ip_address_v6{};
			forward_row->SitePrefixLength = 0;
			forward_row->Metric = metric;
			forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
			forward_row->Origin = NlroManual;

			if (const auto status = ::CreateIpForwardEntry2(forward_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
				return forward_row;

			return nullptr;
		}

		[[nodiscard]] std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> configure_allowed_ips_v4(const std::vector<std::variant<net::ip_subnet<net::ip_address_v4>, net::ip_subnet<net::ip_address_v6>>>& ips) const
		{
			std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> retval;

			std::for_each(ips.cbegin(), ips.cend(), [this, &retval](auto&& v)
				{
					if (auto subnet_v4_ptr = std::get_if<net::ip_subnet<net::ip_address_v4>>(&v); subnet_v4_ptr)
					{
						auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
						::InitializeIpForwardEntry(forward_row.get());

						forward_row->InterfaceIndex = if_index_;
						forward_row->InterfaceLuid = luid_;
						forward_row->DestinationPrefix.Prefix.si_family = AF_INET;
						forward_row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
						forward_row->DestinationPrefix.Prefix.Ipv4.sin_addr = subnet_v4_ptr->get_address();
						forward_row->DestinationPrefix.PrefixLength = subnet_v4_ptr->get_prefix();
						forward_row->NextHop.si_family = AF_INET;
						forward_row->NextHop.Ipv4.sin_family = AF_INET;
						forward_row->NextHop.Ipv4.sin_addr = net::ip_address_v4{}; 
						forward_row->SitePrefixLength = 0; 
						forward_row->Metric = 0;
						forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
						forward_row->Origin = NlroManual;

						if (const auto status = ::CreateIpForwardEntry2(forward_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
							retval.push_back(std::move(forward_row));
					}
				});

			return retval;
		}

		[[nodiscard]] std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> configure_allowed_ips_v6(const std::vector<std::variant<net::ip_subnet<net::ip_address_v4>, net::ip_subnet<net::ip_address_v6>>>& ips) const
		{
			std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> retval;

			std::for_each(ips.cbegin(), ips.cend(), [this, &retval](auto&& v)
				{
					if (auto subnet_v6_ptr = std::get_if<net::ip_subnet<net::ip_address_v6>>(&v); subnet_v6_ptr)
					{
						auto forward_row = std::make_unique<MIB_IPFORWARD_ROW2>();
						::InitializeIpForwardEntry(forward_row.get());

						forward_row->InterfaceIndex = ipv6_if_index_;
						forward_row->InterfaceLuid = luid_;
						forward_row->DestinationPrefix.Prefix.si_family = AF_INET6;
						forward_row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
						forward_row->DestinationPrefix.Prefix.Ipv6.sin6_addr = subnet_v6_ptr->get_address();
						forward_row->DestinationPrefix.PrefixLength = subnet_v6_ptr->get_prefix();
						forward_row->NextHop.si_family = AF_INET6;
						forward_row->NextHop.Ipv6.sin6_family = AF_INET6;
						forward_row->NextHop.Ipv6.sin6_addr = net::ip_address_v6{};
						forward_row->SitePrefixLength = 0;
						forward_row->Metric = 0;
						forward_row->Protocol = MIB_IPPROTO_NT_STATIC;
						forward_row->Origin = NlroManual;

						if (const auto status = ::CreateIpForwardEntry2(forward_row.get()); status == NO_ERROR || status == ERROR_OBJECT_ALREADY_EXISTS)
							retval.push_back(std::move(forward_row));
					}
				});
			
			return retval;
		}

		[[nodiscard]] static bool delete_routes(const std::unique_ptr<MIB_IPFORWARD_ROW2> address)
		{
			return NO_ERROR == ::DeleteIpForwardEntry2(address.get());
		}

		[[nodiscard]] static bool delete_routes(std::vector<std::unique_ptr<MIB_IPFORWARD_ROW2>> address)
		{
			auto status = true;

			std::for_each(address.begin(), address.end(), [&status](auto&& a)
			{
				status = status && ::DeleteIpForwardEntry2(a.get());
			});

			return status;
		}

		[[nodiscard]] bool reset_adapter_routes() const
		{
			PMIB_IPFORWARD_TABLE2 table = nullptr;

			if (::GetIpForwardTable2(AF_UNSPEC, &table) == NO_ERROR)
			{
				for (unsigned i = 0; i < table->NumEntries; ++i)
				{
					if (table->Table[i].InterfaceLuid == luid_)
					{
						::DeleteIpForwardEntry2(&table->Table[i]);
					}
				}

				::FreeMibTable(table);
				return true;
			}

			return false;
		}

		[[nodiscard]] bool reset_unicast_addresses() const
		{
			PMIB_UNICASTIPADDRESS_TABLE  table = nullptr;

			if (::GetUnicastIpAddressTable(AF_UNSPEC, &table) == NO_ERROR)
			{
				for (unsigned i = 0; i < table->NumEntries; ++i)
				{
					if (table->Table[i].InterfaceLuid == luid_)
					{
						::DeleteUnicastIpAddressEntry(&table->Table[i]);
					}
				}

				::FreeMibTable(table);
				return true;
			}

			return false;
		}

		[[nodiscard]] bool reset_adapter () const
		{
			return reset_unicast_addresses() && reset_adapter_routes();
		}

		[[nodiscard]] std::unique_ptr<MIB_IPNET_ROW2> add_ndp_entry(const net::ip_address_v4& address, const net::mac_address& hw_address) const
		{
			auto net_row = std::make_unique<MIB_IPNET_ROW2>();
			::RtlSecureZeroMemory(net_row.get(), sizeof(MIB_IPNET_ROW2));

			net_row->Address.si_family = AF_INET;
			net_row->Address.Ipv4.sin_family = AF_INET;
			net_row->Address.Ipv4.sin_addr = address;
			net_row->InterfaceIndex = if_index_;
			net_row->InterfaceLuid = luid_;
			memmove(net_row->PhysicalAddress, hw_address.data.data(), ETH_ALEN);
			net_row->PhysicalAddressLength = ETH_ALEN;
			net_row->State = NlnsPermanent;
			net_row->IsRouter = TRUE;
			net_row->IsUnreachable = TRUE;

			if (NO_ERROR == ::CreateIpNetEntry2(net_row.get()))
				return net_row;
			
			return nullptr;
		}

		[[nodiscard]] std::unique_ptr<MIB_IPNET_ROW2> add_ndp_entry(const net::ip_address_v6& address, const net::mac_address& hw_address) const
		{
			auto net_row = std::make_unique<MIB_IPNET_ROW2>();
			::RtlSecureZeroMemory(net_row.get(), sizeof(MIB_IPNET_ROW2));

			net_row->Address.si_family = AF_INET6;
			net_row->Address.Ipv6.sin6_family = AF_INET6;
			net_row->Address.Ipv6.sin6_addr = address;
			net_row->InterfaceIndex = ipv6_if_index_;
			net_row->InterfaceLuid = luid_;
			memmove(net_row->PhysicalAddress, hw_address.data.data(), ETH_ALEN);
			net_row->PhysicalAddressLength = ETH_ALEN;
			net_row->State = NlnsPermanent;
			net_row->IsRouter = TRUE;
			net_row->IsUnreachable = TRUE;

			if (NO_ERROR == ::CreateIpNetEntry2(net_row.get()))
				return net_row;

			return nullptr;
		}

		[[nodiscard]] static bool delete_ndp_entry(const std::unique_ptr<MIB_IPNET_ROW2> address)
		{
			return NO_ERROR == ::DeleteIpNetEntry2(address.get());
		}

	private:

		void initialize_gateway_hw_address_list() noexcept
		{
			if (!gateway_address_list_.empty())
			{
				std::for_each(gateway_address_list_.begin(), gateway_address_list_.end(), [this](auto& address)
				{
					MIB_IPNET_ROW2 row = { 0 };

					row.Address.si_family = address.ss_family;
					row.InterfaceLuid = luid_;

					switch (address.ss_family)
					{
					case AF_INET:
						row.Address.Ipv4 = sockaddr_in(address);
						break;
					case AF_INET6:
						row.Address.Ipv6 = sockaddr_in6(address);
						break;
					default:
						break;
					}

					auto result = ResolveIpNetEntry2(&row, nullptr);

					if (result == NO_ERROR)
					{
						address.m_HwAddress = net::mac_address(row.PhysicalAddress);
					}

				});
			}
		}

		unsigned long if_index_;				// The index of the IPv4 interface
		unsigned long ipv6_if_index_;			// The interface index for the IPv6 IP address. This member is zero if IPv6 is not available on the interface. 
		std::string adapter_name_;		// Contains the name of the adapter. Unlike an adapter's friendly name, the adapter name specified in adapter_name_ is permanent and cannot be modified by the user.
		guid_wrapper true_adapter_name_{};// Contains the name of the underlying hardware adapter.
		std::wstring description_;		// A description for the adapter. 
		std::wstring friendly_name_;	// A user-friendly name for the adapter. 

		std::vector<ip_address_info>	unicast_address_list_;		// List of IP unicast addresses for the adapter.
		std::vector<ip_address_info>	dns_server_address_list_;		// List of DNS server addresses for the adapter.
		std::vector<ip_gateway_info>	gateway_address_list_;		// List of gateways for the adapter.

		net::mac_address	physical_address_;		// The Media Access Control (MAC) address for the adapter.
		uint16_t			mtu_;					// The maximum transmission unit (MTU) size, in bytes.
		unsigned			if_type_;				// The interface type as defined by the Internet Assigned Names Authority (IANA). Possible values for the interface type are listed in the Ipifcons.h header file. 
		ULONG64				transmit_link_speed_;	// The current speed in bits per second of the transmit link for the adapter.
		ULONG64				receive_link_speed_;	// The current speed in bits per second of the receive link for the adapter. 
		IF_LUID				luid_;					// The interface LUID for the adapter address. 
		
		NDIS_MEDIUM	media_type_;												// The NDIS media type for the interface. This member can be one of the values from the NDIS_MEDIUM enumeration type defined in the Ntddndis.h header file.
		NDIS_PHYSICAL_MEDIUM physical_medium_type_;								// The NDIS physical medium type.This member can be one of the values from the NDIS_PHYSICAL_MEDIUM enumeration type defined in the Ntddndis.h header file.
		NDIS_PHYSICAL_MEDIUM true_medium_type_ = NdisPhysicalMediumUnspecified;	// If value above is NdisPhysicalMediumUnspecified (virtual network interface on top of the real one) this one may contain real physical media

		net::mac_address ndis_wan_ip_link_;
		net::mac_address ndis_wan_ipv6_link_;

		// Static class members
	public:
		static std::vector<network_adapter_info> get_external_network_connections() {
			std::vector<network_adapter_info> ret_val;
			unsigned long dw_size = 0;
			PMIB_IF_TABLE2 mib_table = nullptr;

			// Query detailed information on available network interfaces
			if (NO_ERROR != GetIfTable2(&mib_table))
			{
				return ret_val;
			}

			// Get available unicast addresses
			if ((ERROR_BUFFER_OVERFLOW == ::GetAdaptersAddresses(
				AF_UNSPEC,
				GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS |
				GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, NULL, &dw_size)) && (dw_size))
			{
				do
				{
					auto ip_address_info = std::make_unique<unsigned char[]>(dw_size);

					if (
						const auto status = GetAdaptersAddresses(
							AF_UNSPEC,
							GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
							NULL,
							reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get()),
							&dw_size);
						status == NO_ERROR)
					{
						auto* current_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get());

						while (current_address)
						{
							if ((current_address->FirstUnicastAddress == nullptr) ||
								(current_address->OperStatus != IfOperStatusUp) ||
								(current_address->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
								)
							{
								current_address = current_address->Next;
								continue;
							}

							// Lookup an advanced information on the network interface
							for (size_t i = 0; i < mib_table->NumEntries; ++i)
							{
								if (mib_table->Table[i].InterfaceLuid == current_address->Luid)
								{
									ret_val.emplace_back(current_address, mib_table, i);
									break;
								}
							}

							current_address = current_address->Next;
						}

						break;
					}
					else
					{
						// In case of insufficient buffer size we try to recover by reallocating buffer
						if (status != ERROR_BUFFER_OVERFLOW)
							break;
					}
				} while (true);
			}
			else
			{
				// GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
			}

			// Free interface table
			::FreeMibTable(mib_table);

			return ret_val;
		}
		
		static std::optional<network_adapter_info> get_connection_by_luid(IF_LUID& luid)
		{
			unsigned long dw_size = 0;
			PMIB_IF_TABLE2 mib_table = nullptr;

			// Query detailed information on available network interfaces
			if (NO_ERROR != GetIfTable2(&mib_table))
			{
				return {};
			}

			// Get available unicast addresses
			if ((ERROR_BUFFER_OVERFLOW == ::GetAdaptersAddresses(
				AF_UNSPEC,
				GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS |
				GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, NULL, &dw_size)) && (dw_size))
			{
				do
				{
					auto ip_address_info = std::make_unique<unsigned char[]>(dw_size);

					if (
						const auto status = GetAdaptersAddresses(
							AF_UNSPEC,
							GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES,
							NULL,
							reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get()),
							&dw_size);
						status == NO_ERROR)
					{
						auto* current_address = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(ip_address_info.get());

						while (current_address)
						{
							if (current_address->Luid != luid)
							{
								current_address = current_address->Next;
								continue;
							}

							// Lookup an advanced information on the network interface
							for (size_t i = 0; i < mib_table->NumEntries; ++i)
							{
								if (mib_table->Table[i].InterfaceLuid == current_address->Luid)
								{
									network_adapter_info result{ current_address, mib_table, i };
									::FreeMibTable(mib_table);
									return std::move(result);
								}
							}

							current_address = current_address->Next;
						}

						break;
					}
					else
					{
						// In case of insufficient buffer size we try to recover by reallocating buffer
						if (status != ERROR_BUFFER_OVERFLOW)
							break;
					}
				} while (true);
			}
			else
			{
				// GetAdaptersAddresses has failed with status different from ERROR_BUFFER_OVERFLOW when obtaining required buffer size
			}

			// Free interface table
			::FreeMibTable(mib_table);

			return {};
		}
	};

	template<typename T>
	class network_config_info
	{
		using mutex_type = std::mutex;
		using read_lock = std::unique_lock<mutex_type>;
		using write_lock = std::unique_lock<mutex_type>;

		HANDLE notify_ip_interface_change_{ nullptr };
		std::atomic_uint32_t notify_ip_interface_ref_{ 0 };
		mutex_type lock_;
		
	public:

		network_config_info() = default;

		network_config_info(const network_config_info& other) = delete;

		network_config_info(network_config_info&& other) noexcept 
		{
			write_lock rhs_lk(other.lock_);

			notify_ip_interface_change_ = other.notify_ip_interface_change_;
			other.notify_ip_interface_change_ = nullptr;
			notify_ip_interface_ref_ = other.notify_ip_interface_ref_.exchange(0);
		}

		network_config_info& operator=(const network_config_info& other) = delete;

		network_config_info& operator=(network_config_info&& other)
		{
			if (this == &other)
				return *this;

			write_lock lhs_lk(lock_, std::defer_lock);
			write_lock rhs_lk(other.lock_, std::defer_lock);
			std::lock(lhs_lk, rhs_lk);
			
			notify_ip_interface_change_ = other.notify_ip_interface_change_;
			other.notify_ip_interface_change_ = nullptr;
			
			notify_ip_interface_ref_ = other.notify_ip_interface_ref_.exchange(0);
			return *this;
		}

		~network_config_info()
		{
			if(notify_ip_interface_change_)
				cancel_notify_ip_interface_change();
		}

		static std::optional<network_adapter_info> get_best_interface(const net::ip_address_v4& ip_address)
		{
			unsigned long best_if_index = 0;
			sockaddr_in socket_address{};

			socket_address.sin_family = AF_INET;
			socket_address.sin_addr = ip_address;

			auto adapters = network_adapter_info::get_external_network_connections();

			if (NO_ERROR == ::GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&socket_address), &best_if_index))
			{
				for (auto& adapter : adapters)
				{
					if (adapter.get_if_index() == best_if_index)
						return adapter;
				}
			}

			return {};
		}

		static std::optional<network_adapter_info> get_best_interface(const net::ip_address_v6& ip_address)
		{
			unsigned long best_if_index = 0;
			sockaddr_in6 socket_address{};

			socket_address.sin6_family = AF_INET6;
			socket_address.sin6_addr = ip_address;

			auto adapters = network_adapter_info::get_external_network_connections();

			if (NO_ERROR == ::GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&socket_address), &best_if_index))
			{
				for (auto& adapter : adapters)
				{
					if (adapter.get_if_index() == best_if_index)
						return adapter;
				}
			}

			return {};
		}

		static std::vector<network_adapter_info> get_routable_interfaces(const net::ip_address_v4& ip_address)
		{
			auto is_valid_route = [&ip_address](auto adapter) {
				SOCKADDR_INET dest_address{}, best_route_address{};
				dest_address.si_family = AF_INET;
				dest_address.Ipv4.sin_family = AF_INET;
				dest_address.Ipv4.sin_addr = ip_address;
				MIB_IPFORWARD_ROW2 forward_row{};

				return NO_ERROR != GetBestRoute2(nullptr, adapter.get_if_index(), nullptr, &dest_address, 0, &forward_row, &best_route_address);
			};

			auto adapters = network_adapter_info::get_external_network_connections();

			adapters.erase(std::remove_if(adapters.begin(), adapters.end(), [&is_valid_route](auto a)
			{
					return is_valid_route(a);
			}), adapters.end());

			return adapters;
		}
		
		static std::vector<network_adapter_info> get_routable_interfaces(const net::ip_address_v6& ip_address)
		{
			auto is_valid_route = [&ip_address](auto adapter) {
				SOCKADDR_INET dest_address{}, best_route_address{};
				dest_address.si_family = AF_INET6;
				dest_address.Ipv6.sin6_family = AF_INET6;
				dest_address.Ipv6.sin6_addr = ip_address;
				MIB_IPFORWARD_ROW2 forward_row{};

				return NO_ERROR != GetBestRoute2(nullptr, adapter.get_if_index(), nullptr, &dest_address, 0, &forward_row, &best_route_address);
			};
			
			auto adapters = network_adapter_info::get_external_network_connections();

			adapters.erase(std::remove_if(adapters.begin(), adapters.end(), [&is_valid_route](auto a)
				{
					return is_valid_route(a);
				}), adapters.end());

			return adapters;
		}
	protected:
		
		bool set_notify_ip_interface_change() noexcept
		{
			return (NO_ERROR == ::NotifyIpInterfaceChange(
				       AF_UNSPEC, &network_config_info::ip_interface_changed_callback, this, FALSE,
				       &notify_ip_interface_change_))
				       ? true
				       : false;
		}

		bool cancel_notify_ip_interface_change() noexcept
		{
			const auto result = (NO_ERROR == ::CancelMibChangeNotify2(notify_ip_interface_change_)) ? true : false;

			notify_ip_interface_change_ = nullptr;

			return result;
		}

		static void __stdcall ip_interface_changed_callback (void* caller_context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE notification_type)
		{
			auto* const this_pointer = static_cast<T*>(caller_context);

			if (this_pointer)
			{
				this_pointer->notify_ip_interface_ref_.fetch_add(1);
				this_pointer->ip_interface_changed_callback(row, notification_type);
				this_pointer->notify_ip_interface_ref_.fetch_sub(1);
			}
		}

		bool notify_ip_interface_can_unload() const
		{
			return (notify_ip_interface_ref_ == 0);
		}
	};
}
