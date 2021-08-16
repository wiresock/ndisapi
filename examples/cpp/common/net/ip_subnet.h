#pragma once

namespace net
{
	/// <summary>
	/// Represents IPv4/IPv6 subnet
	/// </summary>
	/// <typeparam name="T">net::ip_address_v4 or net::ip_address_v6</typeparam>
	template <typename T>
	struct ip_subnet
	{
		// --------------------------------------------------------------------------------
		/// <summary>
		/// Helper struct for IPv6 calculations
		/// </summary>
		// --------------------------------------------------------------------------------
		struct ip6_addr
		{
			union
			{
				uint8_t byte[16];
				uint16_t word[8];
				uint32_t dword[4];
				uint64_t qword[2];
			} u;
		};

		/// <summary>
		/// IP subnet address
		/// </summary>
		T address;

		/// <summary>
		/// IP subnet network mask
		/// </summary>
		T mask;

		/// <summary>
		/// Default constructor
		/// </summary>
		ip_subnet() = default;

		/// <summary>
		/// Constructs single IP subnet from IP address (192.168.1.1/32 or 2001::1/128)
		/// </summary>
		/// <param name="ip">IP address to create the subnet</param>
		explicit ip_subnet(const T& ip) : address(ip) { memset(reinterpret_cast<char*>(&mask), 0xFF, sizeof(T)); }

		/// <summary>
		/// Constructs single IP subnet from IP address string representation (192.168.1.1/32 or 2001::1/128)
		/// </summary>
		/// <param name="ip">string with IP address to create the subnet</param>
		explicit ip_subnet(const std::string& ip) : address(ip)
		{
			memset(reinterpret_cast<char*>(&mask), 0xFF, sizeof(T));
		}

		/// <summary>
		/// Constructs single IP subnet from IP address wide char string representation (192.168.1.1/32 or 2001::1/128)
		/// </summary>
		/// <param name="ip">wide char string with IP address to create the subnet</param>
		explicit ip_subnet(const std::wstring& ip) : address(ip)
		{
			memset(reinterpret_cast<char*>(&mask), 0xFF, sizeof(T));
		}

		/// <summary>
		/// Constructs object from provided IP address and mask
		/// </summary>
		/// <param name="ip">subnet IP address</param>
		/// <param name="mask">subnet network mask</param>
		ip_subnet(const T& ip, const T& mask) : address(ip), mask(mask)
		{
		}

		/// <summary>
		/// Constructs object from provided IP address and mask strings
		/// </summary>
		/// <param name="ip">string with subnet IP address</param>
		/// <param name="mask">string with subnet network mask</param>
		ip_subnet(const std::string& ip, const std::string& mask) : address(ip), mask(mask)
		{
		}

		/// <summary>
		/// Constructs object from provided IP address and mask wide char strings
		/// </summary>
		/// <param name="ip">wide char string with subnet IP address</param>
		/// <param name="mask">wide char string with subnet network mask</param>
		ip_subnet(const std::wstring& ip, const std::wstring& mask) : address(ip), mask(mask)
		{
		}

		/// <summary>
		/// Gets subnet address
		/// </summary>
		/// <returns>subnet IP address</returns>
		[[nodiscard]] T get_address() const { return address; }

		/// <summary>
		/// Gets subnet network mask
		/// </summary>
		/// <returns>subnet network mask</returns>
		[[nodiscard]] T get_mask() const { return mask; }

		/// <summary>
		/// Gets subnet mask as network prefix
		/// </summary>
		/// <returns></returns>
		[[nodiscard]] uint8_t get_prefix() const
		{
			if constexpr (std::is_same<std::decay_t<T>, ip_address_v6>::value)
			{
				auto ip_subnet_mask_ptr = reinterpret_cast<const ip6_addr*>(&mask);
				return static_cast<uint8_t>(std::bitset<32>(ip_subnet_mask_ptr->u.dword[0]).count() + std::bitset<
						32>(ip_subnet_mask_ptr->u.dword[1]).count() +
					std::bitset<32>(ip_subnet_mask_ptr->u.dword[2]).count() + std::bitset<32>(ip_subnet_mask_ptr
						->u.dword[3]).count());
			}
			else if constexpr (std::is_same<std::decay_t<T>, ip_address_v4>::value)
			{
				const auto ip_subnet_mask_ptr = reinterpret_cast<const in_addr*>(&mask);
				return static_cast<uint8_t>(std::bitset<32>(ip_subnet_mask_ptr->S_un.S_addr).count());
			}
			return 0;
		}

		/// <summary>
		/// Gets string representation of subnet as IP/prefix (e.g. '192.168.1.0/24')
		/// </summary>
		explicit operator std::string() const
		{
			return std::string(get_address()) + "/" + std::to_string(get_prefix());
		}

		/// <summary>
		/// Gets wide char string representation of subnet as IP/prefix (e.g. '192.168.1.0/24')
		/// </summary>
		explicit operator std::wstring() const
		{
			return std::wstring(get_address()) + L"/" + std::to_wstring(get_prefix());
		}

		/// <summary>
		/// Equality operator for ip_subnet
		/// </summary>
		/// <param name="rhs">value to compare to</param>
		/// <returns>true if subnets are equal</returns>
		bool operator ==(const ip_subnet<T>& rhs) const { return (address == rhs.address) && (mask == rhs.mask); }

		/// <summary>
		/// Checks if specified IP address belongs to this subnet
		/// </summary>
		/// <param name="ip">IP address to check</param>
		/// <returns>true if specified IP address belongs to this subnet</returns>
		[[nodiscard]] bool address_in_subnet(T ip) const
		{
			if constexpr (std::is_same<std::decay_t<T>, ip_address_v6>::value)
			{
				auto ip_ptr = reinterpret_cast<ip6_addr*>(&ip);
				auto ip_subnet_ptr = reinterpret_cast<const ip6_addr*>(this);

				if (auto ip_subnet_mask_ptr = reinterpret_cast<const ip6_addr*>(&mask); ((ip_ptr->u.qword[0] &
						ip_subnet_mask_ptr->u.qword[0]) == (ip_subnet_ptr->u.qword[0] &
						ip_subnet_mask_ptr->u.qword[0])) &&
					((ip_ptr->u.qword[1] & ip_subnet_mask_ptr->u.qword[1]) == (ip_subnet_ptr->u.qword[1] &
						ip_subnet_mask_ptr->u.qword[1])))
					return true;
			}
			else if constexpr (std::is_same<std::decay_t<T>, ip_address_v4>::value)
			{
				const auto ip_ptr = reinterpret_cast<in_addr*>(&ip);
				const auto ip_subnet_ptr = reinterpret_cast<const in_addr*>(this);

				if (const auto ip_subnet_mask_ptr = reinterpret_cast<const in_addr*>(&mask); (ip_ptr->S_un.S_addr &
					ip_subnet_mask_ptr->S_un.S_addr) == (ip_subnet_ptr->S_un.S_addr &
					ip_subnet_mask_ptr->S_un.S_addr))
					return true;
			}

			return false;
		}
	};
}
