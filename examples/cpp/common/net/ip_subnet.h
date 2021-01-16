#pragma once

namespace net
{
	template<typename T>
	struct ip_subnet
	{
		// --------------------------------------------------------------------------------
		/// <summary>
		/// Helper struct for IPv6 calculations
		/// </summary>
		// --------------------------------------------------------------------------------
		struct ip6_addr {
			union {
				uint8_t     byte[16];
				uint16_t    word[8];
				uint32_t	dword[4];
				uint64_t	qword[2];
			} u;
		};

		T address;
		T mask;

		ip_subnet() = default;

		explicit ip_subnet(const T& ip) :address(ip) { memset(reinterpret_cast<char*>(&mask), 0xFF, sizeof(T)); }
		explicit ip_subnet(const std::string& ip) : address(ip) { memset(reinterpret_cast<char*>(&mask), 0xFF, sizeof(T)); }
		explicit ip_subnet(const std::wstring& ip) : address(ip) { memset(reinterpret_cast<char*>(&mask), 0xFF, sizeof(T)); }

		ip_subnet(const T& ip, const T& mask) :address(ip), mask(mask) {}
		ip_subnet(const std::string& ip, const std::string& mask) : address(ip), mask(mask) {}
		ip_subnet(const std::wstring& ip, const std::wstring& mask) : address(ip), mask(mask) {}

		[[nodiscard]] T get_address() const { return address; }
		[[nodiscard]] T get_mask() const { return mask; }

		uint8_t get_prefix() const
		{
			if constexpr (std::is_same<std::decay_t<T>, net::ip_address_v6>::value)
			{
				auto ip_subnet_mask_ptr = reinterpret_cast<ip6_addr const*>(&mask);
				return static_cast<uint8_t>(std::bitset<32>(ip_subnet_mask_ptr->u.dword[0]).count() + std::bitset<32>(ip_subnet_mask_ptr->u.dword[1]).count() +
					std::bitset<32>(ip_subnet_mask_ptr->u.dword[2]).count() + std::bitset<32>(ip_subnet_mask_ptr->u.dword[3]).count());
			}
			else if constexpr (std::is_same<std::decay_t<T>, net::ip_address_v4>::value)
			{
				const auto ip_subnet_mask_ptr = reinterpret_cast<in_addr const*>(&mask);
				return static_cast<uint8_t>(std::bitset<32>(ip_subnet_mask_ptr->S_un.S_addr).count());
			}
		}

		explicit operator std::string() const
		{
			return std::string(get_address()) + "/" + std::to_string(get_prefix());
		}

		explicit operator std::wstring() const
		{
			return std::wstring(get_address()) + L"/" + std::to_wstring(get_prefix());
		}

		bool operator ==(const ip_subnet<T>& rhs) const { return T::operator==(rhs) && (mask == rhs.mask); }

		[[nodiscard]] bool address_in_subnet(T ip) const
		{
			if constexpr (std::is_same<std::decay_t<T>, net::ip_address_v6>::value)
			{
				auto ip_ptr = reinterpret_cast<ip6_addr*>(&ip);
				auto ip_subnet_ptr = reinterpret_cast<ip6_addr const*>(this);
				auto ip_subnet_mask_ptr = reinterpret_cast<ip6_addr const*>(&mask);

				if (((ip_ptr->u.qword[0] & ip_subnet_mask_ptr->u.qword[0]) == (ip_subnet_ptr->u.qword[0] & ip_subnet_mask_ptr->u.qword[0])) &&
					((ip_ptr->u.qword[1] & ip_subnet_mask_ptr->u.qword[1]) == (ip_subnet_ptr->u.qword[1] & ip_subnet_mask_ptr->u.qword[1])))
					return true;
			}
			else if constexpr (std::is_same<std::decay_t<T>, net::ip_address_v4>::value)
			{
				const auto ip_ptr = reinterpret_cast<in_addr*>(&ip);
				const auto ip_subnet_ptr = reinterpret_cast<in_addr const*>(this);
				const auto ip_subnet_mask_ptr = reinterpret_cast<in_addr const*>(&mask);

				if ((ip_ptr->S_un.S_addr & ip_subnet_mask_ptr->S_un.S_addr) == (ip_subnet_ptr->S_un.S_addr & ip_subnet_mask_ptr->S_un.S_addr))
					return true;
			}

			return false;
		}
	};
}
