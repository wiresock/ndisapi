// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  ip_address.h
/// Abstract: IP address wrappers definitions
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#include <in6addr.h>
#include <ip2string.h>
#include <cassert>

#pragma comment(lib, "ntdll.lib")

namespace net
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Wrapper for in_addr. Represents IP version 4 address.
	/// </summary>
	// --------------------------------------------------------------------------------
	struct ip_address_v4 : in_addr
	{
		static constexpr size_t ipv4_address_max_length = 16;
		static constexpr ADDRESS_FAMILY af_type = AF_INET;

		explicit ip_address_v4(const uint32_t addr = 0) : in_addr() { S_un.S_addr = addr; }
		ip_address_v4(const in_addr& ip) : in_addr() { *static_cast<in_addr*>(this) = ip; }

		explicit ip_address_v4(const std::string& ip) : in_addr()
		{
			PCSTR terminator = nullptr;

			[[maybe_unused]] const auto result = ::RtlIpv4StringToAddressA(ip.c_str(), TRUE, &terminator, this);

			assert(0 == result);
		}

		explicit ip_address_v4(const std::wstring& ip) : in_addr()
		{
			LPCWSTR terminator = nullptr;

			[[maybe_unused]] const auto result = ::RtlIpv4StringToAddressW(ip.c_str(), TRUE, &terminator, this);

			assert(0 == result);
		}

		explicit operator std::string() const
		{
			std::vector<char> ip_vec(ipv4_address_max_length, 0);
			::RtlIpv4AddressToStringA(this, &ip_vec[0]);

			return std::string(&ip_vec[0]);
		}

		explicit operator std::wstring() const
		{
			std::vector<wchar_t> ip_vec(ipv4_address_max_length, 0);
			::RtlIpv4AddressToStringW(this, &ip_vec[0]);

			return std::wstring(&ip_vec[0]);
		}

		static std::pair<bool, ip_address_v4> from_string(const std::string& ip)
		{
			PCSTR terminator = nullptr;
			ip_address_v4 address{};

			[[maybe_unused]] const auto result = ::RtlIpv4StringToAddressA(ip.c_str(), TRUE, &terminator, &address);

			return { 0 == result, address };
		}

		static std::pair<bool, ip_address_v4> from_wstring(const std::wstring& ip)
		{
			LPCWSTR terminator = nullptr;
			ip_address_v4 address{};

			[[maybe_unused]] const auto result = ::RtlIpv4StringToAddressW(ip.c_str(), TRUE, &terminator, &address);

			return { 0 == result, address };
		}

		bool operator ==(const ip_address_v4& rhs) const { return (S_un.S_addr == rhs.S_un.S_addr); }
		bool operator !=(const ip_address_v4& rhs) const { return (S_un.S_addr != rhs.S_un.S_addr); }
		bool operator <(const ip_address_v4& rhs) const { return (S_un.S_addr < rhs.S_un.S_addr); }

		friend std::ostream& operator<<(std::ostream& os, const ip_address_v4& dt);
		friend std::wostream& operator<<(std::wostream& os, const ip_address_v4& dt);
	};

	inline std::ostream& operator<<(std::ostream& os, const ip_address_v4& dt)
	{
		os << std::string(dt);
		return os;
	}

	inline std::wostream& operator<<(std::wostream& os, const ip_address_v4& dt)
	{
		os << std::wstring(dt);
		return os;
	}

	// --------------------------------------------------------------------------------
	/// <summary>
	/// Wrapper for in_addr6. Represents IP version 6 address.
	/// </summary>
	// --------------------------------------------------------------------------------
	struct ip_address_v6 : in6_addr
	{
		static constexpr size_t ipv6_address_max_string_length = 48;
		static constexpr size_t ipv6_address_max_length = 16;
		static constexpr ADDRESS_FAMILY af_type = AF_INET6;

		ip_address_v6() : in6_addr() { memset(reinterpret_cast<void*>(this), 0, sizeof(ip_address_v6)); }
		explicit ip_address_v6(const uint8_t addr[ipv6_address_max_length]) : in6_addr() { memmove(reinterpret_cast<void*>(this), addr, sizeof(in_addr6)); }
		ip_address_v6(const in_addr6& ip) : in6_addr() { memcpy(reinterpret_cast<void*>(this), reinterpret_cast<const void*>(&ip), sizeof(ip_address_v6)); }

		explicit ip_address_v6(const std::string& ip) : in6_addr()
		{
			PCSTR terminator = nullptr;

			[[maybe_unused]] const auto result = ::RtlIpv6StringToAddressA(ip.c_str(), &terminator, this);

			assert(0 == result);
		}

		explicit ip_address_v6(const std::wstring& ip) : in6_addr()
		{
			LPCWSTR terminator = nullptr;

			[[maybe_unused]] const auto result = ::RtlIpv6StringToAddressW(ip.c_str(), &terminator, this);

			assert(0 == result);
		}

		explicit operator std::string() const
		{
			std::vector<char> ip_vec(ipv6_address_max_string_length, 0);
			::RtlIpv6AddressToStringA(this, &ip_vec[0]);

			return std::string(&ip_vec[0]);
		}

		explicit operator std::wstring() const
		{
			std::vector<wchar_t> ip_vec(ipv6_address_max_string_length, 0);
			::RtlIpv6AddressToStringW(this, &ip_vec[0]);

			return std::wstring(&ip_vec[0]);
		}

		static std::pair<bool, ip_address_v6> from_string(const std::string& ip)
		{
			PCSTR terminator = nullptr;
			ip_address_v6 address{};

			[[maybe_unused]] const auto result = ::RtlIpv6StringToAddressA(ip.c_str(), &terminator, &address);

			return { 0 == result, address };
		}

		static std::pair<bool, ip_address_v6> from_wstring(const std::wstring& ip)
		{
			LPCWSTR terminator = nullptr;
			ip_address_v6 address{};

			[[maybe_unused]] const auto result = ::RtlIpv6StringToAddressW(ip.c_str(), &terminator, &address);

			return { 0 == result, address };
		}

		bool operator ==(const ip_address_v6& rhs) const
		{
			return !memcmp(reinterpret_cast<const void*>(this), reinterpret_cast<const void*>(&rhs), sizeof(ip_address_v6));
		}

		bool operator !=(const ip_address_v6& rhs) const
		{
			return memcmp(reinterpret_cast<const void*>(this), reinterpret_cast<const void*>(&rhs), sizeof(ip_address_v6));
		}

		bool operator <(const ip_address_v6& rhs) const { return (memcmp(this, &rhs, sizeof(in_addr6)) < 0); }

		explicit operator uint32_t() const
		{
			const auto dword = reinterpret_cast<const uint32_t*>(this);
			return dword[0] ^ dword[1] ^ dword[2] ^ dword[3];
		}

		friend std::ostream& operator<<(std::ostream& os, const ip_address_v6& dt);
		friend std::wostream& operator<<(std::wostream& os, const ip_address_v6& dt);
	};

	inline std::ostream& operator<<(std::ostream& os, const ip_address_v6& dt)
	{
		os << std::string(dt);
		return os;
	}

	inline std::wostream& operator<<(std::wostream& os, const ip_address_v6& dt)
	{
		os << std::wstring(dt);
		return os;
	}
}

namespace std
{
	template<> struct hash<net::ip_address_v6>
	{
		using argument_type = net::ip_address_v6;
		using result_type = size_t;
		result_type operator()(argument_type const& ip) const noexcept
		{
			auto const h1(std::hash<uint32_t>{}(static_cast<uint32_t>(ip)));

			return h1;
		}
	};

	template<> struct hash<net::ip_address_v4>
	{
		using argument_type = net::ip_address_v4;
		using result_type = size_t;
		result_type operator()(argument_type const& ip) const noexcept
		{
			auto const h1(std::hash<uint32_t>{}(ip.S_un.S_addr));

			return h1;
		}
	};
}