/*************************************************************************/
/*                Copyright (c) 2000-2018 NT Kernel Resources.           */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ip_address.h                                            */
/*                                                                       */
/* Abstract: IP address wrappers definitions                             */
/*                                                                       */
/* Environment:                                                          */
/*   User mode, Kernel mode                                              */
/*                                                                       */
/*************************************************************************/

#ifndef _NET_IP_ADDRESS_H
#define _NET_IP_ADDRESS_H

#pragma comment(lib, "ntdll.lib")

namespace net
{
	//
	// Wrapper for in_addr. Represents IP version 4 address.
	//
	struct ip_address_v4 : public in_addr
	{
		static constexpr size_t IPV4_ADDRESS_MAX_LENGTH = 16;

		ip_address_v4() { S_un.S_addr = 0; }
		ip_address_v4(const in_addr& ip) { *static_cast<in_addr*>(this) = ip; }
		ip_address_v4(const std::string& ip)
		{
			PCSTR Terminator = NULL;

			::RtlIpv4StringToAddressA(ip.c_str(), TRUE, &Terminator, this);
		}
		ip_address_v4(const std::wstring& ip)
		{
			LPCWSTR Terminator = NULL;

			::RtlIpv4StringToAddressW(ip.c_str(), TRUE, &Terminator, this);
		}

		operator std::string() const
		{
			std::vector<char> ip_vec(IPV4_ADDRESS_MAX_LENGTH, 0);
			::RtlIpv4AddressToStringA(this, &ip_vec[0]);

			return std::string(&ip_vec[0]);
		}

		operator std::wstring() const
		{
			std::vector<wchar_t> ip_vec(IPV4_ADDRESS_MAX_LENGTH, 0);
			::RtlIpv4AddressToStringW(this, &ip_vec[0]);

			return std::wstring(&ip_vec[0]);
		}

		bool operator ==(const ip_address_v4& rhs) const { return (S_un.S_addr == rhs.S_un.S_addr); }

		bool operator <(const ip_address_v4& rhs) const { return (S_un.S_addr < rhs.S_un.S_addr); }
	};

	//
	// Wrapper for in_addr6. Represents IP version 6 address.
	//
	struct ip_address_v6 : in_addr6
	{
		static constexpr size_t IPV6_ADDRESS_MAX_LENGTH = 48;

		ip_address_v6() { memset(reinterpret_cast<void*>(this), 0, sizeof(ip_address_v6)); }
		ip_address_v6(const in_addr6& ip) { memcpy(reinterpret_cast<void*>(this), reinterpret_cast<const void*>(&ip), sizeof(ip_address_v6)); }
		ip_address_v6(const std::string& ip)
		{
			PCSTR Terminator = NULL;

			::RtlIpv6StringToAddressA(ip.c_str(), &Terminator, this);
		}
		ip_address_v6(const std::wstring& ip)
		{
			LPCWSTR Terminator = NULL;

			::RtlIpv6StringToAddressW(ip.c_str(), &Terminator, this);
		}

		operator std::string() const
		{
			std::vector<char> ip_vec(IPV6_ADDRESS_MAX_LENGTH, 0);
			::RtlIpv6AddressToStringA(this, &ip_vec[0]);

			return std::string(&ip_vec[0]);
		}

		operator std::wstring() const
		{
			std::vector<wchar_t> ip_vec(IPV6_ADDRESS_MAX_LENGTH, 0);
			::RtlIpv6AddressToStringW(this, &ip_vec[0]);

			return std::wstring(&ip_vec[0]);
		}

		bool operator ==(const ip_address_v6& rhs) const
		{
			return !memcmp(reinterpret_cast<const void*>(this), reinterpret_cast<const void*>(&rhs), sizeof(ip_address_v6));
		}

		bool operator <(const ip_address_v6& rhs) const { return (memcmp(this, &rhs, sizeof(in_addr6)) < 0); }

		operator uint32_t() const
		{
			auto _dwords = reinterpret_cast<const uint32_t*>(this);
			return _dwords[0] ^ _dwords[1] ^ _dwords[2] ^ _dwords[3];
		}
	};

	
}

namespace std
{
	template<> struct hash<net::ip_address_v6>
	{
		using argument_type = net::ip_address_v6;
		using result_type = size_t;
		result_type operator()(argument_type const& ip) const
		{
			result_type const h1(std::hash<uint32_t>{}(ip));

			return h1;
		}
	};

	template<> struct hash<net::ip_address_v4>
	{
		using argument_type = net::ip_address_v4;
		using result_type = size_t;
		result_type operator()(argument_type const& ip) const
		{
			result_type const h1(std::hash<uint32_t>{}(ip.S_un.S_addr));

			return h1;
		}
	};
}
#endif //_NET_IP_ADDRESS_H

