#pragma once
#include <iomanip>
#include <sstream>

namespace net {
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Simple wrapper for MAC address
	/// </summary>
	// --------------------------------------------------------------------------------
	struct mac_address {
		static constexpr int eth_addr_length = 6;

		mac_address() { data.fill(0); }  // NOLINT(cppcoreguidelines-pro-type-member-init)
		explicit mac_address(const unsigned char* ptr) { memmove(&data[0], ptr, eth_addr_length); }

		unsigned char& operator[](const size_t index) { return data[index]; }
		const unsigned char& operator[](const size_t index)const { return data[index]; }

		bool operator ==(const mac_address& rhs) const {
			return data == rhs.data;
		}

		bool operator !=(const mac_address& rhs) const {
			return !(*this == rhs);
		}

		bool operator <(const mac_address & rhs) const {
			return (memcmp(&data[0], &rhs.data[0], eth_addr_length) < 0);
		}

		explicit operator bool() const { return *this != mac_address{}; };

		explicit operator std::array<unsigned char, eth_addr_length>() const { return data; }

		template<typename T>
		explicit operator std::basic_string<T>() const {
			std::basic_ostringstream<T> oss;
			oss << std::hex
				<< std::uppercase
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (data[0]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (data[1]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (data[2]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (data[3]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (data[4]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned> (data[5]);
			return oss.str();
		}

		const mac_address& reverse() { std::reverse(data.begin(), data.end()); return *this; }

		[[nodiscard]] bool is_broadcast() const
		{
			auto broadcast = mac_address{};
			broadcast.data.fill(0xFF);
			if (broadcast == *this)
				return true;
			return false;
		}

		[[nodiscard]] bool is_multicast() const
		{
			if ((data[0] & 0x01) == 0x01)
				return true;
			return false;
		}

		std::array<unsigned char, eth_addr_length> data;
	};

	inline std::ostream& operator<<(std::ostream& os, const mac_address& dt)
	{
		os << std::string(dt);
		return os;
	}

	inline std::wostream& operator<<(std::wostream& os, const mac_address& dt)
	{
		os << std::wstring(dt);
		return os;
	}
}

namespace std
{
	template<> struct hash<net::mac_address>
	{
		typedef net::mac_address argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& mac) const noexcept
		{
			const auto arg = (static_cast<uint64_t>(mac[0]) << 40) +
				(static_cast<uint64_t>(mac[1]) << 32) +
				(static_cast<uint64_t>(mac[2]) << 24) +
				(static_cast<uint64_t>(mac[3]) << 16) +
				(static_cast<uint64_t>(mac[4]) << 8) +
				mac[5];

			auto const h1(
				std::hash<uint64_t>{}(arg)
			);

			return h1;
		}
	};
}
