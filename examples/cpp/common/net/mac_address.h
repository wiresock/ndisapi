#pragma once
#include <iomanip>
#include <sstream>

namespace net
{
	// --------------------------------------------------------------------------------
	/// <summary>
	/// Simple wrapper for hardware MAC address
	/// </summary>
	// --------------------------------------------------------------------------------
	struct mac_address
	{
		/// <summary>
		/// Hardware MAC address size
		/// </summary>
		static constexpr int eth_address_length = 6;

		/// <summary>
		/// Default constructor creates zero MAC address
		/// </summary>
		mac_address() { data.fill(0); } // NOLINT(cppcoreguidelines-pro-type-member-init)

		/// <summary>
		/// Constructs MAC address object from the provided bytes
		/// </summary>
		/// <param name="ptr">pointer to data buffer with MAC address</param>
		explicit mac_address(const unsigned char* ptr) { memmove(&data[0], ptr, eth_address_length); }
		// NOLINT(cppcoreguidelines-pro-type-member-init)

		/// <summary>
		/// Constructs MAC address by parsing its string representation
		/// </summary>
		/// <param name="address">MAC address represented as string, e.g. '01:02:03:04:05:06'</param>
		explicit mac_address(const std::string& address) // NOLINT(cppcoreguidelines-pro-type-member-init)
		{
			std::stringstream mss(address);
			std::string hex;
			std::vector<unsigned char> mac;
			while (getline(mss, hex, ':'))
			{
				std::stringstream hss(hex);
				unsigned int b;
				hss >> std::hex >> b;
				mac.push_back(static_cast<unsigned char>(b));
			}

			if (mac.size() == eth_address_length)
			{
				std::copy_n(mac.cbegin(), eth_address_length, data.begin());
			}
		}

		/// <summary>
		/// Index operator to retrieve MAC address byte reference by specifying its index
		/// </summary>
		/// <param name="index">index of MAC address array</param>
		/// <returns>modifiable MAC address byte reference by its index</returns>
		unsigned char& operator[](const size_t index) { return data[index]; }

		/// <summary>
		/// Index operator to retrieve MAC address byte reference by specifying its index
		/// </summary>
		/// <param name="index">index of MAC address array</param>
		/// <returns>constant MAC address byte reference by its index</returns>
		const unsigned char& operator[](const size_t index) const { return data[index]; }

		/// <summary>
		/// Equality operator
		/// </summary>
		/// <param name="rhs">MAC address to compare to</param>
		/// <returns>true is MAC addresses are equal</returns>
		bool operator ==(const mac_address& rhs) const
		{
			return data == rhs.data;
		}

		/// <summary>
		/// Non-equality operator
		/// </summary>
		/// <param name="rhs">MAC address to compare to</param>
		/// <returns>true is MAC addresses are non-equal</returns>
		bool operator !=(const mac_address& rhs) const
		{
			return !(*this == rhs);
		}

		/// <summary>
		/// Less operator (lexicographic)
		/// </summary>
		/// <param name="rhs">MAC address to compare to</param>
		/// <returns>true is MAC addresses is lexicographically less than specified</returns>
		bool operator <(const mac_address& rhs) const
		{
			return (memcmp(&data[0], &rhs.data[0], eth_address_length) < 0);
		}

		/// <summary>
		/// Checks if MAC address is zero initialized
		/// </summary>
		explicit operator bool() const { return *this != mac_address{}; };

		/// <summary>
		/// Returns MAC address as std::array
		/// </summary>
		explicit operator std::array<unsigned char, eth_address_length>() const { return data; }

		/// <summary>
		/// Template to_string conversion operator for MAC address
		/// </summary>
		template <typename T>
		explicit operator std::basic_string<T>() const
		{
			std::basic_ostringstream<T> oss;
			oss << std::hex
				<< std::uppercase
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned>(data[0]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned>(data[1]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned>(data[2]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned>(data[3]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned>(data[4]) //<< ":"
				<< std::setfill(T('0')) << std::setw(2)
				<< static_cast<unsigned>(data[5]);
			return oss.str();
		}

		/// <summary>
		/// Reverses bytes in MAC address
		/// </summary>
		/// <returns>MAC address with reversed bytes order</returns>
		const mac_address& reverse()
		{
			std::reverse(data.begin(), data.end());
			return *this;
		}

		/// <summary>
		/// Checks if MAC address is broadcast
		/// </summary>
		/// <returns>true if broadcast</returns>
		[[nodiscard]] bool is_broadcast() const
		{
			auto broadcast = mac_address{};
			broadcast.data.fill(0xFF);
			if (broadcast == *this)
				return true;
			return false;
		}

		/// <summary>
		 /// Checks if MAC address is multicast
		 /// </summary>
		 /// <returns>true if multicast</returns>
		[[nodiscard]] bool is_multicast() const
		{
			if ((data[0] & 0x01) == 0x01)
				return true;
			return false;
		}

		/// <summary>
		/// MAC address storage
		/// </summary>
		std::array<unsigned char, eth_address_length> data;
	};

	/// <summary>
	/// Char stream output operator
	/// </summary>
	/// <param name="os">stream instance reference</param>
	/// <param name="dt">mac_address value</param>
	/// <returns>stream instance reference</returns>
	inline std::ostream& operator<<(std::ostream& os, const mac_address& dt)
	{
		os << std::string(dt);
		return os;
	}

	/// <summary>
	/// Wide char stream output operator
	/// </summary>
	/// <param name="os">stream instance reference</param>
	/// <param name="dt">mac_address value</param>
	/// <returns>stream instance reference</returns>
	inline std::wostream& operator<<(std::wostream& os, const mac_address& dt)
	{
		os << std::wstring(dt);
		return os;
	}
}

namespace std
{
	/// <summary>
	/// Hash for mac_address
	/// </summary>
	template <>
	struct hash<net::mac_address>
	{
		using argument_type = net::mac_address;
		using result_type = std::size_t;

		result_type operator()(const argument_type& mac) const noexcept
		{
			const auto arg = (static_cast<uint64_t>(mac[0]) << 40) +
				(static_cast<uint64_t>(mac[1]) << 32) +
				(static_cast<uint64_t>(mac[2]) << 24) +
				(static_cast<uint64_t>(mac[3]) << 16) +
				(static_cast<uint64_t>(mac[4]) << 8) +
				mac[5];

			const auto h1(
				std::hash<uint64_t>{}(arg)
			);

			return h1;
		}
	};
}
