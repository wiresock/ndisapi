// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  network_helpers.h
/// Abstract: helper definitions
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#pragma comment(lib, "ntdll.lib")

namespace ndisapi
{
	//
	// Simple wrapper class for Windows handle
	//
	class safe_object_handle : public std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)>
	{
	public:
		explicit safe_object_handle(HANDLE handle) : unique_ptr(handle, &safe_object_handle::close)
		{
		}

		explicit operator HANDLE() const
		{
			return get();
		}

		bool valid() const
		{
			return (get() != INVALID_HANDLE_VALUE);
		}

	private:
		static void close(HANDLE handle)
		{
			if (handle != INVALID_HANDLE_VALUE)
				CloseHandle(handle);
		}
	};

	//
	// Simple Wrapper for Windows event object
	//
	class safe_event : public safe_object_handle
	{
	public:
		explicit safe_event(HANDLE handle) : safe_object_handle(handle)
		{
		}

		unsigned wait(const unsigned milliseconds) const
		{
			return WaitForSingleObject(get(), milliseconds);
		}

		bool signal() const
		{
			return SetEvent(get()) ? true : false;
		}

		bool reset_event() const
		{
			return ResetEvent(get()) ? true : false;
		}

	};

	//
	// Required to use IPv4 in_addr as a key in unordered map
	//
	inline bool operator < (const in_addr& lh, const in_addr& rh) { return lh.S_un.S_addr < rh.S_un.S_addr; }
	inline bool operator == (const in_addr& lh, const in_addr& rh) { return lh.S_un.S_addr == rh.S_un.S_addr; }

	//
	// Simple wrapper for MAC address
	//
	struct mac_address {
	#ifndef ETH_ALEN
		static constexpr int ETH_ALEN = 6;
	#endif //ETH_ALEN

		mac_address() noexcept { data.fill(0); }
		explicit mac_address(const unsigned char* ptr) { memmove(&data[0], ptr, ETH_ALEN); }

		unsigned char& operator[](const std::size_t index) { return data[index]; }
		const unsigned char& operator[](const std::size_t index)const { return data[index]; }

		bool operator ==(const mac_address& rhs) const {
			return data == rhs.data;
		}

		bool operator !=(const mac_address& rhs) const {
			return !(*this == rhs);
		}

		bool operator <(const mac_address& rhs) const {
			return (memcmp(&data[0], &rhs.data[0], ETH_ALEN) < 0);
		}

		explicit operator std::array<unsigned char, ETH_ALEN>() const { return data; }

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
		std::array<unsigned char, ETH_ALEN> data{};
	};
}

namespace std
{
	template<> struct hash<in_addr>
	{
		typedef in_addr argument_type;
		typedef std::size_t result_type;
		result_type operator()(argument_type const& ip) const noexcept
		{
			auto const h1(std::hash<unsigned long>{}(ip.S_un.S_addr));

			return h1;
		}
	};
}