#pragma once

namespace proxy
{
	template<typename...> constexpr bool false_v = false;

	enum class proxy_io_operation
	{
		relay_io_read,
		relay_io_write,
		negotiate_io_read,
		negotiate_io_write,
		inject_io_write
	};

	// --------------------------------------------------------------------------------
	/// <summary>
	/// Used to pass data required to negotiate connection to the remote proxy
	/// </summary>
	// --------------------------------------------------------------------------------
	template<typename T>
	struct negotiate_context
	{
		negotiate_context(const T& remote_address, const uint16_t remote_port)
			: remote_address(remote_address),
			remote_port(remote_port)
		{
		}

		virtual ~negotiate_context() {}

		T remote_address;
		uint16_t remote_port;
	};
}