// sni_inspector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>

using packet_filter = ndisapi::simple_packet_filter;
using packet_action = ndisapi::simple_packet_filter::packet_action;

/**
 * @brief The tcp_context class represents a context for a TCP connection.
 * It stores the remote endpoint (IP address and port), and two Hyperscan streams for incoming and outgoing data.
 */
class tcp_context
{
	net::ip_endpoint<net::ip_address_v4> remote_endpoint_; ///< The remote endpoint of the TCP connection.
	hs_stream_t* in_stream_{ nullptr }; ///< The Hyperscan stream for incoming data.
	hs_stream_t* out_stream_{ nullptr }; ///< The Hyperscan stream for outgoing data.
	std::optional<llhttp_t> in_parser_;     ///< An optional container that holds an instance of an LLHTTP parser for incoming data.
	std::optional<llhttp_t> out_parser_;    ///< An optional container that holds an instance of an LLHTTP parser for outgoing data.
	std::optional<llhttp_settings_t> settings_; ///< An optional container that holds the LLHTTP settings. The settings are initialized in `init_http_parsers()` and can be accessed by both `in_parser_` and `out_parser_`. If the container is empty, it means that the settings have not yet been initialized.
	std::atomic_bool is_http_{ false };     ///< A boolean atomic flag that indicates whether the parsers are in HTTP mode or not. Initialized to false.


public:
	/**
	 * @brief Construct a new tcp_context object.
	 *
	 * @param db The Hyperscan database to use for pattern matching.
	 * @param remote_ip The remote IP address.
	 * @param remote_port The remote port number.
	 *
	 * @throws std::runtime_error if there is an error while opening the Hyperscan streams.
	 */
	tcp_context(const hs_database_t* db, const net::ip_address_v4 remote_ip, const uint16_t remote_port) :
		remote_endpoint_{ remote_ip, remote_port }
	{
		if (hs_open_stream(db, 0, &in_stream_) != HS_SUCCESS ||
			hs_open_stream(db, 0, &out_stream_) != HS_SUCCESS)
		{
			throw std::runtime_error("Failed to initialize hyperscan streams");
		}
	}

	/**
	 * @brief Destroy the tcp_context object.
	 */
	~tcp_context()
	{
		if (in_stream_ != nullptr)
			hs_close_stream(in_stream_, nullptr, nullptr, nullptr);

		if (out_stream_ != nullptr)
			hs_close_stream(out_stream_, nullptr, nullptr, nullptr);
	}

	tcp_context(const tcp_context& other) = delete; ///< Copy constructor is deleted.

	/**
	 * @brief Construct a new tcp_context object by moving another object.
	 *
	 * @param other The object to move.
	 */
	tcp_context(tcp_context&& other) noexcept
		: remote_endpoint_(other.remote_endpoint_),
		in_stream_(other.in_stream_),
		out_stream_(other.out_stream_)
	{
	}

	tcp_context& operator=(const tcp_context& other) = delete; ///< Copy assignment operator is deleted.

	/**
	 * @brief Move assignment operator.
	 *
	 * @param other The object to move.
	 * @return tcp_context& A reference to this object.
	 */
	tcp_context& operator=(tcp_context&& other) noexcept
	{
		if (this == &other)
			return *this;
		remote_endpoint_ = other.remote_endpoint_;
		in_stream_ = other.in_stream_;
		out_stream_ = other.out_stream_;
		return *this;
	}

	/**
	 * @brief Get the remote endpoint of the TCP connection.
	 *
	 * @return net::ip_endpoint<net::ip_address_v4> The remote endpoint.
	 */
	[[nodiscard]] net::ip_endpoint<net::ip_address_v4> get_remote_endpoint() const
	{
		return remote_endpoint_;
	}

	/**
	 * @brief Get the Hyperscan stream for incoming data.
	 *
	 * @return hs_stream_t* The stream for incoming data.
	 */
	[[nodiscard]] hs_stream_t* get_in_stream() const
	{
		return in_stream_;
	}

	/**
	 * @brief Get the Hyperscan stream for outgoing data.
	 *
	 * @return hs_stream_t* The stream for outgoing data.
	 */
	[[nodiscard]] hs_stream_t* get_out_stream() const
	{
		return out_stream_;
	}

	/**
	 * @brief Initialize the LLHTTP parsers with user-defined callbacks.
	 *
	 * @param handle_on_url The callback function for handling URLs.
	 * @param handle_header_field The callback function to handle header name
	 * @param handle_header_value The callback function to handle header value
	 */
	void init_http_parsers(const llhttp_data_cb handle_on_url, const llhttp_data_cb handle_header_field, const llhttp_data_cb handle_header_value )
	{
		settings_.emplace();

		// Initialize user callbacks and settings.
		llhttp_settings_init(&settings_.value());

		// Set the user-defined callback for handling URLs.
		settings_.value().on_url = handle_on_url;
		settings_.value().on_header_field = handle_header_field;
		settings_.value().on_header_value = handle_header_value;

		// Initialize the parsers in HTTP_BOTH mode, meaning that they will select between
		// HTTP_REQUEST and HTTP_RESPONSE parsing automatically while reading the first input.
		in_parser_.emplace();
		out_parser_.emplace();
		llhttp_init(&in_parser_.value(), HTTP_BOTH, &settings_.value());
		llhttp_init(&out_parser_.value(), HTTP_BOTH, &settings_.value());
		is_http_ = true;
	}

	/**
	 * @brief Check if the parsers are in HTTP mode.
	 *
	 * @return true if the parsers are in HTTP mode, false otherwise.
	 */
	bool is_http() const
	{
		return is_http_;
	}

	/**
	 * @brief Execute the LLHTTP parser on incoming data.
	 *
	 * @param data A pointer to the buffer containing the data to be parsed.
	 * @param len The length of the data buffer.
	 *
	 * @return true if the data was parsed successfully, false otherwise.
	 */
	bool execute_in(const char* data, size_t len)
	{
		const auto result = llhttp_execute(&in_parser_.value(), data, len);
		if (result == HPE_OK) {
			// The data was parsed successfully.
			return true;
		}

		// There was a parse error.
		std::cerr << "Parse error: " << llhttp_errno_name(result) << " " << in_parser_.value().reason << std::endl;
		return false;
	}

	/**
	 * @brief Execute the LLHTTP parser on outgoing data.
	 *
	 * @param data A pointer to the buffer containing the data to be parsed.
	 * @param len The length of the data buffer.
	 *
	 * @return true if the data was parsed successfully, false otherwise.
	 */
	bool execute_out(const char* data, size_t len)
	{
		const auto result = llhttp_execute(&out_parser_.value(), data, len);
		if (result == HPE_OK) {
			// The data was parsed successfully.
			return true;
		}

		// There was a parse error.
		std::cerr << "Parse error: " << llhttp_errno_name(result) << " " << out_parser_.value().reason << std::endl;
		return false;
	}
};

/**
 * @brief A class that provides an interface for scanning network traffic for HTTP traffic using Hyperscan and LLHTTP libraries.
 *
 * This class uses the Hyperscan library to scan incoming and outgoing network traffic for HTTP sessions, and the LLHTTP
 * library to parse the HTTP protocol of detected sessions. The class maintains a map of TCP contexts that hold Hyperscan
 * streams for incoming and outgoing data.
 */
class hs_state {
	std::unordered_map<uint16_t, std::shared_ptr<tcp_context>> tcp_sessions_; ///< A map that stores TCP contexts using the local port as the key.
	std::shared_mutex lock_; ///< A shared mutex that protects access to the `tcp_sessions_` map.

	hs_database_t* database_{ nullptr }; ///< The compiled Hyperscan database.
	hs_scratch_t* scratch_{ nullptr };   ///< The Hyperscan scratch space.

	/**
	 * @brief The callback function for handling the URL.
	 *
	 * @param at A pointer to the start of the URL string.
	 * @param length The length of the URL string.
	 *
	 * @return 0
	 */
	static int handle_on_url (llhttp_t*, const char* at, size_t length)
	{
		const std::string_view url(at, length);

		std::cout << "URL: " << url << std::endl;

		return 0;
	}

	/**
	 * @brief The callback function for handling the header field.
	 *
	 * @param at A pointer to the start of the header field string.
	 * @param length The length of the header field string.
	 *
	 * @return 0
	 */
	static int handle_on_header_field(llhttp_t*, const char* at, size_t length)
	{
		const std::string_view header(at, length);

		std::cout << header << " : ";

		return 0;
	}

	/**
	 * @brief The callback function for handling the header value.
	 *
	 * @param at A pointer to the start of the header value string.
	 * @param length The length of the header value string.
	 *
	 * @return 0
	 */
	static int handle_on_header_value(llhttp_t*, const char* at, size_t length)
	{
		const std::string_view header_value(at, length);

		std::cout << header_value << std::endl;

		return 0;
	}

	/**
	 * @brief The event handler function that gets called when a match is found.
	 *
	 * @param id The ID of the matching pattern.
	 * @param from The offset of the start of the match.
	 * @param to The offset of the end of the match.
	 * @param flags The match flags.
	 * @param ctx A pointer to the context.
	 *
	 * @return HS_SCAN_TERMINATED to halt scanning.
	 */
	static int event_handler(
		unsigned int id,
		unsigned long long from,
		unsigned long long to,
		unsigned int flags,
		void* ctx
	)
	{
		const auto context = static_cast<tcp_context*>(ctx);
		context->init_http_parsers(handle_on_url, handle_on_header_field, handle_on_header_value);
		return HS_SCAN_TERMINATED; //halt scanning
	}

public:

	hs_state() = default;
	hs_state(const hs_state& other) = delete;
	hs_state(hs_state&& other) = delete;
	hs_state& operator=(const hs_state& other) = delete;
	hs_state& operator=(hs_state&& other) = delete;

	/**
	 * @brief Construct an `hs_state` object with the given Hyperscan pattern.
	 *
	 * This constructor compiles the given pattern using Hyperscan and allocates scratch space for scanning.
	 *
	 * @param pattern The Hyperscan pattern to compile and use for scanning.
	 *
	 * @throw std::runtime_error if the pattern cannot be compiled or scratch space cannot be allocated.
	 */
	explicit hs_state(const std::string& pattern)
	{
		hs_compile_error_t* compile_err;
		std::stringstream ss;
		if (hs_compile(pattern.c_str(), HS_FLAG_CASELESS, HS_MODE_STREAM, nullptr, &database_,
			&compile_err) != HS_SUCCESS) {
			ss << "ERROR: Unable to compile pattern " << pattern << " : " << compile_err->message << std::endl;
			hs_free_compile_error(compile_err);
			std::cout << ss.str() << std::endl;
			throw std::runtime_error(ss.str());
		}

		if (hs_alloc_scratch(database_, &scratch_) != HS_SUCCESS) {
			ss << "ERROR: Unable to allocate scratch space." << std::endl;
			hs_free_database(database_);
			throw std::runtime_error(ss.str());
		}
	}

	~hs_state()
	{
		if (scratch_ != nullptr)
			hs_free_scratch(scratch_);

		if (database_ != nullptr)
			hs_free_database(database_);
	}

	/**
	 * @brief Scan input data for Hyperscan pattern matches.
	 *
	 * This function scans input data using Hyperscan for pattern matches. It uses the input stream of the given
	 * `tcp_context` to scan the data.
	 *
	 * @param context The `tcp_context` object containing the input stream to use for scanning.
	 * @param data A pointer to the buffer containing the input data to scan.
	 * @param length The length of the input data buffer.
	 *
	 * @return `true` if the data was scanned successfully, `false` otherwise.
	 */
	bool scan_in(const std::shared_ptr<tcp_context>& context, const char* data, const uint32_t length) const
	{
		if (const auto status = hs_scan_stream(context->get_in_stream(), data, length, 0, scratch_, event_handler, context.get());
			status != HS_SUCCESS && status != HS_SCAN_TERMINATED) {
			std::cout << "ERROR: Unable to scan input buffer.\n";
			return false;
		}

		return true;
	}

	/**
	 * @brief Scan output data for Hyperscan pattern matches.
	 *
	 * This function scans output data using Hyperscan for pattern matches. It uses the output stream of the given
	 * `tcp_context` to scan the data.
	 *
	 * @param context The `tcp_context` object containing the output stream to use for scanning.
	 * @param data A pointer to the buffer containing the output data to scan.
	 * @param length The length of the output data buffer.
	 *
	 * @return `true` if the data was scanned successfully, `false` otherwise.
	 */
	bool scan_out(const std::shared_ptr<tcp_context>& context, const char* data, const uint32_t length) const
	{
		if (const auto status = hs_scan_stream(context->get_out_stream(), data, length, 0, scratch_, event_handler, context.get());
			status != HS_SUCCESS && status != HS_SCAN_TERMINATED) {
			std::cout << "ERROR: Unable to scan input buffer.\n";
			return false;
		}

		return true;
	}

	/**
	 * @brief Add a new TCP session to the internal map.
	 *
	 * This function adds a new TCP session to the internal map of the `hs_state` object. The `local_port` argument
	 * specifies the local port number of the session, while `remote_ip` and `remote_port` specify the remote IP
	 * address and port number of the session, respectively.
	 *
	 * @param local_port The local port number of the TCP session.
	 * @param remote_ip The remote IP address of the TCP session.
	 * @param remote_port The remote port number of the TCP session.
	 */
	void add_tcp_session (const uint16_t local_port, const net::ip_address_v4 remote_ip, const uint16_t remote_port)
	{
		std::lock_guard lock(lock_);
		tcp_sessions_[local_port] = std::make_shared<tcp_context>(database_, remote_ip, remote_port);
		std::cout << "[" << local_port << "] --> " << remote_ip << " : " << remote_port << std::endl;
	}

	/**
	* @brief Looks for a TCP session in the internal storage.
	*
	* @param local_port The local port to look for.
	* @param remote_ip The remote IP address to look for.
	* @param remote_port The remote port to look for.
	*
	* @return A pointer to the tcp_context object that matches the input parameters, or a nullptr if no match is found.
	*/
	std::shared_ptr<tcp_context> find_tcp_session(const uint16_t local_port, const net::ip_address_v4 remote_ip, const uint16_t remote_port)
	{
		std::shared_lock lock(lock_);
		const auto it = tcp_sessions_.find(local_port);
		if (it == tcp_sessions_.end())
			return nullptr;
		if (auto [ip, port] = it->second->get_remote_endpoint(); ip == remote_ip && port == remote_port)
			return it->second;
		return nullptr;
	}
};

/**
* @brief Processes an outgoing packet.
* This function processes an outgoing packet by first checking if the protocol is IP and if so, whether the IP protocol is TCP.
* If it is, it checks TCP-SYN packet, and if it is, it adds a TCP session. Then, it extracts the payload and its size and searches
* for a matching TCP session in the hs_state object. If a matching session is found and the payload size is greater than 0,
* the payload is scanned using the HS engine. If the session is HTTP, it executes the LLHTTP parser on the payload.
* @param state A reference to the hs_state object to search for matching TCP sessions and scan payload.
* @param buffer The packet buffer to be processed.
* @return packet_action::pass to indicate that the packet should be passed to the next filter.
*/
packet_action hs_process_outgoing_packet(hs_state& state, const INTERMEDIATE_BUFFER& buffer)
{
	if (const auto* const eth_header = reinterpret_cast<const ether_header*>(buffer.m_IBuffer); ntohs(
		eth_header->h_proto) == ETH_P_IP)
	{
		if (const auto* const ip_header = reinterpret_cast<const iphdr*>(eth_header + 1); ip_header->ip_p ==
			IPPROTO_TCP)
		{
			const auto* const tcp_header = reinterpret_cast<const tcphdr*>(reinterpret_cast<const uint8_t*>(ip_header)
				+
				sizeof(DWORD) * ip_header->ip_hl);

			if ((tcp_header->th_flags & (TH_SYN | TH_ACK)) == TH_SYN)
			{
				state.add_tcp_session(ntohs(tcp_header->th_sport), ip_header->ip_dst, ntohs(tcp_header->th_dport));
			}

			const auto* payload = reinterpret_cast<const uint8_t*>(tcp_header) + tcp_header->th_off * sizeof(uint32_t);
			const auto payload_size = ntohs(ip_header->ip_len) - static_cast<uint16_t>(payload - reinterpret_cast<const uint8_t*>(ip_header));

			if(const auto session = state.find_tcp_session(
				ntohs(tcp_header->th_sport), ip_header->ip_dst, ntohs(tcp_header->th_dport));
				session && payload_size > 0)
			{
				// If session is not marked as HTTP try to inspect it with Hyperscan
				if (!session->is_http())
					state.scan_out(session, reinterpret_cast<const char*>(payload), payload_size);

				// If session marked as HTTP then parse with llhttp parser
				if (session->is_http())
				{
					std::cout << "OUTGOING HTTP:\n";
					session->execute_out(reinterpret_cast<const char*>(payload), payload_size);
				}
			}
		}
	}
	return packet_action::pass;
}

/**
 * @brief Process an incoming network packet, looking for HTTP protocol sessions and parsing any encountered HTTP data.
 *
 * @param state The `hs_state` object that manages the Hyperscan scanning engine and HTTP session state.
 * @param buffer A reference to the `INTERMEDIATE_BUFFER` object containing the network packet to be processed.
 *
 * @return The `packet_action` value that specifies how the packet should be handled by the system.
 */
packet_action hs_process_incoming_packet(hs_state& state, const INTERMEDIATE_BUFFER& buffer)
{
	if (auto* const eth_header = reinterpret_cast<const ether_header*>(buffer.m_IBuffer); ntohs(
		eth_header->h_proto) == ETH_P_IP)
	{
		if (auto* const ip_header = reinterpret_cast<const iphdr*>(eth_header + 1); ip_header->ip_p ==
			IPPROTO_TCP)
		{
			auto* const tcp_header = reinterpret_cast<const tcphdr*>(reinterpret_cast<const uint8_t*>(ip_header)
				+
				sizeof(DWORD) * ip_header->ip_hl);

			const auto* payload = reinterpret_cast<const uint8_t*>(tcp_header) + tcp_header->th_off * sizeof(uint32_t);
			const auto payload_size = ntohs(ip_header->ip_len) - static_cast<uint16_t>(payload - reinterpret_cast<const uint8_t*>(ip_header));

			if (const auto session = state.find_tcp_session(
				ntohs(tcp_header->th_dport), ip_header->ip_src, ntohs(tcp_header->th_sport));
				session && payload_size > 0)
			{
				// If session is not marked as HTTP try to inspect it with Hyperscan
				if (!session->is_http())
					state.scan_in(session, reinterpret_cast<const char*>(payload), payload_size);

				// If session marked as HTTP then parse with llhttp parser
				if (session->is_http())
				{
					std::cout << "INCOMING HTTP:\n";
					session->execute_in(reinterpret_cast<const char*>(payload), payload_size);
				}
			}
		}
	}
	return packet_action::pass;
}

int main()
{
	hs_state state{R"(^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT) \S+ HTTP/1\.[01]\r\n)"};

	const auto ndis_api = std::make_unique<ndisapi::simple_packet_filter>(
		[&state](HANDLE, const INTERMEDIATE_BUFFER& buffer)
		{
			return hs_process_incoming_packet(state, buffer);
		},
		[&state](HANDLE, const INTERMEDIATE_BUFFER& buffer)
		{
			return hs_process_outgoing_packet(state, buffer);
		});

	if (ndis_api->IsDriverLoaded())
	{
		std::cout << "WinpkFilter is loaded" << std::endl << std::endl;
	}
	else
	{
		std::cout << "WinpkFilter is not loaded" << std::endl << std::endl;
		return 1;
	}

	std::cout << "Available network interfaces:" << std::endl << std::endl;
	size_t index = 0;
	for (auto& e : ndis_api->get_interface_names_list())
	{
		std::cout << ++index << ")\t" << e << std::endl;
	}

	std::cout << std::endl << "Select interface to filter:";
	std::cin >> index;

	if (index > ndis_api->get_interface_names_list().size())
	{
		std::cout << "Wrong parameter was selected. Out of range." << std::endl;
		return 0;
	}

	ndis_api->start_filter(index - 1);

	std::cout << "Press any key to stop filtering" << std::endl;

	std::ignore = _getch();

	std::cout << "Exiting..." << std::endl;

	return 0;
}
