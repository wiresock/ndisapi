// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  etw_packet_attributor.h
/// Abstract: ETW based owner-process attribution for outbound UDP datagrams,
/// TCP connection attempts and Dnscache DNS queries.
///
/// Header-only and self-contained (Windows SDK + C++17 standard library only), so it
/// can be dropped unchanged into other WinpkFilter based projects.
///
/// Why: IP Helper tables (GetExtendedUdpTable/GetExtendedTcpTable) are snapshots. A
/// socket that sends one datagram and closes within a few milliseconds is gone before
/// the snapshot is taken, so the packet is attributed to nobody (SYSTEM). The kernel
/// writes an ETW event with the owner PID on the send path of that very datagram, so
/// the owner is known even after closesocket(). The only delay is ETW buffer delivery,
/// which this class controls with explicit flushes.
///
/// Evidence labels used in comments:
///   [M26300] measured on Windows build 26300 (bare metal)
///   [M19045] measured on Windows 10 22H2 19045 (Hyper-V VM)
///   [M7601]  measured on Windows 7 SP1 7601 (Hyper-V VM)
///   [V-doc]  Microsoft Learn documentation
///   [V-manifest] provider manifest dumps:
///       https://github.com/jdu2600/Windows10EtwEvents (TSV per release, 1511..25H2)
///       https://github.com/repnz/etw-providers-docs (XML manifests, Win7 7600, Win10 10240/17134/18990)
///   [U] unverified: do not rely on it; the run-time gates decide.
///
/// Usage:
///   iphelper::etw_packet_attributor attributor{config};
///   if (attributor.start()) { ... attributor.lookup(tuple, packet_qpc) ... }
///   else { keep IP Helper behaviour; attributor.report().to_string() says why }
/// </summary>
// --------------------------------------------------------------------------------

#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <iphlpapi.h>
#include <winsvc.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_MSC_VER)
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace iphelper
{
	namespace etw
	{
		// ------------------------------------------------------------------------
		// Constants that older SDK headers (or _WIN32_WINNT < 0x0603) may not define.
		// ------------------------------------------------------------------------

		/// <summary>EVENT_TRACE_INDEPENDENT_SESSION_MODE, Windows 8.1+ [V-doc]</summary>
		constexpr ULONG independent_session_mode = 0x08000000;
		/// <summary>EVENT_TRACE_USE_MS_FLUSH_TIMER: UNDOCUMENTED. FlushTimer is then in
		/// milliseconds. Accepted on 7601/19045/26300, but on 7601 delivery was still ~1.6 s
		/// [M7601], so only the loopback self-test may enable timer mode.</summary>
		constexpr ULONG use_ms_flush_timer = 0x00000010;
		/// <summary>EVENT_FILTER_TYPE_EVENT_ID, Windows 8.1+ [V-doc]</summary>
		constexpr ULONG filter_type_event_id = 0x80000200;
		/// <summary>PROCESS_TRACE_MODE_RAW_TIMESTAMP: header TimeStamp stays raw QPC
		/// when Wnode.ClientContext == 1 [V-doc]</summary>
		constexpr ULONG process_trace_mode_raw_timestamp = 0x00001000;

		// Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88} [V-manifest]
		inline constexpr GUID kernel_network_provider =
			{0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
		// Microsoft-Windows-TCPIP {2F07E2EE-15DB-40F1-90EF-9D7BA282188A} [V-manifest]
		inline constexpr GUID tcpip_provider =
			{0x2f07e2ee, 0x15db, 0x40f1, {0x90, 0xef, 0x9d, 0x7b, 0xa2, 0x82, 0x18, 0x8a}};
		// Microsoft-Windows-DNS-Client {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} [V-manifest]
		inline constexpr GUID dns_client_provider =
			{0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};

		// Keywords [V-manifest] (repnz Win7-7600 and Win10-18990 TCPIP/Kernel-Network manifests)
		constexpr ULONGLONG kn_keyword_ipv4 = 0x10;
		constexpr ULONGLONG kn_keyword_ipv6 = 0x20;
		constexpr ULONGLONG tcpip_keyword_tcb = 0x4;                  // ut:TcpipTcb
		constexpr ULONGLONG tcpip_keyword_bind = 0x8;                 // ut:TcpipBind
		constexpr ULONGLONG tcpip_keyword_endpoint = 0x400;           // ut:Endpoint
		constexpr ULONGLONG tcpip_keyword_send_path = 0x100000000;    // ut:SendPath
		constexpr ULONGLONG tcpip_keyword_connect_path = 0x400000000; // ut:ConnectPath

		// ------------------------------------------------------------------------
		// Event ids.
		//
		// UDP (measured):
		//   Kernel-Network 42 (UDPv4 send) / 58 (UDPv6 send), v0: PID, size, daddr, saddr,
		//     dport, sport, seqnum, connid. Ports big-endian. [V-manifest][M7601][M19045][M26300]
		//   TCPIP 1169 UdpEndpointSendMessages: v0 Pid; v1 Pid + ProcessStartKey.
		//     v0 on 7601, v1 on 19045 and 26300 [M]. SOCKADDR: family @0, port (network
		//     order) @+2, IPv4 @+4 [M26300]. One event per datagram (NumMessages=1) [M26300][M19045].
		//   TCPIP 1396 UdpBindEndpointComplete v1: Pid + ProcessStartKey, local address
		//     only. Misses sockets bound before the session [M19045]. Enrichment only.
		//
		// TCP (manifests, plus packet_owner measurements where marked; the TDH gate
		// decides at run time):
		//   Kernel-Network 12 (TCPv4 "Connection attempted") / 28 (TCPv6), v0, same
		//     address/port layout as 42/58 plus mss/sackopt/...; present in every dump
		//     from 1511 to 25H2 [V-manifest]. Written with 1033 after the handshake, about
		//     one RTT after the SYN, and not at all for a connect aborted before it was
		//     established [M26300]. KN 28 not observed yet.
		//   Kernel-Network 15 (TCPv4 "Connection accepted") / 31 (TCPv6), v0 [V-manifest].
		//     saddr/daddr orientation for accepted connections is [U]; both orientations
		//     are cached.
		//   TCPIP 1031 TcpConnectTcbProceeding: LocalAddressLength, LocalAddress,
		//     RemoteAddressLength, RemoteAddress, Status, ProcessId, Compartment, Tcb;
		//     v1 adds ProcessStartKey (the Win10 18990 XML names it ProcessSequenceNumber).
		//     v0 in Win7 7600 XML and 1511+ dumps, v1 from 2004 [V-manifest]. Keywords
		//     ut:TcpipTcb|ut:ConnectPath. Written at SYN send (0.4 us after TCPIP 1004
		//     TcpTcbSynSend), 0.03-0.17 ms before WinpkFilter reads the SYN. Payload
		//     ProcessId and ProcessStartKey are 0; the header PID is the connecting
		//     process [M26300][M19045].
		//   TCPIP 1033 TcpConnectTcbComplete (same template): handshake completed; header
		//     PID 4, payload ProcessId real, start key nonzero [M26300].
		//   TCPIP 1034 TcpConnectTcbFailure (same template): e.g. RST from a closed port
		//     [V-manifest]; local abort (0xC0000120) measured with the real PID in header
		//     and payload [M26300]; remote RST not measured.
		//   TCPIP 1017 TcpAcceptListenerComplete (same template): inbound accept [V-manifest].
		//   TCPIP 1300 TcpConnectionRundown: Tcb, LocalAddress(+Length), RemoteAddress(+Length),
		//     State, Pid (+ ProcessStartKey v1+). Expected on EVENT_CONTROL_CODE_CAPTURE_STATE
		//     for connections that already exist [U]; v0 7600..1809, v1 2004+, v2 21H2+,
		//     v3 24H2+ [V-manifest]. Used for "connection" lookups only.
		//   The TCPIP LocalAddress/RemoteAddress blobs are SOCKADDR: length 28, AF_INET6,
		//   IPv4-mapped ::ffff: for IPv4 connections [M26300]; the parser checks family and
		//   length, folds v4-mapped addresses to IPv4 and rejects anything else.
		//
		// DNS-Client (keyword mask 0) [V-manifest][M19045][M26300]:
		//   3006 "query called" v0: QueryName, QueryType, ...; header PID = caller.
		//   3010 "query sent" v0: QueryName, QueryType, DnsServerIpAddress; v1 + ClientPID.
		//   3019 "query wire called" v0: QueryName, QueryType, InterfaceIndex, NetworkIndex;
		//     v1/v2 + ClientPID. ClientPID present on 26300, absent on 19045 [M].
		// ------------------------------------------------------------------------
		constexpr USHORT kn_udp_send_v4 = 42;
		constexpr USHORT kn_udp_send_v6 = 58;
		constexpr USHORT kn_tcp_connect_v4 = 12;
		constexpr USHORT kn_tcp_connect_v6 = 28;
		constexpr USHORT kn_tcp_accept_v4 = 15;
		constexpr USHORT kn_tcp_accept_v6 = 31;
		constexpr USHORT tcpip_udp_send = 1169;
		constexpr USHORT tcpip_udp_bind = 1396;
		constexpr USHORT tcpip_tcp_connect_proceeding = 1031;
		constexpr USHORT tcpip_tcp_connect_complete = 1033;
		constexpr USHORT tcpip_tcp_connect_failure = 1034;
		constexpr USHORT tcpip_tcp_accept_complete = 1017;
		constexpr USHORT tcpip_tcp_rundown = 1300;
		constexpr USHORT dns_query_called = 3006;
		constexpr USHORT dns_query_sent = 3010;
		constexpr USHORT dns_query_wire = 3019;

		/// <summary>Which event produced an owner record</summary>
		enum class event_source : uint8_t
		{
			none = 0,
			kn_udp_send,         // Kernel-Network 42/58
			tcpip_udp_send,      // TCPIP 1169
			tcpip_udp_bind,      // TCPIP 1396 (start-key enrichment only, never decides)
			kn_tcp_connect,      // Kernel-Network 12/28
			kn_tcp_accept,       // Kernel-Network 15/31
			tcpip_tcp_connect,   // TCPIP 1031
			tcpip_tcp_connected, // TCPIP 1033
			tcpip_tcp_failed,    // TCPIP 1034
			tcpip_tcp_accept,    // TCPIP 1017
			tcpip_tcp_rundown,   // TCPIP 1300
			dns_query_called,    // DNS-Client 3006
			dns_query_sent,      // DNS-Client 3010
			dns_query_wire,      // DNS-Client 3019
			count
		};

		inline const char* to_string(const event_source s) noexcept
		{
			switch (s)
			{
			case event_source::kn_udp_send: return "KN42/58";
			case event_source::tcpip_udp_send: return "TCPIP1169";
			case event_source::tcpip_udp_bind: return "TCPIP1396";
			case event_source::kn_tcp_connect: return "KN12/28";
			case event_source::kn_tcp_accept: return "KN15/31";
			case event_source::tcpip_tcp_connect: return "TCPIP1031";
			case event_source::tcpip_tcp_connected: return "TCPIP1033";
			case event_source::tcpip_tcp_failed: return "TCPIP1034";
			case event_source::tcpip_tcp_accept: return "TCPIP1017";
			case event_source::tcpip_tcp_rundown: return "TCPIP1300";
			case event_source::dns_query_called: return "DNS3006";
			case event_source::dns_query_sent: return "DNS3010";
			case event_source::dns_query_wire: return "DNS3019";
			default: return "none";
			}
		}

		/// <summary>Formats a bit mask of (1 << event_source) as "A,B,C"</summary>
		inline std::string sources_to_string(const uint32_t mask)
		{
			std::string s;
			for (uint8_t i = 1; i < static_cast<uint8_t>(event_source::count); ++i)
			{
				if (mask & (1u << i))
				{
					if (!s.empty())
						s += ',';
					s += to_string(static_cast<event_source>(i));
				}
			}
			return s;
		}

		/// <summary>Flush strategy (implementation plan 3.3)</summary>
		enum class flush_mode : uint8_t
		{
			/// <summary>10 ms timer if the self-test proves it, plus light on-demand flushes;
			/// otherwise on-demand with back-off</summary>
			automatic,
			/// <summary>EVENT_TRACE_CONTROL_FLUSH, at most every 10 ms while lookups are
			/// pending, backing off to 50 ms under load</summary>
			on_demand,
			/// <summary>Undocumented EVENT_TRACE_USE_MS_FLUSH_TIMER with FlushTimer=10;
			/// used only if the self-test confirms ~10 ms delivery, else on_demand</summary>
			timer
		};

		inline const char* to_string(const flush_mode m) noexcept
		{
			switch (m)
			{
			case flush_mode::automatic: return "auto";
			case flush_mode::on_demand: return "ondemand";
			case flush_mode::timer: return "timer";
			}
			return "?";
		}

		/// <summary>Effective flush behaviour after calibration</summary>
		enum class effective_flush : uint8_t
		{
			none,                     // not started / no mode delivers in time
			on_demand,                // 1 s session timer + on-demand flushes with back-off
			timer,                    // ms timer only, no flush calls
			timer_and_light_on_demand // ms timer + on-demand flushes while few lookups wait
		};

		inline const char* to_string(const effective_flush m) noexcept
		{
			switch (m)
			{
			case effective_flush::on_demand: return "on-demand";
			case effective_flush::timer: return "ms-timer";
			case effective_flush::timer_and_light_on_demand: return "ms-timer+light-on-demand";
			default: return "none";
			}
		}

		/// <summary>How a cached record may match a packet</summary>
		enum class match_kind : uint8_t
		{
			/// <summary>The event of this very packet: same 5-tuple and event time within
			/// [packet - before, packet + after]. Used for UDP datagrams and TCP SYNs.</summary>
			datagram,
			/// <summary>Any record of this TCP connection that is still within the
			/// connection TTL (includes 1300 rundown). Used for packets of connections whose
			/// SYN was not seen.</summary>
			connection
		};

		// ------------------------------------------------------------------------
		/// <summary>
		/// Transport 5-tuple as seen from this host: local = source of an outbound packet.
		/// Addresses in network byte order (IPv4 in the first 4 bytes), ports in host order.
		/// </summary>
		// ------------------------------------------------------------------------
		struct packet_tuple
		{
			uint16_t family{AF_INET};
			uint8_t protocol{IPPROTO_UDP};
			std::array<uint8_t, 16> local_ip{};
			std::array<uint8_t, 16> remote_ip{};
			uint16_t local_port{};
			uint16_t remote_port{};

			static packet_tuple make_v4(const uint8_t proto, const void* local_ip_be, const uint16_t local_port_host,
			                            const void* remote_ip_be, const uint16_t remote_port_host) noexcept
			{
				packet_tuple t;
				t.family = AF_INET;
				t.protocol = proto;
				std::memcpy(t.local_ip.data(), local_ip_be, 4);
				std::memcpy(t.remote_ip.data(), remote_ip_be, 4);
				t.local_port = local_port_host;
				t.remote_port = remote_port_host;
				return t;
			}

			static packet_tuple make_v6(const uint8_t proto, const void* local_ip_be, const uint16_t local_port_host,
			                            const void* remote_ip_be, const uint16_t remote_port_host) noexcept
			{
				packet_tuple t;
				t.family = AF_INET6;
				t.protocol = proto;
				std::memcpy(t.local_ip.data(), local_ip_be, 16);
				std::memcpy(t.remote_ip.data(), remote_ip_be, 16);
				t.local_port = local_port_host;
				t.remote_port = remote_port_host;
				return t;
			}

			[[nodiscard]] packet_tuple reversed() const noexcept
			{
				packet_tuple t = *this;
				std::swap(t.local_ip, t.remote_ip);
				std::swap(t.local_port, t.remote_port);
				return t;
			}

			bool operator==(const packet_tuple& o) const noexcept
			{
				return family == o.family && protocol == o.protocol && local_port == o.local_port &&
					remote_port == o.remote_port && local_ip == o.local_ip && remote_ip == o.remote_ip;
			}

			bool operator!=(const packet_tuple& o) const noexcept { return !(*this == o); }

			[[nodiscard]] static std::string address_to_string(const uint16_t family, const std::array<uint8_t, 16>& ip)
			{
				char buffer[64] = {};
				if (family == AF_INET)
				{
					std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
					return buffer;
				}
				// Uncompressed IPv6 formatting (no dependency on inet_ntop)
				std::string s;
				for (size_t i = 0; i < 16; i += 2)
				{
					char part[8];
					std::snprintf(part, sizeof(part), "%x", (static_cast<unsigned>(ip[i]) << 8) | ip[i + 1]);
					if (i)
						s += ':';
					s += part;
				}
				return s;
			}

			[[nodiscard]] std::string local_to_string() const
			{
				const auto a = address_to_string(family, local_ip);
				return (family == AF_INET6 ? "[" + a + "]" : a) + ":" + std::to_string(local_port);
			}

			[[nodiscard]] std::string remote_to_string() const
			{
				const auto a = address_to_string(family, remote_ip);
				return (family == AF_INET6 ? "[" + a + "]" : a) + ":" + std::to_string(remote_port);
			}

			[[nodiscard]] std::string to_string() const
			{
				return std::string(protocol == IPPROTO_TCP ? "TCP " : protocol == IPPROTO_UDP ? "UDP " : "IP ") +
					local_to_string() + " -> " + remote_to_string();
			}
		};

		/// <summary>FNV-1a hash of a packet_tuple</summary>
		struct packet_tuple_hash
		{
			size_t operator()(const packet_tuple& t) const noexcept
			{
				uint64_t h = 1469598103934665603ULL;
				auto mix = [&h](const void* p, const size_t n)
				{
					const auto* b = static_cast<const uint8_t*>(p);
					for (size_t i = 0; i < n; ++i)
					{
						h ^= b[i];
						h *= 1099511628211ULL;
					}
				};
				mix(&t.family, sizeof(t.family));
				mix(&t.protocol, sizeof(t.protocol));
				mix(t.local_ip.data(), t.family == AF_INET ? 4 : 16);
				mix(t.remote_ip.data(), t.family == AF_INET ? 4 : 16);
				mix(&t.local_port, sizeof(t.local_port));
				mix(&t.remote_port, sizeof(t.remote_port));
				return static_cast<size_t>(h);
			}
		};

		// ------------------------------------------------------------------------
		/// <summary>Owner of a packet according to ETW</summary>
		// ------------------------------------------------------------------------
		struct owner_info
		{
			/// <summary>Owner PID. Taken from the event payload, except for TCPIP 1031 whose
			/// payload ProcessId is 0: there the event header PID is used (see pid_policy in
			/// etw_packet_attributor::on_event). 0 means unknown, never "Idle".</summary>
			uint32_t pid{};
			/// <summary>true if pid came from EVENT_HEADER.ProcessId instead of the payload</summary>
			bool pid_from_header{};
			/// <summary>ProcessStartKey (TCPIP v1 events), 0 if unknown</summary>
			uint64_t process_start_key{};
			/// <summary>Full image path, resolved on the consumer thread when the event
			/// arrived; empty if the process could not be opened</summary>
			std::wstring image_path;
			/// <summary>true if the image path belongs to the process that emitted the event
			/// (start key or creation time check); false if PID reuse could not be excluded</summary>
			bool image_verified{};
			/// <summary>Event that decided this owner</summary>
			event_source source{event_source::none};
			uint16_t event_id{};
			uint8_t event_version{};
			/// <summary>Event header timestamp (raw QPC)</summary>
			int64_t event_qpc{};
			/// <summary>QPC when the consumer received the event</summary>
			int64_t received_qpc{};
			/// <summary>TCPIP Status field where present (1031/1033/1034/1017), else 0</summary>
			uint32_t status{};
			/// <summary>Bit mask (1 << event_source) of every source that produced a matching
			/// record for this lookup (lets callers compare 42 vs 1169, 1031 vs KN12, ...)</summary>
			uint32_t sources_seen{};
			/// <summary>true if matching records named different (known, nonzero) PIDs</summary>
			bool conflict{};
			/// <summary>TCP only, filled by etw_packet_attributor::tcp_outcome(): a TCPIP 1034
			/// (connect failed) record exists for this connection attempt</summary>
			bool connect_failed{};
			/// <summary>Status of that TCPIP 1034 record (e.g. 0xC0000120 STATUS_CANCELLED for a
			/// local abort), 0 if none</summary>
			uint32_t connect_status{};
			/// <summary>TCP only: TCPIP 1033 or Kernel-Network 12/28 (connected) was seen</summary>
			bool connect_completed{};
			/// <summary>TCP only: the owner was first taken from a TCPIP 1031 header PID, and the
			/// first TCPIP 1033/1034 of the same connect attempt (after that 1031 and before the
			/// next 1031 of the tuple) named a different (nonzero) payload PID, which replaced
			/// it (pid, process_start_key and image now come from that record; source, event
			/// id and latency stay those of the 1031). Guards against a connect completed in
			/// another process's context, e.g. by a WFP callout that pends ALE connect
			/// authorization; that case is not verified.</summary>
			bool header_pid_overridden{};
			/// <summary>The 1031 header PID that was replaced (0 if none)</summary>
			uint32_t overridden_header_pid{};
			/// <summary>TCP only: the matching 1031 had no usable PID (payload 0, header 0 or
			/// 4), and the owner was filled from the first 1033/1034 of the same connect attempt;
			/// source, event id, event time and latency are those of that record (about one RTT
			/// after the SYN).</summary>
			bool pid_from_outcome{};

			/// <summary>PID 4 (System). PID 0 is "unknown", not a system owner.</summary>
			[[nodiscard]] bool is_system() const noexcept { return pid == 4; }
			/// <summary>No event named a real PID (e.g. TCPIP 1031 payload ProcessId 0 with a
			/// header PID of 0 or 4)</summary>
			[[nodiscard]] bool is_unknown() const noexcept { return pid == 0; }

			[[nodiscard]] std::wstring image_name() const
			{
				if (pid == 4)
					return L"System";
				if (pid == 0)
					return L"unknown";
				const auto pos = image_path.find_last_of(L"\\/");
				return pos == std::wstring::npos ? image_path : image_path.substr(pos + 1);
			}
		};

		/// <summary>One DNS caller candidate for a Dnscache wire query</summary>
		struct dns_caller
		{
			uint32_t pid{};
			std::wstring image_path;
			bool image_verified{};
			event_source source{event_source::none};
			uint8_t event_version{};
			/// <summary>true if the PID came from a ClientPID field (tier 1), false if from the
			/// 3006 event header (tier 2)</summary>
			bool from_client_pid{};
			/// <summary>Query name as logged by the event (lower case, no trailing dot)</summary>
			std::wstring query_name;
			int64_t event_qpc{};
			int64_t received_qpc{};

			[[nodiscard]] std::wstring image_name() const
			{
				const auto pos = image_path.find_last_of(L"\\/");
				return pos == std::wstring::npos ? image_path : image_path.substr(pos + 1);
			}
		};

		enum class dns_tier : uint8_t
		{
			none,       // no candidate
			client_pid, // tier 1: 3019 (3010) ClientPID
			header_pid  // tier 2: 3006 header PID + QNAME/QTYPE (+ search suffix) match
		};

		inline const char* to_string(const dns_tier t) noexcept
		{
			switch (t)
			{
			case dns_tier::client_pid: return "tier1:ClientPID";
			case dns_tier::header_pid: return "tier2:3006-header-PID";
			default: return "none";
			}
		}

		/// <summary>Result of a DNS caller lookup</summary>
		struct dns_attribution
		{
			dns_tier tier{dns_tier::none};
			/// <summary>All candidate callers (coalesced queries yield several)</summary>
			std::vector<dns_caller> callers;
			/// <summary>3010/3019 confirmed that this name and type went to the network</summary>
			bool wire_confirmed{};
			/// <summary>At least one candidate matched only through a DNS search suffix</summary>
			bool suffix_match{};
		};

		/// <summary>Per (provider, id, version) schema verdict</summary>
		struct schema_status
		{
			std::string provider;
			uint16_t id{};
			uint8_t version{};
			bool accepted{};
			/// <summary>Property list as reported by TDH: name:intype ...</summary>
			std::string properties;
			/// <summary>Which wanted fields were found / why the schema was rejected</summary>
			std::string detail;
			uint64_t events{};
		};

		/// <summary>Per provider enable status</summary>
		struct provider_status
		{
			std::string name;
			bool requested{};
			bool enabled{};
			ULONG enable_status{ERROR_SUCCESS};
			ULONGLONG keywords{};
			std::vector<USHORT> event_ids;
			/// <summary>An event id that was not requested arrived: the event-id filter is not
			/// honoured, so the provider's events are ignored (plan gate 3)</summary>
			bool unfiltered{};
			std::vector<USHORT> unrequested_ids_seen;
		};

		/// <summary>Loopback self-test result (implementation plan gate 5)</summary>
		struct self_test_status
		{
			bool ran{};
			bool ipv4_ok{};
			bool ipv6_attempted{};
			bool ipv6_ok{};
			/// <summary>Worst delivery latency with an immediate EVENT_TRACE_CONTROL_FLUSH, ms (-1 = none)</summary>
			double on_demand_ms{-1};
			/// <summary>Median delivery latency with no flush call (session timer only), ms
			/// (-1 = none). One slow sample on a loaded 2-vCPU VM must not decide [M19045].</summary>
			double timer_ms{-1};
			/// <summary>Every timer probe sample, ms, in the order taken</summary>
			std::vector<double> timer_samples;
			/// <summary>Every on-demand IPv4 probe sample, ms</summary>
			std::vector<double> on_demand_samples;
			/// <summary>timer_ms (median) is <= 50 ms</summary>
			bool timer_ok{};
			uint32_t ipv4_sources{};
			uint32_t ipv6_sources{};
			bool tcp_attempted{};
			/// <summary>true only if the loopback connect was attributed to this process
			/// (find_owner on the connect tuple returned our own PID)</summary>
			bool tcp_ok{};
			double tcp_on_demand_ms{-1};
			uint32_t tcp_sources{};
			/// <summary>PID that the attributor chose for the loopback connect (0 = unknown)</summary>
			uint32_t tcp_owner_pid{};
			/// <summary>Event that decided tcp_owner_pid</summary>
			event_source tcp_owner_source{event_source::none};
			bool tcp_owner_from_header{};
			/// <summary>GetCurrentProcessId() of the attributor</summary>
			uint32_t own_pid{};
			uint64_t runs{};
			uint64_t failures{};
			std::string detail;
		};

		/// <summary>Capability gate report</summary>
		struct gate_report
		{
			bool elevated{};
			bool session_started{};
			ULONG start_status{ERROR_SUCCESS};
			std::string session_name;
			ULONG requested_log_file_mode{};
			ULONG actual_log_file_mode{};
			ULONG flush_timer{};
			bool independent_mode_kept{};
			bool ms_timer_bit_kept{};
			std::vector<provider_status> providers;
			std::vector<schema_status> schemas;
			self_test_status self_test;
			flush_mode requested_flush{flush_mode::automatic};
			effective_flush flush{effective_flush::none};
			bool udp_available{};
			bool tcp_available{};
			bool dns_available{};
			dns_tier dns_tier_detected{dns_tier::none};
			bool available{};
			std::string failure;

			[[nodiscard]] std::string to_string() const
			{
				std::ostringstream os;
				char hex[32];
				os << "ETW attribution: " << (available ? "AVAILABLE" : "UNAVAILABLE");
				if (!failure.empty())
					os << " (" << failure << ")";
				os << "\n  elevated=" << (elevated ? "yes" : "no")
					<< " session_started=" << (session_started ? "yes" : "no")
					<< " StartTrace=" << start_status << " session=" << session_name;
				std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(requested_log_file_mode));
				os << "\n  LogFileMode requested=" << hex;
				std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(actual_log_file_mode));
				os << " read-back=" << hex << " FlushTimer=" << flush_timer
					<< " INDEPENDENT kept=" << (independent_mode_kept ? "yes" : "no")
					<< " ms-timer bit kept=" << (ms_timer_bit_kept ? "yes" : "no");
				for (const auto& p : providers)
				{
					if (!p.requested)
						continue;
					std::snprintf(hex, sizeof(hex), "0x%llX", static_cast<unsigned long long>(p.keywords));
					os << "\n  provider " << p.name << ": enabled=" << (p.enabled ? "yes" : "no")
						<< " status=" << p.enable_status << " keywords=" << hex << " ids={";
					for (size_t i = 0; i < p.event_ids.size(); ++i)
						os << (i ? "," : "") << p.event_ids[i];
					os << "}";
					if (p.unfiltered)
					{
						os << " FILTER NOT HONOURED, unrequested ids seen={";
						for (size_t i = 0; i < p.unrequested_ids_seen.size(); ++i)
							os << (i ? "," : "") << p.unrequested_ids_seen[i];
						os << "}";
					}
				}
				for (const auto& s : schemas)
				{
					os << "\n  schema " << s.provider << " " << s.id << " v" << static_cast<unsigned>(s.version)
						<< ": " << (s.accepted ? "accepted" : "REJECTED") << " [" << s.detail << "] events=" << s.events
						<< "\n      " << s.properties;
				}
				os << "\n  self-test: ran=" << (self_test.ran ? "yes" : "no")
					<< " ipv4=" << (self_test.ipv4_ok ? "ok" : "fail")
					<< " ipv6=" << (!self_test.ipv6_attempted ? "n/a" : self_test.ipv6_ok ? "ok" : "fail")
					<< " tcp=" << (!self_test.tcp_attempted ? "n/a" : self_test.tcp_ok ? "ok" : "fail")
					<< " on-demand=" << self_test.on_demand_ms << "ms"
					<< " timer=" << self_test.timer_ms << "ms"
					<< " timer_ok=" << (self_test.timer_ok ? "yes" : "no")
					<< " tcp-on-demand=" << self_test.tcp_on_demand_ms << "ms"
					<< " runs=" << self_test.runs << " failures=" << self_test.failures;
				auto samples = [&os](const char* name, const std::vector<double>& v)
				{
					os << " " << name << "={";
					for (size_t i = 0; i < v.size(); ++i)
						os << (i ? "," : "") << v[i];
					os << "}";
				};
				os << "\n   ";
				samples("timer-samples-ms", self_test.timer_samples);
				samples("on-demand-samples-ms", self_test.on_demand_samples);
				if (self_test.tcp_attempted)
				{
					os << "\n    tcp-owner=" << self_test.tcp_owner_pid
						<< (self_test.tcp_owner_pid == self_test.own_pid && self_test.own_pid != 0 ? " (self)" : " (NOT self)")
						<< " own-pid=" << self_test.own_pid << " via " << etw::to_string(self_test.tcp_owner_source)
						<< (self_test.tcp_owner_from_header ? " (header PID)" : "");
				}
				os
					<< "\n    v4-sources={" << sources_to_string(self_test.ipv4_sources) << "}"
					<< " v6-sources={" << sources_to_string(self_test.ipv6_sources) << "}"
					<< " tcp-sources={" << sources_to_string(self_test.tcp_sources) << "}";
				if (!self_test.detail.empty())
					os << "\n    " << self_test.detail;
				os << "\n  flush: requested=" << etw::to_string(requested_flush) << " effective=" << etw::to_string(flush)
					<< "\n  udp=" << (udp_available ? "yes" : "no") << " tcp=" << (tcp_available ? "yes" : "no")
					<< " dns=" << (dns_available ? "yes" : "no") << " dns-tier=" << etw::to_string(dns_tier_detected);
				return os.str();
			}
		};

		/// <summary>Latency histogram bucket upper bounds, milliseconds</summary>
		inline constexpr std::array<double, 12> latency_bucket_ms = {0, 1, 2, 5, 10, 20, 30, 50, 75, 100, 250, 1000};

		/// <summary>Counter snapshot</summary>
		struct counters
		{
			uint64_t events_total{};
			std::array<uint64_t, static_cast<size_t>(event_source::count)> events_by_source{};
			uint64_t events_unrequested{};
			uint64_t events_schema_rejected{};
			uint64_t events_parse_failed{};
			uint64_t events_own_process{};
			/// <summary>Finished lookups: matches + timeouts. A caller that polls lookup()
			/// for one packet counts once (when it matches or calls record_timeout()).</summary>
			uint64_t lookups{};
			uint64_t matches{};
			uint64_t timeouts{};
			uint64_t conflicts{};
			uint64_t flush_calls{};
			uint64_t flush_call_max_us{};
			uint32_t flush_interval_ms{};
			uint64_t image_lookups{};
			uint64_t image_unverified{};
			uint64_t cache_entries{};
			uint64_t dns_entries{};
			ULONG events_lost{};
			ULONG log_buffers_lost{};
			ULONG realtime_buffers_lost{};
			/// <summary>Delivery latency (event received - packet read) of matches;
			/// slot i counts latency in (bound[i-1], bound[i]]; the last slot counts > 1000 ms</summary>
			std::array<uint64_t, latency_bucket_ms.size() + 1> latency_histogram{};
		};

		/// <summary>Configuration</summary>
		struct attributor_config
		{
			/// <summary>Real-time session name. Empty (default):
			/// "<session_name_prefix>-<pid>-<process creation time, 16 hex>-<module, hex>-<n>",
			/// where module is the base address of the module (EXE or DLL) that contains this
			/// code and n counts instances in that module, so concurrent instances (in other
			/// processes, in other modules of the same process, or in the same module) never
			/// share (and never stop) each other's session. A non-empty name is used verbatim.
			/// If a session with the name already exists, start() fails instead of stopping it.
			/// The one exception: if stop() failed to stop this object's own default-named
			/// session, the next start() retries that STOP first.</summary>
			std::wstring session_name;
			/// <summary>Prefix of the default session name. At start, sessions named
			/// "<prefix>-<pid>-<creation>-..." are stopped if no process with that pid AND
			/// that creation time is running (left behind by a crashed or killed instance; a
			/// reused PID has a different creation time). Sessions of live processes are never
			/// touched; if the creation time of a running pid cannot be read, its sessions are
			/// kept. The older form "<prefix>-<pid>" is stopped only if that pid is not
			/// running (or is our own pid: this process never creates that form).</summary>
			std::wstring session_name_prefix = L"NdisApi-PacketOwner";
			/// <summary>Enable TCP connection events (UDP is always enabled: it is the
			/// liveness source of the loopback self-test)</summary>
			bool enable_tcp = true;
			/// <summary>Enable DNS-Client events for Dnscache caller attribution</summary>
			bool enable_dns = false;
			/// <summary>Request a TCPIP capture-state (1300 rundown of existing connections) [U]</summary>
			bool tcp_rundown = true;
			flush_mode flush = flush_mode::automatic;
			/// <summary>Strict window for datagram matches: [t - before, t + after]
			/// (plan 3.4; measured offsets -80..-370 us on 26300)</summary>
			std::chrono::microseconds window_before{50000};
			std::chrono::microseconds window_after{1000};
			/// <summary>TCP connection events may be written after the SYN is read [U]; the
			/// after-window for TCP is therefore wider</summary>
			std::chrono::microseconds tcp_window_after{50000};
			/// <summary>UDP record TTL after the last event</summary>
			std::chrono::milliseconds udp_ttl{2000};
			/// <summary>TCP connection record TTL after the last event</summary>
			std::chrono::milliseconds tcp_ttl{120000};
			size_t max_cache_entries = 65536;
			/// <summary>DNS correlation window before the wire packet</summary>
			std::chrono::milliseconds dns_window{2000};
			/// <summary>Repeat the loopback self-test this often (0 = never)</summary>
			std::chrono::seconds self_test_interval{60};
			/// <summary>Ignore events emitted for this process (except self-test tuples)</summary>
			bool ignore_own_process = true;
			/// <summary>Optional diagnostic sink (called from internal threads)</summary>
			std::function<void(const std::string&)> log;
		};
	}

	// --------------------------------------------------------------------------------
	/// <summary>
	/// ETW owner attributor: one real-time session, one consumer thread, one maintenance
	/// thread. lookup(), wait_for(), tcp_outcome(), dns_lookup(), wait_for_dns(),
	/// request_flush(), get_counters() and report() may be called from any thread, also
	/// while another thread runs start() or stop() (lookup(), wait_for(), dns_lookup() and
	/// wait_for_dns() return nothing while ETW is unavailable). start() and stop()
	/// serialize with each other; the destructor must not run concurrently with any call.
	/// </summary>
	// --------------------------------------------------------------------------------
	class etw_packet_attributor
	{
	public:
		using clock = std::chrono::steady_clock;

		explicit etw_packet_attributor(etw::attributor_config config = {}) : config_(std::move(config))
		{
			LARGE_INTEGER f;
			QueryPerformanceFrequency(&f);
			qpc_frequency_ = f.QuadPart;
			own_pid_ = GetCurrentProcessId();
			own_creation_ = process_creation_time(GetCurrentProcess());
			if (config_.session_name.empty())
			{
				// pid + creation time identify this process even after PID reuse; the module
				// base address and the counter (one per module: each EXE/DLL that includes
				// this header has its own) separate instances inside it.
				HMODULE module = nullptr;
				GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				                   reinterpret_cast<LPCWSTR>(&instance_counter()), &module);
				wchar_t ids[64];
				std::swprintf(ids, sizeof(ids) / sizeof(ids[0]), L"%016llX-%llX",
				              static_cast<unsigned long long>(own_creation_),
				              static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(module)));
				session_name_ = config_.session_name_prefix + L"-" + std::to_wstring(own_pid_) + L"-" + ids + L"-" +
					std::to_wstring(instance_counter().fetch_add(1) + 1);
			}
			else
				session_name_ = config_.session_name;
			init_provider_table();
		}

		~etw_packet_attributor() { stop(); }

		etw_packet_attributor(const etw_packet_attributor&) = delete;
		etw_packet_attributor& operator=(const etw_packet_attributor&) = delete;
		etw_packet_attributor(etw_packet_attributor&&) = delete;
		etw_packet_attributor& operator=(etw_packet_attributor&&) = delete;

		// ****************************************************************************
		/// <summary>Current QPC value; take it as soon as the packet is read</summary>
		// ****************************************************************************
		static int64_t qpc_now() noexcept
		{
			LARGE_INTEGER c;
			QueryPerformanceCounter(&c);
			return c.QuadPart;
		}

		[[nodiscard]] double qpc_to_ms(const int64_t delta) const noexcept
		{
			return static_cast<double>(delta) * 1000.0 / static_cast<double>(qpc_frequency_);
		}

		[[nodiscard]] int64_t us_to_qpc(const int64_t us) const noexcept
		{
			return us * qpc_frequency_ / 1000000;
		}

		// ****************************************************************************
		/// <summary>
		/// Starts the session and runs every capability gate (implementation plan 2).
		/// Returns true if ETW attribution is usable. On false the session is stopped and
		/// report() explains why; the caller keeps its IP Helper behaviour.
		/// </summary>
		// ****************************************************************************
		bool start()
		{
			std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
			if (started_)
				return available_.load();

			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				const auto providers = std::move(report_.providers);
				report_ = etw::gate_report{};
				report_.providers = providers;
				for (auto& p : report_.providers)
				{
					p.enabled = false;
					p.enable_status = ERROR_SUCCESS;
				}
				report_.requested_flush = config_.flush;
				report_.elevated = is_elevated();
			}

			WSADATA wsa{};
			wsa_started_ = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

			stopping_ = false;
			live_ = false;
			gate_final_ = false;
			// A "filter not honoured" observation belongs to the previous session: the
			// providers are enabled again below. TDH schemas are kept (they do not change).
			for (auto& u : provider_unfiltered_)
				u = false;
			{
				std::lock_guard<std::mutex> lock(unrequested_mutex_);
				for (auto& u : unrequested_seen_)
					u.clear();
			}
			calibrate_clock();

			// Gate 1: elevation. Real-time sessions with kernel providers need admin.
			if (!report_.elevated)
				return fail_start("process is not elevated");

			// Gate 2: the session must keep INDEPENDENT_SESSION_MODE in the read-back.
			const bool want_ms_timer = config_.flush != etw::flush_mode::on_demand;
			if (!start_session(want_ms_timer))
				return fail_start(report_.failure.empty() ? std::string("StartTrace failed") : report_.failure);

			// Gate 3: providers with event-id filters (unrequested ids are detected by the consumer).
			if (!enable_providers())
				return fail_start("neither Kernel-Network nor TCPIP could be enabled with an event-id filter");

			if (!start_consumer())
				return fail_start("OpenTraceW failed");

			if (config_.enable_dns)
			{
				refresh_suffixes();
				refresh_dnscache_pid();
			}
			started_ = true;
			maintenance_thread_ = std::thread(&etw_packet_attributor::maintenance_proc, this);

			// Gate 4 (TDH schema) runs on the first event of each (provider, id, version).
			// Gate 5: the loopback self-test proves liveness and picks the flush mode.
			run_initial_self_test();

			if (config_.enable_tcp && config_.tcp_rundown && provider_enabled(tcpip_index))
			{
				// Ask TCPIP for a rundown (1300) of connections that already exist [U].
				const auto status = EnableTraceEx2(session_handle_, &etw::tcpip_provider,
				                                   EVENT_CONTROL_CODE_CAPTURE_STATE, TRACE_LEVEL_VERBOSE,
				                                   0, 0, 0, nullptr);
				log("TCPIP capture-state (1300 rundown) request status=" + std::to_string(status));
			}

			gate_final_ = true;
			refresh_availability();
			if (!available_.load())
			{
				std::string reason;
				{
					std::lock_guard<std::mutex> lock(report_mutex_);
					reason = report_.failure.empty() ? std::string("gate failed") : report_.failure;
				}
				return fail_start(reason);
			}

			log(report().to_string());
			return true;
		}

		// ****************************************************************************
		/// <summary>Stops the session and joins all threads. Idempotent.</summary>
		// ****************************************************************************
		void stop()
		{
			std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
			stop_locked();
		}

		/// <summary>true while ETW attribution is usable (all gates passed and the
		/// periodic self-test still passes)</summary>
		[[nodiscard]] bool available() const noexcept { return available_.load(); }

		/// <summary>true while TCP owners are served: available(), TCP enabled, a TCP connect
		/// schema accepted, and the loopback TCP self-test at start attributed the connect
		/// to this process. lookup() and wait_for() return nothing for TCP tuples otherwise.</summary>
		[[nodiscard]] bool tcp_available() const noexcept { return tcp_available_.load(); }

		// ****************************************************************************
		/// <summary>Gate report snapshot (schemas, unrequested ids and DNS tier are live)</summary>
		// ****************************************************************************
		[[nodiscard]] etw::gate_report report() const
		{
			std::lock_guard<std::mutex> lock(report_mutex_);
			etw::gate_report r = report_;
			{
				std::lock_guard<std::mutex> schema_lock(schema_mutex_);
				r.schemas.clear();
				for (const auto& kv : schemas_)
					r.schemas.push_back(kv.second->status);
			}
			std::sort(r.schemas.begin(), r.schemas.end(), [](const etw::schema_status& a, const etw::schema_status& b)
			{
				return std::tie(a.provider, a.id, a.version) < std::tie(b.provider, b.id, b.version);
			});
			{
				std::lock_guard<std::mutex> u(unrequested_mutex_);
				for (size_t i = 0; i < provider_count && i < r.providers.size(); ++i)
				{
					r.providers[i].unfiltered = provider_unfiltered_[i].load();
					r.providers[i].unrequested_ids_seen.assign(unrequested_seen_[i].begin(),
					                                           unrequested_seen_[i].end());
				}
			}
			r.dns_tier_detected = dns_tier_seen_.load();
			r.available = available_.load();
			return r;
		}

		// ****************************************************************************
		/// <summary>
		/// Non-blocking lookup. Returns the owner if an event for this tuple has already
		/// been consumed. packet_qpc is QueryPerformanceCounter() at packet read.
		/// Each successful call counts as one match: callers that poll should stop after
		/// the first match, and call record_timeout() when they give up.
		/// Records whose PID is unknown (0) never outrank a record with a real PID. If only
		/// unknown-PID records match, nullopt is returned unless accept_unknown is true
		/// (pass true on the last attempt to report "an event was seen, owner unknown").
		/// </summary>
		// ****************************************************************************
		std::optional<etw::owner_info> lookup(const etw::packet_tuple& tuple, const int64_t packet_qpc,
		                                      const etw::match_kind kind = etw::match_kind::datagram,
		                                      const bool accept_unknown = false)
		{
			if (!available_.load() || (tuple.protocol == IPPROTO_TCP && !tcp_available_.load()))
				return std::nullopt;
			auto result = find_owner(tuple, packet_qpc, kind);
			if (result && result->is_unknown() && !accept_unknown)
				return std::nullopt;
			if (result)
				count_match(*result, packet_qpc);
			return result;
		}

		// ****************************************************************************
		/// <summary>
		/// TCP connect outcome for a SYN read at packet_qpc: scans every record of the
		/// tuple written from window_before ahead of the SYN onwards (1033/1034 and KN 12
		/// come about one RTT later, a local abort much later [M26300]) and fills
		/// connect_completed / connect_failed / connect_status of owner. Only records of the
		/// same connect attempt count: from the owner's 1031 up to the next 1031 of the tuple
		/// (connect_attempt()). If owner came from a 1031 header PID and the first 1033/1034
		/// of the attempt names a different payload PID, that PID replaces it
		/// (header_pid_overridden); if owner has no PID, it is filled from that record
		/// (pid_from_outcome). Does not count as a lookup. Returns true if the outcome
		/// (completed or failed) is known.
		/// </summary>
		// ****************************************************************************
		bool tcp_outcome(const etw::packet_tuple& tuple, const int64_t packet_qpc, etw::owner_info& owner) const
		{
			const auto before = us_to_qpc(config_.window_before.count());
			std::shared_lock<std::shared_mutex> lock(cache_mutex_);
			const auto it = cache_.find(tuple);
			if (it == cache_.end())
				return owner.connect_completed || owner.connect_failed;
			const auto attempt = scan_attempt(it->second,
			                                  connect_attempt(it->second, (std::min)(packet_qpc - before, owner.event_qpc),
			                                                  owner.event_qpc));
			owner.sources_seen |= attempt.sources;
			if (attempt.pids_differ || (owner.pid != 0 && attempt.known_pid != 0 && attempt.known_pid != owner.pid))
				owner.conflict = true;
			owner.connect_completed = owner.connect_completed || attempt.completed;
			if (attempt.failed)
			{
				owner.connect_failed = true;
				owner.connect_status = attempt.failed_status;
			}
			if (attempt.payload)
				apply_payload_pid(owner, *attempt.payload);
			return owner.connect_completed || owner.connect_failed;
		}

		// ****************************************************************************
		/// <summary>
		/// Blocking lookup: waits until the event arrives or the deadline passes, issuing
		/// rate-limited flushes while it waits. A timeout is counted.
		/// </summary>
		// ****************************************************************************
		std::optional<etw::owner_info> wait_for(const etw::packet_tuple& tuple, const int64_t packet_qpc,
		                                        const clock::time_point deadline,
		                                        const etw::match_kind kind = etw::match_kind::datagram)
		{
			waiter_scope scope(waiters_);
			for (;;)
			{
				const auto seen = generation();
				if (!available_.load() || stopping_.load() ||
					(tuple.protocol == IPPROTO_TCP && !tcp_available_.load()))
					break;
				if (auto r = find_owner(tuple, packet_qpc, kind); r && !r->is_unknown())
				{
					count_match(*r, packet_qpc);
					return r;
				}
				const auto now = clock::now();
				if (now >= deadline)
					break;
				request_flush(waiters_.load());
				wait_for_events(seen, std::min(deadline, now + std::chrono::milliseconds(flush_interval_ms_.load())));
			}
			++timeouts_;
			return std::nullopt;
		}

		/// <summary>Records a timeout for callers that poll lookup() themselves</summary>
		void record_timeout() noexcept { ++timeouts_; }

		/// <summary>Event generation counter; increases whenever a record is inserted</summary>
		[[nodiscard]] uint64_t generation() const noexcept { return generation_.load(); }

		// ****************************************************************************
		/// <summary>Waits until generation() differs from seen_generation or the deadline</summary>
		// ****************************************************************************
		void wait_for_events(const uint64_t seen_generation, const clock::time_point deadline)
		{
			std::unique_lock<std::mutex> lock(wake_mutex_);
			wake_waiters_.fetch_add(1);
			wake_cv_.wait_until(lock, deadline, [&]
			{
				return generation_.load() != seen_generation || stopping_.load();
			});
			wake_waiters_.fetch_sub(1);
		}

		// ****************************************************************************
		/// <summary>
		/// Requests an EVENT_TRACE_CONTROL_FLUSH according to the effective flush policy
		/// (implementation plan 3.3). pending = number of lookups currently waiting.
		/// Rate-limited and non-blocking for concurrent callers; cheap to call often.
		/// </summary>
		// ****************************************************************************
		void request_flush(const size_t pending)
		{
			const auto mode = effective_flush_.load();
			if (mode == etw::effective_flush::none || mode == etw::effective_flush::timer)
				return;
			// With a working ms timer, flush on demand only while few lookups wait and
			// the last flush call was cheap.
			if (mode == etw::effective_flush::timer_and_light_on_demand &&
				(pending > 8 || last_flush_us_.load() > 2000))
				return;

			std::unique_lock<std::mutex> lock(flush_mutex_, std::try_to_lock);
			if (!lock.owns_lock())
				return;

			if (clock::now() - last_flush_ < std::chrono::milliseconds(flush_interval_ms_.load()))
				return;

			const auto us = flush_now();
			last_flush_ = clock::now();

			if (mode == etw::effective_flush::on_demand)
			{
				// Double up to 50 ms when more than 64 lookups wait or a flush call took more
				// than 5 ms (the call blocked up to 85 ms on a 2-vCPU VM [M19045]); back to
				// 10 ms once the backlog clears.
				auto interval = flush_interval_ms_.load();
				if (pending > 64 || us > 5000)
					interval = std::min<uint32_t>(interval * 2, 50);
				else
					interval = 10;
				flush_interval_ms_.store(interval);
			}
		}

		// ****************************************************************************
		/// <summary>Dnscache service PID, 0 if unknown. Returns a snapshot (no I/O): it is
		/// queried from the SCM in start() and every 10 s on the maintenance thread (with
		/// enable_dns), so a caller on the packet path never waits for SCM RPCs.
		/// refresh = true queries the SCM synchronously on the caller's thread and updates
		/// the snapshot; use it only off the packet path (e.g. at start-up, or when the
		/// attributor is not started).</summary>
		// ****************************************************************************
		uint32_t dnscache_pid(const bool refresh = false)
		{
			if (refresh)
				refresh_dnscache_pid();
			return dnscache_pid_.load();
		}

		// ****************************************************************************
		/// <summary>
		/// DNS caller lookup for a wire query sent by Dnscache (implementation plan 4).
		/// wire_qname: QNAME from the packet (any case, trailing dot optional).
		/// Tier 1: 3019 (and 3010) ClientPID, de-duplicated per PID across NetworkIndex.
		/// Tier 2: 3006 header PID with QNAME/QTYPE match, including search-suffix
		/// rewrites. 3006 entries are never consumed (they also cover cache hits).
		/// 3010/3019 without ClientPID only confirm that the query went to the network.
		/// </summary>
		// ****************************************************************************
		etw::dns_attribution dns_lookup(const std::string_view wire_qname, const uint16_t qtype,
		                                const int64_t packet_qpc)
		{
			etw::dns_attribution result;
			if (!available_.load() || !config_.enable_dns)
				return result;

			const auto wire = normalize_name(widen(wire_qname));
			const auto from = packet_qpc - us_to_qpc(std::chrono::duration_cast<std::chrono::microseconds>(
				config_.dns_window).count());
			const auto to = packet_qpc + us_to_qpc(config_.window_after.count());
			const auto dnscache = dnscache_pid();
			const auto suffixes = search_suffixes(); // snapshot; refreshed by the maintenance thread

			std::vector<etw::dns_caller> tier1;
			std::vector<etw::dns_caller> tier2;
			bool suffix_used = false;
			auto contains = [](const std::vector<etw::dns_caller>& v, const uint32_t pid)
			{
				return std::any_of(v.begin(), v.end(), [pid](const etw::dns_caller& c) { return c.pid == pid; });
			};
			{
				std::lock_guard<std::mutex> lock(dns_mutex_);
				for (const auto& e : dns_events_)
				{
					if (e.caller.event_qpc < from || e.caller.event_qpc > to || e.qtype != qtype)
						continue;

					if (e.caller.source == etw::event_source::dns_query_wire ||
						e.caller.source == etw::event_source::dns_query_sent)
					{
						if (e.caller.query_name != wire)
							continue;
						result.wire_confirmed = true;
						if (e.has_client_pid && e.caller.pid != 0 && e.caller.pid != dnscache &&
							!contains(tier1, e.caller.pid))
							tier1.push_back(e.caller);
					}
					else if (e.caller.source == etw::event_source::dns_query_called)
					{
						if (e.caller.pid == 0 || e.caller.pid == dnscache ||
							(config_.ignore_own_process && e.caller.pid == own_pid_))
							continue;
						bool via_suffix = false;
						if (!name_matches(wire, e.caller.query_name, *suffixes, via_suffix))
							continue;
						if (!contains(tier2, e.caller.pid))
						{
							tier2.push_back(e.caller);
							suffix_used = suffix_used || via_suffix;
						}
					}
				}
			}

			if (!tier1.empty())
			{
				result.tier = etw::dns_tier::client_pid;
				result.callers = std::move(tier1);
			}
			else if (!tier2.empty())
			{
				result.tier = etw::dns_tier::header_pid;
				result.callers = std::move(tier2);
				result.suffix_match = suffix_used;
			}
			return result;
		}

		// ****************************************************************************
		/// <summary>Blocking DNS caller lookup with rate-limited flushes</summary>
		// ****************************************************************************
		etw::dns_attribution wait_for_dns(const std::string_view wire_qname, const uint16_t qtype,
		                                  const int64_t packet_qpc, const clock::time_point deadline)
		{
			waiter_scope scope(waiters_);
			for (;;)
			{
				const auto seen = generation();
				auto r = dns_lookup(wire_qname, qtype, packet_qpc);
				if (!r.callers.empty() || !available_.load() || stopping_.load())
					return r;
				const auto now = clock::now();
				if (now >= deadline)
					return r;
				request_flush(waiters_.load());
				wait_for_events(seen, std::min(deadline, now + std::chrono::milliseconds(flush_interval_ms_.load())));
			}
		}

		// ****************************************************************************
		/// <summary>Counter snapshot (EventsLost etc. read with EVENT_TRACE_CONTROL_QUERY)</summary>
		// ****************************************************************************
		etw::counters get_counters() const
		{
			etw::counters c;
			c.events_total = events_total_.load();
			for (size_t i = 0; i < c.events_by_source.size(); ++i)
				c.events_by_source[i] = events_by_source_[i].load();
			c.events_unrequested = events_unrequested_.load();
			c.events_schema_rejected = events_schema_rejected_.load();
			c.events_parse_failed = events_parse_failed_.load();
			c.events_own_process = events_own_process_.load();
			c.matches = matches_.load();
			c.timeouts = timeouts_.load();
			c.lookups = c.matches + c.timeouts;
			c.conflicts = conflicts_.load();
			c.flush_calls = flush_calls_.load();
			c.flush_call_max_us = flush_call_max_us_.load();
			c.flush_interval_ms = flush_interval_ms_.load();
			c.image_lookups = image_lookups_.load();
			c.image_unverified = image_unverified_.load();
			{
				std::shared_lock<std::shared_mutex> lock(cache_mutex_);
				c.cache_entries = cache_.size();
			}
			{
				std::lock_guard<std::mutex> lock(dns_mutex_);
				c.dns_entries = dns_events_.size();
			}
			for (size_t i = 0; i < c.latency_histogram.size(); ++i)
				c.latency_histogram[i] = latency_histogram_[i].load();
			query_loss(c.events_lost, c.log_buffers_lost, c.realtime_buffers_lost);
			return c;
		}

		[[nodiscard]] const etw::attributor_config& config() const noexcept { return config_; }

	private:
		struct waiter_scope
		{
			explicit waiter_scope(std::atomic<size_t>& w) : w_(w) { w_.fetch_add(1); }
			~waiter_scope() { w_.fetch_sub(1); }
			waiter_scope(const waiter_scope&) = delete;
			waiter_scope& operator=(const waiter_scope&) = delete;
			std::atomic<size_t>& w_;
		};

		void count_match(const etw::owner_info& r, const int64_t packet_qpc)
		{
			++matches_;
			if (r.conflict)
				++conflicts_;
			record_latency(r.received_qpc - packet_qpc);
		}

		// ------------------------------------------------------------------------
		// Provider table
		// ------------------------------------------------------------------------
		static constexpr size_t kernel_network_index = 0;
		static constexpr size_t tcpip_index = 1;
		static constexpr size_t dns_client_index = 2;
		static constexpr size_t provider_count = 3;

		struct provider_def
		{
			GUID guid;
			const char* name;
		};

		static const provider_def& provider(const size_t index)
		{
			static const provider_def defs[provider_count] = {
				{etw::kernel_network_provider, "Microsoft-Windows-Kernel-Network"},
				{etw::tcpip_provider, "Microsoft-Windows-TCPIP"},
				{etw::dns_client_provider, "Microsoft-Windows-DNS-Client"},
			};
			return defs[index];
		}

		void init_provider_table()
		{
			report_.providers.clear();
			report_.providers.resize(provider_count);
			for (size_t i = 0; i < provider_count; ++i)
				report_.providers[i].name = provider(i).name;

			auto& kn = report_.providers[kernel_network_index];
			kn.requested = true;
			kn.keywords = etw::kn_keyword_ipv4 | etw::kn_keyword_ipv6;
			kn.event_ids = {etw::kn_udp_send_v4, etw::kn_udp_send_v6};

			auto& tcpip = report_.providers[tcpip_index];
			tcpip.requested = true;
			tcpip.keywords = etw::tcpip_keyword_send_path | etw::tcpip_keyword_bind | etw::tcpip_keyword_endpoint;
			tcpip.event_ids = {etw::tcpip_udp_send, etw::tcpip_udp_bind};

			if (config_.enable_tcp)
			{
				kn.event_ids.insert(kn.event_ids.end(), {
					                    etw::kn_tcp_connect_v4, etw::kn_tcp_connect_v6,
					                    etw::kn_tcp_accept_v4, etw::kn_tcp_accept_v6
				                    });
				tcpip.keywords |= etw::tcpip_keyword_tcb | etw::tcpip_keyword_connect_path;
				tcpip.event_ids.insert(tcpip.event_ids.end(), {
					                       etw::tcpip_tcp_connect_proceeding, etw::tcpip_tcp_connect_complete,
					                       etw::tcpip_tcp_connect_failure, etw::tcpip_tcp_accept_complete,
					                       etw::tcpip_tcp_rundown
				                       });
			}

			auto& dns = report_.providers[dns_client_index];
			dns.requested = config_.enable_dns;
			dns.keywords = 0; // 3006..3020 carry keyword mask 0 [V-manifest]
			dns.event_ids = {etw::dns_query_called, etw::dns_query_sent, etw::dns_query_wire};

			for (size_t i = 0; i < provider_count; ++i)
			{
				requested_ids_[i].clear();
				if (!report_.providers[i].requested)
					continue;
				for (const auto id : report_.providers[i].event_ids)
					requested_ids_[i].insert(id);
			}
		}

		bool provider_enabled(const size_t index) const
		{
			std::lock_guard<std::mutex> lock(report_mutex_);
			return index < report_.providers.size() && report_.providers[index].enabled;
		}

		// ------------------------------------------------------------------------
		// Lifecycle helpers
		// ------------------------------------------------------------------------
		bool fail_start(const std::string& reason)
		{
			stop_locked();
			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				report_.available = false;
				report_.failure = reason;
			}
			log("ETW attribution unavailable: " + reason);
			return false;
		}

		void stop_locked()
		{
			// stopping_ makes refresh_availability() a no-op, so events the consumer still
			// drains below cannot turn available_ back on.
			stopping_ = true;
			live_ = false;
			available_ = false;
			tcp_available_ = false;
			{
				std::lock_guard<std::mutex> lock(wake_mutex_);
				++generation_;
			}
			wake_cv_.notify_all();
			{
				std::lock_guard<std::mutex> lock(maintenance_mutex_);
			}
			maintenance_cv_.notify_all();
			if (maintenance_thread_.joinable())
				maintenance_thread_.join();

			stop_session_and_consumer();
			effective_flush_ = etw::effective_flush::none;
			started_ = false;
			// Both internal threads are joined: nothing can call refresh_availability() any
			// more. Store the final state again in case one ran concurrently with the stores
			// at the top.
			available_ = false;
			tcp_available_ = false;
			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				report_.available = false;
				report_.udp_available = report_.tcp_available = report_.dns_available = false;
			}
			if (wsa_started_)
			{
				WSACleanup();
				wsa_started_ = false;
			}
		}

		void stop_session_and_consumer()
		{
			TRACEHANDLE session = 0;
			{
				// Public flush/query callers hold the shared lock while they use the handle:
				// once this returns, none of them can use the logger id being stopped.
				std::unique_lock<std::shared_mutex> lock(session_mutex_);
				std::swap(session, session_handle_);
			}
			if (session != 0)
			{
				auto props = make_properties();
				const auto status = ControlTraceW(session, nullptr, props.get(), EVENT_TRACE_CONTROL_STOP);
				// ERROR_MORE_DATA: stopped, the properties buffer was only too small for the
				// names; ERROR_WMI_INSTANCE_NOT_FOUND: the session is already gone.
				own_stop_failed_ = status != ERROR_SUCCESS && status != ERROR_MORE_DATA &&
					status != ERROR_WMI_INSTANCE_NOT_FOUND;
				if (own_stop_failed_)
					log("ControlTraceW(STOP) of " + narrow(session_name_) + " returned " + std::to_string(status) +
						": the session may still run (stop it with logman stop <name> -ets)");
			}
			if (consumer_handle_ != invalid_processtrace_handle())
			{
				CloseTrace(consumer_handle_);
				consumer_handle_ = invalid_processtrace_handle();
			}
			if (consumer_thread_.joinable())
				consumer_thread_.join();
		}

		static TRACEHANDLE invalid_processtrace_handle() noexcept
		{
			return static_cast<TRACEHANDLE>(reinterpret_cast<ULONG_PTR>(INVALID_HANDLE_VALUE));
		}

		static bool is_elevated()
		{
			HANDLE token = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
				return false;
			TOKEN_ELEVATION elevation{};
			DWORD size = 0;
			const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
				elevation.TokenIsElevated != 0;
			CloseHandle(token);
			return ok;
		}

		void refresh_dnscache_pid() { dnscache_pid_ = query_service_pid(L"Dnscache"); }

		static uint32_t query_service_pid(const wchar_t* service)
		{
			uint32_t pid = 0;
			if (const auto scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT); scm)
			{
				if (const auto svc = OpenServiceW(scm, service, SERVICE_QUERY_STATUS); svc)
				{
					SERVICE_STATUS_PROCESS ssp{};
					DWORD needed = 0;
					if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp),
					                         &needed) && ssp.dwCurrentState == SERVICE_RUNNING)
						pid = ssp.dwProcessId;
					CloseServiceHandle(svc);
				}
				CloseServiceHandle(scm);
			}
			return pid;
		}

		void log(const std::string& message) const
		{
			if (config_.log)
				config_.log(message);
		}

		// ------------------------------------------------------------------------
		// Session
		// ------------------------------------------------------------------------
		struct properties_deleter
		{
			void operator()(EVENT_TRACE_PROPERTIES* p) const noexcept { std::free(p); }
		};

		using properties_ptr = std::unique_ptr<EVENT_TRACE_PROPERTIES, properties_deleter>;

		[[nodiscard]] properties_ptr make_properties() const
		{
			const size_t name_bytes = (session_name_.size() + 1) * sizeof(wchar_t);
			const size_t size = sizeof(EVENT_TRACE_PROPERTIES) + name_bytes + 1024 * sizeof(wchar_t);
			auto* p = static_cast<EVENT_TRACE_PROPERTIES*>(std::calloc(1, size));
			if (!p)
				throw std::bad_alloc();
			p->Wnode.BufferSize = static_cast<ULONG>(size);
			p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
			p->LogFileNameOffset = 0;
			return properties_ptr(p);
		}

		/// <summary>Process-wide instance counter for the default session name</summary>
		static std::atomic<uint32_t>& instance_counter() noexcept
		{
			static std::atomic<uint32_t> counter{0};
			return counter;
		}

		/// <summary>Creation time (FILETIME as uint64_t) of a process handle, 0 if unknown</summary>
		static uint64_t process_creation_time(const HANDLE process) noexcept
		{
			FILETIME creation{}, exit_time{}, kernel_time{}, user_time{};
			if (!GetProcessTimes(process, &creation, &exit_time, &kernel_time, &user_time))
				return 0;
			return (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
		}

		/// <summary>true if a process with this PID is running now; creation receives its
		/// creation time, or 0 if it could not be read (e.g. access denied)</summary>
		static bool process_alive(const uint32_t pid, uint64_t& creation)
		{
			creation = 0;
			if (pid == 0)
				return false;
			const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if (!process)
				return GetLastError() == ERROR_ACCESS_DENIED; // exists, but we may not open it
			DWORD code = 0;
			const bool alive = GetExitCodeProcess(process, &code) && code == STILL_ACTIVE;
			if (alive)
				creation = process_creation_time(process);
			CloseHandle(process);
			return alive;
		}

		/// <summary>
		/// Stops sessions left behind by an instance that was killed (a real-time session
		/// outlives its process):
		/// "<session_name_prefix>-<pid>-<creation>-<instance>" if no process with that pid and that
		/// creation time is running. The name of a live instance always matches its own
		/// running process, so it is never stopped, and a PID reused between enumeration and
		/// ControlTrace(STOP) cannot make a live session match. If the creation time of a
		/// running pid cannot be read, its sessions are kept.
		/// "<session_name_prefix>-<pid>" (earlier builds) if that pid is not running or is
		/// our own pid (this process never creates that form). A reused pid keeps it until
		/// that process exits.
		/// The legacy fixed name without a pid is never stopped.
		/// </summary>
		void stop_stale_sessions()
		{
			constexpr size_t name_chars = 1024;
			constexpr size_t entry_size = sizeof(EVENT_TRACE_PROPERTIES) + 2 * name_chars * sizeof(wchar_t);
			ULONG max_sessions = 256;
			std::vector<std::unique_ptr<uint8_t[]>> storage;
			std::vector<EVENT_TRACE_PROPERTIES*> array;
			ULONG count = 0;
			ULONG status = ERROR_SUCCESS;
			for (int attempt = 0; attempt < 2; ++attempt)
			{
				storage.clear();
				array.clear();
				for (ULONG i = 0; i < max_sessions; ++i)
				{
					storage.push_back(std::make_unique<uint8_t[]>(entry_size));
					std::memset(storage.back().get(), 0, entry_size);
					auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(storage.back().get());
					p->Wnode.BufferSize = static_cast<ULONG>(entry_size);
					p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
					p->LogFileNameOffset = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + name_chars * sizeof(wchar_t));
					array.push_back(p);
				}
				count = 0;
				status = QueryAllTracesW(array.data(), max_sessions, &count);
				if (status != ERROR_INVALID_PARAMETER)
					break;
				max_sessions = 64; // documented maximum on older systems [V-doc]
			}
			if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA)
			{
				log("QueryAllTracesW returned " + std::to_string(status) + ": stale session cleanup skipped");
				return;
			}
			const std::wstring prefix = config_.session_name_prefix + L"-";
			for (ULONG i = 0; i < count && i < max_sessions; ++i)
			{
				const auto* p = array[i];
				if (p->LoggerNameOffset == 0)
					continue;
				const std::wstring name(reinterpret_cast<const wchar_t*>(
					reinterpret_cast<const char*>(p) + p->LoggerNameOffset));
				if (name.size() <= prefix.size() || name.compare(0, prefix.size(), prefix) != 0)
					continue;
				// "<pid>" or "<pid>-<16 hex creation>-<instance id: hex digits and '-'>"
				const auto rest = name.substr(prefix.size());
				const auto dash1 = rest.find(L'-');
				const auto digits = rest.substr(0, dash1);
				if (digits.empty() || digits.size() > 10 ||
					digits.find_first_not_of(L"0123456789") != std::wstring::npos)
					continue;
				const auto pid = static_cast<uint32_t>(std::wcstoul(digits.c_str(), nullptr, 10));
				uint64_t running_creation = 0;
				bool stale;
				if (dash1 == std::wstring::npos)
					stale = pid == own_pid_ || !process_alive(pid, running_creation);
				else
				{
					const auto dash2 = rest.find(L'-', dash1 + 1);
					if (dash2 == std::wstring::npos || dash2 - dash1 - 1 != 16)
						continue;
					const auto hex = rest.substr(dash1 + 1, 16);
					const auto instance = rest.substr(dash2 + 1);
					if (hex.find_first_not_of(L"0123456789ABCDEFabcdef") != std::wstring::npos || instance.empty() ||
						instance.size() > 40 || instance.find_first_not_of(L"0123456789ABCDEFabcdef-") != std::wstring::npos)
						continue;
					const auto creation = static_cast<uint64_t>(std::wcstoull(hex.c_str(), nullptr, 16));
					if (pid == own_pid_ && creation == own_creation_)
						continue; // this process (another instance, or a name we will not reuse)
					if (!process_alive(pid, running_creation))
						stale = true;
					else
						stale = running_creation != 0 && creation != 0 && running_creation != creation;
				}
				if (!stale)
					continue;
				auto props = make_properties();
				const auto stop_status = ControlTraceW(0, name.c_str(), props.get(), EVENT_TRACE_CONTROL_STOP);
				log("stopped stale ETW session " + narrow(name) + " of exited pid " + std::to_string(pid) +
					", status=" + std::to_string(stop_status));
			}
		}

		bool start_session(const bool ms_timer)
		{
			if (config_.session_name.empty())
			{
				stop_stale_sessions();
				if (own_stop_failed_)
				{
					// Our own session from an earlier start() of this object (the default name
					// is unique to it) whose STOP failed: retry the STOP by name.
					auto stop = make_properties();
					const auto stop_status =
						ControlTraceW(0, session_name_.c_str(), stop.get(), EVENT_TRACE_CONTROL_STOP);
					own_stop_failed_ = false;
					log("retried STOP of this object's own session " + narrow(session_name_) + ", status=" +
						std::to_string(stop_status));
				}
			}

			auto props = make_properties();
			SYSTEM_INFO si{};
			GetSystemInfo(&si);
			const ULONG cpus = std::max<ULONG>(1, si.dwNumberOfProcessors);

			props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
			props->Wnode.ClientContext = 1; // QPC: raw timestamps are comparable with QueryPerformanceCounter
			props->BufferSize = 64; // KB
			props->MinimumBuffers = 2 * cpus;
			props->MaximumBuffers = 4 * cpus + 16;
			props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | etw::independent_session_mode |
				(ms_timer ? etw::use_ms_flush_timer : 0);
			props->FlushTimer = ms_timer ? 10 : 1;

			std::lock_guard<std::mutex> lock(report_mutex_);
			report_.requested_log_file_mode = props->LogFileMode;
			report_.flush_timer = props->FlushTimer;
			report_.session_name = narrow(session_name_);

			// An existing session with this name is not stopped: the default name is unique per
			// process (pid + creation time), module and instance, so it can only exist if this
			// very object created it and its STOP failed, which was retried above.
			TRACEHANDLE handle = 0;
			auto status = StartTraceW(&handle, session_name_.c_str(), props.get());
			report_.start_status = status;
			if (status != ERROR_SUCCESS)
			{
				report_.failure = "StartTraceW returned " + std::to_string(status) +
					(status == ERROR_ALREADY_EXISTS ? " (a session with this name is running; not stopped)" : "");
				return false;
			}
			{
				std::unique_lock<std::shared_mutex> session_lock(session_mutex_);
				session_handle_ = handle;
			}
			report_.session_started = true;

			// Read back. Windows 7 returns 0 from StartTrace and silently clears the
			// INDEPENDENT bit (EVENT_TRACE_INDEPENDENT_SESSION_MODE, 0x08000000) [M7601]:
			// never trust the return code alone.
			// Extra bits the OS adds (0x00800000 on 19045, 0x00400000 on 26300) are ignored.
			auto query = make_properties();
			status = ControlTraceW(session_handle_, nullptr, query.get(), EVENT_TRACE_CONTROL_QUERY);
			if (status != ERROR_SUCCESS)
			{
				report_.failure = "ControlTraceW(QUERY) returned " + std::to_string(status);
				return false;
			}
			report_.actual_log_file_mode = query->LogFileMode;
			report_.independent_mode_kept = (query->LogFileMode & etw::independent_session_mode) != 0;
			report_.ms_timer_bit_kept = (query->LogFileMode & etw::use_ms_flush_timer) != 0;
			if (!report_.independent_mode_kept)
			{
				// Do not retry without INDEPENDENT: a non-independent session can make provider
				// writes fail in other sessions [V-doc].
				char hex[16];
				std::snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(query->LogFileMode));
				report_.failure = std::string("INDEPENDENT_SESSION_MODE not honoured (LogFileMode=") + hex + ")";
				return false;
			}
			return true;
		}

		bool enable_providers()
		{
			bool udp_source = false;
			std::vector<std::string> messages;
			std::unique_lock<std::mutex> lock(report_mutex_);
			for (size_t i = 0; i < provider_count; ++i)
			{
				auto& p = report_.providers[i];
				if (!p.requested)
					continue;

				// EVENT_FILTER_EVENT_ID layout: BOOLEAN FilterIn; UCHAR Reserved; USHORT Count;
				// USHORT Events[Count] [V-doc]
				std::vector<uint8_t> filter(4 + sizeof(USHORT) * p.event_ids.size());
				filter[0] = TRUE;
				filter[1] = 0;
				const auto count = static_cast<USHORT>(p.event_ids.size());
				std::memcpy(&filter[2], &count, sizeof(count));
				std::memcpy(&filter[4], p.event_ids.data(), sizeof(USHORT) * p.event_ids.size());

				EVENT_FILTER_DESCRIPTOR descriptor{};
				descriptor.Ptr = reinterpret_cast<ULONGLONG>(filter.data());
				descriptor.Size = static_cast<ULONG>(filter.size());
				descriptor.Type = etw::filter_type_event_id;

				ENABLE_TRACE_PARAMETERS params{};
				params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
				params.EnableFilterDesc = &descriptor;
				params.FilterDescCount = 1;

				const auto status = EnableTraceEx2(session_handle_, &provider(i).guid,
				                                   EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
				                                   p.keywords, 0, 0, &params);
				p.enable_status = status;
				p.enabled = (status == ERROR_SUCCESS);
				// No keyword-only fallback: Kernel-Network keyword 0x10 alone delivers every IPv4
				// TCP and UDP send/receive event system-wide (plan gate 3).
				if (p.enabled && (i == kernel_network_index || i == tcpip_index))
					udp_source = true;
				messages.push_back(std::string("EnableTraceEx2 ") + p.name + " status=" + std::to_string(status));
			}
			lock.unlock();
			for (const auto& m : messages)
				log(m);
			return udp_source;
		}

		bool start_consumer()
		{
			EVENT_TRACE_LOGFILEW logfile{};
			logfile.LoggerName = const_cast<LPWSTR>(session_name_.c_str());
			logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD |
				etw::process_trace_mode_raw_timestamp;
			logfile.EventRecordCallback = &etw_packet_attributor::event_record_callback;
			logfile.Context = this;

			consumer_handle_ = OpenTraceW(&logfile);
			if (consumer_handle_ == invalid_processtrace_handle())
				return false;

			consumer_running_ = true;
			consumer_thread_ = std::thread([this, handle = consumer_handle_]
			{
				TRACEHANDLE h = handle;
				const auto status = ProcessTrace(&h, 1, nullptr, nullptr);
				consumer_running_ = false;
				if (!stopping_.load())
					log("ETW consumer stopped unexpectedly, ProcessTrace=" + std::to_string(status));
			});
			return true;
		}

		/// <summary>Issues EVENT_TRACE_CONTROL_FLUSH; returns the call duration in microseconds</summary>
		uint64_t flush_now()
		{
			auto props = make_properties();
			uint64_t us;
			{
				std::shared_lock<std::shared_mutex> lock(session_mutex_);
				if (session_handle_ == 0)
					return 0;
				const auto t0 = qpc_now();
				ControlTraceW(session_handle_, nullptr, props.get(), EVENT_TRACE_CONTROL_FLUSH);
				us = static_cast<uint64_t>(qpc_to_ms(qpc_now() - t0) * 1000.0);
			}
			++flush_calls_;
			last_flush_us_ = us;
			auto prev = flush_call_max_us_.load();
			while (us > prev && !flush_call_max_us_.compare_exchange_weak(prev, us))
			{
			}
			return us;
		}

		void query_loss(ULONG& events_lost, ULONG& log_buffers_lost, ULONG& realtime_buffers_lost) const
		{
			events_lost = log_buffers_lost = realtime_buffers_lost = 0;
			auto props = make_properties();
			std::shared_lock<std::shared_mutex> lock(session_mutex_);
			if (session_handle_ == 0)
				return;
			if (ControlTraceW(session_handle_, nullptr, props.get(), EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS)
			{
				events_lost = props->EventsLost;
				log_buffers_lost = props->LogBuffersLost;
				realtime_buffers_lost = props->RealTimeBuffersLost;
			}
		}

		// ------------------------------------------------------------------------
		// QPC <-> FILETIME, for the "process created after the event" PID-reuse check.
		// GetSystemTimeAsFileTime is sampled right after it ticks, so the pair is accurate
		// to well under a millisecond without GetSystemTimePreciseAsFileTime (Windows 8+),
		// which keeps the import table Windows 7 compatible for products that still load
		// there (the gates switch the feature off on Windows 7 anyway).
		// ------------------------------------------------------------------------
		void calibrate_clock()
		{
			FILETIME ft0{};
			GetSystemTimeAsFileTime(&ft0);
			FILETIME ft1 = ft0;
			int64_t qpc = qpc_now();
			const auto limit = qpc + qpc_frequency_ / 20; // at most 50 ms
			while (std::memcmp(&ft0, &ft1, sizeof(FILETIME)) == 0 && qpc < limit)
			{
				GetSystemTimeAsFileTime(&ft1);
				qpc = qpc_now();
			}
			std::lock_guard<std::mutex> lock(clock_mutex_);
			clock_qpc_ = qpc;
			clock_filetime_ = (static_cast<uint64_t>(ft1.dwHighDateTime) << 32) | ft1.dwLowDateTime;
		}

		[[nodiscard]] uint64_t qpc_to_filetime(const int64_t qpc) const
		{
			std::lock_guard<std::mutex> lock(clock_mutex_);
			const auto delta_100ns = static_cast<int64_t>(static_cast<double>(qpc - clock_qpc_) * 1e7 /
				static_cast<double>(qpc_frequency_));
			return static_cast<uint64_t>(static_cast<int64_t>(clock_filetime_) + delta_100ns);
		}

		// ------------------------------------------------------------------------
		// TDH schema handling (gate 4). Fields are located by NAME from the TDH property
		// list, never by guessed offsets. A schema without the wanted fields, with a wrong
		// type, or with a property we cannot size in front of them is rejected, so a wrong
		// guess about a TCP event disables that (id, version) instead of misparsing it.
		// ------------------------------------------------------------------------
		enum field_id : uint8_t
		{
			f_pid,
			f_start_key,
			f_saddr,
			f_daddr,
			f_sport,
			f_dport,
			f_local_sockaddr,
			f_remote_sockaddr,
			f_status,
			f_query_name,
			f_query_type,
			f_client_pid,
			f_network_index,
			f_field_count
		};

		enum class value_class : uint8_t { u16, u32, u64, address, sockaddr, wstring };

		struct field_spec
		{
			field_id id;
			std::array<const wchar_t*, 3> names;
			value_class cls;
			bool required;
		};

		// TDH in-types (tdh.h _TDH_IN_TYPE)
		static constexpr USHORT in_unicode_string = 1;
		static constexpr USHORT in_ansi_string = 2;
		static constexpr USHORT in_int8 = 3;
		static constexpr USHORT in_uint8 = 4;
		static constexpr USHORT in_int16 = 5;
		static constexpr USHORT in_uint16 = 6;
		static constexpr USHORT in_int32 = 7;
		static constexpr USHORT in_uint32 = 8;
		static constexpr USHORT in_int64 = 9;
		static constexpr USHORT in_uint64 = 10;
		static constexpr USHORT in_float = 11;
		static constexpr USHORT in_double = 12;
		static constexpr USHORT in_boolean = 13;
		static constexpr USHORT in_binary = 14;
		static constexpr USHORT in_guid = 15;
		static constexpr USHORT in_pointer = 16;
		static constexpr USHORT in_filetime = 17;
		static constexpr USHORT in_systemtime = 18;
		static constexpr USHORT in_hexint32 = 20;
		static constexpr USHORT in_hexint64 = 21;

		// PROPERTY_FLAGS (tdh.h)
		static constexpr ULONG prop_struct = 0x1;
		static constexpr ULONG prop_param_length = 0x2;
		static constexpr ULONG prop_param_count = 0x4;
		static constexpr ULONG prop_param_fixed_length = 0x10;

		static const char* in_type_name(const USHORT t) noexcept
		{
			switch (t)
			{
			case in_unicode_string: return "UnicodeString";
			case in_ansi_string: return "AnsiString";
			case in_int8: return "Int8";
			case in_uint8: return "UInt8";
			case in_int16: return "Int16";
			case in_uint16: return "UInt16";
			case in_int32: return "Int32";
			case in_uint32: return "UInt32";
			case in_int64: return "Int64";
			case in_uint64: return "UInt64";
			case in_float: return "Float";
			case in_double: return "Double";
			case in_boolean: return "Boolean";
			case in_binary: return "Binary";
			case in_guid: return "Guid";
			case in_pointer: return "Pointer";
			case in_filetime: return "FileTime";
			case in_systemtime: return "SystemTime";
			case in_hexint32: return "HexInt32";
			case in_hexint64: return "HexInt64";
			default: return "Other";
			}
		}

		struct prop_desc
		{
			std::wstring name;
			USHORT in_type{};
			ULONG flags{};
			USHORT count{1};
			USHORT count_index{};
			USHORT length{};
			USHORT length_index{};
		};

		struct event_schema
		{
			etw::schema_status status;
			etw::event_source source{etw::event_source::none};
			size_t provider_index{};
			bool accepted{};
			std::vector<prop_desc> props;
			std::array<int, f_field_count> field_prop{};
			int last_needed{-1};
		};

		static uint64_t schema_key(const size_t provider_index, const USHORT id, const UCHAR version) noexcept
		{
			return (static_cast<uint64_t>(provider_index) << 32) | (static_cast<uint64_t>(id) << 8) | version;
		}

		/// <summary>Maps (provider, id) to the event source; none for ids we do not use</summary>
		static etw::event_source source_of(const size_t provider_index, const USHORT id) noexcept
		{
			if (provider_index == kernel_network_index)
			{
				switch (id)
				{
				case etw::kn_udp_send_v4:
				case etw::kn_udp_send_v6: return etw::event_source::kn_udp_send;
				case etw::kn_tcp_connect_v4:
				case etw::kn_tcp_connect_v6: return etw::event_source::kn_tcp_connect;
				case etw::kn_tcp_accept_v4:
				case etw::kn_tcp_accept_v6: return etw::event_source::kn_tcp_accept;
				default: return etw::event_source::none;
				}
			}
			if (provider_index == tcpip_index)
			{
				switch (id)
				{
				case etw::tcpip_udp_send: return etw::event_source::tcpip_udp_send;
				case etw::tcpip_udp_bind: return etw::event_source::tcpip_udp_bind;
				case etw::tcpip_tcp_connect_proceeding: return etw::event_source::tcpip_tcp_connect;
				case etw::tcpip_tcp_connect_complete: return etw::event_source::tcpip_tcp_connected;
				case etw::tcpip_tcp_connect_failure: return etw::event_source::tcpip_tcp_failed;
				case etw::tcpip_tcp_accept_complete: return etw::event_source::tcpip_tcp_accept;
				case etw::tcpip_tcp_rundown: return etw::event_source::tcpip_tcp_rundown;
				default: return etw::event_source::none;
				}
			}
			if (provider_index == dns_client_index)
			{
				switch (id)
				{
				case etw::dns_query_called: return etw::event_source::dns_query_called;
				case etw::dns_query_sent: return etw::event_source::dns_query_sent;
				case etw::dns_query_wire: return etw::event_source::dns_query_wire;
				default: return etw::event_source::none;
				}
			}
			return etw::event_source::none;
		}

		/// <summary>Wanted fields per source. Names are alternatives (first match wins).</summary>
		static std::vector<field_spec> wanted_fields(const etw::event_source s)
		{
			using es = etw::event_source;
			const field_spec pid_kn{f_pid, {L"PID", nullptr, nullptr}, value_class::u32, true};
			// 1169/1396/1300 use "Pid", 1031/1033/1034/1017 use "ProcessId" [V-manifest]
			const field_spec pid_tcpip{f_pid, {L"Pid", L"ProcessId", L"PID"}, value_class::u32, true};
			// v1 name per the jdu2600 dumps; the repnz Win10 18990 XML calls it ProcessSequenceNumber
			const field_spec start_key{
				f_start_key, {L"ProcessStartKey", L"ProcessSequenceNumber", nullptr}, value_class::u64, false
			};
			// 1169: LocalSockAddr/RemoteSockAddr; TCP events and 1396: LocalAddress/RemoteAddress
			const field_spec local_sa{
				f_local_sockaddr, {L"LocalSockAddr", L"LocalAddress", nullptr}, value_class::sockaddr, true
			};
			const field_spec remote_sa{
				f_remote_sockaddr, {L"RemoteSockAddr", L"RemoteAddress", nullptr}, value_class::sockaddr, true
			};
			const field_spec status{f_status, {L"Status", nullptr, nullptr}, value_class::u32, false};
			const field_spec query_name{f_query_name, {L"QueryName", nullptr, nullptr}, value_class::wstring, true};
			const field_spec query_type{f_query_type, {L"QueryType", nullptr, nullptr}, value_class::u32, true};
			const field_spec client_pid{f_client_pid, {L"ClientPID", nullptr, nullptr}, value_class::u32, false};

			switch (s)
			{
			case es::kn_udp_send:
			case es::kn_tcp_connect:
			case es::kn_tcp_accept:
				return {
					pid_kn,
					{f_saddr, {L"saddr", nullptr, nullptr}, value_class::address, true},
					{f_daddr, {L"daddr", nullptr, nullptr}, value_class::address, true},
					{f_sport, {L"sport", nullptr, nullptr}, value_class::u16, true},
					{f_dport, {L"dport", nullptr, nullptr}, value_class::u16, true},
				};
			case es::tcpip_udp_send:
			case es::tcpip_tcp_rundown:
				return {local_sa, remote_sa, pid_tcpip, start_key};
			case es::tcpip_udp_bind:
				return {local_sa, pid_tcpip, start_key};
			case es::tcpip_tcp_connect:
			case es::tcpip_tcp_connected:
			case es::tcpip_tcp_failed:
			case es::tcpip_tcp_accept:
				return {local_sa, remote_sa, pid_tcpip, start_key, status};
			case es::dns_query_called:
				return {query_name, query_type};
			case es::dns_query_sent:
				return {query_name, query_type, client_pid};
			case es::dns_query_wire:
				return {
					query_name, query_type, client_pid,
					{f_network_index, {L"NetworkIndex", nullptr, nullptr}, value_class::u32, false},
				};
			default:
				return {};
			}
		}

		static bool class_accepts(const value_class cls, const prop_desc& p) noexcept
		{
			const bool scalar = (p.flags & (prop_struct | prop_param_count)) == 0 && p.count <= 1;
			switch (cls)
			{
			case value_class::u16:
				return scalar && (p.in_type == in_uint16 || p.in_type == in_int16);
			case value_class::u32:
				return scalar && (p.in_type == in_uint32 || p.in_type == in_int32 || p.in_type == in_hexint32);
			case value_class::u64:
				return scalar && (p.in_type == in_uint64 || p.in_type == in_int64 || p.in_type == in_hexint64);
			case value_class::address:
				// IPv4 events: UInt32; IPv6 events: Binary of 16 bytes [V-manifest]
				return scalar && (p.in_type == in_uint32 || p.in_type == in_hexint32 ||
					(p.in_type == in_binary && (p.flags & prop_param_length) == 0 && p.length == 16));
			case value_class::sockaddr:
				return scalar && p.in_type == in_binary;
			case value_class::wstring:
				return scalar && p.in_type == in_unicode_string;
			}
			return false;
		}

		static std::string narrow(const std::wstring& w)
		{
			std::string s;
			s.reserve(w.size());
			for (const auto c : w)
				s.push_back(c < 0x80 ? static_cast<char>(c) : '?');
			return s;
		}

		static std::wstring widen(const std::string_view s)
		{
			std::wstring w;
			w.reserve(s.size());
			for (const auto c : s)
				w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
			return w;
		}

		std::shared_ptr<event_schema> build_schema(const EVENT_RECORD* record, const size_t provider_index,
		                                           const etw::event_source source) const
		{
			auto schema = std::make_shared<event_schema>();
			schema->source = source;
			schema->provider_index = provider_index;
			schema->field_prop.fill(-1);
			schema->status.provider = provider(provider_index).name;
			schema->status.id = record->EventHeader.EventDescriptor.Id;
			schema->status.version = record->EventHeader.EventDescriptor.Version;

			auto* rec = const_cast<PEVENT_RECORD>(record);
			ULONG size = 0;
			auto status = TdhGetEventInformation(rec, 0, nullptr, nullptr, &size);
			std::vector<uint8_t> buffer;
			if (status == ERROR_INSUFFICIENT_BUFFER)
			{
				buffer.resize(size);
				status = TdhGetEventInformation(rec, 0, nullptr, reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data()),
				                                &size);
			}
			if (status != ERROR_SUCCESS)
			{
				schema->status.detail = "TdhGetEventInformation failed: " + std::to_string(status);
				return schema;
			}

			const auto* info = reinterpret_cast<const TRACE_EVENT_INFO*>(buffer.data());
			std::ostringstream props_text;
			for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
			{
				const auto& epi = info->EventPropertyInfoArray[i];
				prop_desc p;
				p.name = reinterpret_cast<const wchar_t*>(buffer.data() + epi.NameOffset);
				p.flags = static_cast<ULONG>(epi.Flags);
				if ((p.flags & prop_struct) == 0)
					p.in_type = epi.nonStructType.InType;
				p.count = epi.count;
				p.count_index = epi.countPropertyIndex;
				p.length = epi.length;
				p.length_index = epi.lengthPropertyIndex;
				props_text << (i ? " " : "") << narrow(p.name) << ":"
					<< ((p.flags & prop_struct) ? "Struct" : in_type_name(p.in_type));
				if (p.flags & prop_param_length)
					props_text << "(len=#" << p.length_index << ")";
				else if (p.in_type == in_binary)
					props_text << "(" << p.length << ")";
				if (p.flags & prop_param_count)
					props_text << "[count=#" << p.count_index << "]";
				schema->props.push_back(std::move(p));
			}
			schema->status.properties = props_text.str();

			std::ostringstream detail;
			bool ok = true;
			for (const auto& spec : wanted_fields(source))
			{
				int found = -1;
				for (size_t i = 0; i < schema->props.size() && found < 0; ++i)
				{
					for (const auto* n : spec.names)
					{
						if (n && _wcsicmp(schema->props[i].name.c_str(), n) == 0)
						{
							found = static_cast<int>(i);
							break;
						}
					}
				}
				const auto label = narrow(spec.names[0]);
				if (found >= 0 && !class_accepts(spec.cls, schema->props[found]))
				{
					detail << narrow(schema->props[found].name) << ":BAD-TYPE ";
					if (spec.required)
						ok = false;
				}
				else if (found >= 0)
				{
					detail << narrow(schema->props[found].name) << ":ok ";
					schema->field_prop[spec.id] = found;
					schema->last_needed = std::max(schema->last_needed, found);
				}
				else
				{
					detail << label << (spec.required ? ":MISSING " : ":absent ");
					if (spec.required)
						ok = false;
				}
			}
			// A SOCKADDR blob must be sized by a preceding length property (or a fixed size
			// large enough for sockaddr_in).
			for (const auto f : {f_local_sockaddr, f_remote_sockaddr})
			{
				const auto idx = schema->field_prop[f];
				if (idx >= 0)
				{
					const auto& p = schema->props[idx];
					if ((p.flags & prop_param_length) == 0 && p.length < 8)
					{
						detail << "sockaddr-without-length ";
						ok = false;
					}
				}
			}
			if (schema->last_needed >= static_cast<int>(max_layout_props))
			{
				detail << "too-many-properties ";
				ok = false;
			}
			schema->accepted = ok;
			schema->status.accepted = ok;
			schema->status.detail = detail.str();
			return schema;
		}

		static constexpr size_t max_layout_props = 32;
		using layout_t = std::array<std::pair<uint32_t, uint32_t>, max_layout_props>;

		/// <summary>Computes offset and size of properties [0..last_needed] of one event</summary>
		static bool layout(const event_schema& schema, const EVENT_RECORD* record, layout_t& out, size_t& out_count)
		{
			const auto* data = static_cast<const uint8_t*>(record->UserData);
			const uint32_t total = record->UserDataLength;
			const uint32_t ptr_size = (record->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
			uint32_t offset = 0;
			out_count = 0;
			if (schema.last_needed < 0)
				return true;
			const auto last = static_cast<size_t>(schema.last_needed);
			if (last >= out.size())
				return false;

			auto read_uint = [&](const size_t index, uint64_t& value) -> bool
			{
				if (index >= out_count)
					return false;
				const auto& p = schema.props[index];
				const auto [off, sz] = out[index];
				value = 0;
				if (sz == 2 && (p.in_type == in_uint16 || p.in_type == in_int16))
				{
					uint16_t v;
					std::memcpy(&v, data + off, 2);
					value = v;
					return true;
				}
				if (sz == 4 && (p.in_type == in_uint32 || p.in_type == in_int32 || p.in_type == in_hexint32))
				{
					uint32_t v;
					std::memcpy(&v, data + off, 4);
					value = v;
					return true;
				}
				return false;
			};

			for (size_t i = 0; i <= last; ++i)
			{
				const auto& p = schema.props[i];
				if (p.flags & prop_struct)
					return false;

				uint64_t count = p.count == 0 ? 1 : p.count;
				if (p.flags & prop_param_count)
				{
					if (!read_uint(p.count_index, count))
						return false;
				}

				uint64_t size;
				switch (p.in_type)
				{
				case in_int8:
				case in_uint8:
					size = 1;
					break;
				case in_int16:
				case in_uint16:
					size = 2;
					break;
				case in_int32:
				case in_uint32:
				case in_hexint32:
				case in_float:
				case in_boolean:
					size = 4;
					break;
				case in_int64:
				case in_uint64:
				case in_hexint64:
				case in_double:
				case in_filetime:
					size = 8;
					break;
				case in_guid:
				case in_systemtime:
					size = 16;
					break;
				case in_pointer:
					size = ptr_size;
					break;
				case in_binary:
					if (p.flags & prop_param_length)
					{
						if (!read_uint(p.length_index, size))
							return false;
					}
					else
						size = p.length;
					count = 1;
					break;
				case in_unicode_string:
				case in_ansi_string:
					{
						const uint64_t unit = p.in_type == in_unicode_string ? 2 : 1;
						if (count != 1)
							return false;
						if (p.flags & prop_param_length)
						{
							uint64_t chars = 0;
							if (!read_uint(p.length_index, chars))
								return false;
							size = chars * unit;
						}
						else if (p.flags & prop_param_fixed_length)
							size = static_cast<uint64_t>(p.length) * unit;
						else
						{
							// null-terminated
							uint64_t o = offset;
							for (;;)
							{
								if (o + unit > total)
									return false;
								const bool zero = unit == 2 ? (data[o] == 0 && data[o + 1] == 0) : data[o] == 0;
								o += unit;
								if (zero)
									break;
							}
							size = o - offset;
						}
					}
					break;
				default:
					return false; // SID, counted strings, ...: cannot size; the fields behind are unusable
				}

				size *= count;
				if (static_cast<uint64_t>(offset) + size > total)
					return false;
				out[i] = {offset, static_cast<uint32_t>(size)};
				out_count = i + 1;
				offset += static_cast<uint32_t>(size);
			}
			return true;
		}

		struct parsed_event
		{
			std::array<bool, f_field_count> has{};
			std::array<uint64_t, f_field_count> num{};
			std::array<uint16_t, f_field_count> addr_family{};
			std::array<std::array<uint8_t, 16>, f_field_count> addr{};
			std::array<uint16_t, f_field_count> addr_port{};
			std::wstring text;
		};

		/// <summary>SOCKADDR blob: family @0, port (network order) @+2, IPv4 @+4, IPv6 @+8
		/// [M26300 for 1169 and the TCPIP TCP events]. IPv4-mapped IPv6 addresses
		/// (dual-mode sockets) are folded to IPv4 so they match the IPv4 packet.</summary>
		static bool parse_sockaddr(const uint8_t* p, const uint32_t len, uint16_t& family,
		                           std::array<uint8_t, 16>& ip, uint16_t& port_host) noexcept
		{
			if (len < 8)
				return false;
			uint16_t fam;
			std::memcpy(&fam, p, 2);
			port_host = static_cast<uint16_t>((p[2] << 8) | p[3]);
			ip.fill(0);
			if (fam == AF_INET)
			{
				family = AF_INET;
				std::memcpy(ip.data(), p + 4, 4);
				return true;
			}
			if (fam == AF_INET6 && len >= 24)
			{
				static constexpr uint8_t mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
				if (std::memcmp(p + 8, mapped_prefix, 12) == 0)
				{
					family = AF_INET;
					std::memcpy(ip.data(), p + 8 + 12, 4);
				}
				else
				{
					family = AF_INET6;
					std::memcpy(ip.data(), p + 8, 16);
				}
				return true;
			}
			return false;
		}

		static bool parse(const event_schema& schema, const EVENT_RECORD* record, parsed_event& out)
		{
			layout_t pos{};
			size_t count = 0;
			if (!layout(schema, record, pos, count))
				return false;
			const auto* data = static_cast<const uint8_t*>(record->UserData);

			for (uint8_t f = 0; f < f_field_count; ++f)
			{
				const auto idx = schema.field_prop[f];
				if (idx < 0 || static_cast<size_t>(idx) >= count)
					continue;
				const auto [off, sz] = pos[idx];
				const uint8_t* v = data + off;
				switch (f)
				{
				case f_saddr:
				case f_daddr:
					out.addr[f].fill(0);
					if (sz == 4)
					{
						out.addr_family[f] = AF_INET;
						std::memcpy(out.addr[f].data(), v, 4); // raw network-order UInt32 [V-manifest][M26300]
					}
					else if (sz == 16)
					{
						out.addr_family[f] = AF_INET6;
						std::memcpy(out.addr[f].data(), v, 16);
					}
					else
						return false;
					out.has[f] = true;
					break;
				case f_sport:
				case f_dport:
					if (sz != 2)
						return false;
					// Kernel-Network ports are big-endian (PerfView ByteSwap16) [M26300]
					out.num[f] = static_cast<uint16_t>((v[0] << 8) | v[1]);
					out.has[f] = true;
					break;
				case f_local_sockaddr:
				case f_remote_sockaddr:
					if (!parse_sockaddr(v, sz, out.addr_family[f], out.addr[f], out.addr_port[f]))
						return false;
					out.has[f] = true;
					break;
				case f_query_name:
					if (sz >= 2)
					{
						out.text.assign(reinterpret_cast<const wchar_t*>(v), sz / 2);
						while (!out.text.empty() && out.text.back() == L'\0')
							out.text.pop_back();
						out.has[f] = true;
					}
					break;
				default:
					if (sz == 2)
					{
						uint16_t x;
						std::memcpy(&x, v, 2);
						out.num[f] = x;
					}
					else if (sz == 4)
					{
						uint32_t x;
						std::memcpy(&x, v, 4);
						out.num[f] = x;
					}
					else if (sz == 8)
					{
						uint64_t x;
						std::memcpy(&x, v, 8);
						out.num[f] = x;
					}
					else
						return false;
					out.has[f] = true;
					break;
				}
			}
			return true;
		}

		// ------------------------------------------------------------------------
		// Consumer
		// ------------------------------------------------------------------------
		static VOID WINAPI event_record_callback(PEVENT_RECORD record)
		{
			if (auto* self = static_cast<etw_packet_attributor*>(record->UserContext); self)
				self->on_event(record);
		}

		static size_t provider_index_of(const GUID& g) noexcept
		{
			for (size_t i = 0; i < provider_count; ++i)
			{
				if (std::memcmp(&g, &provider(i).guid, sizeof(GUID)) == 0)
					return i;
			}
			return provider_count;
		}

		std::shared_ptr<event_schema> schema_for(const EVENT_RECORD* record, const size_t pi,
		                                         const etw::event_source source)
		{
			const auto& d = record->EventHeader.EventDescriptor;
			const auto key = schema_key(pi, d.Id, d.Version);
			{
				std::lock_guard<std::mutex> lock(schema_mutex_);
				if (const auto it = schemas_.find(key); it != schemas_.end())
				{
					++it->second->status.events;
					return it->second;
				}
			}

			auto schema = build_schema(record, pi, source);
			schema->status.events = 1;
			{
				std::lock_guard<std::mutex> lock(schema_mutex_);
				schemas_[key] = schema;
			}
			log("schema " + schema->status.provider + " " + std::to_string(schema->status.id) + " v" +
				std::to_string(schema->status.version) + (schema->accepted ? " accepted: " : " REJECTED: ") +
				schema->status.detail + "| " + schema->status.properties);

			if (schema->accepted && source == etw::event_source::dns_query_wire &&
				schema->field_prop[f_client_pid] >= 0)
				dns_tier_seen_ = etw::dns_tier::client_pid;
			else if (schema->accepted && source == etw::event_source::dns_query_called &&
				dns_tier_seen_.load() == etw::dns_tier::none)
				dns_tier_seen_ = etw::dns_tier::header_pid;

			refresh_availability();
			return schema;
		}

		void on_event(const EVENT_RECORD* record)
		{
			const auto received = qpc_now();
			const auto pi = provider_index_of(record->EventHeader.ProviderId);
			if (pi == provider_count)
				return; // e.g. the EventTrace header event of the session itself
			++events_total_;

			const auto id = record->EventHeader.EventDescriptor.Id;
			if (requested_ids_[pi].find(id) == requested_ids_[pi].end())
			{
				// Gate 3: the event-id filter is not honoured. EnableTraceEx2 returned 0 on
				// Windows 7 although the filter is documented from 8.1 only [M7601].
				++events_unrequested_;
				if (!provider_unfiltered_[pi].exchange(true))
				{
					log(std::string("event-id filter not honoured by ") + provider(pi).name + " (id " +
						std::to_string(id) + "): its events are ignored");
					refresh_availability();
				}
				std::lock_guard<std::mutex> lock(unrequested_mutex_);
				if (unrequested_seen_[pi].size() < 32)
					unrequested_seen_[pi].insert(id);
				return;
			}
			if (provider_unfiltered_[pi].load())
				return;

			const auto source = source_of(pi, id);
			if (source == etw::event_source::none)
				return;

			const auto schema = schema_for(record, pi, source);
			if (!schema->accepted)
			{
				++events_schema_rejected_;
				return;
			}

			parsed_event ev;
			if (!parse(*schema, record, ev))
			{
				++events_parse_failed_;
				return;
			}
			++events_by_source_[static_cast<size_t>(source)];

			const int64_t event_qpc = record->EventHeader.TimeStamp.QuadPart;

			switch (source)
			{
			case etw::event_source::dns_query_called:
			case etw::event_source::dns_query_sent:
			case etw::event_source::dns_query_wire:
				on_dns_event(record, *schema, source, ev, event_qpc, received);
				return;
			case etw::event_source::tcpip_udp_bind:
				on_bind_event(ev, received);
				return;
			default:
				break;
			}

			// Tuple as seen from this host (local = source of an outbound packet)
			etw::packet_tuple tuple;
			bool both_orientations = false;
			if (source == etw::event_source::kn_udp_send || source == etw::event_source::kn_tcp_connect ||
				source == etw::event_source::kn_tcp_accept)
			{
				if (ev.addr_family[f_saddr] != ev.addr_family[f_daddr])
				{
					++events_parse_failed_;
					return;
				}
				tuple.family = ev.addr_family[f_saddr];
				tuple.protocol = source == etw::event_source::kn_udp_send ? IPPROTO_UDP : IPPROTO_TCP;
				tuple.local_ip = ev.addr[f_saddr];
				tuple.remote_ip = ev.addr[f_daddr];
				tuple.local_port = static_cast<uint16_t>(ev.num[f_sport]);
				tuple.remote_port = static_cast<uint16_t>(ev.num[f_dport]);
				// saddr/daddr orientation for accepted connections is [U]: cache both.
				both_orientations = source == etw::event_source::kn_tcp_accept;
			}
			else
			{
				if (ev.addr_family[f_local_sockaddr] != ev.addr_family[f_remote_sockaddr])
				{
					++events_parse_failed_;
					return;
				}
				tuple.family = ev.addr_family[f_local_sockaddr];
				tuple.protocol = source == etw::event_source::tcpip_udp_send ? IPPROTO_UDP : IPPROTO_TCP;
				tuple.local_ip = ev.addr[f_local_sockaddr];
				tuple.remote_ip = ev.addr[f_remote_sockaddr];
				tuple.local_port = ev.addr_port[f_local_sockaddr];
				tuple.remote_port = ev.addr_port[f_remote_sockaddr];
			}

			// PID policy, per event id [M26300, M19045]:
			//   TCPIP 1031 (connect proceeding, written at SYN send in the connecting
			//     thread): payload ProcessId and ProcessStartKey are 0; the event header PID
			//     is the connecting process. Use the header PID unless it is 0 or 4.
			//   TCPIP 1033 (connected): header PID is 4 (System), payload ProcessId is the
			//     owner. Payload only.
			//   TCPIP 1034 (connect failed): header and payload both named the owner after a
			//     local abort; a remote RST is processed in an arbitrary context, so payload
			//     only.
			//   Every other source (KN 12/15/28/31/42/58, TCPIP 1017/1169/1300): payload only.
			// A remaining PID of 0 means "unknown": such a record never outranks one with a
			// real PID (find_owner) and is not reported as Idle.
			auto pid = static_cast<uint32_t>(ev.num[f_pid]);
			bool pid_from_header = false;
			if (pid == 0 && source == etw::event_source::tcpip_tcp_connect)
			{
				const auto header_pid = static_cast<uint32_t>(record->EventHeader.ProcessId);
				if (header_pid != 0 && header_pid != 4 && header_pid != 0xFFFFFFFFu)
				{
					pid = header_pid;
					pid_from_header = true;
				}
			}
			if (pid == own_pid_ && config_.ignore_own_process && !is_self_test_tuple(tuple))
			{
				++events_own_process_;
				return;
			}

			etw::owner_info owner;
			owner.pid = pid;
			owner.pid_from_header = pid_from_header;
			owner.process_start_key = ev.has[f_start_key] ? ev.num[f_start_key] : 0;
			owner.source = source;
			owner.event_id = id;
			owner.event_version = record->EventHeader.EventDescriptor.Version;
			owner.event_qpc = event_qpc;
			owner.received_qpc = received;
			owner.status = ev.has[f_status] ? static_cast<uint32_t>(ev.num[f_status]) : 0;
			resolve_image(owner);

			insert_owner(tuple, owner);
			if (both_orientations)
				insert_owner(tuple.reversed(), owner);

			note_self_test(tuple, source, received);
			bump_generation();
		}

		void on_bind_event(const parsed_event& ev, const int64_t received)
		{
			// 1396 never decides: keyed by local endpoint only it matched rows to Umbrella
			// processes under load [M19045]. It only adds a start key to a 5-tuple match.
			if (!ev.has[f_pid] || !ev.has[f_start_key])
				return;
			bind_record r;
			r.pid = static_cast<uint32_t>(ev.num[f_pid]);
			r.start_key = ev.num[f_start_key];
			r.received_qpc = received;
			const bind_key k{ev.addr_family[f_local_sockaddr], ev.addr[f_local_sockaddr], ev.addr_port[f_local_sockaddr]};
			std::unique_lock<std::shared_mutex> lock(cache_mutex_);
			binds_[k] = r;
		}

		void on_dns_event(const EVENT_RECORD* record, const event_schema& schema, const etw::event_source source,
		                  const parsed_event& ev, const int64_t event_qpc, const int64_t received)
		{
			if (!ev.has[f_query_name] || !ev.has[f_query_type])
				return;
			dns_record r;
			r.qtype = static_cast<uint16_t>(ev.num[f_query_type]);
			r.caller.source = source;
			r.caller.event_version = record->EventHeader.EventDescriptor.Version;
			r.caller.query_name = normalize_name(ev.text);
			r.caller.event_qpc = event_qpc;
			r.caller.received_qpc = received;
			r.network_index = ev.has[f_network_index] ? static_cast<uint32_t>(ev.num[f_network_index]) : 0;
			if (source == etw::event_source::dns_query_called)
			{
				// 3006 is written inside the caller (dnsapi): header PID = caller [M19045][M26300]
				r.caller.pid = record->EventHeader.ProcessId;
			}
			else if (schema.field_prop[f_client_pid] >= 0 && ev.has[f_client_pid])
			{
				r.caller.pid = static_cast<uint32_t>(ev.num[f_client_pid]);
				r.caller.from_client_pid = true;
				r.has_client_pid = true;
			}
			// else: v0 without ClientPID (19045): header PID is Dnscache; confirmation only

			if (r.caller.pid != 0 && r.caller.pid != 4)
			{
				etw::owner_info tmp;
				tmp.pid = r.caller.pid;
				tmp.event_qpc = event_qpc;
				resolve_image(tmp);
				r.caller.image_path = std::move(tmp.image_path);
				r.caller.image_verified = tmp.image_verified;
			}

			{
				std::lock_guard<std::mutex> lock(dns_mutex_);
				dns_events_.push_back(std::move(r));
				while (dns_events_.size() > 8192) // time-based pruning runs in maintenance
					dns_events_.pop_front();
			}
			bump_generation();
		}

		void bump_generation()
		{
			// Increment first, then look for waiters (both seq_cst). A waiter increments
			// wake_waiters_ under wake_mutex_ before it checks the generation, so either it
			// sees the new value or we see it waiting and notify under the mutex.
			++generation_;
			if (wake_waiters_.load() == 0)
				return;
			{
				std::lock_guard<std::mutex> lock(wake_mutex_);
			}
			wake_cv_.notify_all();
		}

		// ------------------------------------------------------------------------
		// Image resolution on the consumer thread, at event time (plan 3.5)
		// ------------------------------------------------------------------------
		struct image_memo
		{
			uint64_t start_key{};
			uint64_t creation{};
			std::wstring image;
			/// <summary>QPC taken just before the last OpenProcess that found this PID held by
			/// the process with this creation time. A PID cannot be reused while any process
			/// object holds it, so every event written before this moment by this PID with
			/// a creation time at or before the event came from that process.</summary>
			int64_t verified_qpc{};
		};

		void resolve_image(etw::owner_info& owner)
		{
			owner.image_verified = false;
			if (owner.pid == 0)
				return; // unknown owner: nothing to verify (not "Idle")
			if (owner.pid == 4)
			{
				owner.image_verified = true;
				return;
			}

			std::lock_guard<std::mutex> lock(image_mutex_);
			auto it = image_memo_.find(owner.pid);

			// (pid, start key) memo: a recycled PID has a different start key.
			if (owner.process_start_key != 0 && it != image_memo_.end() &&
				it->second.start_key == owner.process_start_key && !it->second.image.empty())
			{
				owner.image_path = it->second.image;
				owner.image_verified = true;
				return;
			}

			// (pid, creation, time) memo for events without a start key (Kernel-Network, one
			// per datagram system-wide): an event written before the last successful open of
			// this PID, by a process created no later than the event, is that process. This
			// re-opens about once per delivered buffer per PID instead of once per event.
			const auto event_ft = qpc_to_filetime(owner.event_qpc);
			constexpr uint64_t tolerance = 20 * 10000; // 20 ms in 100 ns units
			if (it != image_memo_.end() && it->second.creation != 0 && !it->second.image.empty() &&
				it->second.verified_qpc != 0 && owner.event_qpc <= it->second.verified_qpc &&
				it->second.creation <= event_ft + tolerance &&
				(owner.process_start_key == 0 || it->second.start_key == 0))
			{
				if (owner.process_start_key != 0)
					it->second.start_key = owner.process_start_key;
				owner.image_path = it->second.image;
				owner.image_verified = true;
				return;
			}

			++image_lookups_;
			const auto open_qpc = qpc_now();
			const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner.pid);
			if (!process)
			{
				// Exited (or protected). A memo is trusted only if the start key proves identity.
				if (it != image_memo_.end())
				{
					owner.image_path = it->second.image;
					owner.image_verified = owner.process_start_key != 0 &&
						it->second.start_key == owner.process_start_key;
				}
				if (!owner.image_verified)
					++image_unverified_;
				return;
			}

			const uint64_t created = process_creation_time(process);

			// A process created after the event cannot have emitted it: the PID was reused.
			if (created != 0 && created > event_ft + tolerance)
			{
				CloseHandle(process);
				if (it != image_memo_.end() && it->second.creation != 0 && it->second.creation <= event_ft + tolerance)
					owner.image_path = it->second.image; // the earlier process with this PID (unverified)
				++image_unverified_;
				return;
			}

			if (it != image_memo_.end() && created != 0 && it->second.creation == created && !it->second.image.empty())
			{
				if (owner.process_start_key != 0)
					it->second.start_key = owner.process_start_key;
				it->second.verified_qpc = open_qpc;
				owner.image_path = it->second.image;
				owner.image_verified = true;
				CloseHandle(process);
				return;
			}

			std::wstring image(MAX_PATH * 4, L'\0');
			auto size = static_cast<DWORD>(image.size());
			if (QueryFullProcessImageNameW(process, 0, &image[0], &size))
				image.resize(size);
			else
				image.clear();
			CloseHandle(process);

			if (image_memo_.size() > 4096)
				image_memo_.clear();
			image_memo_[owner.pid] = image_memo{owner.process_start_key, created, image, created != 0 ? open_qpc : 0};
			owner.image_path = std::move(image);
			owner.image_verified = !owner.image_path.empty();
			if (!owner.image_verified)
				++image_unverified_;
		}

		// ------------------------------------------------------------------------
		// Owner cache (plan 3.4)
		// ------------------------------------------------------------------------
		struct bind_key
		{
			uint16_t family{};
			std::array<uint8_t, 16> ip{};
			uint16_t port{};

			bool operator==(const bind_key& o) const noexcept
			{
				return family == o.family && port == o.port && ip == o.ip;
			}
		};

		struct bind_key_hash
		{
			size_t operator()(const bind_key& k) const noexcept
			{
				etw::packet_tuple t;
				t.family = k.family;
				t.local_ip = k.ip;
				t.local_port = k.port;
				return etw::packet_tuple_hash{}(t);
			}
		};

		struct bind_record
		{
			uint32_t pid{};
			uint64_t start_key{};
			int64_t received_qpc{};
		};

		static constexpr size_t max_records_per_tuple = 8;

		void insert_owner(const etw::packet_tuple& tuple, const etw::owner_info& owner)
		{
			std::unique_lock<std::shared_mutex> lock(cache_mutex_);
			auto& records = cache_[tuple];
			if (records.size() >= max_records_per_tuple)
				records.erase(records.begin());
			records.push_back(owner);
		}

		/// <summary>TCPIP 1033 / 1034: payload PID written for the connection itself</summary>
		static bool is_payload_override_source(const etw::event_source s) noexcept
		{
			return s == etw::event_source::tcpip_tcp_connected || s == etw::event_source::tcpip_tcp_failed;
		}

		/// <summary>Event-time range [lo, hi) of one TCP connect attempt of a tuple</summary>
		struct attempt_range
		{
			int64_t lo{};
			int64_t hi{};
		};

		/// <summary>
		/// The connect attempt that owner_qpc belongs to: from the latest TCPIP 1031 at or
		/// after from_qpc and at or before owner_qpc (from_qpc if there is none) up to, but
		/// not including, the next 1031 of the tuple after owner_qpc. A reused 5-tuple (fast
		/// reconnect, fixed source port, another process getting the same port) starts a
		/// new attempt with its own 1031, so its 1033/1034/KN 12 are not mixed in.
		/// </summary>
		static attempt_range connect_attempt(const std::vector<etw::owner_info>& records, const int64_t from_qpc,
		                                     const int64_t owner_qpc) noexcept
		{
			attempt_range a{from_qpc, (std::numeric_limits<int64_t>::max)()};
			for (const auto& r : records)
			{
				if (r.source != etw::event_source::tcpip_tcp_connect)
					continue;
				if (r.event_qpc >= from_qpc && r.event_qpc <= owner_qpc)
					a.lo = (std::max)(a.lo, r.event_qpc);
				else if (r.event_qpc > owner_qpc)
					a.hi = (std::min)(a.hi, r.event_qpc);
			}
			return a;
		}

		struct attempt_scan
		{
			/// <summary>First (by event time) 1033/1034 of the attempt with a payload PID</summary>
			const etw::owner_info* payload{};
			bool completed{};
			bool failed{};
			uint32_t failed_status{};
			uint32_t sources{};
			/// <summary>First known (nonzero) PID of the attempt</summary>
			uint32_t known_pid{};
			/// <summary>Records of the attempt named different known PIDs</summary>
			bool pids_differ{};
		};

		/// <summary>Outcome records of one connect attempt. Caller holds cache_mutex_; the
		/// payload pointer is valid only while it does.</summary>
		static attempt_scan scan_attempt(const std::vector<etw::owner_info>& records, const attempt_range& range) noexcept
		{
			attempt_scan a;
			for (const auto& r : records)
			{
				if (r.event_qpc < range.lo || r.event_qpc >= range.hi)
					continue;
				a.sources |= 1u << static_cast<unsigned>(r.source);
				if (r.pid != 0)
				{
					if (a.known_pid == 0)
						a.known_pid = r.pid;
					else if (r.pid != a.known_pid)
						a.pids_differ = true;
				}
				if (r.source == etw::event_source::tcpip_tcp_failed)
				{
					a.failed = true;
					a.failed_status = r.status;
				}
				else if (r.source == etw::event_source::tcpip_tcp_connected ||
					r.source == etw::event_source::kn_tcp_connect)
					a.completed = true;
				if (r.pid != 0 && is_payload_override_source(r.source) &&
					(!a.payload || r.event_qpc < a.payload->event_qpc))
					a.payload = &r;
			}
			return a;
		}

		/// <summary>
		/// Applies the payload PID of the attempt's first 1033/1034 to owner:
		/// - owner has no PID (1031 payload 0, header 0 or 4): owner becomes that record
		///   (pid_from_outcome); the connect's PID is known only from then on;
		/// - owner came from a 1031 header PID and the payload names another PID (S8): a
		///   header PID is only as good as the context the event was written in, so the
		///   payload wins and the owner is marked header_pid_overridden.
		/// </summary>
		static void apply_payload_pid(etw::owner_info& owner, const etw::owner_info& payload)
		{
			if (payload.pid == 0 || !is_payload_override_source(payload.source))
				return;
			if (owner.pid == 0)
			{
				const auto sources = owner.sources_seen;
				const auto conflict = owner.conflict;
				const auto completed = owner.connect_completed;
				const auto failed = owner.connect_failed;
				const auto status = owner.connect_status;
				owner = payload;
				owner.sources_seen = sources | payload.sources_seen;
				owner.conflict = conflict;
				owner.connect_completed = completed;
				owner.connect_failed = failed;
				owner.connect_status = status;
				owner.pid_from_outcome = true;
				return;
			}
			if (!owner.pid_from_header || payload.pid == owner.pid)
				return;
			owner.overridden_header_pid = owner.pid;
			owner.pid = payload.pid;
			owner.process_start_key = payload.process_start_key;
			owner.image_path = payload.image_path;
			owner.image_verified = payload.image_verified;
			owner.pid_from_header = false;
			owner.header_pid_overridden = true;
			owner.conflict = true;
		}

		static int source_rank(const etw::event_source s) noexcept
		{
			// Lower is preferred. UDP: 1169 (start key, written earlier) over 42/58 (plan 3.1).
			// TCP: 1031 (connect proceeding) over KN 12/28, then completion, failure, accept.
			// find_owner() ranks known PIDs above unknown (0) ones before applying this.
			switch (s)
			{
			case etw::event_source::tcpip_udp_send: return 0;
			case etw::event_source::kn_udp_send: return 1;
			case etw::event_source::tcpip_tcp_connect: return 0;
			case etw::event_source::kn_tcp_connect: return 1;
			case etw::event_source::tcpip_tcp_connected: return 2;
			case etw::event_source::tcpip_tcp_failed: return 3;
			case etw::event_source::tcpip_tcp_accept: return 4;
			case etw::event_source::kn_tcp_accept: return 5;
			case etw::event_source::tcpip_tcp_rundown: return 6;
			default: return 9;
			}
		}

		std::optional<etw::owner_info> find_owner(const etw::packet_tuple& tuple, const int64_t packet_qpc,
		                                          const etw::match_kind kind) const
		{
			const bool tcp = tuple.protocol == IPPROTO_TCP;
			const auto before = us_to_qpc(config_.window_before.count());
			const auto after = us_to_qpc(tcp ? config_.tcp_window_after.count() : config_.window_after.count());
			const auto ttl = us_to_qpc(std::chrono::duration_cast<std::chrono::microseconds>(
				tcp ? config_.tcp_ttl : config_.udp_ttl).count());

			std::shared_lock<std::shared_mutex> lock(cache_mutex_);
			const auto it = cache_.find(tuple);
			if (it == cache_.end())
				return std::nullopt;

			// Preference: a known PID first (a pid-0 record never outranks a real one, so a
			// pid-0 1031 falls back to the next ranked record, e.g. 1033 or KN 12), then
			// source_rank, then distance from the packet.
			auto better = [](const etw::owner_info& a, const int64_t a_distance, const etw::owner_info& b,
			                 const int64_t b_distance)
			{
				if ((a.pid == 0) != (b.pid == 0))
					return a.pid != 0;
				const auto ra = source_rank(a.source), rb = source_rank(b.source);
				if (ra != rb)
					return ra < rb;
				return a_distance < b_distance;
			};
			const etw::owner_info* best = nullptr;
			uint32_t seen = 0;
			uint32_t known_pid = 0;
			bool conflict = false;
			int64_t best_distance = 0;
			for (const auto& r : it->second)
			{
				bool in_window;
				if (kind == etw::match_kind::datagram)
				{
					// Strict: "the event of this datagram/SYN". A rundown (1300) describes an
					// existing connection, not this packet.
					in_window = r.source != etw::event_source::tcpip_tcp_rundown &&
						r.event_qpc >= packet_qpc - before && r.event_qpc <= packet_qpc + after;
				}
				else
				{
					in_window = r.received_qpc + ttl >= packet_qpc && r.event_qpc <= packet_qpc + after;
				}
				if (!in_window)
					continue;
				seen |= 1u << static_cast<unsigned>(r.source);
				if (r.pid != 0)
				{
					// Unknown (0) is not a different owner: only known PIDs can conflict.
					if (known_pid != 0 && known_pid != r.pid)
						conflict = true;
					known_pid = r.pid;
				}
				const auto distance = r.event_qpc > packet_qpc ? r.event_qpc - packet_qpc : packet_qpc - r.event_qpc;
				if (!best || better(r, distance, *best, best_distance))
				{
					best = &r;
					best_distance = distance;
				}
			}
			if (!best)
				return std::nullopt;

			etw::owner_info result = *best;
			result.sources_seen = seen;
			result.conflict = conflict;
			if (tcp)
			{
				// Outcome and payload PID come from the connect attempt of the chosen record
				// only (not limited to the match window: 1033 comes one RTT after the SYN).
				const auto attempt = scan_attempt(it->second,
				                                  connect_attempt(it->second, (std::min)(packet_qpc - before, best->event_qpc),
				                                                  best->event_qpc));
				result.connect_completed = attempt.completed;
				if (attempt.failed)
				{
					result.connect_failed = true;
					result.connect_status = attempt.failed_status;
				}
				if (attempt.payload)
					apply_payload_pid(result, *attempt.payload);
			}

			if (result.process_start_key == 0 && !tcp)
			{
				// 1396 enrichment: same local endpoint (or wildcard bind) AND same PID
				bind_key k{tuple.family, tuple.local_ip, tuple.local_port};
				auto b = binds_.find(k);
				if (b == binds_.end())
				{
					k.ip.fill(0);
					b = binds_.find(k);
				}
				if (b != binds_.end() && b->second.pid == result.pid)
				{
					result.process_start_key = b->second.start_key;
					result.sources_seen |= 1u << static_cast<unsigned>(etw::event_source::tcpip_udp_bind);
				}
			}
			return result;
		}

		void prune()
		{
			const auto now = qpc_now();
			const auto udp_ttl = us_to_qpc(
				std::chrono::duration_cast<std::chrono::microseconds>(config_.udp_ttl).count());
			const auto tcp_ttl = us_to_qpc(
				std::chrono::duration_cast<std::chrono::microseconds>(config_.tcp_ttl).count());
			{
				std::unique_lock<std::shared_mutex> lock(cache_mutex_);
				for (auto it = cache_.begin(); it != cache_.end();)
				{
					const auto ttl = it->first.protocol == IPPROTO_TCP ? tcp_ttl : udp_ttl;
					auto& v = it->second;
					v.erase(std::remove_if(v.begin(), v.end(), [&](const etw::owner_info& r)
					{
						return r.received_qpc + ttl < now;
					}), v.end());
					it = v.empty() ? cache_.erase(it) : std::next(it);
				}
				// Hard bound: drop UDP entries older than half the TTL, then anything idle
				// longer than the UDP TTL, if the cache is still too big.
				for (int pass = 0; pass < 2 && cache_.size() > config_.max_cache_entries; ++pass)
				{
					const auto limit = pass == 0 ? udp_ttl / 2 : udp_ttl;
					for (auto it = cache_.begin(); it != cache_.end();)
					{
						const bool old = it->second.back().received_qpc + limit < now &&
							(pass == 1 || it->first.protocol == IPPROTO_UDP);
						it = old ? cache_.erase(it) : std::next(it);
					}
				}
				for (auto it = binds_.begin(); it != binds_.end();)
					it = it->second.received_qpc + udp_ttl < now ? binds_.erase(it) : std::next(it);
			}
			{
				const auto dns_ttl = 2 * us_to_qpc(
					std::chrono::duration_cast<std::chrono::microseconds>(config_.dns_window).count());
				std::lock_guard<std::mutex> lock(dns_mutex_);
				while (!dns_events_.empty() && dns_events_.front().caller.received_qpc + dns_ttl < now)
					dns_events_.pop_front();
			}
		}

		void record_latency(const int64_t delta_qpc)
		{
			const double ms = delta_qpc <= 0 ? 0.0 : qpc_to_ms(delta_qpc);
			size_t i = 0;
			while (i < etw::latency_bucket_ms.size() && ms > etw::latency_bucket_ms[i])
				++i;
			++latency_histogram_[i];
		}

		// ------------------------------------------------------------------------
		// DNS helpers (plan 4)
		// ------------------------------------------------------------------------
		struct dns_record
		{
			etw::dns_caller caller;
			uint16_t qtype{};
			uint32_t network_index{};
			bool has_client_pid{};
		};

		static std::wstring normalize_name(std::wstring name)
		{
			for (auto& c : name)
			{
				if (c >= L'A' && c <= L'Z')
					c = static_cast<wchar_t>(c - L'A' + L'a');
			}
			while (!name.empty() && name.back() == L'.')
				name.pop_back();
			return name;
		}

		/// <summary>wire == called, or wire == called + "." + suffix (Dnscache appends search
		/// suffixes; example.com went out as example.com.mshome.net [M19045])</summary>
		static bool name_matches(const std::wstring& wire, const std::wstring& called,
		                         const std::vector<std::wstring>& suffixes, bool& via_suffix)
		{
			via_suffix = false;
			if (called.empty())
				return false;
			if (wire == called)
				return true;
			if (wire.size() <= called.size() + 1 || wire.compare(0, called.size(), called) != 0 ||
				wire[called.size()] != L'.')
				return false;
			const auto rest = wire.substr(called.size() + 1);
			for (const auto& s : suffixes)
			{
				if (rest == s)
				{
					via_suffix = true;
					return true;
				}
			}
			return false;
		}

		static void add_suffix_list(std::vector<std::wstring>& out, const std::wstring& list)
		{
			size_t start = 0;
			while (start <= list.size())
			{
				auto end = list.find_first_of(L", ;", start);
				if (end == std::wstring::npos)
					end = list.size();
				auto item = normalize_name(list.substr(start, end - start));
				while (!item.empty() && item.front() == L'.')
					item.erase(item.begin());
				if (!item.empty() && std::find(out.begin(), out.end(), item) == out.end())
					out.push_back(std::move(item));
				start = end + 1;
			}
		}

		static std::wstring read_registry_string(const wchar_t* key, const wchar_t* value)
		{
			DWORD size = 0;
			if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS ||
				size < sizeof(wchar_t))
				return {};
			std::wstring s(size / sizeof(wchar_t), L'\0');
			if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, nullptr, &s[0], &size) != ERROR_SUCCESS)
				return {};
			s.resize(wcsnlen(s.c_str(), s.size()));
			return s;
		}

		/// <summary>Current DNS search suffix snapshot (never empty pointer, no I/O)</summary>
		std::shared_ptr<const std::vector<std::wstring>> search_suffixes() const
		{
			std::lock_guard<std::mutex> lock(suffix_mutex_);
			return suffixes_;
		}

		/// <summary>Reloads the DNS search suffixes: per-adapter DnsSuffix plus the
		/// global/policy SearchList and primary domain. GetAdaptersAddresses can take tens of
		/// ms, so this runs in start() and every 30 s on the maintenance thread, never on a
		/// dns_lookup() caller's thread.</summary>
		void refresh_suffixes()
		{
			std::vector<std::wstring> out;
			ULONG size = 16 * 1024;
			std::vector<uint8_t> buffer;
			ULONG status = ERROR_BUFFER_OVERFLOW;
			for (int i = 0; i < 3 && status == ERROR_BUFFER_OVERFLOW; ++i)
			{
				buffer.resize(size);
				status = GetAdaptersAddresses(AF_UNSPEC,
				                              GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
				                              GAA_FLAG_SKIP_DNS_SERVER, nullptr,
				                              reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &size);
			}
			if (status == NO_ERROR)
			{
				for (auto* a = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()); a; a = a->Next)
				{
					if (a->DnsSuffix && *a->DnsSuffix)
						add_suffix_list(out, a->DnsSuffix);
				}
			}
			const wchar_t* tcpip = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
			const wchar_t* policy = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
			add_suffix_list(out, read_registry_string(policy, L"SearchList"));
			add_suffix_list(out, read_registry_string(tcpip, L"SearchList"));
			add_suffix_list(out, read_registry_string(tcpip, L"Domain"));
			add_suffix_list(out, read_registry_string(tcpip, L"NV Domain"));
			add_suffix_list(out, read_registry_string(tcpip, L"DhcpDomain"));

			auto snapshot = std::make_shared<const std::vector<std::wstring>>(std::move(out));
			std::lock_guard<std::mutex> lock(suffix_mutex_);
			suffixes_ = std::move(snapshot);
		}

		// ------------------------------------------------------------------------
		// Loopback self-test (plan gate 5). Our own loopback datagram / connection must
		// come back as an event naming our PID within the bound. It proves the session is
		// live, measures delivery latency with and without on-demand flushes, and is
		// repeated periodically.
		// ------------------------------------------------------------------------
		struct self_test_slot
		{
			uint64_t id{};
			etw::packet_tuple tuple;
			bool tcp{};
			uint32_t sources{};
			int64_t first_received{};
		};

		struct self_test_result
		{
			bool ok{};
			double ms{-1};
			uint32_t sources{};
			std::string error;
			/// <summary>TCP: owner chosen by find_owner() for the connect tuple</summary>
			uint32_t owner_pid{};
			etw::event_source owner_source{etw::event_source::none};
			bool owner_from_header{};
		};

		bool is_self_test_tuple(const etw::packet_tuple& t)
		{
			if (self_test_active_.load() == 0)
				return false;
			std::lock_guard<std::mutex> lock(self_test_mutex_);
			for (const auto& s : self_test_slots_)
			{
				if (s.tuple == t || s.tuple == t.reversed())
					return true;
			}
			return false;
		}

		static bool is_connect_source(const etw::event_source s) noexcept
		{
			return s == etw::event_source::tcpip_tcp_connect || s == etw::event_source::tcpip_tcp_connected ||
				s == etw::event_source::kn_tcp_connect;
		}

		void note_self_test(const etw::packet_tuple& t, const etw::event_source source, const int64_t received)
		{
			if (self_test_active_.load() == 0)
				return;
			std::lock_guard<std::mutex> lock(self_test_mutex_);
			for (auto& s : self_test_slots_)
			{
				if (!(s.tuple == t || s.tuple == t.reversed()))
					continue;
				s.sources |= 1u << static_cast<unsigned>(source);
				const bool relevant = s.tcp
					                      ? is_connect_source(source)
					                      : (source == etw::event_source::kn_udp_send ||
						                      source == etw::event_source::tcpip_udp_send);
				if (relevant && s.first_received == 0 && s.tuple == t)
					s.first_received = received;
			}
		}

		struct socket_guard
		{
			SOCKET s{INVALID_SOCKET};
			~socket_guard()
			{
				if (s != INVALID_SOCKET)
					closesocket(s);
			}
		};

		static int make_loopback(const uint16_t family, sockaddr_storage& ss)
		{
			std::memset(&ss, 0, sizeof(ss));
			if (family == AF_INET)
			{
				auto* a = reinterpret_cast<sockaddr_in*>(&ss);
				a->sin_family = AF_INET;
				a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				return sizeof(sockaddr_in);
			}
			auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
			a->sin6_family = AF_INET6;
			a->sin6_addr = in6addr_loopback;
			return sizeof(sockaddr_in6);
		}

		static uint16_t port_of(const sockaddr_storage& ss) noexcept
		{
			return ntohs(ss.ss_family == AF_INET
				             ? reinterpret_cast<const sockaddr_in&>(ss).sin_port
				             : reinterpret_cast<const sockaddr_in6&>(ss).sin6_port);
		}

		static etw::packet_tuple loopback_tuple(const uint16_t family, const uint8_t protocol, const uint16_t local_port,
		                                        const uint16_t remote_port)
		{
			etw::packet_tuple t;
			t.family = family;
			t.protocol = protocol;
			if (family == AF_INET)
			{
				t.local_ip[0] = t.remote_ip[0] = 127;
				t.local_ip[3] = t.remote_ip[3] = 1;
			}
			else
				t.local_ip[15] = t.remote_ip[15] = 1;
			t.local_port = local_port;
			t.remote_port = remote_port;
			return t;
		}

		/// <summary>Non-blocking loopback connect + accept bounded by timeout: a firewall that
		/// drops (rather than rejects) loopback connects must not hold the maintenance thread,
		/// and with it stop(), for the OS connect timeout.</summary>
		static bool connect_loopback(const SOCKET sender, const SOCKET listener, SOCKET& accepted,
		                             sockaddr_storage& target, const int len, const std::chrono::milliseconds timeout)
		{
			u_long non_blocking = 1;
			if (ioctlsocket(sender, FIONBIO, &non_blocking) != 0 || ioctlsocket(listener, FIONBIO, &non_blocking) != 0)
				return false;
			const auto deadline = clock::now() + timeout;
			auto wait = [&deadline](const SOCKET s, const bool write)
			{
				const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - clock::now());
				if (left.count() <= 0)
					return false;
				fd_set set, except;
				FD_ZERO(&set);
				FD_ZERO(&except);
				FD_SET(s, &set);
				FD_SET(s, &except);
				timeval tv{static_cast<long>(left.count() / 1000000), static_cast<long>(left.count() % 1000000)};
				return select(0, write ? nullptr : &set, write ? &set : nullptr, &except, &tv) > 0 &&
					FD_ISSET(s, &set) && !FD_ISSET(s, &except);
			};
			if (connect(sender, reinterpret_cast<sockaddr*>(&target), len) != 0)
			{
				if (WSAGetLastError() != WSAEWOULDBLOCK)
					return false;
				if (!wait(sender, true))
				{
					int error = 0;
					int error_len = sizeof(error);
					getsockopt(sender, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &error_len);
					WSASetLastError(error != 0 ? error : WSAETIMEDOUT);
					return false;
				}
			}
			if (!wait(listener, false))
			{
				WSASetLastError(WSAETIMEDOUT);
				return false;
			}
			accepted = accept(listener, nullptr, nullptr);
			return accepted != INVALID_SOCKET;
		}

		/// <summary>One self-test probe. use_flush: issue EVENT_TRACE_CONTROL_FLUSH every
		/// 10 ms while waiting (on-demand mode); otherwise rely on the session timer.</summary>
		self_test_result self_test_once(const uint16_t family, const bool tcp, const bool use_flush,
		                                const std::chrono::milliseconds timeout)
		{
			self_test_result result;
			sockaddr_storage target{}, local{};
			const int len = make_loopback(family, target);
			socket_guard receiver, sender, accepted;

			receiver.s = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP);
			sender.s = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP);
			if (receiver.s == INVALID_SOCKET || sender.s == INVALID_SOCKET)
			{
				result.error = "socket() failed: " + std::to_string(WSAGetLastError());
				return result;
			}
			int name_len = len;
			if (bind(receiver.s, reinterpret_cast<sockaddr*>(&target), len) != 0 ||
				getsockname(receiver.s, reinterpret_cast<sockaddr*>(&target), &name_len) != 0 ||
				(tcp && listen(receiver.s, 1) != 0))
			{
				result.error = "bind/listen failed: " + std::to_string(WSAGetLastError());
				return result;
			}
			sockaddr_storage local_bind{};
			make_loopback(family, local_bind);
			name_len = len;
			if (bind(sender.s, reinterpret_cast<sockaddr*>(&local_bind), len) != 0 ||
				getsockname(sender.s, reinterpret_cast<sockaddr*>(&local), &name_len) != 0)
			{
				result.error = "bind failed: " + std::to_string(WSAGetLastError());
				return result;
			}

			const auto tuple = loopback_tuple(family, tcp ? IPPROTO_TCP : IPPROTO_UDP, port_of(local),
			                                  port_of(target));
			const auto slot_id = ++self_test_seq_;
			{
				std::lock_guard<std::mutex> lock(self_test_mutex_);
				self_test_slots_.push_back(self_test_slot{slot_id, tuple, tcp, 0, 0});
			}
			++self_test_active_;

			const auto t0 = qpc_now();
			bool sent;
			if (tcp)
				sent = connect_loopback(sender.s, receiver.s, accepted.s, target, len, timeout);
			else
			{
				char nonce[16];
				std::snprintf(nonce, sizeof(nonce), "ndisapi%llu", static_cast<unsigned long long>(slot_id));
				sent = sendto(sender.s, nonce, static_cast<int>(std::strlen(nonce)), 0,
				              reinterpret_cast<sockaddr*>(&target), len) > 0;
			}

			auto slot_state = [&](uint32_t& sources, int64_t& first)
			{
				std::lock_guard<std::mutex> lock(self_test_mutex_);
				for (const auto& s : self_test_slots_)
				{
					if (s.id == slot_id)
					{
						sources = s.sources;
						first = s.first_received;
					}
				}
			};

			uint32_t sources = 0;
			int64_t first = 0;
			if (sent)
			{
				const auto deadline = clock::now() + timeout;
				for (;;)
				{
					const auto seen = generation();
					slot_state(sources, first);
					if (first != 0 || clock::now() >= deadline || stopping_.load())
						break;
					if (use_flush)
						flush_now();
					wait_for_events(seen, std::min(deadline, clock::now() + std::chrono::milliseconds(10)));
				}
				if (first != 0)
				{
					// Collect the other sources of the same packet/connection (one more flush)
					if (use_flush)
						flush_now();
					std::this_thread::sleep_for(std::chrono::milliseconds(use_flush ? 20 : 60));
					slot_state(sources, first);
					if (tcp)
					{
						// The gate is the owner, not the mere arrival of a connect event:
						// TCPIP 1031 arrives with payload ProcessId 0 [M26300].
						if (const auto owner = find_owner(tuple, t0, etw::match_kind::datagram))
						{
							result.owner_pid = owner->pid;
							result.owner_source = owner->source;
							result.owner_from_header = owner->pid_from_header;
						}
					}
				}
			}
			else
				result.error = std::string(tcp ? "connect" : "sendto") + " failed: " + std::to_string(WSAGetLastError());

			{
				std::lock_guard<std::mutex> lock(self_test_mutex_);
				self_test_slots_.erase(std::remove_if(self_test_slots_.begin(), self_test_slots_.end(),
				                                      [&](const self_test_slot& s) { return s.id == slot_id; }),
				                       self_test_slots_.end());
			}
			--self_test_active_;

			result.sources = sources;
			if (first != 0 && tcp && result.owner_pid != own_pid_)
			{
				result.ms = qpc_to_ms(first - t0);
				result.error = "loopback connect attributed to pid " + std::to_string(result.owner_pid) + " via " +
					etw::to_string(result.owner_source) + ", expected own pid " + std::to_string(own_pid_);
			}
			else if (first != 0)
			{
				result.ok = true;
				result.ms = qpc_to_ms(first - t0);
			}
			else if (result.error.empty())
				result.error = "no event within " + std::to_string(timeout.count()) + " ms";
			return result;
		}

		struct probe_series
		{
			bool ok{true};
			double worst{-1};
			double median{-1};
			std::vector<double> samples;
			uint32_t sources{};
			std::string error;
			uint32_t owner_pid{};
			etw::event_source owner_source{etw::event_source::none};
			bool owner_from_header{};
		};

		probe_series probe(const uint16_t family, const bool tcp, const bool use_flush, const int runs,
		                   const std::chrono::milliseconds timeout)
		{
			probe_series s;
			for (int i = 0; i < runs && !stopping_.load(); ++i)
			{
				const auto r = self_test_once(family, tcp, use_flush, timeout);
				s.sources |= r.sources;
				if (tcp)
				{
					s.owner_pid = r.owner_pid;
					s.owner_source = r.owner_source;
					s.owner_from_header = r.owner_from_header;
				}
				if (r.ms >= 0)
					s.samples.push_back(r.ms);
				if (!r.ok)
				{
					s.ok = false;
					s.error = r.error;
					break;
				}
				s.worst = std::max(s.worst, r.ms);
			}
			if (!s.samples.empty())
			{
				auto sorted = s.samples;
				std::sort(sorted.begin(), sorted.end());
				const auto n = sorted.size();
				s.median = n % 2 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
			}
			return s;
		}

		static bool ipv6_loopback_supported()
		{
			const SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if (s == INVALID_SOCKET)
				return false;
			sockaddr_in6 a{};
			a.sin6_family = AF_INET6;
			a.sin6_addr = in6addr_loopback;
			const bool ok = bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
			closesocket(s);
			return ok;
		}

		void run_initial_self_test()
		{
			etw::self_test_status st;
			st.ran = true;
			std::ostringstream detail;
			std::string fallback_reason;

			bool ms_bit_kept;
			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				ms_bit_kept = report_.ms_timer_bit_kept;
			}

			// Timer probe first, with no flush at all: only the session timer delivers.
			// Used only if the 0x10 bit survived the read-back and the MEDIAN of five
			// samples is <= 50 ms (10 ms timer measured ~31 ms median on 19045, ~28 ms on
			// 26300; ~1.6 s on 7601). The worst sample does not decide: single samples of
			// 69-80 ms next to 32-39 ms ones were seen on a 2-vCPU 19045 VM [M19045].
			if (ms_bit_kept && config_.flush != etw::flush_mode::on_demand)
			{
				const auto t = probe(AF_INET, false, false, 5, std::chrono::milliseconds(500));
				st.timer_samples = t.samples;
				st.timer_ms = t.ok ? t.median : -1;
				st.timer_ok = t.ok && t.median <= 50.0;
				st.ipv4_sources |= t.sources;
				if (!t.ok)
					detail << "timer probe: " << t.error << "; ";
				else if (!st.timer_ok)
					detail << "timer probe median " << t.median << " ms exceeds 50 ms; ";
			}
			else
				detail << "timer probe skipped (" << (ms_bit_kept ? "on-demand requested" : "ms-timer bit not kept")
					<< "); ";

			const auto od = probe(AF_INET, false, true, 3, std::chrono::milliseconds(1500));
			st.ipv4_ok = od.ok;
			st.on_demand_ms = od.ok ? od.worst : -1;
			st.on_demand_samples = od.samples;
			st.ipv4_sources |= od.sources;
			if (!od.ok)
				detail << "ipv4: " << od.error << "; ";

			if (ipv6_loopback_supported())
			{
				st.ipv6_attempted = true;
				const auto v6 = probe(AF_INET6, false, true, 1, std::chrono::milliseconds(1500));
				st.ipv6_ok = v6.ok;
				st.ipv6_sources = v6.sources;
				if (!v6.ok)
					detail << "ipv6: " << v6.error << "; ";
			}

			if (config_.enable_tcp)
			{
				st.tcp_attempted = true;
				const auto t = probe(AF_INET, true, true, 2, std::chrono::milliseconds(1500));
				st.tcp_ok = t.ok;
				st.tcp_on_demand_ms = t.ok ? t.worst : -1;
				st.tcp_sources = t.sources;
				st.tcp_owner_pid = t.owner_pid;
				st.tcp_owner_source = t.owner_source;
				st.tcp_owner_from_header = t.owner_from_header;
				if (!t.ok)
					detail << "tcp: " << t.error << "; ";
			}

			// Flush mode selection (plan 3.3)
			auto mode = etw::effective_flush::none;
			if (st.ipv4_ok && st.on_demand_ms <= 250.0)
			{
				switch (config_.flush)
				{
				case etw::flush_mode::timer:
					if (st.timer_ok)
						mode = etw::effective_flush::timer;
					else
					{
						mode = etw::effective_flush::on_demand;
						detail << "timer requested but not confirmed: falling back to on-demand; ";
					}
					break;
				case etw::flush_mode::automatic:
					// Prefer the ms timer whenever it is confirmed: under sustained load on a
					// 2-vCPU VM the timer held while on-demand flushing degraded [M19045].
					if (st.timer_ok)
						mode = etw::effective_flush::timer_and_light_on_demand;
					else
					{
						mode = etw::effective_flush::on_demand;
						std::ostringstream why;
						why << "auto: falling back to on-demand flushes because ";
						if (!ms_bit_kept)
							why << "the ms-timer bit was not kept in the read-back";
						else if (st.timer_ms < 0)
							why << "the timer probe got no event";
						else
							why << "the timer probe median " << st.timer_ms << " ms exceeds 50 ms";
						detail << why.str() << "; ";
						fallback_reason = why.str();
					}
					break;
				case etw::flush_mode::on_demand:
					mode = etw::effective_flush::on_demand;
					break;
				}
			}
			else if (st.ipv4_ok)
				detail << "on-demand delivery " << st.on_demand_ms << " ms exceeds 250 ms; ";

			st.runs = 1;
			st.failures = mode == etw::effective_flush::none ? 1 : 0;
			st.detail = detail.str();
			st.own_pid = own_pid_;
			if (!fallback_reason.empty())
				log(fallback_reason);
			effective_flush_ = mode;
			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				report_.self_test = st;
				report_.flush = mode;
			}
			// After the result is in report_: a concurrent refresh_availability() must not see
			// live_ with the TCP self-test still unrecorded (it would treat TCP as passed).
			live_ = mode != etw::effective_flush::none;
		}

		void run_periodic_self_test()
		{
			const auto mode = effective_flush_.load();
			if (mode == etw::effective_flush::none)
				return;
			calibrate_clock();
			const bool use_flush = mode != etw::effective_flush::timer;
			const auto r = self_test_once(AF_INET, false, use_flush,
			                              std::chrono::milliseconds(use_flush ? 1500 : 500));
			bool changed;
			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				++report_.self_test.runs;
				if (!r.ok)
				{
					++report_.self_test.failures;
					report_.self_test.detail = "periodic: " + r.error;
				}
				changed = live_.load() != r.ok;
			}
			if (!r.ok)
			{
				// Two consecutive failures switch attribution off until a probe passes again.
				if (++consecutive_self_test_failures_ >= 2)
					live_ = false;
			}
			else
			{
				consecutive_self_test_failures_ = 0;
				live_ = true;
			}
			if (changed)
			{
				log(std::string("periodic self-test: ") + (r.ok ? "ok " + std::to_string(r.ms) + " ms" : r.error));
				refresh_availability();
			}
		}

		// ------------------------------------------------------------------------
		// Availability
		// ------------------------------------------------------------------------
		void refresh_availability()
		{
			// Never turn availability back on while stop() drains the consumer; stop_locked()
			// stores the final state after joining both threads.
			if (stopping_.load())
				return;
			bool udp_schema = false, tcp_schema = false, dns_schema = false;
			{
				std::lock_guard<std::mutex> lock(schema_mutex_);
				for (const auto& kv : schemas_)
				{
					const auto& s = *kv.second;
					if (!s.accepted || provider_unfiltered_[s.provider_index].load())
						continue;
					switch (s.source)
					{
					case etw::event_source::kn_udp_send:
					case etw::event_source::tcpip_udp_send:
						udp_schema = true;
						break;
					case etw::event_source::tcpip_tcp_connect:
					case etw::event_source::tcpip_tcp_connected:
					case etw::event_source::kn_tcp_connect:
						tcp_schema = true;
						break;
					case etw::event_source::dns_query_called:
					case etw::event_source::dns_query_wire:
					case etw::event_source::dns_query_sent:
						dns_schema = true;
						break;
					default:
						break;
					}
				}
			}

			bool available;
			bool was;
			std::string log_line;
			{
				std::lock_guard<std::mutex> lock(report_mutex_);
				auto filtered_enabled = [&](const size_t i)
				{
					return i < report_.providers.size() && report_.providers[i].enabled &&
						!provider_unfiltered_[i].load();
				};
				const bool udp_provider = filtered_enabled(kernel_network_index) || filtered_enabled(tcpip_index);
				// The TCP self-test gates TCP only: it runs once at start (the periodic self-test
				// is UDP), and a failure (wrong owner, or loopback TCP blocked) switches TCP owners
				// off for this session while UDP stays on. The IPv6 self-test is reported only:
				// it is skipped when ::1 cannot be bound, and IPv6 events are unmeasured.
				const bool tcp_self_test_ok = !report_.self_test.tcp_attempted || report_.self_test.tcp_ok;
				report_.udp_available = udp_provider && udp_schema && live_.load();
				report_.tcp_available = config_.enable_tcp && udp_provider && tcp_schema && tcp_self_test_ok &&
					live_.load();
				report_.dns_available = config_.enable_dns && filtered_enabled(dns_client_index) && live_.load();
				(void)dns_schema; // DNS schemas are checked lazily on the first DNS event

				available = started_.load() && report_.udp_available;
				if (!available && started_.load())
				{
					std::string reason;
					if (!udp_provider)
						reason = "no UDP provider with an honoured event-id filter";
					else if (!udp_schema)
						reason = "no accepted UDP send schema (42/58/1169)";
					else if (!live_.load())
						reason = "loopback self-test failed: " + report_.self_test.detail;
					if (!reason.empty() && reason != report_.failure)
					{
						report_.failure = reason;
						log_line = reason;
					}
				}
				else if (available)
					report_.failure.clear();
				report_.available = available;
				// Publish under the same lock as the computation: two threads refreshing at
				// once (consumer: new schema; maintenance: self-test) must not leave an older
				// verdict in the atomics after a newer one.
				tcp_available_ = available && report_.tcp_available;
				was = available_.exchange(available);
			}
			// While start() runs its gates, schemas arrive one by one and the verdict is not
			// final yet ("no accepted UDP send schema" before the first 42/1169): stay quiet.
			if (!gate_final_.load())
				return;
			if (was != available || !log_line.empty())
				log(std::string("ETW attribution ") + (available ? "available" : "unavailable") +
					(log_line.empty() ? "" : ": " + log_line));
		}

		// ------------------------------------------------------------------------
		// Maintenance thread: pruning, loss monitoring, consumer liveness, self-test
		// ------------------------------------------------------------------------
		void maintenance_proc()
		{
			auto next_loss_check = clock::now() + std::chrono::seconds(5);
			auto next_self_test = clock::now() + config_.self_test_interval;
			auto next_suffix_refresh = clock::now() + std::chrono::seconds(30);
			auto next_dnscache_refresh = clock::now() + std::chrono::seconds(10);
			ULONG last_lost = 0;
			bool consumer_dead_logged = false;

			for (;;)
			{
				{
					std::unique_lock<std::mutex> lock(maintenance_mutex_);
					maintenance_cv_.wait_for(lock, std::chrono::milliseconds(250), [this] { return stopping_.load(); });
				}
				if (stopping_.load())
					break;

				prune();
				const auto now = clock::now();

				if (config_.enable_dns && now >= next_suffix_refresh)
				{
					next_suffix_refresh = now + std::chrono::seconds(30);
					refresh_suffixes();
				}
				if (config_.enable_dns && now >= next_dnscache_refresh)
				{
					next_dnscache_refresh = now + std::chrono::seconds(10);
					refresh_dnscache_pid();
				}

				if (!consumer_running_.load() && !consumer_dead_logged)
				{
					consumer_dead_logged = true;
					live_ = false;
					{
						std::lock_guard<std::mutex> lock(report_mutex_);
						report_.self_test.detail = "ETW consumer thread exited";
					}
					refresh_availability();
				}

				bool force_self_test = false;
				if (now >= next_loss_check)
				{
					next_loss_check = now + std::chrono::seconds(5);
					ULONG lost = 0, log_lost = 0, rt_lost = 0;
					query_loss(lost, log_lost, rt_lost);
					if (lost > last_lost || rt_lost > 0)
					{
						if (lost > last_lost)
						{
							log("ETW events lost: " + std::to_string(lost) + " (realtime buffers lost: " +
								std::to_string(rt_lost) + ")");
							force_self_test = true;
						}
						last_lost = lost;
					}
				}

				if (config_.self_test_interval.count() > 0 && (now >= next_self_test || force_self_test))
				{
					next_self_test = now + config_.self_test_interval;
					run_periodic_self_test();
				}
			}
		}

		// ------------------------------------------------------------------------
		// State
		// ------------------------------------------------------------------------
		etw::attributor_config config_;
		/// <summary>Effective session name (config_.session_name or prefix-pid-creation-n)</summary>
		std::wstring session_name_;
		int64_t qpc_frequency_{1};
		uint32_t own_pid_{};
		/// <summary>Creation time of this process (FILETIME), part of the default session name</summary>
		uint64_t own_creation_{};
		/// <summary>The last STOP of this object's session failed (lifecycle thread only)</summary>
		bool own_stop_failed_{false};
		/// <summary>false while start() is still running its gates: intermediate
		/// availability changes are not logged, only the final verdict is</summary>
		std::atomic<bool> gate_final_{false};

		std::mutex lifecycle_mutex_;
		mutable std::mutex report_mutex_;
		etw::gate_report report_;

		std::atomic<bool> started_{false};
		bool wsa_started_{false};
		std::atomic<bool> stopping_{false};
		std::atomic<bool> available_{false};
		std::atomic<bool> tcp_available_{false};
		std::atomic<bool> live_{false};
		std::atomic<bool> consumer_running_{false};
		std::atomic<etw::dns_tier> dns_tier_seen_{etw::dns_tier::none};

		/// <summary>Written only by the lifecycle thread under an exclusive session_mutex_;
		/// other threads read it under a shared lock (flush_now, query_loss), so stop() never
		/// races with them and they never use a stopped (possibly reused) logger id.</summary>
		mutable std::shared_mutex session_mutex_;
		TRACEHANDLE session_handle_{0};
		TRACEHANDLE consumer_handle_{invalid_processtrace_handle()};
		std::thread consumer_thread_;
		std::thread maintenance_thread_;
		std::mutex maintenance_mutex_;
		std::condition_variable maintenance_cv_;

		std::array<std::unordered_set<USHORT>, provider_count> requested_ids_;
		std::array<std::atomic<bool>, provider_count> provider_unfiltered_{};
		mutable std::mutex unrequested_mutex_;
		std::array<std::set<USHORT>, provider_count> unrequested_seen_;

		mutable std::mutex schema_mutex_;
		std::unordered_map<uint64_t, std::shared_ptr<event_schema>> schemas_;

		mutable std::shared_mutex cache_mutex_;
		std::unordered_map<etw::packet_tuple, std::vector<etw::owner_info>, etw::packet_tuple_hash> cache_;
		std::unordered_map<bind_key, bind_record, bind_key_hash> binds_;

		mutable std::mutex dns_mutex_;
		std::deque<dns_record> dns_events_;

		std::mutex image_mutex_;
		std::unordered_map<uint32_t, image_memo> image_memo_;

		mutable std::mutex clock_mutex_;
		int64_t clock_qpc_{};
		uint64_t clock_filetime_{};

		std::mutex wake_mutex_;
		std::condition_variable wake_cv_;
		std::atomic<size_t> wake_waiters_{0};
		std::atomic<uint64_t> generation_{0};
		std::atomic<size_t> waiters_{0};

		std::mutex flush_mutex_;
		clock::time_point last_flush_{};
		std::atomic<uint32_t> flush_interval_ms_{10};
		std::atomic<uint64_t> last_flush_us_{0};
		std::atomic<etw::effective_flush> effective_flush_{etw::effective_flush::none};

		std::mutex self_test_mutex_;
		std::vector<self_test_slot> self_test_slots_;
		std::atomic<uint64_t> self_test_seq_{0};
		std::atomic<int> self_test_active_{0};
		int consecutive_self_test_failures_{0};

		std::atomic<uint32_t> dnscache_pid_{0};

		mutable std::mutex suffix_mutex_;
		std::shared_ptr<const std::vector<std::wstring>> suffixes_{std::make_shared<const std::vector<std::wstring>>()};

		std::atomic<uint64_t> events_total_{0};
		std::array<std::atomic<uint64_t>, static_cast<size_t>(etw::event_source::count)> events_by_source_{};
		std::atomic<uint64_t> events_unrequested_{0};
		std::atomic<uint64_t> events_schema_rejected_{0};
		std::atomic<uint64_t> events_parse_failed_{0};
		std::atomic<uint64_t> events_own_process_{0};
		std::atomic<uint64_t> matches_{0};
		std::atomic<uint64_t> timeouts_{0};
		std::atomic<uint64_t> conflicts_{0};
		std::atomic<uint64_t> flush_calls_{0};
		std::atomic<uint64_t> flush_call_max_us_{0};
		std::atomic<uint64_t> image_lookups_{0};
		std::atomic<uint64_t> image_unverified_{0};
		std::array<std::atomic<uint64_t>, etw::latency_bucket_ms.size() + 1> latency_histogram_{};
	};
}
