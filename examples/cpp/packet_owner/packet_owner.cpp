// --------------------------------------------------------------------------------
/// <summary>
/// Module Name:  packet_owner.cpp
/// Abstract: Proof of concept: attributes outbound UDP datagrams and TCP SYNs seen by
/// the Windows Packet Filter to their owning process twice -- with the IP Helper API
/// (connection/endpoint tables, as most ndisapi based tools do) and with ETW events
/// (iphelper::etw_packet_attributor) -- and prints both side by side.
///
/// The filter never holds or modifies packets: every packet is passed unchanged and
/// the ETW answer is collected asynchronously. --hold-ms only sets the budget used to
/// classify an ETW answer as "in budget" (it would have been available had the packet
/// been held that long) or "late".
/// </summary>
// --------------------------------------------------------------------------------

#include "pch.h"

namespace
{
	using clock_type = std::chrono::steady_clock;
	using iphelper::etw::packet_tuple;

	// ----------------------------------------------------------------------------
	// Options
	// ----------------------------------------------------------------------------
	struct options
	{
		std::string adapter;
		bool udp = true;
		bool tcp = true;
		bool dns = false;
		iphelper::etw::flush_mode flush = iphelper::etw::flush_mode::automatic;
		int hold_ms = 75;
		int late_ms = 2000;
		std::string csv_path;
		bool udp_all = false;
		bool tcp_existing = false;
		bool quiet = false;
		int stats_sec = 0;
		bool no_etw = false;
		bool gates_only = false;
		/// <summary>true: start even if the adapter already has a non-zero filter mode
		/// (another process is filtering it)</summary>
		bool force_adapter = false;
		/// <summary>false: never refresh the IP Helper tables on a cache miss (diagnostic;
		/// the IP Helper column then shows only what the cached tables knew)</summary>
		bool iph_refresh = true;
		/// <summary>Minimum interval between two IP Helper table refreshes of one kind</summary>
		int iph_refresh_ms = 25;
	};

	void print_usage()
	{
		std::cout <<
			"packet_owner - who owns this packet? IP Helper vs ETW, side by side\n\n"
			"Usage: packet_owner [options]\n"
			"  --adapter <index|name>   adapter to filter (1-based index as listed, or friendly name);\n"
			"                           without it the adapters are listed and you are asked\n"
			"  --force-adapter          start even if another process is already filtering the\n"
			"                           adapter (unsupported: see README)\n"
			"  --udp                    attribute outbound UDP only\n"
			"  --tcp                    attribute outbound TCP SYNs only (default: both)\n"
			"  --dns                    resolve the callers of DNS queries sent by the DNS Client\n"
			"                           service (Dnscache) via Microsoft-Windows-DNS-Client events\n"
			"  --flush auto|ondemand|timer\n"
			"                           ETW delivery strategy (default auto; see README)\n"
			"  --hold-ms N              latency budget for 'in budget' (default 75)\n"
			"  --late-ms N              give up waiting for an ETW owner after N ms (default 2000)\n"
			"  --csv <file>             write one row per attributed packet\n"
			"  --udp-all                report every UDP datagram (default: one per 5-tuple per 5 s;\n"
			"                           with --dns every DNS query datagram is reported anyway)\n"
			"  --tcp-existing           also report the first packet of TCP flows whose SYN was\n"
			"                           not seen (matched against connection/rundown events)\n"
			"  --stats-sec N            print statistics every N seconds\n"
			"  --quiet                  no per-packet lines (statistics only)\n"
			"  --no-etw                 IP Helper only\n"
			"  --no-iph-refresh         diagnostic: never refresh the IP Helper tables on a miss\n"
			"  --iph-refresh-ms N       minimum interval between IP Helper table refreshes, coalesced\n"
			"                           on a background thread (default 25)\n"
			"  --gates-only             run the ETW capability gates and self-test, print the\n"
			"                           report and exit (no driver needed; exit code 0 = available)\n\n"
			"Run elevated. Press Ctrl+C to stop; the adapter mode is restored on exit.\n";
	}

	bool parse_int(const std::string& s, int& out)
	{
		const auto* first = s.data();
		const auto* last = s.data() + s.size();
		const auto [ptr, ec] = std::from_chars(first, last, out);
		return ec == std::errc() && ptr == last;
	}

	std::optional<options> parse_options(const int argc, char* argv[])
	{
		options o;
		bool udp_flag = false, tcp_flag = false;
		for (int i = 1; i < argc; ++i)
		{
			const std::string a = argv[i];
			auto value = [&](std::string& out) -> bool
			{
				if (i + 1 >= argc)
				{
					std::cerr << "missing value for " << a << "\n";
					return false;
				}
				out = argv[++i];
				return true;
			};
			std::string v;
			if (a == "--adapter")
			{
				if (!value(o.adapter))
					return std::nullopt;
			}
			else if (a == "--udp")
				udp_flag = true;
			else if (a == "--tcp")
				tcp_flag = true;
			else if (a == "--dns")
				o.dns = true;
			else if (a == "--flush")
			{
				if (!value(v))
					return std::nullopt;
				if (v == "auto")
					o.flush = iphelper::etw::flush_mode::automatic;
				else if (v == "ondemand" || v == "on-demand")
					o.flush = iphelper::etw::flush_mode::on_demand;
				else if (v == "timer")
					o.flush = iphelper::etw::flush_mode::timer;
				else
				{
					std::cerr << "--flush must be auto, ondemand or timer\n";
					return std::nullopt;
				}
			}
			else if (a == "--hold-ms" || a == "--late-ms" || a == "--stats-sec" || a == "--iph-refresh-ms")
			{
				int n = 0;
				if (!value(v) || !parse_int(v, n) || n < 0)
				{
					std::cerr << a << " needs a non-negative number\n";
					return std::nullopt;
				}
				(a == "--hold-ms"
					 ? o.hold_ms
					 : a == "--late-ms"
					 ? o.late_ms
					 : a == "--stats-sec"
					 ? o.stats_sec
					 : o.iph_refresh_ms) = n;
			}
			else if (a == "--csv")
			{
				if (!value(o.csv_path))
					return std::nullopt;
			}
			else if (a == "--udp-all")
				o.udp_all = true;
			else if (a == "--tcp-existing")
				o.tcp_existing = true;
			else if (a == "--quiet")
				o.quiet = true;
			else if (a == "--no-etw")
				o.no_etw = true;
			else if (a == "--no-iph-refresh")
				o.iph_refresh = false;
			else if (a == "--gates-only")
				o.gates_only = true;
			else if (a == "--force-adapter")
				o.force_adapter = true;
			else if (a == "-h" || a == "--help" || a == "/?")
			{
				print_usage();
				std::exit(0);
			}
			else
			{
				std::cerr << "unknown option " << a << "\n\n";
				print_usage();
				return std::nullopt;
			}
		}
		if (udp_flag || tcp_flag)
		{
			o.udp = udp_flag;
			o.tcp = tcp_flag;
		}
		if (o.dns)
			o.udp = true; // DNS queries are UDP
		if (o.late_ms < o.hold_ms)
			o.late_ms = o.hold_ms;
		return o;
	}

	// ----------------------------------------------------------------------------
	// Helpers
	// ----------------------------------------------------------------------------
	std::string to_utf8(const std::wstring& w)
	{
		if (w.empty())
			return {};
		const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr,
		                                  nullptr);
		std::string s(static_cast<size_t>(n), '\0');
		WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
		return s;
	}

	std::wstring file_name(const std::wstring& path)
	{
		const auto pos = path.find_last_of(L"\\/");
		return pos == std::wstring::npos ? path : path.substr(pos + 1);
	}

	bool is_elevated()
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

	std::string csv_escape(const std::string& s)
	{
		if (s.find_first_of(",\"\r\n") == std::string::npos)
			return s;
		std::string r = "\"";
		for (const auto c : s)
		{
			if (c == '"')
				r += "\"\"";
			else
				r += c;
		}
		return r + "\"";
	}

	std::string format_ms(const double ms)
	{
		std::ostringstream os;
		os << std::fixed << std::setprecision(ms < 10 ? 2 : 1) << ms;
		return os.str();
	}

	// ----------------------------------------------------------------------------
	// Packet parsing (Ethernet frames as delivered by the filter)
	// ----------------------------------------------------------------------------
	enum class item_kind : uint8_t
	{
		udp,          // outbound UDP datagram
		tcp_syn,      // outbound TCP SYN (connection attempt)
		tcp_existing  // first packet of a TCP flow whose SYN was not seen
	};

	struct dns_question
	{
		std::string qname;
		uint16_t qtype{};
		uint16_t id{};
	};

	struct parsed_packet
	{
		packet_tuple tuple;
		bool tcp{};
		bool syn{};
		std::optional<dns_question> dns;
	};

	std::optional<dns_question> parse_dns_query(const uint8_t* p, const size_t len)
	{
		// header: id, flags, qdcount, ancount, nscount, arcount
		if (len < 12)
			return std::nullopt;
		const auto flags = static_cast<uint16_t>((p[2] << 8) | p[3]);
		const auto qdcount = static_cast<uint16_t>((p[4] << 8) | p[5]);
		if ((flags & 0x8000) != 0 || qdcount == 0) // response, or no question
			return std::nullopt;
		dns_question q;
		q.id = static_cast<uint16_t>((p[0] << 8) | p[1]);
		size_t pos = 12;
		while (pos < len)
		{
			const uint8_t label = p[pos++];
			if (label == 0)
				break;
			if ((label & 0xC0) != 0 || pos + label > len || q.qname.size() + label > 255)
				return std::nullopt; // compression is not used in a question
			if (!q.qname.empty())
				q.qname += '.';
			q.qname.append(reinterpret_cast<const char*>(p + pos), label);
			pos += label;
		}
		if (pos + 2 > len)
			return std::nullopt;
		q.qtype = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
		return q;
	}

	std::optional<parsed_packet> parse_packet(const INTERMEDIATE_BUFFER& buffer, const options& opt)
	{
		const auto* frame = buffer.m_IBuffer;
		const size_t length = buffer.m_Length;
		if (length < sizeof(ether_header))
			return std::nullopt;
		const auto* eth = reinterpret_cast<const ether_header*>(frame);
		const uint8_t* l4 = nullptr;
		size_t l4_len = 0;
		uint8_t protocol = 0;
		parsed_packet out;

		// Skip up to two 802.1Q / 802.1ad tags (NDIS normally moves the tag out of band,
		// but a tagged frame must not be dropped from the report).
		size_t l2_len = sizeof(ether_header);
		uint16_t ether_type = ntohs(eth->h_proto);
		for (int tags = 0; tags < 2 && (ether_type == 0x8100 || ether_type == 0x88A8); ++tags)
		{
			if (length < l2_len + 4)
				return std::nullopt;
			uint16_t inner = 0;
			std::memcpy(&inner, frame + l2_len + 2, sizeof(inner));
			ether_type = ntohs(inner);
			l2_len += 4;
		}

		if (ether_type == ETH_P_IP)
		{
			if (length < l2_len + sizeof(iphdr))
				return std::nullopt;
			const auto* ip = reinterpret_cast<const iphdr*>(frame + l2_len);
			const size_t ihl = static_cast<size_t>(ip->ip_hl) * 4;
			if (ihl < 20 || length < l2_len + ihl)
				return std::nullopt;
			if ((ntohs(ip->ip_off) & 0x1FFF) != 0)
				return std::nullopt; // non-first fragment
			protocol = ip->ip_p;
			l4 = reinterpret_cast<const uint8_t*>(ip) + ihl;
			l4_len = length - l2_len - ihl;
			out.tuple.family = AF_INET;
			std::memcpy(out.tuple.local_ip.data(), &ip->ip_src, 4);
			std::memcpy(out.tuple.remote_ip.data(), &ip->ip_dst, 4);
		}
		else if (ether_type == ETH_P_IPV6)
		{
			if (length < l2_len + sizeof(ipv6hdr))
				return std::nullopt;
			const auto* ip6 = reinterpret_cast<const ipv6hdr*>(frame + l2_len);
			const auto* p = reinterpret_cast<const uint8_t*>(ip6 + 1);
			size_t remaining = length - l2_len - sizeof(ipv6hdr);
			uint8_t next = ip6->ip6_next;
			// Skip hop-by-hop (0), routing (43), destination options (60) and the fragment
			// header (44) of a first fragment; a non-first fragment has no L4 header.
			for (int i = 0; i < 8 && (next == 0 || next == 43 || next == 60 || next == 44); ++i)
			{
				if (remaining < 8)
					return std::nullopt;
				size_t ext;
				if (next == 44)
				{
					if (((static_cast<unsigned>(p[2]) << 8 | p[3]) & 0xFFF8u) != 0)
						return std::nullopt; // non-first fragment
					ext = 8;
				}
				else
					ext = (static_cast<size_t>(p[1]) + 1) * 8;
				if (remaining < ext)
					return std::nullopt;
				next = p[0];
				p += ext;
				remaining -= ext;
			}
			protocol = next;
			l4 = p;
			l4_len = remaining;
			out.tuple.family = AF_INET6;
			std::memcpy(out.tuple.local_ip.data(), &ip6->ip6_src, 16);
			std::memcpy(out.tuple.remote_ip.data(), &ip6->ip6_dst, 16);
		}
		else
			return std::nullopt;

		if (protocol == IPPROTO_UDP && opt.udp)
		{
			if (l4_len < sizeof(udphdr))
				return std::nullopt;
			const auto* udp = reinterpret_cast<const udphdr*>(l4);
			out.tuple.protocol = IPPROTO_UDP;
			out.tuple.local_port = ntohs(udp->th_sport);
			out.tuple.remote_port = ntohs(udp->th_dport);
			if (out.tuple.remote_port == 53)
				out.dns = parse_dns_query(l4 + sizeof(udphdr), l4_len - sizeof(udphdr));
			return out;
		}
		if (protocol == IPPROTO_TCP && opt.tcp)
		{
			if (l4_len < sizeof(tcphdr))
				return std::nullopt;
			const auto* tcp = reinterpret_cast<const tcphdr*>(l4);
			out.tuple.protocol = IPPROTO_TCP;
			out.tuple.local_port = ntohs(tcp->th_sport);
			out.tuple.remote_port = ntohs(tcp->th_dport);
			out.tcp = true;
			out.syn = (tcp->th_flags & (TH_SYN | TH_ACK)) == TH_SYN;
			if (!out.syn && !opt.tcp_existing)
				return std::nullopt;
			return out;
		}
		return std::nullopt;
	}

	// ----------------------------------------------------------------------------
	// IP Helper lookups (connection / endpoint tables)
	// ----------------------------------------------------------------------------
	enum class iph_state : uint8_t { hit, refreshed_hit, miss };

	const char* to_string(const iph_state s)
	{
		switch (s)
		{
		case iph_state::hit: return "hit";
		case iph_state::refreshed_hit: return "refreshed-hit";
		default: return "miss";
		}
	}

	template <typename T>
	std::shared_ptr<iphelper::network_process> iph_lookup_family(const packet_tuple& t, const T& src, const T& dst)
	{
		auto& helper = iphelper::process_lookup<T>::get_process_helper();
		if (t.protocol == IPPROTO_TCP)
			return helper.template lookup_process_for_tcp<false>(net::ip_session<T>{src, dst, t.local_port, t.remote_port});
		return helper.template lookup_process_for_udp<false>(net::ip_endpoint<T>{src, t.local_port});
	}

	std::shared_ptr<iphelper::network_process> iph_lookup(const packet_tuple& t)
	{
		if (t.family == AF_INET)
		{
			in_addr src{}, dst{};
			std::memcpy(&src, t.local_ip.data(), 4);
			std::memcpy(&dst, t.remote_ip.data(), 4);
			return iph_lookup_family(t, net::ip_address_v4(src), net::ip_address_v4(dst));
		}
		in6_addr src{}, dst{};
		std::memcpy(&src, t.local_ip.data(), 16);
		std::memcpy(&dst, t.remote_ip.data(), 16);
		return iph_lookup_family(t, net::ip_address_v6(src), net::ip_address_v6(dst));
	}

	// ----------------------------------------------------------------------------
	// IP Helper table refresh, off the packet path.
	//
	// A refresh (GetExtended*Table + GetOwnerModuleFrom*Entry per row) takes milliseconds
	// to tens of milliseconds. Done per miss on the worker it stalled the worker, and the
	// exclusive table lock it held stalled the filter callback's cached lookup: at 1000 new
	// sockets/s about 99% of rows ended with no ETW owner [M26300]. Now refreshes run on
	// one background thread, at most one per kind (IPv4/IPv6 x TCP/UDP) at a time and at
	// most one per min_interval; all misses that arrive meanwhile share the next refresh.
	// process_lookup::actualize builds the new table outside its lookup lock.
	// ----------------------------------------------------------------------------
	class iph_refresher
	{
	public:
		static constexpr size_t kinds = 4;

		explicit iph_refresher(const std::chrono::milliseconds min_interval) : min_interval_(min_interval)
		{
		}

		~iph_refresher() { stop(); }

		iph_refresher(const iph_refresher&) = delete;
		iph_refresher& operator=(const iph_refresher&) = delete;

		static size_t kind_of(const packet_tuple& t) noexcept
		{
			return (t.family == AF_INET6 ? 2u : 0u) + (t.protocol == IPPROTO_TCP ? 1u : 0u);
		}

		void start() { thread_ = std::thread(&iph_refresher::proc, this); }

		void stop()
		{
			{
				std::lock_guard<std::mutex> lock(mutex_);
				stopping_ = true;
			}
			cv_.notify_all();
			if (thread_.joinable())
				thread_.join();
		}

		/// <summary>Requests a refresh that starts after this call. Returns the refresh
		/// number to wait for with done().</summary>
		uint64_t request(const size_t kind)
		{
			uint64_t need;
			{
				std::lock_guard<std::mutex> lock(mutex_);
				need = started_[kind] + 1;
				requested_[kind] = std::max(requested_[kind], need);
				++requests_;
			}
			cv_.notify_one();
			return need;
		}

		[[nodiscard]] bool done(const size_t kind, const uint64_t need) const noexcept
		{
			return completed_[kind].load() >= need;
		}

		[[nodiscard]] uint64_t refreshes() const noexcept { return refreshes_.load(); }
		[[nodiscard]] uint64_t max_us() const noexcept { return max_us_.load(); }
		[[nodiscard]] uint64_t requests()
		{
			std::lock_guard<std::mutex> lock(mutex_);
			return requests_;
		}

	private:
		static void actualize(const size_t kind)
		{
			const bool tcp = (kind & 1u) != 0;
			if (kind < 2)
				iphelper::process_lookup<net::ip_address_v4>::get_process_helper().actualize(tcp, !tcp);
			else
				iphelper::process_lookup<net::ip_address_v6>::get_process_helper().actualize(tcp, !tcp);
		}

		void proc()
		{
			std::unique_lock<std::mutex> lock(mutex_);
			while (!stopping_)
			{
				const auto now = clock_type::now();
				std::optional<size_t> ready;
				std::optional<clock_type::time_point> next;
				for (size_t k = 0; k < kinds; ++k)
				{
					if (requested_[k] <= started_[k])
						continue;
					const auto allowed = last_start_[k] + min_interval_;
					if (last_start_[k] == clock_type::time_point{} || now >= allowed)
					{
						ready = k;
						break;
					}
					if (!next || allowed < *next)
						next = allowed;
				}
				if (!ready)
				{
					if (next)
						cv_.wait_until(lock, *next);
					else
						cv_.wait(lock);
					continue;
				}
				const auto k = *ready;
				const auto number = ++started_[k];
				last_start_[k] = now;
				lock.unlock();
				const auto t0 = clock_type::now();
				actualize(k);
				const auto us = static_cast<uint64_t>(
					std::chrono::duration_cast<std::chrono::microseconds>(clock_type::now() - t0).count());
				if (us > max_us_.load())
					max_us_ = us;
				++refreshes_;
				completed_[k] = number;
				lock.lock();
			}
		}

		const std::chrono::milliseconds min_interval_;
		std::mutex mutex_;
		std::condition_variable cv_;
		bool stopping_{false};
		std::array<uint64_t, kinds> requested_{};
		std::array<uint64_t, kinds> started_{};
		std::array<clock_type::time_point, kinds> last_start_{};
		std::array<std::atomic<uint64_t>, kinds> completed_{};
		uint64_t requests_{};
		std::atomic<uint64_t> refreshes_{0};
		std::atomic<uint64_t> max_us_{0};
		std::thread thread_;
	};

	// ----------------------------------------------------------------------------
	// Work items and statistics
	// ----------------------------------------------------------------------------
	struct work_item
	{
		int64_t qpc{};
		clock_type::time_point seen{};
		item_kind kind{item_kind::udp};
		packet_tuple tuple;
		std::optional<dns_question> dns;

		iph_state iph{iph_state::miss};
		uint32_t iph_pid{};
		std::wstring iph_path;
		/// <summary>a refresh was requested on a miss and has not completed yet</summary>
		bool iph_pending{};
		uint64_t iph_need{};

		/// <summary>ETW was available when the item was queued</summary>
		bool etw_attempted{};
		std::optional<iphelper::etw::owner_info> etw;
		/// <summary>TCP SYN: connected (1033/KN 12) or failed (1034) seen, or gave up</summary>
		bool tcp_outcome_done{};
		bool dnscache_owner{};
		iphelper::etw::dns_attribution dns_attr;
	};

	struct proto_stats
	{
		uint64_t total{};
		uint64_t iph_hit{};
		uint64_t iph_refreshed{};
		uint64_t iph_miss{};
		uint64_t etw_in_budget{};
		uint64_t etw_late{};
		uint64_t etw_none{};
		uint64_t etw_unknown_pid{};
		uint64_t etw_pid_from_outcome{}; // owner filled from 1033/1034: not in latency_ms
		uint64_t agree{};
		uint64_t disagree{};
		uint64_t etw_only{};
		uint64_t iph_only{};
		uint64_t neither{};
		uint64_t image_unverified{};
		uint64_t conflicts{};
		std::vector<double> latency_ms;
	};

	struct dns_stats
	{
		uint64_t dnscache_queries{};
		uint64_t tier1{};
		uint64_t tier2{};
		uint64_t none{};
		uint64_t multi_caller{};
		uint64_t suffix{};
		uint64_t wire_confirmed{};
	};

	std::string percent(const uint64_t part, const uint64_t total)
	{
		if (total == 0)
			return "-";
		std::ostringstream os;
		os << std::fixed << std::setprecision(1) << 100.0 * static_cast<double>(part) / static_cast<double>(total) <<
			"%";
		return os.str();
	}

	std::string latency_summary(std::vector<double> v)
	{
		if (v.empty())
			return "n/a";
		std::sort(v.begin(), v.end());
		auto at = [&](const double q)
		{
			return v[std::min(v.size() - 1, static_cast<size_t>(q * static_cast<double>(v.size() - 1) + 0.5))];
		};
		return "median " + format_ms(at(0.5)) + " ms, p95 " + format_ms(at(0.95)) + " ms, max " +
			format_ms(v.back()) + " ms (n=" + std::to_string(v.size()) + ")";
	}

	// ----------------------------------------------------------------------------
	// Engine: queue filled by the filter thread, resolved by one worker thread
	// ----------------------------------------------------------------------------
	class engine
	{
	public:
		engine(const options& opt, iphelper::etw_packet_attributor& attributor, std::mutex& output_mutex)
			: opt_(opt), attributor_(attributor), output_mutex_(output_mutex),
			  refresher_(std::chrono::milliseconds(opt.iph_refresh_ms))
		{
			LARGE_INTEGER f;
			QueryPerformanceFrequency(&f);
			qpc_frequency_ = f.QuadPart;
			start_qpc_ = iphelper::etw_packet_attributor::qpc_now();
			if (!opt_.csv_path.empty())
			{
				csv_.open(opt_.csv_path, std::ios::out | std::ios::trunc);
				if (csv_)
					csv_ << "time_s,proto,kind,local,remote,iph_state,iph_pid,iph_image,etw_state,etw_pid,etw_image,"
						"etw_image_verified,etw_source,etw_event,etw_version,etw_latency_ms,etw_event_offset_ms,etw_sources,"
						"etw_conflict,"
						"verdict,dns_qname,dns_qtype,dns_tier,dns_callers,dns_wire_confirmed,"
						"etw_pid_from_header,tcp_outcome,tcp_connect_status,etw_overridden_header_pid,etw_pid_from_outcome\n";
				else
					std::cerr << "cannot open " << opt_.csv_path << "\n";
			}
		}

		void start()
		{
			if (opt_.iph_refresh)
				refresher_.start();
			worker_ = std::thread(&engine::worker_proc, this);
		}

		void stop()
		{
			{
				std::lock_guard<std::mutex> lock(queue_mutex_);
				stopping_ = true;
			}
			queue_cv_.notify_all();
			if (worker_.joinable())
				worker_.join();
			refresher_.stop();
		}

		/// <summary>Called on the filter thread: must not block</summary>
		void on_outbound(const INTERMEDIATE_BUFFER& buffer)
		{
			const auto qpc = iphelper::etw_packet_attributor::qpc_now(); // first: the packet read time
			auto parsed = parse_packet(buffer, opt_);
			if (!parsed)
				return;

			work_item item;
			item.qpc = qpc;
			item.seen = clock_type::now();
			item.tuple = parsed->tuple;
			item.dns = std::move(parsed->dns);
			item.kind = !parsed->tcp ? item_kind::udp : parsed->syn ? item_kind::tcp_syn : item_kind::tcp_existing;

			// Cached-table IP Helper lookup at packet time (what an inline filter can do
			// without a table refresh). Refresh-and-retry happens on the worker.
			if (const auto p = iph_lookup(item.tuple); p)
			{
				item.iph = iph_state::hit;
				item.iph_pid = p->id;
				item.iph_path = p->path_name.empty() ? p->name : p->path_name;
			}

			{
				std::lock_guard<std::mutex> lock(queue_mutex_);
				if (queue_.size() >= 200000)
				{
					++queue_dropped_;
					return;
				}
				queue_.push_back(std::move(item));
			}
			queue_cv_.notify_one();
		}

		void print_stats(const bool final_stats)
		{
			// Copy under the lock, sort and format outside it: latency_summary() sorts up to
			// 2M samples per block, which must not block finalize() on the worker.
			proto_stats udp, tcp_syn, tcp_existing;
			dns_stats dns;
			{
				std::lock_guard<std::mutex> stats_lock(stats_mutex_);
				udp = udp_;
				tcp_syn = tcp_syn_;
				tcp_existing = tcp_existing_;
				dns = dns_;
			}
			std::ostringstream os;
			os << "\n==== " << (final_stats ? "final statistics" : "statistics") << " (hold budget " << opt_.hold_ms
				<< " ms, late limit " << opt_.late_ms << " ms) ====\n";
			auto block = [&](const char* name, const proto_stats& s)
			{
				if (s.total == 0)
					return;
				os << name << ": " << s.total << " reported\n"
					<< "  IP Helper: hit " << s.iph_hit << " (" << percent(s.iph_hit, s.total) << "), refreshed hit "
					<< s.iph_refreshed << " (" << percent(s.iph_refreshed, s.total) << "), miss " << s.iph_miss << " ("
					<< percent(s.iph_miss, s.total) << ")\n";
				if (!etw_enabled_)
					return;
				os << "  ETW: in budget " << s.etw_in_budget << " (" << percent(s.etw_in_budget, s.total) << "), late "
					<< s.etw_late << " (" << percent(s.etw_late, s.total) << "), none " << s.etw_none << " ("
					<< percent(s.etw_none, s.total) << "), event without PID " << s.etw_unknown_pid
					<< ", owner from outcome " << s.etw_pid_from_outcome << " (not in latency)"
					<< "; image unverified " << s.image_unverified << ", conflicts " << s.conflicts << "\n"
					<< "  ETW delivery latency: " << latency_summary(s.latency_ms) << "\n"
					<< "  verdict: agree " << s.agree << ", disagree " << s.disagree << ", ETW only " << s.etw_only
					<< ", IP Helper only " << s.iph_only << ", neither " << s.neither << "\n";
			};
			block("UDP", udp);
			block("TCP SYN", tcp_syn);
			block("TCP existing", tcp_existing);
			if (opt_.dns && dns.dnscache_queries)
			{
				os << "DNS (queries sent by Dnscache): " << dns.dnscache_queries << ", tier1 (ClientPID) " << dns.tier1
					<< ", tier2 (3006 header PID) " << dns.tier2 << ", no caller " << dns.none << ", several callers "
					<< dns.multi_caller << ", via search suffix " << dns.suffix << ", wire-confirmed "
					<< dns.wire_confirmed << "\n";
			}
			if (etw_enabled_)
			{
				const auto c = attributor_.get_counters();
				os << "ETW counters: events " << c.events_total << ", unrequested " << c.events_unrequested
					<< ", schema-rejected " << c.events_schema_rejected << ", parse-failed " << c.events_parse_failed
					<< ", own-process " << c.events_own_process << "\n"
					<< "  lookups " << c.lookups << " (matched " << c.matches << ", timed out " << c.timeouts << ")\n"
					<< "  per source:";
				for (size_t i = 1; i < c.events_by_source.size(); ++i)
				{
					if (c.events_by_source[i])
						os << " " << iphelper::etw::to_string(static_cast<iphelper::etw::event_source>(i)) << "="
							<< c.events_by_source[i];
				}
				os << "\n  flush calls " << c.flush_calls << " (max " << c.flush_call_max_us << " us, interval "
					<< c.flush_interval_ms << " ms), cache " << c.cache_entries << ", dns records " << c.dns_entries
					<< ", image lookups " << c.image_lookups << " (unverified " << c.image_unverified << ")\n"
					<< "  EventsLost " << c.events_lost << ", RealTimeBuffersLost " << c.realtime_buffers_lost
					<< ", LogBuffersLost " << c.log_buffers_lost << "\n  latency histogram (ms):";
				for (size_t i = 0; i < c.latency_histogram.size(); ++i)
				{
					if (!c.latency_histogram[i])
						continue;
					if (i < iphelper::etw::latency_bucket_ms.size())
						os << " <=" << iphelper::etw::latency_bucket_ms[i] << ":" << c.latency_histogram[i];
					else
						os << " >1000:" << c.latency_histogram[i];
				}
				os << "\n";
			}
			if (opt_.iph_refresh)
				os << "IP Helper refreshes " << refresher_.refreshes() << " for " << refresher_.requests()
					<< " misses (max " << refresher_.max_us() << " us, min interval " << opt_.iph_refresh_ms << " ms)\n";
			else
				os << "IP Helper refresh off (--no-iph-refresh)\n";
			os << "queue dropped " << queue_dropped_.load() << ", UDP duplicates suppressed " << udp_suppressed_.load() << "\n";
			std::lock_guard<std::mutex> lock(output_mutex_);
			std::cout << os.str() << std::flush;
		}

		void set_etw_enabled(const bool enabled) { etw_enabled_ = enabled; }

	private:
		double qpc_ms(const int64_t delta) const
		{
			return static_cast<double>(delta) * 1000.0 / static_cast<double>(qpc_frequency_);
		}

		bool is_duplicate(const work_item& item)
		{
			if (item.kind != item_kind::udp || opt_.udp_all)
				return false;
			// Dnscache sends every query from one socket: per-5-tuple suppression would hide
			// all queries but the first [M26300]. With --dns every DNS query gets a row.
			if (opt_.dns && item.dns)
				return false;
			const auto now = item.seen;
			auto& last = recent_udp_[item.tuple];
			if (last != clock_type::time_point{} && now - last < std::chrono::seconds(5))
			{
				++udp_suppressed_;
				return true;
			}
			last = now;
			if (recent_udp_.size() > 100000)
			{
				for (auto it = recent_udp_.begin(); it != recent_udp_.end();)
					it = now - it->second > std::chrono::seconds(5) ? recent_udp_.erase(it) : std::next(it);
			}
			return false;
		}

		bool is_seen_flow(const work_item& item)
		{
			// SYN registers the flow; later packets of a registered flow are not reported again
			if (item.kind == item_kind::udp)
				return false;
			const auto now = item.seen;
			if (tcp_flows_.size() > 200000)
			{
				for (auto it = tcp_flows_.begin(); it != tcp_flows_.end();)
					it = now - it->second > std::chrono::minutes(10) ? tcp_flows_.erase(it) : std::next(it);
			}
			auto [it, inserted] = tcp_flows_.try_emplace(item.tuple, now);
			const bool seen = !inserted;
			it->second = now;
			if (item.kind == item_kind::tcp_syn)
				return false; // every SYN (including retransmissions) is reported
			return seen;
		}

		/// <summary>On a miss, asks the background refresher for a table refresh that
		/// starts after now; the lookup is retried in resolve_iph() when it completed.</summary>
		void request_iph_refresh(work_item& item)
		{
			if (item.iph != iph_state::miss || !opt_.iph_refresh)
				return;
			item.iph_need = refresher_.request(iph_refresher::kind_of(item.tuple));
			item.iph_pending = true;
		}

		/// <summary>true when the IP Helper side of the item is final</summary>
		bool resolve_iph(work_item& item, const bool expired)
		{
			if (!item.iph_pending)
				return true;
			if (refresher_.done(iph_refresher::kind_of(item.tuple), item.iph_need))
			{
				item.iph_pending = false;
				if (const auto p = iph_lookup(item.tuple); p)
				{
					item.iph = iph_state::refreshed_hit;
					item.iph_pid = p->id;
					item.iph_path = p->path_name.empty() ? p->name : p->path_name;
				}
				return true;
			}
			if (expired)
				item.iph_pending = false; // the refresh did not finish in time: stays a miss
			return !item.iph_pending;
		}

		bool needs_dns(const work_item& item)
		{
			if (!opt_.dns || !item.dns)
				return false;
			const auto dnscache = attributor_.dnscache_pid();
			const uint32_t owner = item.etw ? item.etw->pid : item.iph_pid;
			return dnscache != 0 && owner == dnscache;
		}

		/// <summary>true when the item is complete</summary>
		bool try_resolve(work_item& item, const clock_type::time_point now)
		{
			const bool expired = now - item.seen >= std::chrono::milliseconds(opt_.late_ms);
			const bool iph_done = resolve_iph(item, expired);
			if (!item.etw_attempted)
			{
				if (!iph_done)
					return false;
				if (opt_.dns && item.dns && attributor_.dnscache_pid() == item.iph_pid)
					item.dnscache_owner = true;
				return true;
			}

			if (!item.etw)
			{
				const auto kind = item.kind == item_kind::tcp_existing
					                  ? iphelper::etw::match_kind::connection
					                  : iphelper::etw::match_kind::datagram;
				// A record without a PID (e.g. 1031 whose header PID is 4) is taken only on
				// the last attempt: until then a later 1033 / KN 12 may still name the owner.
				item.etw = attributor_.lookup(item.tuple, item.qpc, kind, expired);
			}
			if (!item.etw)
			{
				if (expired)
					attributor_.record_timeout();
				return expired && iph_done;
			}
			if (item.kind == item_kind::tcp_syn && !item.tcp_outcome_done)
			{
				// Keep the SYN until 1033/KN 12 (connected) or 1034 (failed, with its status)
				// is seen, so the row can show the outcome even though 1031 decided the owner.
				// The owner and its latency stay those of the first match, unless a 1033/1034
				// of the same connect attempt overrides the header PID or fills a missing PID.
				item.tcp_outcome_done = attributor_.tcp_outcome(item.tuple, item.qpc, *item.etw) || expired;
				if (!item.tcp_outcome_done)
					return false;
			}
			if (needs_dns(item))
			{
				item.dnscache_owner = true;
				item.dns_attr = attributor_.dns_lookup(item.dns->qname, item.dns->qtype, item.qpc);
				return (!item.dns_attr.callers.empty() || expired) && iph_done;
			}
			return iph_done;
		}

		void worker_proc()
		{
			std::vector<work_item> pending;
			for (;;)
			{
				std::deque<work_item> batch;
				{
					std::unique_lock<std::mutex> lock(queue_mutex_);
					if (pending.empty())
						queue_cv_.wait_for(lock, std::chrono::milliseconds(100),
						                   [this] { return stopping_ || !queue_.empty(); });
					batch.swap(queue_);
					if (stopping_ && batch.empty())
						break;
				}

				const auto intake = clock_type::now();
				for (auto& item : batch)
				{
					if (is_duplicate(item) || is_seen_flow(item))
						continue;
					request_iph_refresh(item);
					// TCP owners are not served when the TCP gate failed: do not hold TCP rows
					// waiting for them.
					item.etw_attempted = etw_enabled_ && attributor_.available() &&
						(item.tuple.protocol != IPPROTO_TCP || attributor_.tcp_available());
					if (try_resolve(item, intake))
						finalize(item);
					else
						pending.push_back(std::move(item));
				}

				if (pending.empty())
					continue;

				const auto generation = attributor_.generation();
				const auto now = clock_type::now();
				size_t waiting_for_owner = 0;
				// Compact in place (order kept): erasing from the middle of a vector of
				// ~2000 items per pass was quadratic.
				size_t kept = 0;
				for (size_t i = 0; i < pending.size(); ++i)
				{
					auto& item = pending[i];
					if (try_resolve(item, now))
					{
						finalize(item);
						continue;
					}
					if (item.etw_attempted && !item.etw)
						++waiting_for_owner;
					if (kept != i)
						pending[kept] = std::move(item);
					++kept;
				}
				pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(kept), pending.end());
				if (waiting_for_owner != 0)
				{
					// Only items still waiting for their owner drive on-demand flushes; items
					// waiting for a TCP outcome or an IP Helper refresh do not.
					attributor_.request_flush(waiting_for_owner);
					attributor_.wait_for_events(generation, clock_type::now() + std::chrono::milliseconds(5));
				}
				else if (!pending.empty())
				{
					std::unique_lock<std::mutex> lock(queue_mutex_);
					queue_cv_.wait_for(lock, std::chrono::milliseconds(5), [this] { return stopping_ || !queue_.empty(); });
				}
			}
			for (auto& item : pending)
				finalize(item);
		}

		void finalize(work_item& item)
		{
			using namespace iphelper::etw;
			const bool etw_attempted = item.etw_attempted;
			const char* proto = item.tuple.protocol == IPPROTO_TCP ? "TCP" : "UDP";
			const char* kind = item.kind == item_kind::udp
				                   ? "datagram"
				                   : item.kind == item_kind::tcp_syn
				                   ? "syn"
				                   : "existing";

			std::string etw_state = "off";
			double latency = -1;
			double event_offset = 0; // event timestamp minus packet read time (negative: written before)
			if (etw_attempted)
			{
				if (item.etw && item.etw->is_unknown())
				{
					// An event matched but named no PID: not an owner (and not "Idle")
					latency = std::max(0.0, qpc_ms(item.etw->received_qpc - item.qpc));
					event_offset = qpc_ms(item.etw->event_qpc - item.qpc);
					etw_state = "no-pid";
				}
				else if (item.etw)
				{
					latency = std::max(0.0, qpc_ms(item.etw->received_qpc - item.qpc));
					event_offset = qpc_ms(item.etw->event_qpc - item.qpc);
					etw_state = latency <= opt_.hold_ms ? "in-budget" : "late";
				}
				else
					etw_state = "none";
			}

			const bool iph_found = item.iph != iph_state::miss;
			const bool etw_found = item.etw.has_value() && !item.etw->is_unknown();
			const bool etw_event = item.etw.has_value();
			std::string tcp_outcome;
			if (item.kind == item_kind::tcp_syn && etw_event)
				tcp_outcome = item.etw->connect_failed
					              ? "failed"
					              : item.etw->connect_completed
					              ? "connected"
					              : "unknown";
			std::string verdict;
			if (!etw_attempted)
				verdict = iph_found ? "iph" : "neither";
			else if (iph_found && etw_found)
				verdict = item.iph_pid == item.etw->pid ? "agree" : "DISAGREE";
			else if (etw_found)
				verdict = "etw-only";
			else if (iph_found)
				verdict = "iph-only";
			else
				verdict = "neither";

			std::string dns_callers;
			for (const auto& c : item.dns_attr.callers)
			{
				if (!dns_callers.empty())
					dns_callers += ";";
				dns_callers += to_utf8(c.image_name().empty() ? L"?" : c.image_name()) + "(" + std::to_string(c.pid) +
					")";
			}

			{
				std::lock_guard<std::mutex> lock(stats_mutex_);
				auto& s = item.kind == item_kind::udp
					          ? udp_
					          : item.kind == item_kind::tcp_syn
					          ? tcp_syn_
					          : tcp_existing_;
				++s.total;
				if (item.iph == iph_state::hit)
					++s.iph_hit;
				else if (item.iph == iph_state::refreshed_hit)
					++s.iph_refreshed;
				else
					++s.iph_miss;
				if (etw_attempted)
				{
					if (etw_state == "in-budget")
						++s.etw_in_budget;
					else if (etw_state == "late")
						++s.etw_late;
					else if (etw_state == "no-pid")
						++s.etw_unknown_pid;
					else
						++s.etw_none;
					// An owner filled from 1033/1034 (pid_from_outcome) is delivered about one RTT
					// after the SYN: its latency measures the connect, not ETW delivery.
					if (etw_found && item.etw->pid_from_outcome)
						++s.etw_pid_from_outcome;
					else if (etw_found && latency >= 0 && s.latency_ms.size() < 2000000)
						s.latency_ms.push_back(latency);
					if (etw_found && !item.etw->image_verified)
						++s.image_unverified;
					if (etw_event && item.etw->conflict)
						++s.conflicts;
					if (verdict == "agree")
						++s.agree;
					else if (verdict == "DISAGREE")
						++s.disagree;
					else if (verdict == "etw-only")
						++s.etw_only;
					else if (verdict == "iph-only")
						++s.iph_only;
					else
						++s.neither;
				}
				if (item.dnscache_owner)
				{
					++dns_.dnscache_queries;
					if (item.dns_attr.tier == dns_tier::client_pid)
						++dns_.tier1;
					else if (item.dns_attr.tier == dns_tier::header_pid)
						++dns_.tier2;
					else
						++dns_.none;
					if (item.dns_attr.callers.size() > 1)
						++dns_.multi_caller;
					if (item.dns_attr.suffix_match)
						++dns_.suffix;
					if (item.dns_attr.wire_confirmed)
						++dns_.wire_confirmed;
				}
			}

			const double t = qpc_ms(item.qpc - start_qpc_) / 1000.0;
			const std::string iph_image = iph_found ? to_utf8(file_name(item.iph_path)) : "";
			const std::string etw_image = etw_found ? to_utf8(item.etw->image_name()) : "";

			if (!opt_.quiet)
			{
				std::ostringstream os;
				os << "+" << std::fixed << std::setprecision(3) << t << "s " << proto << " "
					<< (item.kind == item_kind::tcp_syn ? "SYN " : item.kind == item_kind::tcp_existing ? "EST " : "")
					<< item.tuple.local_to_string() << " -> " << item.tuple.remote_to_string()
					<< " | IPH " << (iph_found ? (iph_image.empty() ? "?" : iph_image) + "(" +
						                 std::to_string(item.iph_pid) + ")" : "-") << " " << to_string(item.iph);
				if (etw_attempted)
				{
					os << " | ETW ";
					if (etw_event)
					{
						if (etw_found)
							os << (etw_image.empty() ? "?" : etw_image) << "(" << item.etw->pid << ")"
								<< (item.etw->pid_from_header ? "[header-pid]" : "")
								<< (item.etw->header_pid_overridden
									    ? "[header-pid " + std::to_string(item.etw->overridden_header_pid) +
									    " overridden by 1033/1034]"
									    : "")
								<< (item.etw->pid_from_outcome ? "[pid-from-outcome]" : "")
								<< (item.etw->image_verified ? "" : "[unverified]");
						else
							os << "no PID";
						os << " " << item.etw->event_id << "v"
							<< static_cast<unsigned>(item.etw->event_version) << " +" << format_ms(latency) << "ms "
							<< etw_state << " (event " << (event_offset < 0 ? "-" : "+")
							<< format_ms(std::abs(event_offset)) << "ms)";
						if (item.etw->conflict)
							os << " CONFLICT{" << sources_to_string(item.etw->sources_seen) << "}";
						if (item.etw->connect_failed)
							os << " (connect failed, 1034 status 0x" << std::hex << item.etw->connect_status << std::dec
								<< ")";
						else if (item.kind == item_kind::tcp_syn)
							os << " (" << tcp_outcome << ")";
					}
					else
						os << "- none after " << opt_.late_ms << "ms";
				}
				os << " | " << verdict;
				if (item.dns)
				{
					os << " | DNS " << item.dns->qname << " type " << item.dns->qtype;
					if (item.dnscache_owner)
					{
						os << " via Dnscache: " << iphelper::etw::to_string(item.dns_attr.tier);
						if (!dns_callers.empty())
							os << " callers " << dns_callers;
						if (item.dns_attr.suffix_match)
							os << " (search suffix)";
						if (item.dns_attr.wire_confirmed)
							os << " (wire-confirmed)";
					}
				}
				std::lock_guard<std::mutex> lock(output_mutex_);
				std::cout << os.str() << "\n";
			}

			if (csv_)
			{
				std::lock_guard<std::mutex> lock(csv_mutex_);
				csv_ << std::fixed << std::setprecision(3) << t << "," << proto << "," << kind << ","
					<< item.tuple.local_to_string() << "," << item.tuple.remote_to_string() << ","
					<< to_string(item.iph) << "," << (iph_found ? std::to_string(item.iph_pid) : "") << ","
					<< csv_escape(iph_image) << "," << etw_state << ","
					<< (etw_found ? std::to_string(item.etw->pid) : "") << "," << csv_escape(etw_image) << ","
					<< (etw_found ? (item.etw->image_verified ? "1" : "0") : "") << ","
					<< (etw_event ? to_string(item.etw->source) : "") << ","
					<< (etw_event ? std::to_string(item.etw->event_id) : "") << ","
					<< (etw_event ? std::to_string(item.etw->event_version) : "") << ","
					<< (latency >= 0 ? format_ms(latency) : "") << ","
					<< (etw_event ? std::to_string(event_offset) : "") << ","
					<< (etw_event ? csv_escape(sources_to_string(item.etw->sources_seen)) : "") << ","
					<< (etw_event && item.etw->conflict ? "1" : "0") << "," << verdict << ","
					<< csv_escape(item.dns ? item.dns->qname : "") << ","
					<< (item.dns ? std::to_string(item.dns->qtype) : "") << ","
					<< (item.dnscache_owner ? iphelper::etw::to_string(item.dns_attr.tier) : "") << ","
					<< csv_escape(dns_callers) << ","
					<< (item.dnscache_owner ? (item.dns_attr.wire_confirmed ? "1" : "0") : "") << ","
					<< (etw_found ? (item.etw->pid_from_header ? "1" : "0") : "") << "," << tcp_outcome << ",";
				if (etw_event && item.etw->connect_failed)
				{
					char hex[16];
					std::snprintf(hex, sizeof(hex), "0x%08X", static_cast<unsigned>(item.etw->connect_status));
					csv_ << hex;
				}
				csv_ << ",";
				if (etw_event && item.etw->header_pid_overridden)
					csv_ << item.etw->overridden_header_pid;
				csv_ << "," << (etw_found ? (item.etw->pid_from_outcome ? "1" : "0") : "") << "\n";
			}
		}

		const options& opt_;
		iphelper::etw_packet_attributor& attributor_;
		std::mutex& output_mutex_;
		bool etw_enabled_{false};
		int64_t qpc_frequency_{1};
		int64_t start_qpc_{};

		std::mutex queue_mutex_;
		std::condition_variable queue_cv_;
		std::deque<work_item> queue_;
		bool stopping_{false};
		std::atomic<uint64_t> queue_dropped_{0};
		iph_refresher refresher_;
		std::thread worker_;

		// worker-thread only
		std::unordered_map<packet_tuple, clock_type::time_point, iphelper::etw::packet_tuple_hash> recent_udp_;
		std::unordered_map<packet_tuple, clock_type::time_point, iphelper::etw::packet_tuple_hash> tcp_flows_;

		std::mutex stats_mutex_;
		proto_stats udp_;
		proto_stats tcp_syn_;
		proto_stats tcp_existing_;
		dns_stats dns_;
		/// <summary>Written by the worker, read by print_stats on the main thread</summary>
		std::atomic<uint64_t> udp_suppressed_{0};

		std::mutex csv_mutex_;
		std::ofstream csv_;
	};

	// ----------------------------------------------------------------------------
	// Ctrl+C handling
	// ----------------------------------------------------------------------------
	HANDLE g_stop_event = nullptr;
	HANDLE g_cleanup_done_event = nullptr;
	/// <summary>Set by the console handler; cuts the ETW gates short (attributor_config::cancel_start)</summary>
	std::atomic<bool> g_stop_requested{false};

	BOOL WINAPI console_ctrl_handler(const DWORD type)
	{
		switch (type)
		{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
			g_stop_requested = true;
			SetEvent(g_stop_event);
			return TRUE;
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			// The process is terminated when the handler returns, and Windows allows about
			// 5 s for CTRL_CLOSE_EVENT: let main restore the adapter mode (first) and stop
			// the ETW session within 4 s. During the gates, g_stop_requested cuts the
			// probes short (about 1.5 s left at most). If the time still runs out, only the
			// ETW session can be left behind; the next start stops it.
			g_stop_requested = true;
			SetEvent(g_stop_event);
			WaitForSingleObject(g_cleanup_done_event, 4000);
			return TRUE;
		default:
			return FALSE;
		}
	}

	std::optional<size_t> select_adapter(const std::vector<std::string>& names, const std::string& wanted)
	{
		if (names.empty())
			return std::nullopt;
		if (!wanted.empty())
		{
			int index = 0;
			if (parse_int(wanted, index))
			{
				if (index >= 1 && static_cast<size_t>(index) <= names.size())
					return static_cast<size_t>(index - 1);
				return std::nullopt;
			}
			auto lower = [](std::string s)
			{
				std::transform(s.begin(), s.end(), s.begin(),
				               [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
				return s;
			};
			const auto w = lower(wanted);
			std::optional<size_t> partial;
			size_t partial_count = 0;
			for (size_t i = 0; i < names.size(); ++i)
			{
				const auto n = lower(names[i]);
				if (n == w)
					return i;
				if (n.find(w) != std::string::npos)
				{
					partial = i;
					++partial_count;
				}
			}
			if (partial_count == 1)
				return partial;
			if (partial_count > 1)
				std::cerr << "adapter name '" << wanted << "' is ambiguous\n";
			return std::nullopt;
		}

		std::cout << "\nSelect interface to filter: ";
		size_t index = 0;
		if (!(std::cin >> index) || index < 1 || index > names.size())
			return std::nullopt;
		return index - 1;
	}
}

int main(int argc, char* argv[])
{
	SetConsoleOutputCP(CP_UTF8);

	const auto parsed = parse_options(argc, argv);
	if (!parsed)
		return 2;
	const options opt = *parsed;

	if (!is_elevated())
	{
		std::cerr << "packet_owner must run elevated (Run as administrator): both the Windows Packet Filter\n"
			"driver and the ETW real-time session with kernel providers require it.\n";
		return 1;
	}

	WSADATA wsa{};
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		std::cerr << "WSAStartup failed\n";
		return 1;
	}

	g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	g_cleanup_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	// Declared before the attributor and the filter, so it signals the console handler only
	// after both are destroyed (ETW session stopped, adapter mode reset) on every return path.
	struct cleanup_done_signal
	{
		~cleanup_done_signal() { SetEvent(g_cleanup_done_event); }
	} cleanup_done;

	std::mutex output_mutex;

	iphelper::etw::attributor_config config;
	config.enable_tcp = opt.tcp;
	config.enable_dns = opt.dns;
	config.flush = opt.flush;
	config.cancel_start = &g_stop_requested;
	config.log = [&output_mutex](const std::string& message)
	{
		std::lock_guard<std::mutex> lock(output_mutex);
		std::cerr << "[etw] " << message << "\n";
	};
	iphelper::etw_packet_attributor attributor(config);

	if (opt.gates_only)
	{
		// Ctrl+C during the gates must not kill the process with the ETW session running.
		SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
		const bool ok = attributor.start();
		std::cout << attributor.report().to_string() << "\n";
		attributor.stop();
		WSACleanup();
		return ok ? 0 : 3;
	}

	engine eng(opt, attributor, output_mutex);

	auto filter = std::make_unique<ndisapi::simple_packet_filter>(
		nullptr,
		[&eng](HANDLE, INTERMEDIATE_BUFFER& buffer)
		{
			eng.on_outbound(buffer);
			return ndisapi::simple_packet_filter::packet_action::pass;
		});

	if (!filter->IsDriverLoaded())
	{
		std::cerr << "Windows Packet Filter driver is not loaded\n";
		WSACleanup();
		return 1;
	}

	const auto names = filter->get_interface_names_list();
	std::cout << "Available network interfaces:\n\n";
	for (size_t i = 0; i < names.size(); ++i)
		std::cout << (i + 1) << ")\t" << names[i] << "\n";

	const auto adapter = select_adapter(names, opt.adapter);
	if (!adapter)
	{
		std::cerr << "No valid adapter selected\n";
		WSACleanup();
		return 1;
	}

	// The driver is designed for one filtering process at a time: a non-zero adapter mode
	// means another process already filters this adapter. Starting anyway is unsupported:
	// on exit the adapter mode is reset to 0, which stops the other process's filtering too.
	// The driver resets the mode when its owning process exits or crashes, so a non-zero
	// mode is a live filter. This is a check, not a lock: a filter that starts between it
	// and start_filter() is not detected (the driver has no exclusive-open call for this).
	ADAPTER_MODE current_mode{filter->get_interface_list()[*adapter]->get_adapter(), 0};
	if (!filter->GetAdapterMode(&current_mode))
		std::cerr << "Warning: could not query the current filter mode of the selected adapter\n";
	else if (current_mode.dwFlags != 0)
	{
		std::cerr << (opt.force_adapter ? "Warning: " : "Error: ") << "adapter '" << names[*adapter]
			<< "' is already being filtered by another process (filter mode 0x" << std::hex
			<< current_mode.dwFlags << std::dec << ").\n"
			"The Windows Packet Filter driver is designed to be used by a single filtering process at a\n"
			"time; a second instance would also reset the first instance's adapter mode on exit.\n";
		if (!opt.force_adapter)
		{
			std::cerr << "Stop the other filtering process, or pass --force-adapter to start anyway.\n";
			WSACleanup();
			return 1;
		}
		std::cerr << "--force-adapter given: starting anyway (unsupported).\n";
	}

	std::cout << "\nFiltering: " << names[*adapter] << "\n\n";

	// From here on Ctrl+C only signals g_stop_event: the gates below take a few seconds and
	// a default Ctrl+C would leave the ETW session running until the next start. (Not
	// earlier: the interactive adapter prompt should stay interruptible.)
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

	bool etw_ok = false;
	if (opt.no_etw)
		std::cout << "ETW attribution disabled (--no-etw): IP Helper only\n";
	else
	{
		std::cout << "Starting ETW session and running the capability gates...\n";
		etw_ok = attributor.start();
		std::cout << attributor.report().to_string() << "\n";
		if (!etw_ok && g_stop_requested.load())
		{
			// Ctrl+C or console close during the gates: not a capability verdict (the
			// "Stopped during start-up" line follows below).
		}
		else if (!etw_ok)
		{
			std::cout << "\nETW attribution is NOT available on this system (" << attributor.report().failure
				<< ").\nContinuing with IP Helper only.\n";
		}
		else if (opt.tcp && attributor.report().self_test.tcp_attempted && !attributor.report().self_test.tcp_ok)
			std::cout << "\nNote: the loopback TCP self-test failed (see tcp= and tcp-owner above): TCP ETW owners"
				" are switched off; TCP rows use IP Helper only.\n";
		else if (opt.tcp && !attributor.report().tcp_available)
			std::cout << "\nNote: no accepted TCP connect schema: TCP ETW owners are switched off; TCP rows use"
				" IP Helper only.\n";
		if (!opt.iph_refresh)
			std::cout << "IP Helper refresh disabled (--no-iph-refresh): IP Helper shows cached tables only\n";
	}
	if (opt.dns)
	{
		// Queried once here, off the packet path. A started attributor refreshes it every 10 s;
		// without ETW (--no-etw, or gates failed) this start-up value is kept.
		std::cout << "Dnscache PID: " << attributor.dnscache_pid(true) << "\n";
	}
	if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0)
	{
		std::cout << "\nStopped during start-up; the adapter was not touched.\n";
		attributor.stop();
		WSACleanup();
		return 0;
	}

	eng.set_etw_enabled(etw_ok);
	eng.start();

	if (!filter->start_filter(*adapter))
	{
		std::cerr << "Failed to start filtering on the selected adapter\n";
		eng.stop();
		attributor.stop();
		WSACleanup();
		return 1;
	}
	std::cout << "\nOutbound " << (opt.udp ? "UDP" : "") << (opt.udp && opt.tcp ? " and " : "")
		<< (opt.tcp ? "TCP SYN" : "") << " packets are attributed; all packets pass unchanged. Ctrl+C to stop.\n\n";

	const DWORD wait_ms = opt.stats_sec > 0 ? static_cast<DWORD>(opt.stats_sec) * 1000 : INFINITE;
	while (WaitForSingleObject(g_stop_event, wait_ms) == WAIT_TIMEOUT)
		eng.print_stats(false);

	std::cout << "\nStopping: restoring the adapter mode...\n";
	filter->stop_filter(); // resets the adapter mode and releases queued packets
	eng.stop();
	eng.print_stats(true);
	if (etw_ok)
		std::cout << "\n" << attributor.report().to_string() << "\n";
	attributor.stop();
	filter.reset();
	WSACleanup();
	std::cout << "Done.\n";
	return 0;
}
