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
	};

	void print_usage()
	{
		std::cout <<
			"packet_owner - who owns this packet? IP Helper vs ETW, side by side\n\n"
			"Usage: packet_owner [options]\n"
			"  --adapter <index|name>   adapter to filter (1-based index as listed, or friendly name);\n"
			"                           without it the adapters are listed and you are asked\n"
			"  --udp                    attribute outbound UDP only\n"
			"  --tcp                    attribute outbound TCP SYNs only (default: both)\n"
			"  --dns                    resolve the callers of DNS queries sent by the DNS Client\n"
			"                           service (Dnscache) via Microsoft-Windows-DNS-Client events\n"
			"  --flush auto|ondemand|timer\n"
			"                           ETW delivery strategy (default auto; see README)\n"
			"  --hold-ms N              latency budget for 'in budget' (default 75)\n"
			"  --late-ms N              give up waiting for an ETW owner after N ms (default 2000)\n"
			"  --csv <file>             write one row per attributed packet\n"
			"  --udp-all                report every UDP datagram (default: one per 5-tuple per 5 s)\n"
			"  --tcp-existing           also report the first packet of TCP flows whose SYN was\n"
			"                           not seen (matched against connection/rundown events)\n"
			"  --stats-sec N            print statistics every N seconds\n"
			"  --quiet                  no per-packet lines (statistics only)\n"
			"  --no-etw                 IP Helper only\n"
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
			else if (a == "--hold-ms" || a == "--late-ms" || a == "--stats-sec")
			{
				int n = 0;
				if (!value(v) || !parse_int(v, n) || n < 0)
				{
					std::cerr << a << " needs a non-negative number\n";
					return std::nullopt;
				}
				(a == "--hold-ms" ? o.hold_ms : a == "--late-ms" ? o.late_ms : o.stats_sec) = n;
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
			else if (a == "--gates-only")
				o.gates_only = true;
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
		if (s.find_first_of(",\"\n") == std::string::npos)
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

		if (ntohs(eth->h_proto) == ETH_P_IP)
		{
			if (length < sizeof(ether_header) + sizeof(iphdr))
				return std::nullopt;
			const auto* ip = reinterpret_cast<const iphdr*>(eth + 1);
			const size_t ihl = static_cast<size_t>(ip->ip_hl) * 4;
			if (ihl < 20 || length < sizeof(ether_header) + ihl)
				return std::nullopt;
			if ((ntohs(ip->ip_off) & 0x1FFF) != 0)
				return std::nullopt; // non-first fragment
			protocol = ip->ip_p;
			l4 = reinterpret_cast<const uint8_t*>(ip) + ihl;
			l4_len = length - sizeof(ether_header) - ihl;
			out.tuple.family = AF_INET;
			std::memcpy(out.tuple.local_ip.data(), &ip->ip_src, 4);
			std::memcpy(out.tuple.remote_ip.data(), &ip->ip_dst, 4);
		}
		else if (ntohs(eth->h_proto) == ETH_P_IPV6)
		{
			if (length < sizeof(ether_header) + sizeof(ipv6hdr))
				return std::nullopt;
			const auto* ip6 = reinterpret_cast<const ipv6hdr*>(eth + 1);
			const auto* p = reinterpret_cast<const uint8_t*>(ip6 + 1);
			size_t remaining = length - sizeof(ether_header) - sizeof(ipv6hdr);
			uint8_t next = ip6->ip6_next;
			// Skip hop-by-hop (0), routing (43) and destination options (60)
			for (int i = 0; i < 8 && (next == 0 || next == 43 || next == 60); ++i)
			{
				if (remaining < 8)
					return std::nullopt;
				const size_t ext = (static_cast<size_t>(p[1]) + 1) * 8;
				if (remaining < ext)
					return std::nullopt;
				next = p[0];
				p += ext;
				remaining -= ext;
			}
			protocol = next; // fragments (44) are ignored
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

	void iph_refresh(const packet_tuple& t)
	{
		const bool tcp = t.protocol == IPPROTO_TCP;
		if (t.family == AF_INET)
			iphelper::process_lookup<net::ip_address_v4>::get_process_helper().actualize(tcp, !tcp);
		else
			iphelper::process_lookup<net::ip_address_v6>::get_process_helper().actualize(tcp, !tcp);
	}

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

		std::optional<iphelper::etw::owner_info> etw;
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
			: opt_(opt), attributor_(attributor), output_mutex_(output_mutex)
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
						"verdict,dns_qname,dns_qtype,dns_tier,dns_callers,dns_wire_confirmed\n";
				else
					std::cerr << "cannot open " << opt_.csv_path << "\n";
			}
		}

		void start() { worker_ = std::thread(&engine::worker_proc, this); }

		void stop()
		{
			{
				std::lock_guard<std::mutex> lock(queue_mutex_);
				stopping_ = true;
			}
			queue_cv_.notify_all();
			if (worker_.joinable())
				worker_.join();
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
			std::lock_guard<std::mutex> stats_lock(stats_mutex_);
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
					<< percent(s.etw_none, s.total) << "); image unverified " << s.image_unverified << ", conflicts "
					<< s.conflicts << "\n"
					<< "  ETW delivery latency: " << latency_summary(s.latency_ms) << "\n"
					<< "  verdict: agree " << s.agree << ", disagree " << s.disagree << ", ETW only " << s.etw_only
					<< ", IP Helper only " << s.iph_only << ", neither " << s.neither << "\n";
			};
			block("UDP", udp_);
			block("TCP SYN", tcp_syn_);
			block("TCP existing", tcp_existing_);
			if (opt_.dns && dns_.dnscache_queries)
			{
				os << "DNS (queries sent by Dnscache): " << dns_.dnscache_queries << ", tier1 (ClientPID) " << dns_.tier1
					<< ", tier2 (3006 header PID) " << dns_.tier2 << ", no caller " << dns_.none << ", several callers "
					<< dns_.multi_caller << ", via search suffix " << dns_.suffix << ", wire-confirmed "
					<< dns_.wire_confirmed << "\n";
			}
			if (etw_enabled_)
			{
				const auto c = attributor_.get_counters();
				os << "ETW counters: events " << c.events_total << ", unrequested " << c.events_unrequested
					<< ", schema-rejected " << c.events_schema_rejected << ", parse-failed " << c.events_parse_failed
					<< ", own-process " << c.events_own_process << "\n"
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
			os << "queue dropped " << queue_dropped_.load() << ", UDP duplicates suppressed " << udp_suppressed_ << "\n";
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

		void refresh_iph(work_item& item)
		{
			if (item.iph != iph_state::miss)
				return;
			iph_refresh(item.tuple);
			if (const auto p = iph_lookup(item.tuple); p)
			{
				item.iph = iph_state::refreshed_hit;
				item.iph_pid = p->id;
				item.iph_path = p->path_name.empty() ? p->name : p->path_name;
			}
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
			if (!item.etw)
			{
				const auto kind = item.kind == item_kind::tcp_existing
					                  ? iphelper::etw::match_kind::connection
					                  : iphelper::etw::match_kind::datagram;
				item.etw = attributor_.lookup(item.tuple, item.qpc, kind);
			}
			const bool expired = now - item.seen >= std::chrono::milliseconds(opt_.late_ms);
			if (!item.etw)
			{
				if (expired)
					attributor_.record_timeout();
				return expired;
			}
			if (needs_dns(item))
			{
				item.dnscache_owner = true;
				item.dns_attr = attributor_.dns_lookup(item.dns->qname, item.dns->qtype, item.qpc);
				return !item.dns_attr.callers.empty() || expired;
			}
			return true;
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

				for (auto& item : batch)
				{
					if (is_duplicate(item) || is_seen_flow(item))
						continue;
					refresh_iph(item);
					if (!etw_enabled_ || !attributor_.available())
					{
						if (opt_.dns && item.dns && attributor_.dnscache_pid() == item.iph_pid)
							item.dnscache_owner = true;
						finalize(item, false);
					}
					else
						pending.push_back(std::move(item));
				}

				if (pending.empty())
					continue;

				const auto generation = attributor_.generation();
				const auto now = clock_type::now();
				for (auto it = pending.begin(); it != pending.end();)
				{
					if (try_resolve(*it, now))
					{
						finalize(*it, true);
						it = pending.erase(it);
					}
					else
						++it;
				}
				if (!pending.empty())
				{
					attributor_.request_flush(pending.size());
					attributor_.wait_for_events(generation, clock_type::now() + std::chrono::milliseconds(5));
				}
			}
			for (auto& item : pending)
				finalize(item, true);
		}

		void finalize(work_item& item, const bool etw_attempted)
		{
			using namespace iphelper::etw;
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
				if (item.etw)
				{
					latency = std::max(0.0, qpc_ms(item.etw->received_qpc - item.qpc));
					event_offset = qpc_ms(item.etw->event_qpc - item.qpc);
					etw_state = latency <= opt_.hold_ms ? "in-budget" : "late";
				}
				else
					etw_state = "none";
			}

			const bool iph_found = item.iph != iph_state::miss;
			const bool etw_found = item.etw.has_value();
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
					else
						++s.etw_none;
					if (latency >= 0 && s.latency_ms.size() < 2000000)
						s.latency_ms.push_back(latency);
					if (item.etw && !item.etw->image_verified)
						++s.image_unverified;
					if (item.etw && item.etw->conflict)
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
					if (etw_found)
					{
						os << (etw_image.empty() ? "?" : etw_image) << "(" << item.etw->pid << ")"
							<< (item.etw->image_verified ? "" : "[unverified]") << " " << item.etw->event_id << "v"
							<< static_cast<unsigned>(item.etw->event_version) << " +" << format_ms(latency) << "ms "
							<< etw_state << " (event " << (event_offset < 0 ? "-" : "+")
							<< format_ms(std::abs(event_offset)) << "ms)";
						if (item.etw->conflict)
							os << " CONFLICT{" << sources_to_string(item.etw->sources_seen) << "}";
						if (item.etw->source == event_source::tcpip_tcp_failed)
							os << " (connect failed, status 0x" << std::hex << item.etw->status << std::dec << ")";
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
					<< (etw_found ? to_string(item.etw->source) : "") << ","
					<< (etw_found ? std::to_string(item.etw->event_id) : "") << ","
					<< (etw_found ? std::to_string(item.etw->event_version) : "") << ","
					<< (latency >= 0 ? format_ms(latency) : "") << ","
					<< (etw_found ? std::to_string(event_offset) : "") << ","
					<< (etw_found ? csv_escape(sources_to_string(item.etw->sources_seen)) : "") << ","
					<< (etw_found && item.etw->conflict ? "1" : "0") << "," << verdict << ","
					<< csv_escape(item.dns ? item.dns->qname : "") << ","
					<< (item.dns ? std::to_string(item.dns->qtype) : "") << ","
					<< (item.dnscache_owner ? iphelper::etw::to_string(item.dns_attr.tier) : "") << ","
					<< csv_escape(dns_callers) << ","
					<< (item.dnscache_owner ? (item.dns_attr.wire_confirmed ? "1" : "0") : "") << "\n";
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
		std::thread worker_;

		// worker-thread only
		std::unordered_map<packet_tuple, clock_type::time_point, iphelper::etw::packet_tuple_hash> recent_udp_;
		std::unordered_map<packet_tuple, clock_type::time_point, iphelper::etw::packet_tuple_hash> tcp_flows_;

		std::mutex stats_mutex_;
		proto_stats udp_;
		proto_stats tcp_syn_;
		proto_stats tcp_existing_;
		dns_stats dns_;
		uint64_t udp_suppressed_{};

		std::mutex csv_mutex_;
		std::ofstream csv_;
	};

	// ----------------------------------------------------------------------------
	// Ctrl+C handling
	// ----------------------------------------------------------------------------
	HANDLE g_stop_event = nullptr;
	HANDLE g_cleanup_done_event = nullptr;

	BOOL WINAPI console_ctrl_handler(const DWORD type)
	{
		switch (type)
		{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
			SetEvent(g_stop_event);
			return TRUE;
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			// The process is terminated when the handler returns: let main restore the
			// adapter mode and stop the ETW session first.
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

	std::mutex output_mutex;

	iphelper::etw::attributor_config config;
	config.enable_tcp = opt.tcp;
	config.enable_dns = opt.dns;
	config.flush = opt.flush;
	config.log = [&output_mutex](const std::string& message)
	{
		std::lock_guard<std::mutex> lock(output_mutex);
		std::cerr << "[etw] " << message << "\n";
	};
	iphelper::etw_packet_attributor attributor(config);

	if (opt.gates_only)
	{
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
	std::cout << "\nFiltering: " << names[*adapter] << "\n\n";

	bool etw_ok = false;
	if (opt.no_etw)
		std::cout << "ETW attribution disabled (--no-etw): IP Helper only\n";
	else
	{
		std::cout << "Starting ETW session and running the capability gates...\n";
		etw_ok = attributor.start();
		std::cout << attributor.report().to_string() << "\n";
		if (!etw_ok)
		{
			std::cout << "\nETW attribution is NOT available on this system (" << attributor.report().failure
				<< ").\nContinuing with IP Helper only.\n";
		}
		else if (opt.tcp && !attributor.report().tcp_available)
			std::cout << "\nNote: no accepted TCP connect schema yet; TCP rows may show no ETW owner.\n";
		if (opt.dns)
			std::cout << "Dnscache PID: " << attributor.dnscache_pid(true) << "\n";
	}
	eng.set_etw_enabled(etw_ok);
	eng.start();

	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

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
	SetEvent(g_cleanup_done_event);
	return 0;
}
