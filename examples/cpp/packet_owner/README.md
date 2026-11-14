# Windows Packet Filter Packet Owner Example (ETW vs IP Helper)

`packet_owner` answers "which process sent this packet?" for outbound UDP datagrams and
TCP connection attempts (SYN) seen by the Windows Packet Filter, in two ways at once:

* **IP Helper** – the owner tables (`GetExtendedUdpTable` / `GetExtendedTcpTable`) used by
  most WinpkFilter based tools (see `common/iphelper/process_lookup.h`). First the cached
  table is checked at packet time, then the table is refreshed and checked again.
* **ETW** – `common/iphelper/etw_packet_attributor.h`, a header-only class that consumes
  the kernel's own network events (Microsoft-Windows-Kernel-Network, Microsoft-Windows-TCPIP
  and optionally Microsoft-Windows-DNS-Client). These events carry the owner PID and are
  written on the send path of the packet itself, so the owner is known even when the
  socket was closed a few milliseconds after `sendto()`, where the IP Helper tables no
  longer have it.

Both answers are printed side by side, with the ETW delivery latency, so you can see
where they agree, where only one of them knows the owner, and how long a filter would
have to hold a packet to get the ETW answer.

The example is a measurement tool and a proof of concept for integrating ETW
attribution into packet filters such as ProxiFyre. **It never holds, drops or modifies
packets**: the filter callback only records the packet and returns `pass`; attribution
happens on a worker thread.

## Requirements

* Windows 8.1 / Windows Server 2012 R2 or later; Windows 10/11 recommended. Event-ID
  filtering (`EVENT_FILTER_TYPE_EVENT_ID`) and `EVENT_TRACE_INDEPENDENT_SESSION_MODE` are
  required and checked at run time.
* Administrator rights (the driver and the ETW real-time session both need them).
* Windows Packet Filter driver installed.
* Windows 7 is **not supported**: the current driver does not install there, and the ETW
  gates fail on it anyway (see "Limits").

## Build

Open `ndisapi.sln`, select the `packet_owner` project and build it (Debug/Release,
Win32/x64/ARM64). Like the other C++ examples it uses a vcpkg manifest (`ms-gsl`) and links
`ndisapi.lib` from `bin\lib\<platform>\<configuration>`, plus `tdh.lib`, `advapi32.lib`,
`ws2_32.lib` and `iphlpapi.lib`. The binary goes to
`bin\examples\native\<platform>\<configuration>\packet_owner.exe`.

## Usage

```
packet_owner [--adapter <index|name>] [--udp | --tcp] [--dns]
             [--flush auto|ondemand|timer] [--hold-ms N] [--late-ms N]
             [--csv file] [--udp-all] [--tcp-existing] [--stats-sec N] [--quiet] [--no-etw]
             [--gates-only]
```

| Option | Meaning |
|---|---|
| `--adapter` | Adapter to filter: the 1-based index from the printed list, or (part of) its friendly name. Without it you are asked. |
| `--udp`, `--tcp` | Attribute only UDP datagrams or only TCP SYNs. Default: both. |
| `--dns` | Also enable DNS-Client events. For DNS queries sent by the DNS Client service (Dnscache, a `svchost.exe`), print the processes that asked for the name. |
| `--flush` | How ETW buffers are delivered (see below). Default `auto`. |
| `--hold-ms` | Budget used to classify an ETW answer as `in-budget` or `late`. Default 75 ms. Nothing is actually held. |
| `--late-ms` | Stop waiting for an ETW owner after this many ms and report `none`. Default 2000. |
| `--csv` | Write one row per reported packet. |
| `--udp-all` | Report every datagram. By default a UDP 5-tuple is reported once per 5 s. |
| `--tcp-existing` | Also report the first packet of TCP connections whose SYN was not seen (for example, connections opened before the program started). These are matched against any connection event or the TCPIP rundown. |
| `--stats-sec` | Print statistics periodically. Final statistics are always printed. |
| `--quiet` | No per-packet lines. |
| `--no-etw` | IP Helper only. |
| `--gates-only` | Run only the ETW gates and the loopback self-test, print the report and exit (exit code 0 if ETW attribution is available, 3 if not). Does not need the driver. |

Press **Ctrl+C** to stop. The filter is stopped first (this restores the adapter mode and
releases queued packets), then the ETW session is stopped and the final statistics and
the gate report are printed. Closing the console window does the same.

### Output

```
+3.214s UDP 192.168.1.10:53122 -> 8.8.8.8:53 | IPH - miss | ETW nslookup.exe(4312) 1169v1 +12.40ms in-budget (event -0.31ms) | etw-only | DNS example.com type 1
+3.502s TCP SYN 192.168.1.10:50544 -> 93.184.215.14:443 | IPH chrome.exe(9120) hit | ETW chrome.exe(9120) 1031v1 +8.95ms in-budget (event -0.12ms) | agree
+4.010s UDP 192.168.1.10:61001 -> 192.168.1.1:53 | IPH svchost.exe(1588) hit | ETW svchost.exe(1588) 1169v1 +9.80ms in-budget (event -0.28ms) | agree | DNS www.example.org type 28 via Dnscache: tier2:3006-header-PID callers firefox.exe(7720) (wire-confirmed)
```

* `IPH`: owner from the IP Helper tables and how it was found (`hit`, `refreshed-hit` or `miss`).
* `ETW`: owner, the event that decided (`id` `v` `version`), delivery latency (event
  received minus packet read), and `in-budget` / `late` / `none`. `(event ±x ms)` is the
  event's own timestamp relative to the packet read: negative means the event was written
  before the driver saw the packet. `[unverified]` means the
  image path could not be proven to belong to that PID (the process exited and its PID may
  have been reused). `CONFLICT{...}` lists the event sources when they named different PIDs.
* Verdict: `agree`, `DISAGREE`, `etw-only`, `iph-only` or `neither`.
* `DNS ... via Dnscache`: the callers of a query sent by Dnscache. `tier1:ClientPID` comes
  from the `ClientPID` field of DNS-Client 3019/3010 (newer builds); `tier2:3006-header-PID`
  matches DNS-Client 3006 events by name and type (including DNS search suffixes).
  Coalesced queries list several callers.

At start-up the gate report is printed: the session `LogFileMode` requested and read back,
each provider's enable status and event IDs, every event schema seen (by TDH, with its
fields), and the loopback self-test result. The same report is printed again at exit with
the schemas that appeared while running.

## How it works

1. **Gates** (all checked at run time, never by OS version):
   elevation; the session must keep `EVENT_TRACE_INDEPENDENT_SESSION_MODE` in a
   `ControlTrace(QUERY)` read-back (Windows 7 returns success and silently clears it);
   providers are enabled with event-ID filters, and any event with an ID that was not
   requested marks that provider "filter not honoured" and its events are ignored; each
   (provider, ID, version) schema is read with TDH and the fields are located by name;
   a loopback self-test (127.0.0.1, ::1 and a loopback TCP connection) must come back as
   events naming this process.
2. **Flush strategy.** ETW delivers events in buffers; without help a datagram's event
   can take a second or more to arrive. `ondemand` calls `ControlTrace(FLUSH)` at most
   every 10 ms while lookups wait (backing off to 50 ms under load). `timer` starts the
   session with the undocumented millisecond flush timer (`0x10`, FlushTimer=10) and is
   used only if the self-test confirms delivery within 50 ms. `auto` uses the timer when
   confirmed, plus light on-demand flushes while few lookups wait; otherwise on-demand.
3. **Matching.** Events are cached by 5-tuple. A datagram or SYN matches only events of
   the same 5-tuple whose timestamp lies in [packet − 50 ms, packet + 1 ms] (TCP:
   + 50 ms, because connection events may be written after the SYN). Preferred sources:
   UDP – TCPIP 1169, then Kernel-Network 42/58; TCP – TCPIP 1031, then Kernel-Network
   12/28, then 1033/1034/1017. TCPIP 1396 (UDP bind) only adds a process start key.
4. **Image names** are resolved on the ETW consumer thread when the event arrives, and are
   checked against PID reuse with the process start key or the process creation time.

## Events used

| Provider / ID | Use | Confidence |
|---|---|---|
| Kernel-Network 42 / 58 (UDP send v4/v6), v0 | UDP owner | Measured on 7601, 19045, 26300 |
| TCPIP 1169 UdpEndpointSendMessages, v0 / v1 (+ProcessStartKey) | UDP owner (preferred) | Measured: v0 on 7601, v1 on 19045 and 26300 |
| TCPIP 1396 UdpBindEndpointComplete, v1 | Start-key enrichment only | Measured on 19045, 26300 |
| TCPIP 1031 TcpConnectTcbProceeding, v0 / v1 | TCP SYN owner (preferred) | Manifests only; timing relative to the SYN not yet measured |
| Kernel-Network 12 / 28 (TCP connect v4/v6), v0 | TCP SYN owner | Manifests only; may be written after the handshake |
| TCPIP 1033 / 1034 (connect complete / failure) | TCP owner, failed connects | Manifests only |
| TCPIP 1017 TcpAcceptListenerComplete, Kernel-Network 15 / 31 | Inbound connections | Manifests only |
| TCPIP 1300 TcpConnectionRundown (capture state) | `--tcp-existing` | Manifests only |
| DNS-Client 3006 / 3010 / 3019 | Dnscache callers (`--dns`) | Measured on 19045 (no ClientPID) and 26300 (ClientPID) |

Manifest sources: [jdu2600/Windows10EtwEvents](https://github.com/jdu2600/Windows10EtwEvents)
(per-release dumps 1511 to 25H2) and
[repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs) (Windows 7 7600 and
Windows 10 manifests). Unmeasured TCP fields are validated by the TDH schema check at run
time; a schema without the expected fields is rejected and reported, not guessed.

## Measured results (UDP, from the preparatory ETW probe)

These numbers come from a standalone probe that used the same events and flush modes
(datagrams sent from a socket that is closed 0, 2, 10 or 30 ms after `sendto`):

| System | Owner found by ETW | Delivery latency |
|---|---|---|
| Build 26300 (bare metal, 6 CPUs) | 50/50 at every close delay; 30000/30000 at 1000 datagrams/s; no lost events | On-demand: medians 18.6–30.7 ms, max 58.3 ms. 10 ms timer: medians 27.7–30.3 ms, max 45.7 ms. At 1000/s: on-demand median 16.8 ms, p95 24.2 ms; timer median 26.7 ms, p95 41.3 ms |
| Windows 10 22H2 19045 (VM, 2 vCPUs) | 50/50 at every close delay; 30000/30000 at 1000/s; no lost events | On-demand: median 15.7 ms, max 28.1 ms. 10 ms timer: median ~31 ms, max 33.3 ms. At 1000/s on-demand collapsed (median 95 ms, p95 1317 ms); timer median 62 ms, p95 160 ms |
| Windows 7 SP1 7601 (VM) | Gates fail (independent mode cleared); the driver does not install | 10 ms timer accepted but median 1.62 s |

With a 1 s flush timer and no on-demand flush the median was 0.7–1.6 s, which is why the
flush strategy matters. The event is written before WinpkFilter reads the frame (median
about −0.25 ms on 26300), so the only delay is delivery.

TCP and the `packet_owner` example itself have **not been measured yet**; the README will
be updated with the results.

## Limits

* **Windows 7 / Server 2008 R2:** unsupported (see above). The gates turn ETW off and the
  example falls back to IP Helper.
* **DNS cache hits are invisible:** a name answered from the Dnscache cache produces no
  packet, so there is nothing to attribute. DNS-Client events are also only correlated
  with queries that Dnscache puts on the wire.
* **DNS over HTTPS** (browsers' built-in DoH, Windows DoH) is just TLS to a resolver; the
  name and the real caller of the lookup are not visible.
* **Coalesced DNS queries** are attributed to all callers that asked for the same name and
  type within the correlation window; the example lists them all.
* **Loopback traffic** does not pass the driver, so it is never reported (it is used only
  for the self-test).
* **TCP:** the timing of TCPIP 1031 and Kernel-Network 12 relative to the SYN, the SOCKADDR
  layout of the TCPIP TCP address fields and the rundown behaviour are taken from the
  manifests and still need measurement. Retransmitted SYNs are reported again.
* **Under heavy load on small machines** delivery can exceed the hold budget; such packets
  are reported as `late` (or `none` after `--late-ms`).
* **One session name** (`NdisApi-PacketOwner`) is used; a second instance stops the first
  one's session.
