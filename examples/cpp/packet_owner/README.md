# Windows Packet Filter Packet Owner Example (ETW vs IP Helper)

`packet_owner` answers "which process sent this packet?" for outbound UDP datagrams and
TCP connection attempts (SYN) seen by the Windows Packet Filter, in two ways at once:

* **IP Helper** – the owner tables (`GetExtendedUdpTable` / `GetExtendedTcpTable`) used by
  most WinpkFilter based tools (see `common/iphelper/process_lookup.h`). First the cached
  table is checked at packet time; on a miss a table refresh is requested from a
  background thread (coalesced, at most one per `--iph-refresh-ms` per table) and the
  lookup is retried when that refresh has completed.
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

* ETW attribution: Windows 8.1 / Windows Server 2012 R2 or later; Windows 10/11
  recommended. Event-ID filtering (`EVENT_FILTER_TYPE_EVENT_ID`) and
  `EVENT_TRACE_INDEPENDENT_SESSION_MODE` are required and checked at run time.
* Administrator rights (the driver and the ETW real-time session both need them).
* Windows Packet Filter driver installed.
* No other process filtering the selected adapter (see "One filtering process per
  adapter" below).
* **Windows 7 / Server 2008 R2:** the Windows Packet Filter driver runs there, but ETW
  attribution does not. Windows 7 accepts the trace session and silently clears
  `EVENT_TRACE_INDEPENDENT_SESSION_MODE` (`0x08000000`), which the private session needs;
  the read-back gate sees this and turns ETW off, and the example continues with IP Helper
  only (the same as `--no-etw`). See "Limits".

## Build

Open `ndisapi.sln`, select the `packet_owner` project and build it (Debug/Release,
Win32/x64/ARM64). Like the other C++ examples it uses a vcpkg manifest (`ms-gsl`) and links
`ndisapi.lib` from `bin\lib\<platform>\<configuration>`, plus `tdh.lib`, `advapi32.lib`,
`ws2_32.lib` and `iphlpapi.lib`. The binary goes to
`bin\examples\native\<platform>\<configuration>\packet_owner.exe`.

From a Developer Command Prompt, `msbuild ndisapi.sln /t:packet_owner` fails with MSB4057:
in the solution the project sits in the solution folder `examples\C++`, and MSBuild names
solution targets after the folder path, so the target is
`examples\C++\packet_owner` (for example
`msbuild ndisapi.sln /t:examples\C++\packet_owner /p:Configuration=Release /p:Platform=x64`;
verified to build x64, ARM64 and Win32 with no warnings at level 3). Building the two
project files directly also works; `SolutionDir` (with a trailing backslash) must point
at the clone root because the output and library paths use it:

```
msbuild ndisapi.lib\ndisapilib.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=<clone>\ /p:SolutionName=ndisapi
msbuild examples\cpp\packet_owner\packet_owner.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=<clone>\ /p:SolutionName=ndisapi
```

`/p:Platform` is `x64`, `ARM64` or `Win32` for the project files (the solution calls Win32
`x86`).

## Usage

```
packet_owner [--adapter <index|name>] [--udp | --tcp] [--dns]
             [--flush auto|ondemand|timer] [--hold-ms N] [--late-ms N]
             [--csv file] [--udp-all] [--tcp-existing] [--stats-sec N] [--quiet] [--no-etw]
             [--no-iph-refresh] [--iph-refresh-ms N] [--gates-only] [--force-adapter]
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
| `--udp-all` | Report every datagram. By default a UDP 5-tuple is reported once per 5 s. With `--dns`, DNS query datagrams are always reported (Dnscache sends all queries from one socket, so per-5-tuple suppression would hide all but the first). |
| `--tcp-existing` | Also report the first packet of TCP connections whose SYN was not seen (for example, connections opened before the program started). These are matched against any connection event or the TCPIP rundown. |
| `--stats-sec` | Print statistics periodically. Final statistics are always printed. |
| `--quiet` | No per-packet lines. |
| `--no-etw` | IP Helper only. |
| `--no-iph-refresh` | Diagnostic: never refresh the IP Helper tables on a miss; the IP Helper column shows only what the cached tables knew. |
| `--iph-refresh-ms` | Minimum interval between two refreshes of one IP Helper table (IPv4/IPv6 × TCP/UDP). Default 25 ms. Misses that arrive meanwhile share the next refresh. |
| `--gates-only` | Run only the ETW gates and the loopback self-test, print the report and exit (exit code 0 if ETW attribution is available, 3 if not). Does not need the driver. |
| `--force-adapter` | Start even if the selected adapter already has a non-zero filter mode, i.e. another process is filtering it. Prints a warning; unsupported (see below). |

Press **Ctrl+C** to stop. The filter is stopped first (this restores the adapter mode and
releases queued packets), then the ETW session is stopped and the final statistics and
the gate report are printed. Closing the console window does the same.

### One filtering process per adapter

The Windows Packet Filter driver is designed to be used by one filtering process at a
time. Running two filters on the same adapter (two `packet_owner` instances, or
`packet_owner` next to ProxiFyre or another WinpkFilter based tool) is unsupported: both
read from the same adapter, and when either one exits it resets the adapter mode to 0,
which silently stops filtering for the other.

Before it sets the adapter mode, `packet_owner` reads the current mode with
`GetAdapterMode`. If it is non-zero, the adapter is treated as busy and the program exits
with code 1 and this message:

```
Error: adapter '<name>' is already being filtered by another process (filter mode 0x<mode>).
The Windows Packet Filter driver is designed to be used by a single filtering process at a
time; a second instance would also reset the first instance's adapter mode on exit.
Stop the other filtering process, or pass --force-adapter to start anyway.
```

`--force-adapter` skips the refusal (the same text is printed as a warning) for
experiments where the interference is acceptable. If the mode cannot be queried, a
warning is printed and the program continues.

### Output

```
+3.214s UDP 192.168.1.10:53122 -> 8.8.8.8:53 | IPH - miss | ETW nslookup.exe(4312) 1169v1 +12.40ms in-budget (event -0.31ms) | etw-only | DNS example.com type 1
+3.502s TCP SYN 192.168.1.10:50544 -> 93.184.215.14:443 | IPH chrome.exe(9120) hit | ETW chrome.exe(9120)[header-pid] 1031v1 +8.95ms in-budget (event -0.12ms) (connected) | agree
+4.010s UDP 192.168.1.10:61001 -> 192.168.1.1:53 | IPH svchost.exe(1588) hit | ETW svchost.exe(1588) 1169v1 +9.80ms in-budget (event -0.28ms) | agree | DNS www.example.org type 28 via Dnscache: tier2:3006-header-PID callers firefox.exe(7720) (wire-confirmed)
```

* `IPH`: owner from the IP Helper tables and how it was found (`hit`, `refreshed-hit` or `miss`).
* `ETW`: owner, the event that decided (`id` `v` `version`), delivery latency (event
  received minus packet read), and `in-budget` / `late` / `none`. `(event ±x ms)` is the
  event's own timestamp relative to the packet read: negative means the event was written
  before the driver saw the packet. `[unverified]` means the
  image path could not be proven to belong to that PID (the process exited and its PID may
  have been reused). `[header-pid]` means the PID came from the event header (TCPIP 1031,
  see "Matching"). `no PID` with state `no-pid` means an event matched but none named a
  real PID; it is not counted as an ETW owner. `CONFLICT{...}` lists the event sources when
  they named different (nonzero) PIDs.
* TCP SYN rows end with the connect outcome seen later for the same connection:
  `(connected)` (TCPIP 1033 or Kernel-Network 12/28), `(connect failed, 1034 status 0x...)`,
  or `(unknown)` if neither arrived within `--late-ms`. The owner and its latency are
  still those of the first matching event.
* Verdict: `agree`, `DISAGREE`, `etw-only`, `iph-only` or `neither`.
* CSV columns added after `dns_wire_confirmed`: `etw_pid_from_header`, `tcp_outcome`
  (`connected` / `failed` / `unknown`) and `tcp_connect_status` (the 1034 status).
* `DNS ... via Dnscache`: the callers of a query sent by Dnscache. `tier1:ClientPID` comes
  from the `ClientPID` field of DNS-Client 3019/3010 (newer builds); `tier2:3006-header-PID`
  matches DNS-Client 3006 events by name and type (including DNS search suffixes).
  Coalesced queries list several callers.

At start-up the gate report is printed: the session name and `LogFileMode` requested and
read back, each provider's enable status and event IDs, every event schema seen (by TDH,
with its fields), and the loopback self-test result including every timer and on-demand
sample and the owner chosen for the loopback TCP connect (`tcp-owner=<pid> (self)`). The
same report is printed again at exit with the schemas that appeared while running. While
the gates are still running nothing is logged about availability; the first verdict on
stderr is the final one.

The ETW session is named `NdisApi-PacketOwner-<pid>`, so several instances can run at the
same time without touching each other's session (on one adapter the driver still allows
only one of them, see above; `--gates-only` does not use the driver). At start, sessions with that prefix
whose PID no longer runs (left behind by a killed instance; a real-time session outlives
its process) are stopped; sessions of running processes are never stopped. Session
buffers: 64 KB each, `MinimumBuffers` = 2 × logical CPUs, `MaximumBuffers` = 4 × logical
CPUs + 16 (12 / 40 on a 6-CPU machine).

## How it works

1. **Gates** (all checked at run time, never by OS version):
   elevation; the session must keep `EVENT_TRACE_INDEPENDENT_SESSION_MODE` in a
   `ControlTrace(QUERY)` read-back (Windows 7 returns success and silently clears it);
   providers are enabled with event-ID filters, and any event with an ID that was not
   requested marks that provider "filter not honoured" and its events are ignored; each
   (provider, ID, version) schema is read with TDH and the fields are located by name;
   a loopback self-test (127.0.0.1, ::1 and a loopback TCP connection) must come back as
   events naming this process. For TCP the check is the attributed owner: `tcp=ok` only if
   the owner chosen for the loopback connect is this process's PID, not merely that some
   TCP event arrived.
2. **Flush strategy.** ETW delivers events in buffers; without help a datagram's event
   can take a second or more to arrive. `ondemand` calls `ControlTrace(FLUSH)` at most
   every 10 ms while lookups wait (backing off to 50 ms under load). `timer` starts the
   session with the undocumented millisecond flush timer (`0x10`, FlushTimer=10) and is
   used only if the self-test confirms delivery within 50 ms: the median of five timer
   samples must be ≤ 50 ms (single samples of 69–80 ms next to 32–39 ms ones were seen on
   a 2-vCPU VM, so the worst sample does not decide). `auto` uses the timer whenever it is
   confirmed, plus light on-demand flushes while few lookups wait; otherwise on-demand, and
   the reason for the fallback is logged and shown in the self-test detail. On the 2-vCPU
   19045 VM under sustained load the timer held while on-demand flushing degraded; there,
   `--flush timer` is the safer explicit choice.
3. **Matching.** Events are cached by 5-tuple. A datagram or SYN matches only events of
   the same 5-tuple whose timestamp lies in [packet − 50 ms, packet + 1 ms] (TCP:
   + 50 ms, because connection events may be written after the SYN). A record that names
   a real PID always beats one whose PID is unknown (0); among those, preferred sources are:
   UDP – TCPIP 1169, then Kernel-Network 42/58; TCP – TCPIP 1031, then Kernel-Network
   12/28, then 1033/1034/1017. TCPIP 1396 (UDP bind) only adds a process start key.
   **PID per event:** the payload PID is used, except for TCPIP 1031, whose payload
   `ProcessId` (and `ProcessStartKey`) is 0: there the event header PID is used, which is
   the connecting process because 1031 is written at SYN send in the connecting thread.
   A header PID of 0 or 4 is not used. 1033 has header PID 4 and the real PID in the
   payload; 1034 carried the real PID in both after a local abort; both use the payload.
   PID 0 is shown as "unknown", never as a verified Idle process.
4. **Image names** are resolved on the ETW consumer thread when the event arrives, and are
   checked against PID reuse with the process start key or the process creation time.

## Events used

| Provider / ID | Use | Confidence |
|---|---|---|
| Kernel-Network 42 / 58 (UDP send v4/v6), v0 | UDP owner | Measured on 7601, 19045, 26300 |
| TCPIP 1169 UdpEndpointSendMessages, v0 / v1 (+ProcessStartKey) | UDP owner (preferred) | Measured: v0 on 7601, v1 on 19045 and 26300 |
| TCPIP 1396 UdpBindEndpointComplete, v1 | Start-key enrichment only | Measured on 19045, 26300 |
| TCPIP 1031 TcpConnectTcbProceeding, v1 | TCP SYN owner (preferred), header PID | Measured v1 on 19045 and 26300: written at SYN send, before WinpkFilter reads the SYN; payload ProcessId 0 |
| Kernel-Network 12 / 28 (TCP connect v4/v6), v0 | TCP owner after the handshake | KN 12 v0 measured on 19045 and 26300 (about one RTT after the SYN; absent for aborted connects); KN 28 not observed |
| TCPIP 1033 / 1034 (connect complete / failure), v1 | TCP owner (payload PID), connect outcome and 1034 status | Measured v1 on 26300 (1034 also on 19045); a remote RST (1034) is not measured yet |
| TCPIP 1017 TcpAcceptListenerComplete, Kernel-Network 15 / 31 | Inbound connections | 1017 v1 and KN 15 v0 seen in the loopback self-test |
| TCPIP 1300 TcpConnectionRundown (capture state) | `--tcp-existing` | Measured: v3 on 26300, v1 on 19045 |
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
| Windows 7 SP1 7601 (VM) | Gates fail (independent mode cleared): no ETW attribution | 10 ms timer accepted but median 1.62 s |

With a 1 s flush timer and no on-demand flush the median was 0.7–1.6 s, which is why the
flush strategy matters. The event is written before WinpkFilter reads the frame (median
about −0.25 ms on 26300), so the only delay is delivery.

## Measured results (TCP, `packet_owner` on 26300 and 19045)

* TCPIP 1031 v1 fires for an outbound connect at SYN-send time (0.4 µs after TCPIP 1004
  `TcpTcbSynSend` for the same Tcb in a decoded trace). The event is written about 0.03 to
  0.17 ms before WinpkFilter reads the SYN (about 0.1 ms typical). Its payload `ProcessId`
  and `ProcessStartKey` are 0; the event header PID is the connecting process. With the
  payload PID the first build showed every SYN as Idle (PID 0) and disagreed with IP
  Helper. A build that used the header PID agreed with IP Helper on all 50 completed
  connects of one run (latency median 15.8 ms, p95 31.7 ms on the `auto` path).
* TCPIP 1033 v1 and Kernel-Network 12 v0 arrive with the handshake, about one RTT after
  the SYN (+8.0 ms to 1.1.1.1). 1033 has header PID 4 and the real PID and a nonzero
  start key in the payload. KN 12 does not fire for a connect aborted before it was
  established. KN 28 was not observed (no IPv6 route on the test machines).
* TCPIP 1034 v1 for a local abort (`STATUS_CANCELLED`, 0xC0000120) carried the real PID
  in header and payload. A remote RST was not measured (no refusing target was found).
* Addresses are SOCKADDR, length 28, `AF_INET6` with IPv4-mapped `::ffff:` addresses for
  IPv4 connections; they are folded to IPv4 and match the packet 5-tuples.
* TCPIP 1300 (rundown) attributed connections that existed before the start on both
  systems (v3 on 26300, v1 on 19045). It describes existing flows, not a SYN.
* Windows 7 SP1: the session read-back clears `0x08000000`
  (`EVENT_TRACE_INDEPENDENT_SESSION_MODE`), so the gates stop and ETW stays off.

Keep the 75 ms budget for TCP: waiting for 1033 / KN 12 instead of 1031 adds about one RTT
to the flush delay.

## Limits

* **Windows 7 / Server 2008 R2:** the driver runs and packets are filtered, but ETW
  attribution is unavailable: the kernel clears `EVENT_TRACE_INDEPENDENT_SESSION_MODE`
  (`0x08000000`) on the session, the gates turn ETW off ("ETW attribution is NOT
  available ... Continuing with IP Helper only") and every row is attributed by IP Helper
  alone, with its usual misses for short-lived sockets. The ETW part was measured on
  Windows 7 SP1 with the standalone probe; a full `packet_owner` run with the driver on
  Windows 7 has not been tested.
* **One filtering process per adapter:** see above; a busy adapter is refused unless
  `--force-adapter` is given.
* **DNS cache hits are invisible:** a name answered from the Dnscache cache produces no
  packet, so there is nothing to attribute. DNS-Client events are also only correlated
  with queries that Dnscache puts on the wire.
* **DNS over HTTPS** (browsers' built-in DoH, Windows DoH) is just TLS to a resolver; the
  name and the real caller of the lookup are not visible.
* **Coalesced DNS queries** are attributed to all callers that asked for the same name and
  type within the correlation window; the example lists them all.
* **Loopback traffic** does not pass the driver, so it is never reported (it is used only
  for the self-test).
* **TCP:** a connect issued from kernel mode or one whose 1031 header PID is 0 or 4 has no
  PID at SYN time; the owner then comes from 1033 / KN 12 one RTT later. A remote RST
  (1034) and IPv6 (KN 28) are not measured yet. Retransmitted SYNs are reported again.
* **Under heavy load on small machines** delivery can exceed the hold budget; such packets
  are reported as `late` (or `none` after `--late-ms`).
* **Stale sessions:** a killed instance leaves its `NdisApi-PacketOwner-<pid>` session
  behind until the next instance starts and finds that PID no longer running. If the PID
  has been reused by an unrelated live process, that session stays until the process exits
  (stop it with `logman stop NdisApi-PacketOwner-<pid> -ets`). Sessions named only
  `NdisApi-PacketOwner` (earlier builds) are never stopped automatically.
* **IP Helper refresh:** refreshes run off the packet path and are coalesced; a socket that
  is created and closed between two refreshes is still an IP Helper miss.
