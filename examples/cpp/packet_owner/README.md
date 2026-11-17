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
| `--csv` | Write one row per reported packet. The file is created (or truncated) only once the start-up checks have passed. |
| `--udp-all` | Report every datagram. By default a UDP 5-tuple is reported once per 5 s. With `--dns`, DNS query datagrams are always reported (Dnscache sends all queries from one socket, so per-5-tuple suppression would hide all but the first). |
| `--tcp-existing` | Also report the first packet of TCP connections whose SYN was not seen (for example, connections opened before the program started). These are matched against any connection event or the TCPIP rundown. |
| `--stats-sec` | Print statistics every N seconds (at most 86400). Final statistics are always printed. |
| `--quiet` | No per-packet lines. |
| `--no-etw` | IP Helper only. |
| `--no-iph-refresh` | Diagnostic: never refresh the IP Helper tables on a miss; the IP Helper column shows only what the cached tables knew. |
| `--iph-refresh-ms` | Minimum interval between two refreshes of one IP Helper table (IPv4/IPv6 × TCP/UDP). Default 25 ms. Misses that arrive meanwhile share the next refresh. |
| `--gates-only` | Run only the ETW gates and the loopback self-test, print the report and exit (exit code 0 if ETW attribution is available, 3 if not, 1 if stopped with Ctrl+C or a console close before the gates finished). Does not need the driver. |
| `--force-adapter` | Start even if the selected adapter already has a non-zero filter mode, i.e. another process is filtering it. Prints a warning; unsupported (see below). |

Press **Ctrl+C** to stop. The filter is stopped first (this restores the adapter mode and
releases queued packets), then the final statistics and the gate report are printed, and
then the ETW session is stopped. Closing the console window does the same within the
about 5 s Windows allows for it (the adapter mode is restored first; if time runs out,
only the ETW session is left behind, and the next start stops it). Ctrl+C or closing
the window while the gates run (normally well under a second after "Starting ETW
session", up to about 5 s if probes time out) cuts the self-test probes short, so the
gates end within about 1.5 s; the session is then stopped and the program prints
"Stopped during start-up" (the self-test detail reads `cancelled`; this is not an ETW
verdict) and exits without touching the adapter (the same 5 s limit applies when the
window is closed). Ctrl+C, Ctrl+Break or closing the window earlier, from the first lines
of `main` on (including at the interactive adapter prompt), takes the same path: nothing
is started, and the program prints "Stopped during start-up" and exits. Only a signal during process
start-up itself, before `main` runs, ends the process with the default Windows handling;
nothing has been started at that point either.

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

The driver resets an adapter's filter mode when the process that set it exits or
crashes (its driver handle is closed), so a crashed or killed instance does not leave the
adapter marked busy; a non-zero mode means a filter that is still running. The check is
not a lock: a filter that starts between the check and `packet_owner`'s own
`SetAdapterMode` is not detected.

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
  they named different (nonzero) PIDs. `[header-pid N overridden by 1033/1034]` means the
  1031 header PID N was replaced by the different payload PID of TCPIP 1033/1034 of the
  same connect attempt; `[pid-from-outcome]` means 1031 had no usable PID and the owner
  was taken from that 1033/1034 (see "Matching").
* TCP SYN rows end with the connect outcome seen later for the same connect attempt:
  `(connected)` (TCPIP 1033 or Kernel-Network 12/28), `(connect failed, 1034 status 0x...)`,
  or `(unknown)` if neither arrived within `--late-ms`. The event and latency shown are
  still those of the first matching event; the owner is too, unless a 1033/1034 payload
  PID overrode a 1031 header PID. With `[pid-from-outcome]` the event, its time and the
  latency are those of the 1033/1034, because the owner was not known before it. That
  latency is about one RTT (connect time, not ETW delivery), so such a row is usually
  `late`, and it is left out of the latency statistics (`ETW delivery latency` summary
  and the latency histogram); the statistics count these rows as `owner from outcome N`.
* Verdict: `agree`, `DISAGREE`, `etw-only`, `iph-only` or `neither`.
* CSV columns added after `dns_wire_confirmed`: `etw_pid_from_header`, `tcp_outcome`
  (`connected` / `failed` / `unknown`), `tcp_connect_status` (the 1034 status) and
  `etw_overridden_header_pid` (the replaced 1031 header PID, empty if none) and
  `etw_pid_from_outcome` (1 if the owner came from 1033/1034 because 1031 had no PID).
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

The ETW session is named `NdisApi-PacketOwner-<pid>-<creation>-<module>-<n>`
(`<creation>` is the process creation time as 16 hex digits, `<module>` the base address
of the EXE or DLL that contains the attributor, `<n>` counts attributor instances in that
module), so several instances can run at the same time, in different processes, modules
or objects, without touching each other's session (on one adapter the driver still
allows only one of them, see above; `--gates-only` does not use the driver). An existing
session with the same name is never stopped; `start()` fails instead. (Exception: if a
STOP of the object's own session failed, which is logged, the next `start()` of that
object retries it, and keeps retrying on later `start()` calls until a STOP succeeds.
If a DLL whose STOP failed is unloaded and loaded again at the same base address, its
counter restarts and a new object can get the leaked session's name: that object's
`start()` fails with "already exists" (it never stops the leaked session) and it gets no
ETW until the process exits or the session is stopped by hand.) At start, sessions with that
prefix whose process (PID and creation time) no longer runs are stopped: they were left
behind by a killed instance (a real-time session outlives its process). Sessions of
running processes are never stopped, and a reused PID does not make a live session look
stale because its creation time differs. Session
buffers: 64 KB each, `MinimumBuffers` = 2 × logical CPUs, `MaximumBuffers` = 4 × logical
CPUs + 16 (12 / 40 on a 6-CPU machine).

## How it works

1. **Gates** (all checked at run time, never by OS version):
   elevation; the session must keep `EVENT_TRACE_INDEPENDENT_SESSION_MODE` in a
   `ControlTrace(QUERY)` read-back (Windows 7 returns success and silently clears it);
   providers are enabled with event-ID filters, and any event with an ID that was not
   requested marks that provider "filter not honoured" and its events are ignored; each
   (provider, ID, version) schema is read with TDH and the fields are located by name;
   a loopback self-test. What it gates, precisely:
   * IPv4 UDP (127.0.0.1) gates ETW as a whole: its event must arrive within 250 ms with
     an on-demand flush, or ETW is off. It also picks the flush mode, and it is repeated
     every 60 s (and after lost events); two failures in a row switch ETW off until a
     probe passes again.
   * TCP (a loopback connect, at start only) gates TCP owners: `tcp=ok` only if the owner
     chosen for the loopback connect is this process's PID, not merely that some TCP
     event arrived. If it fails (wrong owner, or loopback TCP blocked; the connect is
     bounded by the probe timeout), the self-test line shows `tcp=fail` and the
     availability line `tcp=no`, TCP ETW owners are switched off for the session and TCP
     rows use IP Helper only; UDP is not affected.
   * IPv6 UDP (::1) is reported (`ipv6=ok/fail`, or `n/a` when ::1 cannot be bound) but
     gates nothing: IPv6 events are not measured yet.
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
   + 50 ms, because connection events may be written after the SYN). For UDP, consecutive
   events of one owner (same source, PID, start key and image) written within 1 ms of each
   other are merged into one record that covers their time range, and a datagram matches
   if that range overlaps its window; a tuple keeps up to 512 such records (at least
   256 ms of history at any rate). This keeps a busy tuple (Dnscache sends every query
   from one socket; a steady flow) from evicting the event of an earlier datagram before
   the lookup sees it. A short-lived socket has one datagram per tuple, so nothing is
   merged there; a merged record reports the time of its first event. A record that names
   a real PID always beats one whose PID is unknown (0); among those, preferred sources are:
   UDP – TCPIP 1169, then Kernel-Network 42/58; TCP – TCPIP 1031, then Kernel-Network
   12/28, then 1033/1034/1017. TCPIP 1396 (UDP bind) only adds a process start key.
   **PID per event:** the payload PID is used, except for TCPIP 1031, whose payload
   `ProcessId` (and `ProcessStartKey`) is 0: there the event header PID is used, which is
   the connecting process because 1031 is written at SYN send in the connecting thread.
   A header PID of 0 or 4 is not used. 1033 has header PID 4 and the real PID in the
   payload; 1034 carried the real PID in both after a local abort; both use the payload.
   PID 0 is shown as "unknown", never as a verified Idle process.
   **Connect attempt:** the outcome and the payload PID are taken only from records of
   the same connect attempt: from the matched 1031 up to the next 1031 of the 5-tuple (a
   reused tuple, e.g. a fast reconnect from the same port, starts a new attempt), and the
   first 1033/1034 of that attempt is used. These records are not limited to the 50 ms
   match window, because 1033 comes one RTT after the SYN.
   **Header PID override:** a header PID is only right if 1031 is written in the
   connecting process's context, as measured. If that first 1033/1034 names a different
   nonzero payload PID, it replaces the header PID and the row is marked (see "Output").
   The case this guards against, a connect completed in another process's context (e.g. a
   WFP callout that pends ALE connect authorization), has not been observed or tested.
   **No PID at SYN time:** if 1031 has no usable PID (payload 0 and header 0 or 4), the
   owner is filled from that first 1033/1034 (`[pid-from-outcome]`). KN 12 is not used for
   either; it decides only when it arrives inside the match window.
   **Assumptions and edge cases of the attempt logic:** 1031 is assumed to be written
   once per connect, not per SYN retransmission (consistent with the measurements, not
   verified); if it were written per retransmission, an attempt would end at the next
   1031 and the earlier SYN row would show `(unknown)`, degraded but not misattributed.
   The choice of the matched record itself is not attempt-aware: a 1031 with a known PID
   from another attempt of the same 5-tuple inside the match window (or within the 120 s
   cache lifetime for `--tcp-existing`) outranks a PID-less 1031 of the right attempt.
   For connection matches decided by a record other than 1031, earlier records of the
   same attempt are not scanned. If a reused tuple's next 1031 has not been delivered yet
   while its 1033 has (per-CPU buffer order), an earlier attempt without a 1033/1034 of
   its own can briefly take that 1033's outcome and PID. The first and the last case need
   the same 5-tuple to be reused quickly (normally an RST plus an explicit bind).
4. **Image names** are resolved on the ETW consumer thread when the event arrives, and are
   checked against PID reuse with the process start key or the process creation time.
   Events without a start key (Kernel-Network, one per datagram) reuse the last
   `OpenProcess` result for their PID if the event was written before that open and the
   process was created no later than the event (a PID is not reused while its process
   object exists), so the process is opened about once per delivered buffer per PID
   rather than once per event.
5. **DNS search suffixes** (used by tier 2) and the **Dnscache PID** are loaded at start
   and refreshed on the attributor's maintenance thread (every 30 s and 10 s);
   `dns_lookup()` and `dnscache_pid()` only read snapshots.

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
  `--force-adapter` is given. A crashed instance does not leave the adapter busy: the
  driver resets the mode when the owning process exits.
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
  PID at SYN time; the owner then comes from the attempt's 1033/1034 one RTT later (or
  from KN 12 if it arrives within 50 ms of the SYN), and its latency includes that RTT. If
  neither arrives within `--late-ms`, the row shows `no PID`. Such rows are not part of
  the latency statistics (see "Output"). A remote RST (1034) and IPv6 (KN 28) are not
  measured yet. Retransmitted SYNs are reported again, but 1031 is assumed to be written
  once per connect (see "Matching"): a retransmission read 50 ms or more after it falls
  outside the strict window and usually gets ETW `none`, unless 1033 / KN 12 arrives
  within 50 ms of the retransmission.
* **Header PID override (1031 vs 1033/1034)** is implemented but the asynchronous
  completion case it targets has not been verified; check it with a WFP callout that
  pends connects before relying on it in a product.
* **Image resolution and DNS suffixes under load:** the per-PID open reuse and the
  background refresh of the DNS suffixes and the Dnscache PID remove the obvious per-event
  and per-lookup costs, but none of this has been measured at high datagram rates (tens
  of thousands per second). Without ETW (`--no-etw`, or failed gates) the Dnscache PID is
  read once at start.
* **Under heavy load on small machines** delivery can exceed the hold budget; such packets
  are reported as `late` (or `none` after `--late-ms`).
* **Stale sessions:** a killed instance leaves its `NdisApi-PacketOwner-<pid>-<creation>-...`
  session behind until the next instance starts and finds no process with that PID and
  creation time (stop it by hand with `logman stop <name> -ets`). If the creation time of a
  running PID cannot be read, its sessions are kept. Sessions named
  `NdisApi-PacketOwner-<pid>` (earlier builds of this example) are stopped if that PID no
  longer runs; sessions named only `NdisApi-PacketOwner` are never stopped automatically.
* **Frames:** up to two 802.1Q / 802.1ad tags are skipped; IPv4 and IPv6 non-first
  fragments have no ports and are not reported.
* **IP Helper refresh:** refreshes run off the packet path and are coalesced; a socket that
  is created and closed between two refreshes is still an IP Helper miss.
