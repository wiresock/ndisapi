# NDISAPI

NDISAPI is a comprehensive user-mode interface library designed for seamless interaction with the [Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/) driver. It stands out by offering a straightforward, safe, and efficient interface for filtering (inspecting and modifying) raw network packets at the NDIS level of the network stack, ensuring minimal impact on network performance.

Windows Packet Filter (WinpkFilter) is a robust and efficient packet filtering framework tailored for Windows environments. It empowers developers to handle raw network packets at the NDIS level with ease, providing capabilities for packet inspection, modification, and control. WinpkFilter boasts user-friendly APIs, compatibility across various Windows versions, and streamlines network packet manipulation without the need for kernel-mode programming skills.

## v3.6.2 driver: observation actions

With the v3.6.2 driver, a static rule whose action is `FILTER_PACKET_PASS_RDR` or `FILTER_PACKET_DROP_RDR` is handled exactly like `FILTER_PACKET_REDIRECT`: the adapter mode decides the outcome. In TUNNEL mode the packet is redirected to the application (it is not passed or dropped by the driver); in LISTEN mode the original packet passes and the application receives a copy. `FILTER_PACKET_DROP_RDR` therefore does not drop the original packet on this driver. Use `FILTER_PACKET_DROP` to drop, or `FILTER_PACKET_REDIRECT` and drop in the application. The explicit pass/drop-with-copy semantics in every mode were introduced by the 3.8.2 driver and are not available here.

## WOW64 static table reads

`GetPacketFilterTable` and `GetPacketFilterTableResetStats` keep every validated row readable when a nonzero adapter identity cannot be mapped in a 32-bit process. The SDK attempts adapter enumeration once, then returns `STATIC_FILTER_ADAPTER_UNMAPPED` (`0xFFFFFFFFUL`) in `STATIC_FILTER.m_Adapter` for identities still unknown, including when enumeration fails. Known identities use their application handles; actual zero remains the all-adapters wildcard. The table is translated against one coherent mapping snapshot.

The original table IOCTL is issued once. GET_RESET returns its original counters and byte count without repeating the driver reset. An unmapped identity does not necessarily mean the adapter detached, and the SDK does not purge the rule. Rules remain removable by `RemoveStaticFilter` index, or by replacing the table with `SetPacketFilterTable` / clearing it with `ResetPacketFilterTable`. (Removal by unique filter ID requires the 3.7.1+ driver and is not part of this SDK line.)

The marker is output-only: `SetPacketFilterTable`, `AddStaticFilterFront`, `AddStaticFilterBack`, and `InsertStaticFilter` reject it with `ERROR_INVALID_HANDLE` before any IOCTL on both native and WOW64 callers. Do not replace it with zero when reusing a table; that would broaden an adapter-specific rule to every adapter. Resolve a current adapter handle or explicitly remove the row first.

## Event access and Fast I/O lifetime (v3.6.2 driver)

The v3.6.2 driver references a non-NULL Windows event handle registered with `SetPacketEvent`, `SetWANEvent`, `SetAdapterListChangeEvent`, or `SetHwPacketFilterEvent` with `SYNCHRONIZE` access, so the handle must grant `SYNCHRONIZE`; `EVENT_MODIFY_STATE` alone is not sufficient. If the reference fails (invalid handle, wrong object type or missing access), the call fails and the previously registered event is released: the slot is left with no event, not with the old registration. Re-register a valid event after such a failure. Passing NULL unregisters the event.

Fast I/O has one registering device file-object owner. Initialize the first section and add secondary sections through that same owner. Every successfully registered buffer and its pages must remain valid until that owner closes; there is no unregister IOCTL, and the driver releases the mappings only when the owning handle is closed. Stop readers, close the registering `CNdisApi`/`hOpen` device handle, and only then free its backing storage. `InitializeFastIo` and `AddSecondaryFastIo` are not available to WOW64 callers. The [dedicated-owner example](examples/cpp/common/ndisapi/fastio_packet_filter.h) uses a separate `registration_owner_` and closes it before freeing shared memory.

## Error status (v3.6.2 driver)

Always check the API result before reading `GetLastError`; a failed call has no meaningful output byte count. With the v3.6.2 LWF driver, every failure of a common IOCTL handler (malformed batch or table extents, unknown adapter, empty read, oversized frame, rejected filter table) is reported as `ERROR_INVALID_PARAMETER` (87). The finer-grained statuses documented for the 3.8.2 driver (31, 234, 1784, 6) are not produced by this driver. Fast I/O registration reports `ERROR_DUP_NAME` (52) for a second initialization, a secondary section from a non-owner or too many sections, `ERROR_NOACCESS` (998) when the section memory cannot be locked, and `ERROR_NO_SYSTEM_RESOURCES` (1450) on allocation failure. OID requests (`NdisrdRequest` and helpers) return the Win32 mapping of the NDIS status reported by the miniport.

The SDK validates arguments and driver replies before publishing results, and reports its own failures without issuing (or after rejecting) an IOCTL: `ERROR_INVALID_PARAMETER` for NULL or zero-count requests, `ERROR_INVALID_HANDLE` for unknown WOW64 adapter handles, an unopened driver or the output-only `STATIC_FILTER_ADAPTER_UNMAPPED` marker, `ERROR_INVALID_DATA` for a driver reply whose byte count or element count is out of bounds, `ERROR_ARITHMETIC_OVERFLOW` for request sizes beyond the API's `int` extent, `ERROR_NOT_ENOUGH_MEMORY` for staging allocation failures, and `ERROR_NOT_SUPPORTED` for unsorted packet APIs called from a WOW64 process. These checks do not change IOCTL numbers or structure layouts.

## Unsorted send results (v3.6.2 driver)

`SendPacketsToAdaptersUnsorted` and `SendPacketsToMstcpUnsorted` return an accepted-packet tally in `*pdwPacketSuccess` on a successful call. `TRUE` can report a partial batch: compare the tally with `dwPacketsNum`. The tally is neither a completed prefix nor a per-packet result; adapter grouping and individual packet rejection can leave gaps anywhere in the input array. Acceptance also does not confirm delivery to a remote peer.

With the v3.6.2 driver a short tally on success comes from packets whose `m_hAdapter` is not a known adapter: they are skipped silently. If any packet for a known adapter is rejected (adapter not running, oversized frame or allocation failure), the whole call returns `FALSE` and `*pdwPacketSuccess` is `0`, although the packets accepted before and after the rejected one have already been sent. A `FALSE` result therefore does not mean that nothing was sent.

Do not retry the suffix starting at `*pdwPacketSuccess`, or infer which packets to retry from this count. Per-adapter batches and the sorted send APIs alone do not provide an exactly-once delivery guarantee. Applications requiring that guarantee need their own per-packet acknowledgement and duplicate-handling protocol.

## Key Features

- **Network Adapter Management**: Enumerate and manage network adapter properties.
- **Packet Analysis and Modification**: Capture, filter, and modify network packets.
- **Packet Transmission**: Send raw packets directly through the network stack.

## Resources

- **Homepage**: [Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/)
- **Comprehensive Documentation**: [Windows Packet Filter Documentation](https://www.ntkernel.com/docs/windows-packet-filter-documentation/)

## Library Components

- **ndisapi.dll**: Native Win32 DLL wrapper (x86/x64/ARM64 versions).
- **ndisapi.lib**: Native Win32 static library wrapper (x86/x64/ARM64 versions).
- **ndisapi.net**: .NET C++/CLI mixed class library (x86/x64/ARM64 versions).
- **ndisapi.vs2012**: Visual Studio 2012 project for native Win32 DLL wrapper, supporting Windows XP/2003 (x86/x64).
- **ndisapi.vc6**: Visual C++ 6.0 project for native Win32 DLL wrapper, supporting legacy Windows versions prior to Windows XP/2003.

## Build Prerequisites for Examples

The example projects included with NDISAPI are set up to automatically manage their dependencies using vcpkg manifests when built with Visual Studio 2022. This process is designed to be straightforward and requires no additional manual installation of dependencies.

### Automated Dependency Management with Visual Studio 2022

- Building the examples in Visual Studio 2022 will automatically resolve and install the required dependencies through the vcpkg manifests. This approach is the simplest and is recommended for most users.

### Alternative: Standalone vcpkg Installation

For those using an environment other than Visual Studio 2022 or preferring manual installation, the following vcpkg commands with specific triplets can be used to install the necessary dependencies:

- **Microsoft GSL (Guideline Support Library)**: Required for all examples.
  ```bash
  vcpkg install ms-gsl:x86-windows ms-gsl:x64-windows ms-gsl:arm64-windows ms-gsl:x86-windows-static ms-gsl:x64-windows-static ms-gsl:arm64-windows-static
  ```

- **PcapPlusPlus**: Required only for the `pcapplusplus` example.
  ```bash
  vcpkg install pcapplusplus:x86-windows pcapplusplus:x64-windows
  ```

- **Hyperscan and llhttp**: Required only for the `hyperscan` example.
  - Install Hyperscan:
    ```bash
    vcpkg install hyperscan:x86-windows hyperscan:x64-windows
    ```
  - Install llhttp:
    ```bash
    vcpkg install llhttp:x86-windows llhttp:x64-windows
    ```

### Note

- Using Visual Studio 2022 with built-in vcpkg support is the preferred method for building the examples, as it greatly simplifies the process of dependency management.
- The standalone vcpkg commands with specific triplets are provided as an alternative for those who require manual installation or are working in different environments.

## Example Projects

### Basic C++ Examples

Ideal for beginners, these examples showcase the fundamental capabilities of NDISAPI. They are adaptable to different development environments and Windows versions:

- **With Visual C++ 6.0**: Binaries are compatible with Windows 95/NT and later operating systems.
- **With Visual Studio 2012**: Suitable for running on Windows XP/2003 and later.

The examples include:

- **listadapters**: Enumerates network adapters and their properties.
- **packetsniffer**: Introduces the basics of network packet sniffing.
- **passthru**: Demonstrates single packet processing techniques.
- **packthru**: Explores handling of multiple network packets simultaneously.
- **ndisrequest**: Shows how to send NDIS requests to network adapters.
- **filter**: Uses built-in static filters for selective packet filtering.
- **wwwcensor**: Implements content filtering in HTTP packets based on specific keywords.
- **gretunnel**: Demonstrates IP over GRE tunneling, modifying packet headers.

### Advanced C++ Examples (Visual Studio 2012)

Designed for users with advanced knowledge, these examples delve into more complex functionalities of NDISAPI.

- **snat**: A simple MFC Internet Connection sharing application.
- **lfnemu**: Long Fat Network (LFN) Emulator for simulating LFN behavior over local networks.

### Advanced C++ Examples (Visual Studio 2022)

These examples are intended for experienced users, showcasing sophisticated use of NDISAPI:

- **capture**: Captures and saves network packets in PCAP format.
- **dns_proxy**: Implements a transparent UDP proxy for the DNS protocol.
- **dnstrace**: Intercepts and decodes DNS responses.
- **ethernet_bridge**: Bridges wired and wireless network connections.
- **ipv6_parser**: Intercepts IPv6 packets and parses protocol headers.
- **sni_inspector**: Extracts SNI and Host headers from HTTPS and HTTP packets.
- **socksify**: Redirects TCP connections through a SOCKS5 proxy.
- **udp2tcp**: Converts between UDP and TCP protocols.
- **rebind**: Rebinds TCP/UDP connections to different network interfaces.
- **pcapplusplus**: Utilizes PcapPlusPlus for packet parsing and TLS fingerprinting.
- **hyperscan**: Detects HTTP sessions using Hyperscan and parses HTTP with llhttp.

### Very Advanced C++ Example

- **[ProxiFyre](https://github.com/wiresock/proxifyre)**: An advanced evolution of the Windows Packet Filter's socksify example, ProxiFyre enhances its capabilities by adding UDP support and facilitating the management of multiple proxy instances.

### C# Examples

For C# developers:

- **TestDotNet**: Showcases NDISAPI in filtering scenarios, using [PacketDotNet](https://github.com/chmorgan/packetnet) for network packet header analysis.