# NDISAPI

NDISAPI is a comprehensive user-mode interface library designed for seamless interaction with the [Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/) driver. It stands out by offering a straightforward, safe, and efficient interface for filtering (inspecting and modifying) raw network packets at the NDIS level of the network stack, ensuring minimal impact on network performance.

Windows Packet Filter (WinpkFilter) is a robust and efficient packet filtering framework tailored for Windows environments. It empowers developers to handle raw network packets at the NDIS level with ease, providing capabilities for packet inspection, modification, and control. WinpkFilter boasts user-friendly APIs, compatibility across various Windows versions, and streamlines network packet manipulation without the need for kernel-mode programming skills.

## 3.8.2 observation actions

`FILTER_PACKET_PASS_RDR` explicitly passes the original packet and delivers one observation copy; `FILTER_PACKET_DROP_RDR` explicitly drops the original and delivers one observation copy. This applies in every supported adapter mode, including TUNNEL. Observation copies must not be reinjected as ordinary diverted traffic. The existing `m_FilterID` identifies the matched rule; there is no new public observation flag or packet layout. Applications should use the matched rule/action to distinguish these copies.

## 3.8.2 WOW64 static table reads

`GetPacketFilterTable` and `GetPacketFilterTableResetStats` keep every validated row readable when a nonzero adapter identity cannot be mapped in a 32-bit process. The SDK attempts adapter enumeration once, then returns `STATIC_FILTER_ADAPTER_UNMAPPED` (`0xFFFFFFFFUL`) in `STATIC_FILTER.m_Adapter` for identities still unknown, including when enumeration fails. Known identities use their application handles; actual zero remains the all-adapters wildcard. The table is translated against one coherent mapping snapshot.

The original table IOCTL is issued once. GET_RESET returns its original counters and byte count without repeating the driver reset. An unmapped identity does not necessarily mean the adapter detached, and the SDK does not purge the rule. Rules remain removable by `RemoveStaticFilter` index or `DeleteStaticFilterById` unique filter ID.

The marker is output-only: `SetPacketFilterTable`, `AddStaticFilterFront`, `AddStaticFilterBack`, and `InsertStaticFilter` reject it with `ERROR_INVALID_HANDLE` before any IOCTL on both native and WOW64 callers. Do not replace it with zero when reusing a table; that would broaden an adapter-specific rule to every adapter. Resolve a current adapter handle or explicitly remove the row first.

## 3.8.2 unsorted send results

`SendPacketsToAdaptersUnsorted` and `SendPacketsToMstcpUnsorted` return an accepted-packet tally in `*pdwPacketSuccess` on a successful call. `TRUE` can report a partial batch: compare the tally with `dwPacketsNum`. The tally is neither a completed prefix nor a per-packet result; adapter grouping and individual packet rejection can leave gaps anywhere in the input array. Acceptance also does not confirm delivery to a remote peer.

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