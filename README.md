# NDISAPI

NDISAPI brings [Windows Packet Filter (WinpkFilter)](https://www.ntkernel.com/windows-packet-filter/) packet processing to user-mode applications. Inspect, modify, drop, and inject raw network packets at the NDIS layer without writing your own kernel-mode driver.

Use it to build packet inspection tools, traffic filters, transparent proxies, tunnels, and network emulators. This repository contains the native and .NET interface libraries and examples; running packet-processing applications requires the WinpkFilter driver to be installed separately.

## Key Features

- **Adapter management**: Enumerate network adapters and query their properties.
- **Packet processing**: Inspect and modify packets, then forward or drop them.
- **Packet injection**: Send raw packets to network adapters or the Windows network stack.
- **Static filtering**: Select traffic for processing with driver-level filter rules.
- **Native and .NET interfaces**: Integrate with C/C++ applications or use the C++/CLI wrapper from .NET.

## Getting Started

1. Install the [WinpkFilter driver](https://www.ntkernel.com/windows-packet-filter/download/) appropriate for your Windows version and architecture.
2. Clone this repository and open [ndisapi.sln](ndisapi.sln) in Visual Studio 2022. Install the **Desktop development with C++** workload, the v143 toolset, a Windows SDK, and configure vcpkg MSBuild integration as described below.
3. Select **Release / x64** and build the **capture** project with its **ndisapi.lib** dependency. You do not need to build every example or the .NET projects to try it.
4. Run `bin\examples\native\x64\Release\capture.exe` from an elevated terminal. Select a network interface and a filename for the PCAP capture; press any key to stop.

The [capture example](examples/cpp/capture) records packets and forwards them. Use a test environment when trying examples that modify, redirect, or drop traffic.

For the simpler adapter-enumeration and single-packet examples, see [listadapters](examples/legacy/MSVC/listadapters), [packetsniffer](examples/legacy/MSVC/packetsniffer), and [passthru](examples/legacy/MSVC/passthru) in the separate legacy solution.

## Library Components

- **[ndisapi.dll](ndisapi.dll)**: Native DLL wrapper.
- **[ndisapi.lib](ndisapi.lib)**: Native static library wrapper.
- **[ndisapi.net](ndisapi.net)**: .NET C++/CLI mixed-mode library.

The modern library projects include x86, x64, and ARM64 configurations. Example projects and their dependencies may support a narrower set of targets; check the selected project's configurations before building.

## Building the Examples

### Visual Studio 2022

The modern C++ examples in [examples/cpp](examples/cpp) use the v143 toolset and per-project `vcpkg.json` manifests. Configure [vcpkg MSBuild integration](https://learn.microsoft.com/en-us/vcpkg/users/buildsystems/msbuild-integration) first. With integration enabled, the projects' manifest settings allow vcpkg to restore dependencies during the build.

- **Microsoft GSL** is used by the modern C++ examples.
- **PcapPlusPlus** is also required by `pcapplusplus`.
- **Hyperscan and llhttp** are also required by `hyperscan`.

Choose the target architecture in Visual Studio and build only the projects you need. The .NET projects additionally need C++/CLI support and the .NET Framework targeting components specified by their project files.

### Standalone vcpkg

If you manage dependencies outside manifest mode, install packages for the architecture and linkage your project uses. For example:

```console
vcpkg install ms-gsl:x64-windows-static
vcpkg install pcapplusplus:x64-windows
vcpkg install hyperscan:x64-windows llhttp:x64-windows
```

Use the corresponding `x86-windows` or `arm64-windows` triplet where supported, and `-static` when required by the project. GSL can also be installed with the dynamic triplets. Installing packages alone does not configure MSBuild integration or replace project include/library settings. In manifest mode, use the checked-in manifests instead of these package-by-package commands.

### Legacy Toolchains

- **[ndisapi.vs2012](ndisapi.vs2012)** and [legacy.vs2012.sln](examples/legacy/MSVC/legacy.vs2012.sln) retain the Visual Studio 2012 / `v110_xp` projects for the Windows XP/2003-era targets (x86/x64).
- **[ndisapi.vc6](ndisapi.vc6)** and the Visual C++ 6.0 projects in [examples/legacy/MSVC](examples/legacy/MSVC) retain support for older toolchains and Windows 95/NT-era targets.

These are separate from the modern solution. Running on an older Windows release also requires a compatible driver and runtime; a legacy project file alone does not establish compatibility with a current driver package.

## Example Projects

### Packet Capture and Inspection

- **[capture](examples/cpp/capture)**: Save network packets in PCAP format.
- **[dnstrace](examples/cpp/dnstrace)**: Intercept and decode DNS responses.
- **[ipv6_parser](examples/cpp/ipv6_parser)**: Parse IPv6 protocol headers.
- **[sni_inspector](examples/cpp/sni_inspector)**: Extract TLS SNI and HTTP Host headers.
- **[pcapplusplus](examples/cpp/pcapplusplus)**: Parse packets and perform TLS fingerprinting with PcapPlusPlus.
- **[hyperscan](examples/cpp/hyperscan)**: Detect HTTP sessions with Hyperscan and parse HTTP with llhttp.

### Proxies, Tunnels, and Bridging

- **[dns_proxy](examples/cpp/dns_proxy)**: Transparent UDP proxy for DNS.
- **[socksify](examples/cpp/socksify)**: Redirect TCP connections through a SOCKS5 proxy.
- **[udp2tcp](examples/cpp/udp2tcp)**: Rewrite UDP packets as TCP packets and convert them back at the peer.
- **[rebind](examples/cpp/rebind)**: Rebind TCP/UDP connections to different network interfaces.
- **[ethernet_bridge](examples/cpp/ethernet_bridge)**: Bridge wired and wireless network connections.

### Packet API Basics and Legacy Applications

These examples are in the legacy projects described above:

- **[listadapters](examples/legacy/MSVC/listadapters)**: Enumerate adapters and their properties.
- **[packetsniffer](examples/legacy/MSVC/packetsniffer)**: Inspect network packets.
- **[passthru](examples/legacy/MSVC/passthru)**: Process and forward individual packets.
- **[packthru](examples/legacy/MSVC/packthru)**: Process packets in batches.
- **[ndisrequest](examples/legacy/MSVC/ndisrequest)**: Send NDIS requests to adapters.
- **[filter](examples/legacy/MSVC/filter)**: Select traffic with static filters.
- **[wwwcensor](examples/legacy/MSVC/wwwcensor)**: Filter HTTP content by keywords.
- **[gretunnel](examples/legacy/MSVC/gretunnel)**: Demonstrate IP-over-GRE tunneling.
- **[snat](examples/legacy/MSVC/snat)**: MFC Internet Connection sharing application (Visual Studio 2012).
- **[lfnemu](examples/legacy/MSVC/lfnemu)**: Emulate a Long Fat Network on a local network (Visual Studio 2012).

### C#

- **[TestDotNet](examples/dotNet/TestDotNet)**: Filtering examples using [PacketDotNet](https://github.com/chmorgan/packetnet) to analyze packet headers.

## Related Project

**[ProxiFyre](https://github.com/wiresock/proxifyre)** builds on the `socksify` example with UDP support and multiple proxy instances.

## Resources and Licensing

- [Windows Packet Filter homepage](https://www.ntkernel.com/windows-packet-filter/)
- [API documentation](https://www.ntkernel.com/docs/windows-packet-filter-documentation/)
- [Driver downloads](https://www.ntkernel.com/windows-packet-filter/download/)

The source code in this repository is available under the [MIT License](LICENSE). The WinpkFilter driver has separate [licensing terms](https://www.ntkernel.com/windows-packet-filter/licensing/); review them before distributing a product that includes the driver.
