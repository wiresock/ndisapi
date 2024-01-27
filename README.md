# NDISAPI

NDISAPI is a comprehensive user-mode interface library designed for seamless interaction with the [Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/) driver. It stands out by offering a straightforward, safe, and efficient interface for filtering (inspecting and modifying) raw network packets at the NDIS level of the network stack, ensuring minimal impact on network performance.

Windows Packet Filter (WinpkFilter) is a robust and efficient packet filtering framework tailored for Windows environments. It empowers developers to handle raw network packets at the NDIS level with ease, providing capabilities for packet inspection, modification, and control. WinpkFilter boasts user-friendly APIs, compatibility across various Windows versions, and streamlines network packet manipulation without the need for kernel-mode programming skills.

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