# ndisapi

**Windows Packet Filter** user-mode interface library 

### Homepage

https://www.ntkernel.com/windows-packet-filter/

### Documentation

https://www.ntkernel.com/docs/windows-packet-filter-documentation/

### Library projects

* **ndisapi.dll** - native Win32 DLL wrapper (x86/x64)
* **ndisapi.lib** - native Win32 static library wrapper (x86/x64)
* **ndisapi.net** - .NET C++/CLI mixed class library (x86/x64)
* **ndisapi.vs2012** - Visual Studio 2012 project for native Win32 DLL wrapper (x86/x64). Provides support for the Windows XP/2003.
* **ndisapi.vc6** - Visual C++ 6.0 project for native Win32 DLL wrapper. Provides support for the legacy Windows versions prior Windows XP/2003.

### Examples

* **capture** - native C++ sample, intercepts packets for the specified network interface and saves those into the PCAP file which can be opened and analyzed with WireShark.
* **dns_proxy** - native C++ sample, redirects DNS protocol through the transparent UDP proxy.
* **dnstrace** - native C++ sample, intercepts DNS responses and decodes their content to the console. Has configurations to link NDISAPI statically and dynamically.
* **ethernet_bridge** - native C++ sample, implements bridging wired and wireless networks. More information https://www.ntkernel.com/bridging-networks-with-windows-packet-filter/
* **ipv6_parser** - native C++ sample, intercepts IPv6 packets, matches to originated process (using IP Helper API) parses protocol headers.
* **sni_inspector** - native C++ sample, intercepts network packets and extracts SNI from HTTPS packets and Host from HTTP packets.
* **socksify** - native C++ sample, redirects selected TCP connections through a SOCKS5 proxy. 
* **TestDotNet** - C# sample demonstrates the NDISAPI usage in several filtering scenarios. Available ion x86 and x64 configurations. AnyCPU configuration is not available due to the C++/CLI nature of ndisapi.net wrapper (see https://github.com/kevin-marshall/Managed.AnyCPU for the workaround). Projects references PacketDotNet (https://github.com/chmorgan/packetnet) for dumping network packets headers.
