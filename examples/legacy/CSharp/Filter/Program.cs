using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Net;
using NdisApiWrapper;

namespace Filter
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.WriteLine(
                        "Command line syntax:\n\tfilter.exe index scenario \n\tindex - network interface index.\n\tscenario - sample set of filters to load.\n\tYou can use ListAdapters to determine correct index.");
                    Console.WriteLine("Available Scenarios:");
                    Console.WriteLine("1 - Redirect only IPv4 DNS packets for processing in user mode.");
                    Console.WriteLine("2 - Redirect only HTTP(TCP port 80) packets for processing in user mode. Both IPv4 and IPv6 protocols.");
                    Console.WriteLine("3 - Drop all IPv4 ICMP packets. Redirect all other packets to user mode (default behaviour).");
                    Console.WriteLine("4 - Block IPv4 access to http://www.ntkernel.com. Pass all other packets without processing in user mode.");
                    Console.WriteLine("5 - Redirect only ARP/RARP packets to user mode. Pass all others.");
                    return;
                }

                var adapterIndex = uint.Parse(args[0]) - 1;
                var scena = uint.Parse(args[1]);

                var driverPtr = Ndisapi.OpenFilterDriver();
                if (!Ndisapi.IsDriverLoaded(driverPtr))
                {
                    Console.WriteLine("Driver not installed on this system of failed to load.");
                    return;
                }

                // Retrieve adapter list
                var adapters = new TCP_AdapterList();
                Ndisapi.GetTcpipBoundAdaptersInfo(driverPtr, ref adapters);

                // Set tunnel mode for the selected network interface
                var mode = new ADAPTER_MODE
                {
                    dwFlags = Ndisapi.MSTCP_FLAG_SENT_TUNNEL | Ndisapi.MSTCP_FLAG_RECV_TUNNEL,
                    hAdapterHandle = adapters.m_nAdapterHandle[adapterIndex]
                };

                Ndisapi.SetAdapterMode(driverPtr, ref mode);

                // Create and set event for the adapter
                var manualResetEvent = new ManualResetEvent(false);
                Ndisapi.SetPacketEvent(driverPtr, adapters.m_nAdapterHandle[adapterIndex], manualResetEvent.SafeWaitHandle);

                var filtersTable = new STATIC_FILTER_TABLE();
                filtersTable.m_StaticFilters = new STATIC_FILTER[256];

                switch(scena)
                {
                    case 1:
                        filtersTable.m_TableSize = 3;

                        //**************************************************************************************
                        // 1. Outgoing DNS requests filter: REDIRECT OUT UDP packets with destination PORT 53
                        // Common values
                        filtersTable.m_StaticFilters[0].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[0].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[0].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[0].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND;

                        // Network layer filter
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = 17; //IPPROTO_UDP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_DEST_PORT;
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 53; // DNS
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 53;

                        //****************************************************************************************
                        // 2. Incoming DNS responses filter: REDIRECT IN UDP packets with source PORT 53
                        // Common values
                        filtersTable.m_StaticFilters[1].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[1].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[1].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[1].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE;

                        // Network layer filter
                        filtersTable.m_StaticFilters[1].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                        filtersTable.m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_Protocol = 17;//IPPROTO_UDP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_SRC_PORT;
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = 53; // DNS
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = 53;

                        //***************************************************************************************
                        // 3. Pass all packets (skipped by previous filters) without processing in user mode
                        // Common values
                        filtersTable.m_StaticFilters[2].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[2].m_ValidFields = 0;
                        filtersTable.m_StaticFilters[2].m_FilterAction = Ndisapi.FILTER_PACKET_PASS;
                        filtersTable.m_StaticFilters[2].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE | Ndisapi.PACKET_FLAG_ON_SEND;

                        break;

                    case 2:
                        filtersTable.m_TableSize = 5;

                        //**************************************************************************************
                        // 1. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv4
                        // Common values
                        filtersTable.m_StaticFilters[0].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[0].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[0].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[0].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND;

                        // Network layer filter
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = 6;//IPPROTO_TCP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_DEST_PORT;
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 80; // HTTP
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 80;

                        //****************************************************************************************
                        // 2. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv4
                        // Common values
                        filtersTable.m_StaticFilters[1].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[1].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[1].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[1].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE;

                        // Network layer filter
                        filtersTable.m_StaticFilters[1].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                        filtersTable.m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_Protocol = 6; //IPPROTO_TCP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_SRC_PORT;
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = 80; // HTTP
                        filtersTable.m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = 80;

                        //****************************************************************************************
                        // 3. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv6
                        // Common values
                        filtersTable.m_StaticFilters[2].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[2].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[2].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[2].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND;

                        // Network layer filter
                        filtersTable.m_StaticFilters[2].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV6;
                        filtersTable.m_StaticFilters[2].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V6_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[2].m_NetworkFilter.m_IPv4.m_Protocol = 6; //IPPROTO_TCP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[2].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[2].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_DEST_PORT;
                        filtersTable.m_StaticFilters[2].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 80; // HTTP
                        filtersTable.m_StaticFilters[2].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 80;

                        //****************************************************************************************
                        // 4. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv6
                        // Common values
                        filtersTable.m_StaticFilters[3].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[3].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[3].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[3].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE;

                        // Network layer filter
                        filtersTable.m_StaticFilters[3].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV6;
                        filtersTable.m_StaticFilters[3].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V6_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[3].m_NetworkFilter.m_IPv4.m_Protocol = 6;// IPPROTO_TCP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[3].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[3].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_SRC_PORT;
                        filtersTable.m_StaticFilters[3].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = 80; // HTTP
                        filtersTable.m_StaticFilters[3].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = 80;

                        //***************************************************************************************
                        // 5. Pass all packets (skipped by previous filters) without processing in user mode
                        // Common values
                        filtersTable.m_StaticFilters[4].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[4].m_ValidFields = 0;
                        filtersTable.m_StaticFilters[4].m_FilterAction = Ndisapi.FILTER_PACKET_PASS;
                        filtersTable.m_StaticFilters[4].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE | Ndisapi.PACKET_FLAG_ON_SEND;

                        break;

                    case 3:
                        filtersTable.m_TableSize = 5;

                        //**************************************************************************************
                        // 1. Block all ICMP packets
                        // Common values
                        filtersTable.m_StaticFilters[0].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[0].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID;
                        filtersTable.m_StaticFilters[0].m_FilterAction = Ndisapi.FILTER_PACKET_DROP;
                        filtersTable.m_StaticFilters[0].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND | Ndisapi.PACKET_FLAG_ON_RECEIVE;

                        // Network layer filter
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_PROTOCOL;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = 1;//IPPROTO_ICMP

                        break;

                    case 4:

                        filtersTable.m_TableSize = 2;

                        //**************************************************************************************
                        // 1. Outgoing HTTP requests filter: DROP OUT TCP packets with destination IP 104.196.49.47 PORT 80 - 443 (http://www.ntkernel.com)
                        // Common values
                        filtersTable.m_StaticFilters[0].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[0].m_ValidFields = Ndisapi.NETWORK_LAYER_VALID | Ndisapi.TRANSPORT_LAYER_VALID;
                        filtersTable.m_StaticFilters[0].m_FilterAction = Ndisapi.FILTER_PACKET_DROP;
                        filtersTable.m_StaticFilters[0].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND;

                        // Network layer filter
                        var address = new in_addr();
                        var mask = new in_addr();

                        // IP address 104.196.49.47
                        address.s_b1 = 104;
                        address.s_b2 = 196;
                        address.s_b3 = 49;
                        address.s_b4 = 47;

                        // Network mask 255.255.255.255
                        mask.s_b1 = 255;
                        mask.s_b2 = 255;
                        mask.s_b3 = 255;
                        mask.s_b4 = 255;

                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = Ndisapi.IPV4;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = Ndisapi.IP_V4_FILTER_PROTOCOL | Ndisapi.IP_V4_FILTER_DEST_ADDRESS;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress.m_AddressType = Ndisapi.IP_SUBNET_V4_TYPE;
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_Ip = address.s_addr; // IP address
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_IpMask = mask.s_addr; // network mask
                        filtersTable.m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = 6; //IPPROTO_TCP

                        // Transport layer filter 
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = Ndisapi.TCPUDP;
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = Ndisapi.TCPUDP_DEST_PORT;
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 80; // HTTP
                        filtersTable.m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 443; //HTTPS

                        //***************************************************************************************
                        // 2. Pass all packets (skipped by previous filters) without processing in user mode
                        // Common values
                        filtersTable.m_StaticFilters[1].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[1].m_ValidFields = 0;
                        filtersTable.m_StaticFilters[1].m_FilterAction = Ndisapi.FILTER_PACKET_PASS;
                        filtersTable.m_StaticFilters[1].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE | Ndisapi.PACKET_FLAG_ON_SEND;

                        break;

                    case 5:

                        filtersTable.m_TableSize = 3;

                        //**************************************************************************************
                        // 1. Redirects all ARP packets to be processes by user mode application
                        // Common values
                        filtersTable.m_StaticFilters[0].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[0].m_ValidFields = Ndisapi.DATA_LINK_LAYER_VALID;
                        filtersTable.m_StaticFilters[0].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[0].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND | Ndisapi.PACKET_FLAG_ON_RECEIVE;
                        filtersTable.m_StaticFilters[0].m_DataLinkFilter.m_dwUnionSelector = Ndisapi.ETH_802_3;
                        filtersTable.m_StaticFilters[0].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields = Ndisapi.ETH_802_3_PROTOCOL;
                        filtersTable.m_StaticFilters[0].m_DataLinkFilter.m_Eth8023Filter.m_Protocol = 0x0806; // ETH_P_ARP;


                        //**************************************************************************************
                        // 1. Redirects all RARP packets to be processes by user mode application
                        // Common values
                        filtersTable.m_StaticFilters[1].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[1].m_ValidFields = Ndisapi.DATA_LINK_LAYER_VALID;
                        filtersTable.m_StaticFilters[1].m_FilterAction = Ndisapi.FILTER_PACKET_REDIRECT;
                        filtersTable.m_StaticFilters[1].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_SEND | Ndisapi.PACKET_FLAG_ON_RECEIVE;
                        filtersTable.m_StaticFilters[1].m_DataLinkFilter.m_dwUnionSelector = Ndisapi.ETH_802_3;
                        filtersTable.m_StaticFilters[1].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields = Ndisapi.ETH_802_3_PROTOCOL;
                        filtersTable.m_StaticFilters[1].m_DataLinkFilter.m_Eth8023Filter.m_Protocol = 0x0806; // ETH_P_ARP;


                        //***************************************************************************************
                        // 2. Pass all packets (skipped by previous filters) without processing in user mode
                        // Common values
                        filtersTable.m_StaticFilters[2].m_Adapter = 0; // applied to all adapters
                        filtersTable.m_StaticFilters[2].m_ValidFields = 0;
                        filtersTable.m_StaticFilters[2].m_FilterAction = Ndisapi.FILTER_PACKET_PASS;
                        filtersTable.m_StaticFilters[2].m_dwDirectionFlags = Ndisapi.PACKET_FLAG_ON_RECEIVE | Ndisapi.PACKET_FLAG_ON_SEND;

                        break;
                    default:
                        Console.WriteLine ("Unknown test scenario specified. Exiting.");
		                return;
                }

                // Load filters into driver
                Ndisapi.SetPacketFilterTable(driverPtr, ref filtersTable);
               
                // Allocate and initialize packet structures
                var request = new ETH_REQUEST();
                var buffer = new INTERMEDIATE_BUFFER();
                var bufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));

                Win32Api.ZeroMemory(bufferPtr, Marshal.SizeOf(buffer));

                request.hAdapterHandle = adapters.m_nAdapterHandle[adapterIndex];
                request.EthPacket.Buffer = bufferPtr;

                while(true)
                {
                    manualResetEvent.WaitOne();

                    while (Ndisapi.ReadPacket(driverPtr, ref request))
                    {
                        buffer = (INTERMEDIATE_BUFFER)Marshal.PtrToStructure(bufferPtr, typeof(INTERMEDIATE_BUFFER));

                        WriteToConsole(buffer, bufferPtr);

                        if (buffer.m_dwDeviceFlags == Ndisapi.PACKET_FLAG_ON_SEND)
                            Ndisapi.SendPacketToAdapter(driverPtr, ref request);
                        else
                            Ndisapi.SendPacketToMstcp(driverPtr, ref request);
                    }

                    manualResetEvent.Reset();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private unsafe static void WriteToConsole(INTERMEDIATE_BUFFER packetBuffer, IntPtr packetBufferPtr)
        {
            Console.WriteLine(packetBuffer.m_dwDeviceFlags == Ndisapi.PACKET_FLAG_ON_SEND ? "\nMSTCP --> Interface" : "\nInterface --> MSTCP");
            Console.WriteLine("Packet size = {0}", packetBuffer.m_Length);

            var ethernetHeader = (ETHER_HEADER*)((byte*)packetBufferPtr + (Marshal.OffsetOf(typeof(INTERMEDIATE_BUFFER), "m_IBuffer")).ToInt32());
            Console.WriteLine(
                "\tETHERNET {0:X2}{1:X2}{2:X2}{3:X2}{4:X2}{5:X2} --> {6:X2}{7:X2}{8:X2}{9:X2}{10:X2}{11:X2}",
                ethernetHeader->source.b1,
                ethernetHeader->source.b2,
                ethernetHeader->source.b3,
                ethernetHeader->source.b4,
                ethernetHeader->source.b5,
                ethernetHeader->source.b6,
                ethernetHeader->dest.b1,
                ethernetHeader->dest.b2,
                ethernetHeader->dest.b3,
                ethernetHeader->dest.b4,
                ethernetHeader->dest.b5,
                ethernetHeader->dest.b6
                );

            switch (ntohs(ethernetHeader->proto))
            {
                case ETHER_HEADER.ETH_P_IP:
                    {
                        var ipHeader = (IPHeader*)((byte*)ethernetHeader + Marshal.SizeOf(typeof(ETHER_HEADER)));

                        var sourceAddress = new IPAddress(ipHeader->Src);
                        var destinationAddress = new IPAddress(ipHeader->Dest);

                        Console.WriteLine("\tIP {0} --> {1} PROTOCOL: {2}", sourceAddress, destinationAddress, ipHeader->P);

                        var tcpHeader = ipHeader->P == IPHeader.IPPROTO_TCP ? (TcpHeader*)((byte*)ipHeader + ((ipHeader->IPLenVer) & 0xF) * 4) : null;
                        var udpHeader = ipHeader->P == IPHeader.IPPROTO_UDP ? (UdpHeader*)((byte*)ipHeader + ((ipHeader->IPLenVer) & 0xF) * 4) : null;

                        if (udpHeader != null)
                            Console.WriteLine("\tUDP SRC PORT: {0} DST PORT: {1}", ntohs(udpHeader->th_sport), ntohs(udpHeader->th_dport));

                        if (tcpHeader != null)
                            Console.WriteLine("\tTCP SRC PORT: {0} DST PORT: {1}", ntohs(tcpHeader->th_sport), ntohs(tcpHeader->th_dport));
                    }
                    break;
                case ETHER_HEADER.ETH_P_RARP:
                    Console.WriteLine("\tReverse Addr Res packet");
                    break;
                case ETHER_HEADER.ETH_P_ARP:
                    Console.WriteLine("\tAddress Resolution packet");
                    break;
            }
        }

        static ushort ntohs(ushort netshort)
        {
            var hostshort = (ushort)(((netshort >> 8) & 0x00FF) | ((netshort << 8) & 0xFF00));
            return hostshort;
        }

        [StructLayout(LayoutKind.Explicit, Size = 4)]
        internal struct in_addr
        {
            [FieldOffset(0)]
            internal byte s_b1;
            [FieldOffset(1)]
            internal byte s_b2;
            [FieldOffset(2)]
            internal byte s_b3;
            [FieldOffset(3)]
            internal byte s_b4;

            [FieldOffset(0)]
            internal ushort s_w1;
            [FieldOffset(2)]
            internal ushort s_w2;

            [FieldOffset(0)]
            internal uint S_addr;

            /// <summary>
            /// can be used for most tcp & ip code
            /// </summary>
            internal uint s_addr
            {
                get { return S_addr; }
            }

            /// <summary>
            /// host on imp
            /// </summary>
            internal byte s_host
            {
                get { return s_b2; }
            }

            /// <summary>
            /// network
            /// </summary>
            internal byte s_net
            {
                get { return s_b1; }
            }

            /// <summary>
            /// imp
            /// </summary>
            internal ushort s_imp
            {
                get { return s_w2; }
            }

            /// <summary>
            /// imp #
            /// </summary>
            internal byte s_impno
            {
                get { return s_b4; }
            }

            /// <summary>
            /// logical host
            /// </summary>
            internal byte s_lh
            {
                get { return s_b3; }
            }
        }
    }
}
