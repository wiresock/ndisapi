/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  Program.cs                                              */
/*                                                                       */
/* Abstract: Defines the entry point for the console application.        */
/*                                                                       */
/* Environment:                                                          */
/*   .NET User mode                                                      */
/*                                                                       */
/*************************************************************************/

using System;
using System.Collections.Generic;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NdisApi;
using PacketDotNet;
using ProtocolType = PacketDotNet.ProtocolType;

namespace TestDotNet
{
    // Physical Medium Type definitions. Used with OID_GEN_PHYSICAL_MEDIUM.
    //
    enum NdisPhysicalMedium
    {
        NdisPhysicalMediumUnspecified,
	    NdisPhysicalMediumWirelessLan,
	    NdisPhysicalMediumCableModem,
	    NdisPhysicalMediumPhoneLine,
	    NdisPhysicalMediumPowerLine,
	    NdisPhysicalMediumDSL,      // includes ADSL and UADSL (G.Lite)
	    NdisPhysicalMediumFibreChannel,
	    NdisPhysicalMedium1394,
	    NdisPhysicalMediumWirelessWan,
	    NdisPhysicalMediumNative802_11,
	    NdisPhysicalMediumBluetooth,
	    NdisPhysicalMediumInfiniband,
	    NdisPhysicalMediumWiMax,
	    NdisPhysicalMediumUWB,
	    NdisPhysicalMedium802_3,
	    NdisPhysicalMedium802_5,
	    NdisPhysicalMediumIrda,
	    NdisPhysicalMediumWiredWAN,
	    NdisPhysicalMediumWiredCoWan,
	    NdisPhysicalMediumOther,
	    NdisPhysicalMediumMax       // Not a real physical type, defined as an upper-bound
    };
    class Program
    {
        // used to stop the capture loop
        private static Boolean stopCapturing = false;
        private static ManualResetEvent packetEvent = new ManualResetEvent(false);

        // Useed for sending NDIS request to the network interface
        private const UInt32 OID_802_3_CURRENT_ADDRESS = 0x01010102;
        private const UInt32 OID_GEN_MAXIMUM_TOTAL_SIZE = 0x00010111;
        private const UInt32 OID_GEN_PHYSICAL_MEDIUM = 0x00010202;

        private static NdisApiDotNet ndisapi = new NdisApiDotNet(null);
 
        static void Main(string[] args)
        {
            if (!ndisapi.IsDriverLoaded())
            {
                Console.WriteLine("WinpkFilter driver is not loaded. Exiting.");
                return;
            }

            UInt32 driverVersion = ndisapi.GetVersion();
            UInt32 majorVersion = (driverVersion & (0xF000)) >> 12;
            UInt32 minorVersion1 = (driverVersion & (0xFF000000)) >> 24;
            UInt32 minorVersion2 = (driverVersion & (0xFF0000)) >> 16;

            if (ndisapi != null)
                Console.WriteLine($"Detected Windows Packet Filter version {majorVersion}.{minorVersion1}.{minorVersion2}");

            Console.WriteLine();

            var adapterList = ndisapi.GetTcpipBoundAdaptersInfo();

            if (!adapterList.Item1)
            {
                Console.WriteLine("WinpkFilter failed to query active interfaces. Exiting.");
                return;
            }

            if (adapterList.Item2.Count > 0)
                Console.WriteLine("Available network interfaces: ");

            Console.WriteLine();

            int counter = 0;
            foreach (var adapter in adapterList.Item2)
            {
                Console.WriteLine($"{++counter}) {adapter.FriendlyName}");
                Console.WriteLine($"\t Internal name: {adapter.Name}");
                Console.WriteLine($"\t Handle: {adapter.Handle.ToString("x")}");
                Console.WriteLine($"\t MAC: {adapter.CurrentAddress}");
                Console.WriteLine($"\t Medium: {adapter.Medium}");
                Console.WriteLine($"\t MTU: {adapter.Mtu}");

                if(adapter.Medium == NDIS_MEDIUM.NdisMediumWan)
                {
                    var rasLinkInfoList = ndisapi.GetRasLinks(adapter.Handle);

                    if (rasLinkInfoList.Item1 && (rasLinkInfoList.Item2.Count > 0))
                    {
                        foreach (var e in rasLinkInfoList.Item2)
                        {
                            Console.WriteLine($"----------------------------------------------------------------");
                            Console.WriteLine($"\t\tLinkSpeed = {e.LinkSpeed}");
                            Console.WriteLine($"\t\tMTU: {e.MaximumTotalSize}");
                            Console.WriteLine($"\t\tLocalAddress: {e.LocalAddress}");
                            Console.WriteLine($"\t\tRemoteAddress: {e.RemoteAddress}");

                            Byte[] ipAddress = new Byte[4];
                            Array.Copy(e.ProtocolBuffer, 584, ipAddress, 0, 4);
                            IPAddress ipV4 = new IPAddress(ipAddress);
                            Array.Copy(e.ProtocolBuffer, 588, ipAddress, 0, 4);
                            IPAddress ipMaskV4 = new IPAddress(ipAddress);

                            Console.WriteLine($"\t\tIPv4: {ipV4} Mask: {ipMaskV4}");
                            Console.WriteLine($"----------------------------------------------------------------");
                        }
                    }
                }

                Console.WriteLine();
            }

            Console.Write("Select network interface: ");
            int index = Convert.ToInt32(Console.ReadLine());

            if (index > adapterList.Item2.Count)
            {
                Console.WriteLine($"Wrong interface index {index}");
                return;
            }

            #region Testing NdisrdRequest API call
            Console.WriteLine();
            Console.WriteLine($"Probing NDIS requests on: {adapterList.Item2[index - 1].FriendlyName}:");
            Console.WriteLine();

            PacketOidData oidRequest = new PacketOidData();
            oidRequest.Adapter = adapterList.Item2[index - 1].Handle;
            oidRequest.Oid = OID_802_3_CURRENT_ADDRESS;
            oidRequest.Data = new byte[6];

            if(ndisapi.NdisrdRequest(oidRequest, false))
                Console.WriteLine($@"OID_802_3_CURRENT_ADDRESS:     Status = OK     Value: {new PhysicalAddress(oidRequest.Data)}");
            else
                Console.WriteLine($@"OID_802_3_CURRENT_ADDRESS:     Status = FAILED");

            oidRequest.Oid = OID_GEN_MAXIMUM_TOTAL_SIZE;
            oidRequest.Data = new byte[4];

            if(ndisapi.NdisrdRequest(oidRequest, false))
                Console.WriteLine($@"OID_GEN_MAXIMUM_TOTAL_SIZE:    Status = OK     Value: {BitConverter.ToUInt32(oidRequest.Data, 0)}");
            else
                Console.WriteLine($@"OID_GEN_MAXIMUM_TOTAL_SIZE:    Status = FAILED");

            oidRequest.Oid = OID_GEN_PHYSICAL_MEDIUM;

            if(ndisapi.NdisrdRequest(oidRequest, false))
                Console.WriteLine($@"OID_GEN_PHYSICAL_MEDIUM:       Status = OK     Value: {(NdisPhysicalMedium)BitConverter.ToUInt32(oidRequest.Data, 0)}");
            else
                Console.WriteLine($@"OID_GEN_PHYSICAL_MEDIUM:       Status = FAILED");
            #endregion

            #region Testing static filters
            Console.WriteLine();
            Console.WriteLine("Please select the static filters set to use:");
            Console.WriteLine();
            Console.WriteLine(@"1 - IPv4 DNS filter:    Redirect and dump only IPv4 DNS packets for processing in user mode.");
            Console.WriteLine(@"2 - HTTP filter:        Redirect and dump only HTTP(TCP port 80) packets for processing in user mode.");
            Console.WriteLine(@"3 - FQDN filter:        Redirect and dump only packets destined to/from selected domain name.");
            Console.WriteLine(@"4 - Default filter:     Redirect and dump all network packets.");
            Console.WriteLine(@"5 - Silent default:     Redirect all network packets. Zero output (performance test option).");
            Console.WriteLine();
            Console.Write("Select filter option: ");

            int option = Convert.ToInt32(Console.ReadLine());

            if (option > 5)
            {
                Console.WriteLine($"Wrong filter option {option}");
                return;
            }

            bool dumpPackets = true;

            switch(option)
            {
                case 1:
                    LoadIpv4DnsFilter(adapterList.Item2[index - 1].Handle);
                    break;
                case 2:
                    LoadHttpFilter(adapterList.Item2[index - 1].Handle);
                    break;
                case 3:
                    Console.Write("Enter FQDN: ");
                    LoadFqdnFilter(adapterList.Item2[index - 1].Handle, Console.ReadLine());
                    break;
                case 4:
                    // Do nothing, this is a default behaviour
                    break;
                case 5:
                    dumpPackets = false;
                    break;
                default:
                    Console.WriteLine("Wrong filter option. Exiting...");
                    return;
            }
            #endregion

            // Register a cancel handler that lets us break out of our capture loop
            Console.CancelKeyPress += HandleCancelKeyPress;

            ndisapi.SetAdapterMode(
                adapterList.Item2[index - 1].Handle,
                MSTCP_FLAGS.MSTCP_FLAG_TUNNEL
                );

            ndisapi.SetPacketEvent(adapterList.Item2[index - 1].Handle, packetEvent);

            Console.WriteLine($"-- Filtering on {adapterList.Item2[index - 1].FriendlyName}, hit 'ctrl-c' to stop...");

            // Lists for re-injecting packets
            List<RawPacket> toAdapter = new List<RawPacket>();
            List<RawPacket> toMstcp = new List<RawPacket>();

            // Unmanaged memory resource for sending receiving bulk of packets
            // Maximum number of packets to send/receive = 64
            NdisBufferResource buffer = new NdisBufferResource(64); 

            do {
                packetEvent.WaitOne();
                #region Single packet read/write
                //RawPacket packet = ndisapi.ReadPacket(adapterList[index - 1].Handle);

                //while (packet != null)
                //{
                //    // use PacketDotNet to parse this packet and print out
                //    // its high level information
                //    Packet p = Packet.ParsePacket(LinkLayers.Ethernet, packet.Data);

                //    try
                //    {
                //        Console.WriteLine(p.ToString());
                //    }
                //    catch (Exception)
                //    { }

                //    if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE)
                //    {
                //        ndisapi.SendPacketToMstcp(adapterList[index - 1].Handle, packet);
                //    }
                //    else
                //    {
                //        ndisapi.SendPacketToAdapter(adapterList[index - 1].Handle, packet);
                //    }

                //    packet = ndisapi.ReadPacket(adapterList[index - 1].Handle);
                //};
                #endregion
                #region Bulk of packets read/write

                var packetList = ndisapi.ReadPackets(adapterList.Item2[index - 1].Handle, buffer);

                while (packetList.Item1)
                {
                    foreach (var packet in packetList.Item2)
                    {
                        if (dumpPackets)
                        {
                            Console.WriteLine($"Succesfully read {packetList.Item2.Count} packets from {adapterList.Item2[index - 1].FriendlyName}");
                            try
                            {
                                // Use PacketDotNet to parse this packet and print out
                                // its high level information
                                Packet p = Packet.ParsePacket(LinkLayers.Ethernet, packet.Data);

                                Console.WriteLine(p.ToString());
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"An exeption {ex.Message} occured while trying to parse network packet.");
                            }
                        }

                        // Depending on the packet direction insert it to the appropriate list
                            if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE)
                        {
                            toMstcp.Add(packet);
                        }
                        else
                        {
                            toAdapter.Add(packet);
                        }
                    }

                    if (toMstcp.Count > 0)
                    {
                        // If we have packets to forward upwards the network stack then do it here
                        ndisapi.SendPacketsToMstcp(adapterList.Item2[index - 1].Handle, buffer, toMstcp);
                        toMstcp.Clear();
                    }

                    if (toAdapter.Count > 0)
                    {
                        // If we have packets to forward downwards the network stack then do it here
                        ndisapi.SendPacketsToAdapter(adapterList.Item2[index - 1].Handle, buffer, toAdapter);
                        toAdapter.Clear();
                    }

                    packetList = ndisapi.ReadPackets(adapterList.Item2[index - 1].Handle, buffer);
                };

                #endregion
                packetEvent.Reset();

            } while (!stopCapturing);

            Console.WriteLine("-- Filtering stopped");

            //
            // Release driver and associated resources
            //
            buffer.Dispose();

            ndisapi.SetPacketEvent(adapterList.Item2[index - 1].Handle, null);

            ndisapi.SetAdapterMode(
                adapterList.Item2[index - 1].Handle,
                0
                );

            //
            // Display loaded static filters
            //
            DumpStaticFilters();
        }

        private static bool LoadIpv4DnsFilter(IntPtr adapterHandle)
        {
            var filterList = new List<StaticFilter>(3);

            //
            // Initialize static filters
            //

            // 1.Outgoing DNS requests filter: REDIRECT OUT UDP packets with destination PORT 53
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                null,
                new IpAddressFilter(
                    AddressFamily.InterNetwork,
                    IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_PROTOCOL,
                    null,
                    null,
                    (byte)ProtocolType.Udp
                ),
                new TcpUdpFilter(
                    TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                    new TcpUdpFilter.PortRange { startRange = 0, endRange = 0 },
                    new TcpUdpFilter.PortRange { startRange = 53, endRange = 53 },
                    0)
                ));

            // 2.Incoming DNS requests filter: REDIRECT IN UDP packets with source PORT 53
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                null,
                new IpAddressFilter(
                    AddressFamily.InterNetwork,
                    IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_PROTOCOL,
                    null,
                    null,
                    (byte)ProtocolType.Udp
                ),
                new TcpUdpFilter(
                    TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_SRC_PORT,
                    new TcpUdpFilter.PortRange { startRange = 53, endRange = 53 },
                    new TcpUdpFilter.PortRange { startRange = 0, endRange = 0 },
                    0)
                ));

            // 3.Pass over everything else
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_PASS,
                0,
                null,
                null,
                null
                ));

            // Load static filter into the driver
            return ndisapi.SetPacketFilterTable(filterList);
        }

        private static bool LoadHttpFilter(IntPtr adapterHandle)
        {
            var filterList = new List<StaticFilter>(3);

            //
            // Initialize static filters
            //

            // 1.Outgoing HTTP filter: REDIRECT OUT TCP packets with destination PORT 80
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                null,
                new IpAddressFilter(
                    AddressFamily.InterNetwork,
                    IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_PROTOCOL,
                    null,
                    null,
                    (byte)ProtocolType.Tcp
                ),
                new TcpUdpFilter(
                    TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                    new TcpUdpFilter.PortRange { startRange = 0, endRange = 0 },
                    new TcpUdpFilter.PortRange { startRange = 80, endRange = 80 },
                    0)
                ));

            // 2.Incoming HTTP filter: REDIRECT IN TCP packets with source PORT 80
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                null,
                new IpAddressFilter(
                    AddressFamily.InterNetwork,
                    IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_PROTOCOL,
                    null,
                    null,
                    (byte)ProtocolType.Tcp
                ),
                new TcpUdpFilter(
                    TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_SRC_PORT,
                    new TcpUdpFilter.PortRange { startRange = 80, endRange = 80 },
                    new TcpUdpFilter.PortRange { startRange = 0, endRange = 0 },
                    0)
                ));

            // 3.Pass over everything else
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND | PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_PASS,
                0,
                null,
                null,
                null
                ));

            // Load static filter into the driver
            return ndisapi.SetPacketFilterTable(filterList);
        }

        private static bool LoadFqdnFilter(IntPtr adapterHandle, string domainName)
        {
            IPHostEntry hostEntry;

            try
            {
                hostEntry = Dns.GetHostEntry(domainName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An exeption {ex.Message} occured while trying to resolve {domainName}");
                return false;
            }

            var filterList = new List<StaticFilter>(3);

            //
            // Initialize static filters
            //

            if(hostEntry.AddressList.Length > 0)
            {
                Console.WriteLine($"The following IP addresses match {domainName}:");

                for (int i = 0; i < hostEntry.AddressList.Length; i++)
                {
                    Console.WriteLine(hostEntry.AddressList[i]);

                    // Add pair of filters for incoming and outgoing packets for each IP address
                    filterList.Add(
                         new StaticFilter(
                         adapterHandle,
                         PACKET_FLAG.PACKET_FLAG_ON_SEND,
                         StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                         StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID,
                         null,
                         new IpAddressFilter(
                             hostEntry.AddressList[i].AddressFamily,
                             IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_DEST_ADDRESS,
                             null,
                             new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, hostEntry.AddressList[i], hostEntry.AddressList[i]),
                             0
                         ),
                         null
                         ));

                    filterList.Add(
                       new StaticFilter(
                       adapterHandle,
                       PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                       StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                       StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID,
                       null,
                       new IpAddressFilter(
                           hostEntry.AddressList[i].AddressFamily,
                           IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_SRC_ADDRESS,
                           new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, hostEntry.AddressList[i], hostEntry.AddressList[i]),
                           null,
                           0
                       ),
                       null
                       ));
                }
            }
            else
            {
                Console.WriteLine($"No associated IP addresses are found for the domain name {domainName}");
            }

            // Pass over everything else
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND | PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_PASS,
                0,
                null,
                null,
                null
                ));

            // Load static filter into the driver
            return ndisapi.SetPacketFilterTable(filterList);
        }

        static void HandleCancelKeyPress(Object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("-- Stopping packet filter");
            stopCapturing = true;
            packetEvent.Set();

            e.Cancel = true;
        }

        private static void DumpStaticFilters()
        {
            // Query current filters and print the stats
            var currentFilters = ndisapi.GetPacketFilterTable();

            if (currentFilters.Item1)
            {
                if (currentFilters.Item2.Count > 0)
                {
                    Console.WriteLine($"{currentFilters.Item2.Count} static filters were loaded into the driver:");
                    Console.WriteLine();

                    foreach (var filter in currentFilters.Item2)
                    {
                        Console.WriteLine($"{filter.ToString()}");
                        Console.WriteLine();
                    }
                }
                else
                {
                    Console.WriteLine("No static filters were loaded into the driver");
                }
            }
            else
            {
                Console.WriteLine("Failed to query filters stats from the driver");
            }
        }
    }
}
