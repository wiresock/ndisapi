/*************************************************************************/
/*				Copyright (c) 2000-2013 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  PassThru main module                                    */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Net;
using NdisApiWrapper;

namespace PassThru
{
    static class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine(@"Command line syntax:
    PassThru.exe index num
    index - network interface index.
    num - number or packets to filter
    You can use ListAdapters to determine correct index.\n");
                return;
            }
            
            var adapterIndex = uint.Parse(args[0]) - 1;
            var packetsCount = int.Parse(args[1]);

            try
            {
                var driverPtr = Ndisapi.OpenFilterDriver();
                if (!Ndisapi.IsDriverLoaded(driverPtr)) throw new ApplicationException("Cannot load driver");
                    
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

                // Allocate and initialize packet structures
                var request = new ETH_REQUEST();
                var buffer = new INTERMEDIATE_BUFFER();
                var bufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(buffer));

                Win32Api.ZeroMemory(bufferPtr, Marshal.SizeOf(buffer));

                request.hAdapterHandle = adapters.m_nAdapterHandle[adapterIndex];
                request.EthPacket.Buffer = bufferPtr;

                while (packetsCount > 0)
                {
                    manualResetEvent.WaitOne();

                    while (Ndisapi.ReadPacket(driverPtr, ref request))
                    {
                        --packetsCount;

                        buffer = (INTERMEDIATE_BUFFER)Marshal.PtrToStructure(bufferPtr, typeof(INTERMEDIATE_BUFFER));

                        WriteToConsole(buffer, bufferPtr);

                        if (buffer.m_dwDeviceFlags == Ndisapi.PACKET_FLAG_ON_SEND)
                            Ndisapi.SendPacketToAdapter(driverPtr, ref request);
                        else
                            Ndisapi.SendPacketToMstcp(driverPtr, ref request);
                    }

                    manualResetEvent.Reset();
                }
                Marshal.FreeHGlobal(bufferPtr);
                
                Ndisapi.CloseFilterDriver(driverPtr);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
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
    }
}
