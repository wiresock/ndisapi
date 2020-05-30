/*************************************************************************/
/*                                                                       */
/* Copyright (c) 2000-2013 NT KERNEL RESOURCES, All Rights Reserved.     */
/* http://www.ntkernel.com                                               */
/*																		 */
/* Description: WinpkFilter C# interface	    						 */
/*************************************************************************/

using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NdisApiWrapper
{
    public static class Ndisapi
    {
        // Some size constants
        public const int ADAPTER_NAME_SIZE = 256;
        public const int ADAPTER_LIST_SIZE = 32;
        public const int ETHER_ADDR_LENGTH = 6;
        public const int MAX_ETHER_FRAME = 1514;

        // Adapter flags
        public const uint MSTCP_FLAG_SENT_TUNNEL = 0x00000001;	// Receive packets sent by MSTCP
        public const uint MSTCP_FLAG_RECV_TUNNEL = 0x00000002;	// Receive packets instead MSTCP
        public const uint MSTCP_FLAG_SENT_LISTEN = 0x00000004;	// Receive packets sent by MSTCP, original ones delivered to the network
        public const uint MSTCP_FLAG_RECV_LISTEN = 0x00000008;	// Receive packets received by MSTCP
        public const uint MSTCP_FLAG_FILTER_DIRECT = 0x00000010;	// In promiscuous mode TCP/IP stack receives all
        // all packets in the ethernet segment, to prevent this set this flag
        // All packets with destination MAC different from FF-FF-FF-FF-FF-FF and
        // network interface current MAC will be blocked

        // By default loopback packets are passed to original MSTCP handlers without processing,
        // to change this behavior use the flags below
        public const uint MSTCP_FLAG_LOOPBACK_FILTER = 0x00000020; // Pass loopback packet for processing 
        public const uint MSTCP_FLAG_LOOPBACK_BLOCK = 0x00000040; // Silently drop loopback packets, this flag
        // is recommended for usage in combination with 
        // promiscuous mode

        // Device flags for intermediate buffer
        public const uint PACKET_FLAG_ON_SEND = 0x00000001;
        public const uint PACKET_FLAG_ON_RECEIVE = 0x00000002;

        // WAN connections relative constants
        public const int RAS_LINK_BUFFER_LENGTH = 1024;
        public const int RAS_LINKS_MAX = 256;

        // ETH_802_3_FILTER flags
        public const uint ETH_802_3_SRC_ADDRESS = 0x00000001;
        public const uint ETH_802_3_DEST_ADDRESS = 0x00000002;
        public const uint ETH_802_3_PROTOCOL = 0x00000004;

        // IP_V4_FILTER flags
        public const uint IP_V4_FILTER_SRC_ADDRESS = 0x00000001;
        public const uint IP_V4_FILTER_DEST_ADDRESS = 0x00000002;
        public const uint IP_V4_FILTER_PROTOCOL = 0x00000004;

        // IP_V6_FILTER flags
        public const uint IP_V6_FILTER_SRC_ADDRESS = 0x00000001;
        public const uint IP_V6_FILTER_DEST_ADDRESS = 0x00000002;
        public const uint IP_V6_FILTER_PROTOCOL = 0x00000004;

        // Filter select flags
        public const uint ETH_802_3 = 0x00000001;
        public const uint IPV4 = 0x00000001;
        public const uint IPV6 = 0x00000002;
        public const uint TCPUDP = 0x00000001;

        // IP_ADDRESS_V4 select flags
        public const uint IP_SUBNET_V4_TYPE = 0x00000001;
        public const uint IP_RANGE_V4_TYPE = 0x00000002;

        // IP_ADDRESS_V6 select flags
        public const uint IP_SUBNET_V6_TYPE = 0x00000001;
        public const uint IP_RANGE_V6_TYPE = 0x00000002;

        // TCPUDP_FILTER validity flags
        public const uint TCPUDP_SRC_PORT = 0x00000001;
        public const uint TCPUDP_DEST_PORT = 0x00000002;
	public const uint TCPUDP_TCP_FLAGS = 0x00000004;

        // Global filter flags
        public const uint FILTER_PACKET_PASS = 0x00000001; // Pass packet if if matches the filter
        public const uint FILTER_PACKET_DROP = 0x00000002; // Drop packet if it matches the filter
        public const uint FILTER_PACKET_REDIRECT = 0x00000003; // Redirect packet to WinpkFilter client application

        public const uint DATA_LINK_LAYER_VALID = 0x00000001; // Match packet against data link layer filter
        public const uint NETWORK_LAYER_VALID = 0x00000002; // Match packet against network layer filter
        public const uint TRANSPORT_LAYER_VALID = 0x00000004; // Match packet against transport layer filter

        public const String NDISRD_DRIVER_NAME = "NDISRD";

        [DllImport("ndisapi.dll")]
        private static extern IntPtr OpenFilterDriver(byte[] pszFileName);

        /// <summary>
        /// Creates a pointer to the filter driver.
        /// </summary>
        public static IntPtr OpenFilterDriver(String fileName = NDISRD_DRIVER_NAME)
        {
            byte[] arr = Encoding.GetEncoding("ISO-8859-1").GetBytes(fileName);
            return OpenFilterDriver(arr);
        }

        [DllImport("ndisapi.dll")]
        public static extern void CloseFilterDriver(IntPtr hOpen);

        [DllImport("ndisapi.dll")]
        public static extern uint GetDriverVersion(IntPtr hOpen);

        [DllImport("ndisapi.dll")]
        public static extern bool GetTcpipBoundAdaptersInfo(IntPtr hOpen, ref TCP_AdapterList Adapters);

        [DllImport("ndisapi.dll")]
        public static extern bool SendPacketToMstcp(IntPtr hOpen, ref ETH_REQUEST Packet);

        [DllImport("ndisapi.dll")]
        public static extern bool SendPacketToAdapter(IntPtr hOpen, ref ETH_REQUEST Packet);

        [DllImport("ndisapi.dll")]
        public static extern bool ReadPacket(IntPtr hOpen, ref ETH_REQUEST Packet);

        [DllImport("ndisapi.dll")]
        public static extern bool SendPacketsToMstcp(IntPtr hOpen, ref ETH_M_REQUEST Packets);

        [DllImport("ndisapi.dll")]
        public static extern bool SendPacketsToAdapter(IntPtr hOpen, ref ETH_M_REQUEST Packets);

        [DllImport("ndisapi.dll")]
        public static extern bool ReadPackets(IntPtr hOpen, ref ETH_M_REQUEST Packets);

        [DllImport("ndisapi.dll")]
        public static extern bool SetAdapterMode(IntPtr hOpen, ref ADAPTER_MODE Mode);

        [DllImport("ndisapi.dll")]
        public static extern bool GetAdapterMode(IntPtr hOpen, ref ADAPTER_MODE Mode);

        [DllImport("ndisapi.dll")]
        public static extern bool FlushAdapterPacketQueue(IntPtr hOpen, IntPtr hAdapter);

        [DllImport("ndisapi.dll")]
        public static extern bool GetAdapterPacketQueueSize(IntPtr hOpen, IntPtr hAdapter, ref uint dwSize);

        [DllImport("ndisapi.dll")]
        public static extern bool SetPacketEvent(IntPtr hOpen, IntPtr hAdapter, SafeWaitHandle hWin32Event);

        [DllImport("ndisapi.dll")]
        public static extern bool SetWANEvent(IntPtr hOpen, SafeWaitHandle hWin32Event);

        [DllImport("ndisapi.dll")]
        public static extern bool SetAdapterListChangeEvent(IntPtr hOpen, SafeWaitHandle hWin32Event);

        [DllImport("ndisapi.dll")]
        public static extern bool NdisrdRequest(IntPtr hOpen, ref PACKET_OID_DATA OidData, bool Set);

        [DllImport("ndisapi.dll")]
        private static extern bool GetRasLinks(IntPtr hOpen, IntPtr hAdapter, IntPtr pLinks);

        public static RAS_LINKS GetRasLinks(IntPtr hOpen, IntPtr hAdapter)
        {
            IntPtr linksPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(RAS_LINKS)));
            try
            {
                bool result = GetRasLinks(hOpen, hAdapter, linksPtr);

                if (!result) throw new Exception("Cannot get RAS links.");
                return (RAS_LINKS)Marshal.PtrToStructure(linksPtr, typeof(RAS_LINKS));
            }
            finally
            {
                Marshal.FreeHGlobal(linksPtr);
            }
        }

        [DllImport("ndisapi.dll")]
        public static extern bool SetHwPacketFilter(IntPtr hOpen, IntPtr hAdapter, uint Filter);

        [DllImport("ndisapi.dll")]
        public static extern bool GetHwPacketFilter(IntPtr hOpen, IntPtr hAdapter, ref uint pFilter);

        [DllImport("ndisapi.dll")]
        public static extern bool SetPacketFilterTable(IntPtr hOpen, ref STATIC_FILTER_TABLE pFilterList);

        [DllImport("ndisapi.dll")]
        public static extern bool ResetPacketFilterTable(IntPtr hOpen);

        [DllImport("ndisapi.dll")]
        public static extern bool GetPacketFilterTableSize(IntPtr hOpen, ref uint pdwTableSize);

        [DllImport("ndisapi.dll")]
        public static extern bool GetPacketFilterTable(IntPtr hOpen, ref STATIC_FILTER_TABLE pFilterList);

        [DllImport("ndisapi.dll")]
        public static extern bool GetPacketFilterTableResetStats(IntPtr hOpen, ref STATIC_FILTER_TABLE pFilterList);

        [DllImport("ndisapi.dll")]
        public static extern uint GetMTUDecrement();

        [DllImport("ndisapi.dll")]
        public static extern bool SetMTUDecrement(uint dwMTUDecrement);

        [DllImport("ndisapi.dll")]
        public static extern uint GetAdaptersStartupMode();

        [DllImport("ndisapi.dll")]
        public static extern bool SetAdaptersStartupMode(uint dwStartupMode);

        [DllImport("ndisapi.dll")]
        public static extern bool IsDriverLoaded(IntPtr hOpen);

        [DllImport("ndisapi.dll")]
        public static extern uint GetBytesReturned(IntPtr hOpen);

        [DllImport("ndisapi.dll")]
        private unsafe static extern bool ConvertWindows2000AdapterName(byte* szAdapterName, byte* szUserFriendlyName, uint dwUserFriendlyNameLength);

        [DllImport("ndisapi.dll")]
        private unsafe static extern bool ConvertWindows9xAdapterName(byte* szAdapterName, byte* szUserFriendlyName, uint dwUserFriendlyNameLength);

        [DllImport("ndisapi.dll")]
        private unsafe static extern bool ConvertWindowsNTAdapterName(byte* szAdapterName, byte* szUserFriendlyName, uint dwUserFriendlyNameLength);

        // Simple wrappers for the rotines above (simplifies usage from C#)
        private static unsafe string ConvertAdapterName(byte* bAdapterName, uint dwPlatformId, uint dwMajorVersion)
        {
            byte[] szAdapterName = new byte[256];
            bool success = false;
            string res = null;
            fixed (byte* pbFriendlyName = szAdapterName)
            {
                if (dwPlatformId == 2/*VER_PLATFORM_WIN32_NT*/)
                {
                    if (dwMajorVersion > 4)
                    {
                        // Windows 2000 or XP
                        success = ConvertWindows2000AdapterName(bAdapterName, pbFriendlyName, (uint)szAdapterName.Length);
                    }
                    else if (dwMajorVersion == 4)
                    {
                        // Windows NT 4.0	
                        success = ConvertWindowsNTAdapterName(bAdapterName, pbFriendlyName, (uint)szAdapterName.Length);
                    }
                }
                else
                {
                    // Windows 9x/ME
                    success = ConvertWindows9xAdapterName(bAdapterName, pbFriendlyName, (uint)szAdapterName.Length);
                }
                if (success)
                {
                    int indexOfZero = 0;
                    while (indexOfZero < 256 && szAdapterName[indexOfZero] != 0)
                        ++indexOfZero;
                    res = Encoding.Default.GetString(szAdapterName, 0, indexOfZero);
                }
            }
            return res;
        }

        [Obsolete("Use TCP_AdapterList.GetName() instead.")]
        public static unsafe string ConvertAdapterName(byte[] bAdapterName, int iNameStart, uint dwPlatformId, uint dwMajorVersion)
        {
            fixed (byte* tmp = &bAdapterName[iNameStart])
            {
                return ConvertAdapterName(tmp, dwPlatformId, dwMajorVersion);
            }
        }

    }

    /* Specify here packed structures for data exchange with driver */
    /*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    //
    // TCP_AdapterList structure used for requesting information about currently bound TCPIP adapters
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TCP_AdapterList
    {
        public uint m_nAdapterCount; // Number of adapters
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ADAPTER_LIST_SIZE * Ndisapi.ADAPTER_NAME_SIZE)]
        public byte[] m_szAdapterNameList; // Array of adapter names
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ADAPTER_LIST_SIZE)]
        public IntPtr[] m_nAdapterHandle; // Array of adapter handles, this are key handles for any adapter relative operation 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ADAPTER_LIST_SIZE)]
        public uint[] m_nAdapterMediumList; // List of adapter mediums
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ADAPTER_LIST_SIZE * Ndisapi.ETHER_ADDR_LENGTH)]
        public byte[] m_czCurrentAddress; // current (configured) ethernet address
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ADAPTER_LIST_SIZE)]
        public ushort[] m_usMTU; // current adapter MTU

        /// <summary>
        /// Returns adapter's internal name.
        /// </summary>
        public string GetInternalName(int adapterIndex)
        {
            string internalAdapterName = Encoding.ASCII.GetString(m_szAdapterNameList, adapterIndex * 256, 256);
            int i = internalAdapterName.IndexOf((char)0);
            return i >= 0 ? internalAdapterName.Substring(0, i) : internalAdapterName;
        }

        /// <summary>
        /// Returns adapter's name, as visible to user in Windows Control Panel.
        /// </summary>
        /// <param name="adapterIndex"></param>
        /// <returns></returns>
        public string GetName(int adapterIndex)
        {
            OSVERSIONINFO versionInfo = OSVERSIONINFO.GetVersion();

#pragma warning disable 612,618
            return Ndisapi.ConvertAdapterName(
                m_szAdapterNameList, 
                adapterIndex * 256, 
                (uint)versionInfo.dwPlatformId, 
                (uint)versionInfo.dwMajorVersion);
#pragma warning restore 612,618
        }

        /// <summary>
        /// Returns the MAC address of the adapter, as byte array.
        /// </summary>
        public byte[] GetMacAddress(int adapterIndex)
        {
            return new[]
                       {
                           m_czCurrentAddress[adapterIndex*Ndisapi.ETHER_ADDR_LENGTH],
                           m_czCurrentAddress[adapterIndex*Ndisapi.ETHER_ADDR_LENGTH + 1],
                           m_czCurrentAddress[adapterIndex*Ndisapi.ETHER_ADDR_LENGTH + 2],
                           m_czCurrentAddress[adapterIndex*Ndisapi.ETHER_ADDR_LENGTH + 3],
                           m_czCurrentAddress[adapterIndex*Ndisapi.ETHER_ADDR_LENGTH + 4],
                           m_czCurrentAddress[adapterIndex*Ndisapi.ETHER_ADDR_LENGTH + 5]
                       };
        }
        
        /// <summary>
        /// Returns the MAC address of the adapter, as human readable string.
        /// </summary>
        public string GetMacAddressStr(int adapterIndex)
        {
            var mac = GetMacAddress(adapterIndex);
            return String.Format( "{0:X2}{1:X2}{2:X2}{3:X2}{4:X2}{5:X2}",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        
    }

    //
    // INTERMEDIATE_BUFFER contains packet buffer, packet NDIS flags, WinpkFilter specific flags
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LIST_ENTRY
    {
        public IntPtr Flink;
        public IntPtr Blink;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct INTERMEDIATE_BUFFER
    {
        public LIST_ENTRY m_qLink;
        public uint m_dwDeviceFlags;
        public uint m_Length;
        public uint m_Flags;
        public uint m_8021q;
	    public uint m_FilterID;
	    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
	    public uint[] m_Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.MAX_ETHER_FRAME)]
        public byte[] m_IBuffer;
    }

    //
    // NDISRD_ETH_Packet is a container for INTERMEDIATE_BUFFER pointer
    // This structure can be extended in the future versions
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NDISRD_ETH_Packet
    {
        public IntPtr Buffer;
    }

    //
    // ETH_REQUEST used for passing the "read packet" request to driver
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ETH_REQUEST
    {
        public IntPtr hAdapterHandle;
        public NDISRD_ETH_Packet EthPacket;
    }

    //
    // ETH_M_REQUEST used for passing the blocks of packets to and from the driver
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ETH_M_REQUEST
    {
        public IntPtr hAdapterHandle;
        public uint dwPacketsNumber;
        public uint dwPacketsSuccess;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)] // For easier marshalling used the fixed size of the array, change if you plan to read packets by other chunks
        public NDISRD_ETH_Packet[] EthPacket;
    }

    //
    // ADAPTER_MODE used for setting adapter mode
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ADAPTER_MODE
    {
        public IntPtr hAdapterHandle;
        public uint dwFlags;
    }

    //
    // PACKET_OID_DATA used for passing NDIS_REQUEST to driver
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct PACKET_OID_DATA
    {
        public IntPtr hAdapterHandle;
        public uint Oid;
        public uint Length;
        
        /// <summary>
        /// Use GetData() to access this field.
        /// </summary>
        public byte* Data;

        public byte[] GetData()
        {
            var ptr = Marshal.AllocHGlobal(sizeof(PACKET_OID_DATA));
            try
            {
                Marshal.StructureToPtr(this, ptr, false);
                var intPtr = (IntPtr)(ptr.ToInt64() + Marshal.OffsetOf(typeof(PACKET_OID_DATA), "Data").ToInt64());
                var buffer = new byte[Length];
                Marshal.Copy(intPtr, buffer, 0, (int)Length);

                return buffer;
            }
            finally
            {
                Marshal.DestroyStructure(ptr, typeof(PACKET_OID_DATA));
            }
        }
    }

    //
    // Getting WAN links definitions
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RAS_LINK_INFO
    {
        public uint LinkSpeed;	// Specifies the speed of the link, in units of 100 bps.
        // Zero indicates no change from the speed returned when the protocol called NdisRequest with OID_GEN_LINK_SPEED. 
        public uint MaximumTotalSize;	// Specifies the maximum number of bytes per packet that the protocol can send over the network.
        // Zero indicates no change from the value returned when the protocol called NdisRequest with OID_GEN_MAXIMUM_TOTAL_SIZE. 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ETHER_ADDR_LENGTH)]
        public byte[] RemoteAddress;	// Represents the address of the remote node on the link in Ethernet-style format. NDISWAN supplies this value.
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ETHER_ADDR_LENGTH)]
        public byte[] LocalAddress;	// Represents the protocol-determined context for indications on this link in Ethernet-style format.
        public uint ProtocolBufferLength;// Specifies the number of bytes in the buffer at ProtocolBuffer
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.RAS_LINK_BUFFER_LENGTH)]
        public byte[] ProtocolBuffer; // Containing protocol-specific information supplied by a higher-level component that makes connections through NDISWAN
        // to the appropriate protocol(s). Maximum size is 600 bytes (on Windows Vista)
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RAS_LINKS
    {
        public uint nNumberOfLinks;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.RAS_LINKS_MAX)]
        RAS_LINK_INFO[] RasLinks;
    }

    //
    // Packet filter definitions
    //

    //
    // Ethernet 802.3 filter type
    //

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ETH_802_3_FILTER
    {
        public uint m_ValidFields;						    // Specifies which of the fileds below contain valid values and should be matched against the packet
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ETHER_ADDR_LENGTH)]
        public byte[] m_SrcAddress;                           // Source MAC address
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ndisapi.ETHER_ADDR_LENGTH)]
        public byte[] m_DestAddress;                          // Destination MAC address
        public ushort m_Protocol;							    // EtherType
        public ushort Padding;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP_SUBNET_V4
    {
        public uint m_Ip; // IPv4 address expressed as uint
        public uint m_IpMask; // IPv4 mask expressed as uint
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP_RANGE_V4
    {
        public uint m_StartIp; // IPv4 address expressed as uint
        public uint m_EndIp; // IPv4 address expressed as uint
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IP_ADDRESS_V4
    {
        [FieldOffset(0)]
        public uint m_AddressType; // Specifies which of the IP v4 address types is used below
        [FieldOffset(4)]
        public IP_SUBNET_V4 m_IpSubnet;
        [FieldOffset(4)]
        public IP_RANGE_V4 m_IpRange;
    }

    //
    // IP version 4 filter type
    //

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP_V4_FILTER
    {
        public uint m_ValidFields;	// Specifies which of the fileds below contain valid values and should be matched against the packet
        public IP_ADDRESS_V4 m_SrcAddress;	// IP v4 source address
        public IP_ADDRESS_V4 m_DestAddress;	// IP v4 destination address
        public byte m_Protocol;		// Specifies next protocol
        public unsafe fixed byte Padding[3];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IN6_ADDR
    {
        /// <summary>
        /// Initializes the structure from a 16 bytes array
        /// </summary>
        /// <param name="byteArray"></param>
        public IN6_ADDR(byte[] byteArray)
            : this()
        {
            b0 = byteArray[0];
            b1 = byteArray[1];
            b2 = byteArray[2];
            b3 = byteArray[3];
            b4 = byteArray[4];
            b5 = byteArray[5];
            b6 = byteArray[6];
            b7 = byteArray[7];
            b8 = byteArray[8];
            b9 = byteArray[9];
            b10 = byteArray[10];
            b11 = byteArray[11];
            b12 = byteArray[12];
            b13 = byteArray[13];
            b14 = byteArray[14];
            b15 = byteArray[15];
        }

        public byte b0;
        public byte b1;
        public byte b2;
        public byte b3;
        public byte b4;
        public byte b5;
        public byte b6;
        public byte b7;
        public byte b8;
        public byte b9;
        public byte b10;
        public byte b11;
        public byte b12;
        public byte b13;
        public byte b14;
        public byte b15;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IP_SUBNET_V6
    {
        [FieldOffset(0)]
        public IN6_ADDR m_Ip; // IPv6 address
        [FieldOffset(16)]
        public IN6_ADDR m_IpMask; // IPv6 mask
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP_RANGE_V6
    {
        public IN6_ADDR m_StartIp; // IPv6 address
        public IN6_ADDR m_EndIp; // IPv6 address
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IP_ADDRESS_V6
    {

        [FieldOffset(0)]
        public uint m_AddressType; // Specifies which of the IP v6 address types is used below
        [FieldOffset(4)]
        public IP_SUBNET_V6 m_IpSubnet;
        [FieldOffset(4)]
        public IP_RANGE_V6 m_IpRange;

    }

    //
    // IP version 6 filter type
    //

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IP_V6_FILTER
    {

        public uint m_ValidFields;	// Specifies which of the fileds below contain valid values and should be matched against the packet
        public IP_ADDRESS_V6 m_SrcAddress;	// IP v6 source address
        public IP_ADDRESS_V6 m_DestAddress;	// IP v6 destination address
        public byte m_Protocol;		// Specifies next protocol
        public unsafe fixed byte Padding[3];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PORT_RANGE
    {
        public ushort m_StartRange;
        public ushort m_EndRange;
    }

    //
    // TCP & UDP filter
    //

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TCPUDP_FILTER
    {
        public uint m_ValidFields;	// Specifies which of the fileds below contain valid values and should be matched against the packet
        public PORT_RANGE m_SourcePort;	// Source port
        public PORT_RANGE m_DestPort;	// Destination port
	    public byte m_TCPFlags;	// TCP flags combination
    }

    //
    // Represents data link layer (OSI-7) filter level
    //

    // Weird, but I can't create the same binary structure with Explicit
    // "because it contains an object field at offset 4 that is incorrectly aligned or overlapped by a non-object field"
    // It wants the second field to be at 8 offset, while Sequental places it on 4 bytes offset

    /*[StructLayout(LayoutKind.Explicit, Pack=8)]
    public struct DATA_LINK_LAYER_FILTER
    {
        [FieldOffset(0)]
        public uint            m_dwUnionSelector;
        [FieldOffset(4)]
	    public ETH_802_3_FILTER m_Eth8023Filter;
	}*/

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DATA_LINK_LAYER_FILTER
    {
        public uint m_dwUnionSelector;
        public ETH_802_3_FILTER m_Eth8023Filter;
    }

    //
    // Represents network layer (OSI-7) filter level
    //

    /*[StructLayout(LayoutKind.Explicit, Pack=8)]
    public struct NETWORK_LAYER_FILTER
    {
        [System.Runtime.InteropServices.FieldOffset(0)]
        public uint        m_dwUnionSelector;
        [System.Runtime.InteropServices.FieldOffset(4)]
        public IP_V4_FILTER m_IPv4;
        [System.Runtime.InteropServices.FieldOffset(4)]
        public IP_V6_FILTER m_IPv6;
    }*/

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct NETWORK_LAYER_FILTER
    {
        [FieldOffset(0)]
        public uint m_dwUnionSelector;
        [FieldOffset(4)]
        public IP_V4_FILTER m_IPv4;
        [FieldOffset(4)]
        public IP_V6_FILTER m_IPv6;
    }

    // Represents transport layer (OSI-7) filter level

    /*[StructLayout(LayoutKind.Explicit, Pack=8)]
    public struct TRANSPORT_LAYER_FILTER
    {
        [System.Runtime.InteropServices.FieldOffset(0)]
        public uint            m_dwUnionSelector;
        [System.Runtime.InteropServices.FieldOffset(4)]
        public TCPUDP_FILTER    m_TcpUdp;
    }*/

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TRANSPORT_LAYER_FILTER
    {
        public uint m_dwUnionSelector;
        public TCPUDP_FILTER m_TcpUdp;
    }

    //
    // Defines static filter entry
    //

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct STATIC_FILTER
    {
        public ulong m_Adapter;          // Adapter handle extended to 64 bit size for structure compatibility across x64 and x86
        public uint m_dwDirectionFlags;	// PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE
        public uint m_FilterAction;		// FILTER_PACKET_XXX
        public uint m_ValidFields;		// Specifies which of the fileds below contain valid values and should be matched against the packet

        // Statistics for the filter
        public uint m_LastReset;		// Time of the last counters reset (in seconds passed since 1 Jan 1980)
        public ulong m_PacketsIn;		// Incoming packets passed through this filter
        public ulong m_BytesIn;			// Incoming bytes passed through this filter
        public ulong m_PacketsOut;		// Outgoing packets passed through this filter
        public ulong m_BytesOut;		// Outgoing bytes passed through this filter

        public DATA_LINK_LAYER_FILTER m_DataLinkFilter;
        public NETWORK_LAYER_FILTER m_NetworkFilter;
        public TRANSPORT_LAYER_FILTER m_TransportFilter;
    }

    //
    // Static filters table to be passed to WinpkFilter driver
    //
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct STATIC_FILTER_TABLE
    {
        public uint m_TableSize; // number of STATIC_FILTER entries
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)] // For convinience (easier marshalling to unmanaged memory) the size of the array is fixed to 256 entries
        public STATIC_FILTER[] m_StaticFilters;            // Feel free to change this value if you need more filter entries
    }
}