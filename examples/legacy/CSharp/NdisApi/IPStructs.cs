using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NdisApiWrapper
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct EtherAddr
    {
        public byte b1;
        public byte b2;
        public byte b3;
        public byte b4;
        public byte b5;
        public byte b6;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ETHER_HEADER
    {
        public EtherAddr dest;
        public EtherAddr source;
        public ushort proto;

        public const int ETH_ALEN = 6;
        public const int ETH_P_IP = 0x0800;	        /* Internet Protocol packet	*/
        public const int ETH_P_RARP = 0x8035;		/* Reverse Addr Res packet	*/
        public const int ETH_P_ARP = 0x0806;		/* Address Resolution packet	*/
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IPHeader
    {
        /// <summary>
        /// header length : 4, version :4
        /// </summary>
        public byte IPLenVer;
        /// <summary>
        /// type of service
        /// </summary>
        public byte TOS;
        /// <summary>
        /// Total length
        /// </summary>
        public ushort Len;
        /// <summary>
        /// Identification
        /// </summary>
        public ushort ID;
        /// <summary>
        /// Fragment offset field
        /// </summary>
        public ushort Off;
        /// <summary>
        /// Time to live
        /// </summary>
        public byte TTL;
        /// <summary>
        /// Protocol
        /// </summary>
        public byte P;
        /// <summary>
        /// Checksum
        /// </summary>
        public ushort Sum;
        public uint Src;
        public uint Dest;

        public const int IP_DF = 0x4000;
        public const int IP_MF = 0x2000;
        public const int ETHER_HEADER_LENGTH = 14;

        public const int IPPROTO_TCP = 6;
        public const int IPPROTO_UDP = 17;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TcpHeader
    {
        public ushort th_sport;
        public ushort th_dport;
        public uint Seq;
        public uint Ack;
        public byte Off;
        public byte Flags;
        public ushort Window;
        public ushort CheckSum;
        public ushort Urp;

        public const int TH_FIN = 0x01;
        public const int TH_SYN = 0x02;
        public const int TH_RST = 0x04;
        public const int TH_PSH = 0x08;
        public const int TH_ACK = 0x10;
        public const int TH_URG = 0x20;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UdpHeader
    {
        public ushort th_sport;		// source port 
        public ushort th_dport;		// destination port 
        public ushort length;			// data length 
        public ushort th_sum;			// checksum 
    };

}
