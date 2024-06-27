/*************************************************************************/
/*                     Copyright (c) 2000-2024 NT KERNEL                 */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  filter.cpp                                              */
/*                                                                       */
/* Abstract: Example of Using the Windows Packet Filter Static Filters   */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"
TCP_AdapterList      AdList;
DWORD                iIndex;
CNdisApi             api;
ETH_REQUEST          Request;
INTERMEDIATE_BUFFER  PacketBuffer;
HANDLE               hEvent;
PSTATIC_FILTER_TABLE pFilters = NULL;

USHORT htons(USHORT hostshort)
{
    PUCHAR pBuffer = reinterpret_cast<PUCHAR>(&hostshort);
    USHORT nResult = ((pBuffer[0] << 8) & 0xFF00)
        | (pBuffer[1] & 0x00FF);

    return(nResult);
}

ULONG htonl(ULONG hostlong)
{
    ULONG  nResult = hostlong >> 16;
    USHORT upper = static_cast<USHORT>(nResult) & 0x0000FFFF;
    USHORT lower = static_cast<USHORT>(hostlong) & 0x0000FFFF;

    upper = htons(upper);
    lower = htons(lower);

    nResult = 0x10000 * lower + upper;
    return(nResult);
}

#define ntohs(X) htons(X)
#define ntohl(X) htonl(X)

void ReleaseInterface()
{
    // This function releases packets in the adapter queue and stops listening the interface
    ADAPTER_MODE Mode;

    Mode.dwFlags = 0;
    Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

    // Set NULL event to release previously set event object
    api.SetPacketEvent(AdList.m_nAdapterHandle[iIndex], NULL);

    // Close Event
    if (hEvent)
        CloseHandle(hEvent);

    // Set default adapter mode
    api.SetAdapterMode(&Mode);

    // Empty adapter packets queue
    api.FlushAdapterPacketQueue(AdList.m_nAdapterHandle[iIndex]);

    if (pFilters)
        free(pFilters);
}

//
// IPHLP_FindLastHeader parses IP headers until the payload.
// Returns pointer to IP packet payload (TCP, UDP, ICMP, ICMPv6 and etc..)
//
PVOID
    IPHLP_FindLastHeader(
    iphdr_ptr IPHdrPtr,        // pointer to IP header
    unsigned PacketSize,       // size of IP packet in octets
    unsigned char* IPProto     // returns IPPROTO_ value
    )
{
    unsigned char nextHeader = 0;
    ipv6hdr_ptr   IPv6HdrPtr = reinterpret_cast<ipv6hdr_ptr>(IPHdrPtr);
    ipv6ext_ptr   pHeader = NULL;
    void*         theHeader = NULL;

    //
    // Parse IPv4 headers
    //
    if (IPHdrPtr->ip_v == 4)
    {
        nextHeader = IPHdrPtr->ip_p;
        theHeader = (reinterpret_cast<char*>(IPHdrPtr) + IPHdrPtr->ip_hl * 4);

        *IPProto = nextHeader;
        return theHeader;
    }

    //
    // Parse IPv6 headers
    //

    // Check if this IPv6 packet
    if (IPHdrPtr->ip_v != 6)
    {
        *IPProto = nextHeader;
        return NULL;
    }

    // Find the first header
    nextHeader = IPv6HdrPtr->ip6_next;
    pHeader = reinterpret_cast<ipv6ext_ptr>(IPv6HdrPtr + 1);

    // Loop until we find the last IP header
    while (TRUE)
    {
        // Ensure that current header is still within the packet
        if (reinterpret_cast<char*>(pHeader) > reinterpret_cast<char*>(IPv6HdrPtr) + PacketSize - sizeof(ipv6ext))
        {
            *IPProto = nextHeader;
            return NULL;
        }

        switch (nextHeader)
        {
            // Fragmentation
        case IPPROTO_FRAGMENT:
            {
                ipv6ext_frag_ptr pfrag = reinterpret_cast<ipv6ext_frag_ptr>(pHeader);

                // If this isn't the FIRST fragment, there won't be a TCP/UDP header anyway
                if ((pfrag->ip6_offlg & 0xFC) != 0)
                {
                    // The offset is non-zero
                    nextHeader = pfrag->ip6_next;

                    *IPProto = nextHeader;
                    return NULL;
                }

                // Otherwise it's either an entire segment or the first fragment
                nextHeader = pfrag->ip6_next;

                // Return next octet following the fragmentation header
                pHeader = reinterpret_cast<ipv6ext_ptr>(reinterpret_cast<char*>(pHeader) + sizeof(ipv6ext_frag));

                *IPProto = nextHeader;
                return pHeader;
            }

            // Headers we just skip over
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
            nextHeader = pHeader->ip6_next;

            // As per RFC 2460 : ip6ext_len specifies the extended
            // header length, in units of 8 octets *not including* the
            // first 8 octets.

            pHeader = reinterpret_cast<ipv6ext_ptr>(reinterpret_cast<char*>(pHeader) + 8 + (pHeader->ip6_len) * 8);
            break;

        default:
            // No more IPv6 headers to skip
            *IPProto = nextHeader;
            return pHeader;
        }
    }

    *IPProto = nextHeader;
    return theHeader;
}

int main(int argc, char* argv[])
{
    UINT          scena = 0;
    ether_header* pEtherHdr = NULL;
    iphdr_ptr     pIpHdr = NULL;
    tcphdr_ptr    pTcpHdr = NULL;
    udphdr_ptr    pUdpHdr = NULL;
    ipv6hdr_ptr   pIpv6Hdr = NULL;
    unsigned char Ipv6Proto = 0;
    void*         pIpv6ProtoHdr = NULL;

    if (argc < 3)
    {
        printf("Command line syntax:\n\tfilter.exe index scenario \n\tindex - network interface index.\n\tscenario - sample set of filters to load.\n\t[0|1] - 1 to turn filter cache ON\n\t[0|1] - 1 to turn IP fragments cache ON\n\tYou can use ListAdapters to determine correct index.\n");
        printf("Available Scenarios: \n");
        printf("1 - Redirect only IPv4 DNS packets for processing in user mode.\n");
        printf("2 - Redirect only HTTP(TCP port 80) packets for processing in user mode. Both IPv4 and IPv6 protocols.\n");
        printf("3 - Drop all IPv4 ICMP packets. Redirect all other packets to user mode (default behaviour).\n");
        printf("4 - Block IPv4 access to https://www.ntkernel.com. Pass all other packets without processing in user mode. \n");
        printf("5 - Redirect only ARP/RARP packets to user mode. Pass all others. \n");
        printf("6 - Redirect only outgoing ICMP ping request packets to user mode. Pass all others. \n");
        printf("7 - Redirect only outgoing ICMPv6 ping request packets to user mode. Pass all others. \n");
        return 0;
    }

    iIndex = atoi(argv[1]) - 1;
    scena = atoi(argv[2]);

    if(argc > 3)
    {
        if(atoi(argv[3]))
        {
            api.EnablePacketFilterCache();
        }
        else
        {
            api.DisablePacketFilterCache();
        }
    }

    if(argc > 4)
    {
        if(atoi(argv[4]))
        {
            api.EnablePacketFragmentCache();
        }
        else
        {
            api.DisablePacketFragmentCache();
        } 
    }

    if (!api.IsDriverLoaded())
    {
        printf("Driver not installed on this system of failed to load.\n");
        return 0;
    }

    api.GetTcpipBoundAdaptersInfo(&AdList);

    if (iIndex + 1 > AdList.m_nAdapterCount)
    {
        printf("There is no network interface with such index on this system.\n");
        return 0;
    }

    ADAPTER_MODE Mode;

    Mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL;
    Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

    // Create notification event
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    // Set event for helper driver
    if ((!hEvent) || (!api.SetPacketEvent((HANDLE)AdList.m_nAdapterHandle[iIndex], hEvent)))
    {
        printf("Failed to create notification event or set it for driver.\n");
        return 0;
    }

    atexit(ReleaseInterface);

    // Allocate table filters for 10 filters
    DWORD dwTableSize = sizeof(STATIC_FILTER_TABLE) + sizeof(STATIC_FILTER) * 9;
    pFilters = static_cast<PSTATIC_FILTER_TABLE>(malloc(dwTableSize));
    memset(pFilters, 0, dwTableSize);

    switch (scena)
    {
    case 1:
        pFilters->m_TableSize = 3;

        //**************************************************************************************
        // 1. Outgoing DNS requests filter: REDIRECT OUT UDP packets with destination PORT 53
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

        // Network layer filter
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_UDP;

        // Transport layer filter 
        pFilters->m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_DEST_PORT;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 53; // DNS
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 53;

        //****************************************************************************************
        // 2. Incoming DNS responses filter: REDIRECT IN UDP packets with source PORT 53
        // Common values
        pFilters->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[1].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE;

        // Network layer filter
        pFilters->m_StaticFilters[1].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_UDP;

        // Transport layer filter 
        pFilters->m_StaticFilters[1].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_SRC_PORT;
        pFilters->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = 53; // DNS
        pFilters->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = 53;

        //***************************************************************************************
        // 3. Pass all packets (skipped by previous filters) without processing in user mode
        // Common values
        pFilters->m_StaticFilters[2].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[2].m_ValidFields = 0;
        pFilters->m_StaticFilters[2].m_FilterAction = FILTER_PACKET_PASS;
        pFilters->m_StaticFilters[2].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

        break;

    case 2:

        pFilters->m_TableSize = 5;

        //**************************************************************************************
        // 1. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv4
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

        // Network layer filter
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_TCP;

        // Transport layer filter 
        pFilters->m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_DEST_PORT;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 80; // HTTP
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 80;

        //****************************************************************************************
        // 2. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv4
        // Common values
        pFilters->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[1].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE;

        // Network layer filter
        pFilters->m_StaticFilters[1].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[1].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_TCP;

        // Transport layer filter 
        pFilters->m_StaticFilters[1].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_SRC_PORT;
        pFilters->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = 80; // HTTP
        pFilters->m_StaticFilters[1].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = 80;

        //****************************************************************************************
        // 3. Outgoing HTTP requests filter: REDIRECT OUT TCP packets with destination PORT 80 IPv6
        // Common values
        pFilters->m_StaticFilters[2].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[2].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[2].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[2].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

        // Network layer filter
        pFilters->m_StaticFilters[2].m_NetworkFilter.m_dwUnionSelector = IPV6;
        pFilters->m_StaticFilters[2].m_NetworkFilter.m_IPv6.m_ValidFields = IP_V6_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[2].m_NetworkFilter.m_IPv6.m_Protocol = IPPROTO_TCP;

        // Transport layer filter 
        pFilters->m_StaticFilters[2].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[2].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_DEST_PORT;
        pFilters->m_StaticFilters[2].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 80; // HTTP
        pFilters->m_StaticFilters[2].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 80;

        //****************************************************************************************
        // 4. Incoming HTTP responses filter: REDIRECT IN TCP packets with source PORT 80 IPv6
        // Common values
        pFilters->m_StaticFilters[3].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[3].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[3].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[3].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE;

        // Network layer filter
        pFilters->m_StaticFilters[3].m_NetworkFilter.m_dwUnionSelector = IPV6;
        pFilters->m_StaticFilters[3].m_NetworkFilter.m_IPv6.m_ValidFields = IP_V6_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[3].m_NetworkFilter.m_IPv6.m_Protocol = IPPROTO_TCP;

        // Transport layer filter 
        pFilters->m_StaticFilters[3].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[3].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_SRC_PORT;
        pFilters->m_StaticFilters[3].m_TransportFilter.m_TcpUdp.m_SourcePort.m_StartRange = 80; // HTTP
        pFilters->m_StaticFilters[3].m_TransportFilter.m_TcpUdp.m_SourcePort.m_EndRange = 80;

        //***************************************************************************************
        // 5. Pass all packets (skipped by previous filters) without processing in user mode
        // Common values
        pFilters->m_StaticFilters[4].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[4].m_ValidFields = 0;
        pFilters->m_StaticFilters[4].m_FilterAction = FILTER_PACKET_PASS;
        pFilters->m_StaticFilters[4].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

        break;

    case 3:

        pFilters->m_TableSize = 1;

        //**************************************************************************************
        // 1. Block all ICMP packets
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_DROP;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE;

        // Network layer filter
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_ICMP;

        break;

    case 4:

        pFilters->m_TableSize = 2;

        //**************************************************************************************
        // 1. Outgoing HTTP requests filter: DROP OUT TCP packets with destination IP 95.179.146.125 PORT 443 (https://www.ntkernel.com)
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_DROP;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

        // Network layer filter
        in_addr address;
        in_addr mask;

        // IP address 95.179.146.125
        address.S_un.S_un_b.s_b1 = 95;
        address.S_un.S_un_b.s_b2 = 179;
        address.S_un.S_un_b.s_b3 = 146;
        address.S_un.S_un_b.s_b4 = 125;

        // Network mask 255.255.255.255
        mask.S_un.S_un_b.s_b1 = 255;
        mask.S_un.S_un_b.s_b2 = 255;
        mask.S_un.S_un_b.s_b3 = 255;
        mask.S_un.S_un_b.s_b4 = 255;

        pFilters->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL | IP_V4_FILTER_DEST_ADDRESS;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress.m_AddressType = IP_SUBNET_V4_TYPE;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_Ip = address.S_un.S_addr; // IP address
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_DestAddress.m_IpSubnet.m_IpMask = mask.S_un.S_addr; // network mask
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_TCP;

        // Transport layer filter 
        pFilters->m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = TCPUDP;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_ValidFields = TCPUDP_DEST_PORT;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_StartRange = 443; // HTTPS
        pFilters->m_StaticFilters[0].m_TransportFilter.m_TcpUdp.m_DestPort.m_EndRange = 443;

        //***************************************************************************************
        // 2. Pass all packets (skipped by previous filters) without processing in user mode
        // Common values
        pFilters->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[1].m_ValidFields = 0;
        pFilters->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_PASS;
        pFilters->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

        break;

    case 5:

        pFilters->m_TableSize = 3;

        //**************************************************************************************
        // 1. Redirects all ARP packets to be processes by user mode application
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = DATA_LINK_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE;
        pFilters->m_StaticFilters[0].m_DataLinkFilter.m_dwUnionSelector = ETH_802_3;
        pFilters->m_StaticFilters[0].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields = ETH_802_3_PROTOCOL;
        pFilters->m_StaticFilters[0].m_DataLinkFilter.m_Eth8023Filter.m_Protocol = ETH_P_ARP;


        //**************************************************************************************
        // 2. Redirects all RARP packets to be processes by user mode application
        // Common values
        pFilters->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[1].m_ValidFields = DATA_LINK_LAYER_VALID;
        pFilters->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE;
        pFilters->m_StaticFilters[1].m_DataLinkFilter.m_dwUnionSelector = ETH_802_3;
        pFilters->m_StaticFilters[1].m_DataLinkFilter.m_Eth8023Filter.m_ValidFields = ETH_802_3_PROTOCOL;
        pFilters->m_StaticFilters[1].m_DataLinkFilter.m_Eth8023Filter.m_Protocol = ETH_P_RARP;


        //***************************************************************************************
        // 3. Pass all packets (skipped by previous filters) without processing in user mode
        // Common values
        pFilters->m_StaticFilters[2].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[2].m_ValidFields = 0;
        pFilters->m_StaticFilters[2].m_FilterAction = FILTER_PACKET_PASS;
        pFilters->m_StaticFilters[2].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

        break;

    case 6:

        pFilters->m_TableSize = 2;

        //**************************************************************************************
        // 1. Redirects all ARP packets to be processes by user mode application
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

        pFilters->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV4;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_ValidFields = IP_V4_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv4.m_Protocol = IPPROTO_ICMP;

        // Transport layer filter 
        pFilters->m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = ICMP;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_Icmp.m_ValidFields = ICMP_TYPE;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_Icmp.m_TypeRange.m_StartRange = 8; // ICMP PING REQUEST
        pFilters->m_StaticFilters[0].m_TransportFilter.m_Icmp.m_TypeRange.m_EndRange = 8;

        //***************************************************************************************
        // 2. Pass all packets (skipped by previous filters) without processing in user mode
        // Common values
        pFilters->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[1].m_ValidFields = 0;
        pFilters->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_PASS;
        pFilters->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

        break;

    case 7:

        pFilters->m_TableSize = 2;

        //**************************************************************************************
        // 1. Redirects all ARP packets to be processes by user mode application
        // Common values
        pFilters->m_StaticFilters[0].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[0].m_ValidFields = NETWORK_LAYER_VALID | TRANSPORT_LAYER_VALID;
        pFilters->m_StaticFilters[0].m_FilterAction = FILTER_PACKET_REDIRECT;
        pFilters->m_StaticFilters[0].m_dwDirectionFlags = PACKET_FLAG_ON_SEND;

        pFilters->m_StaticFilters[0].m_NetworkFilter.m_dwUnionSelector = IPV6;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv6.m_ValidFields = IP_V6_FILTER_PROTOCOL;
        pFilters->m_StaticFilters[0].m_NetworkFilter.m_IPv6.m_Protocol = 58; //ICMPv6

        // Transport layer filter 
        pFilters->m_StaticFilters[0].m_TransportFilter.m_dwUnionSelector = ICMP;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_Icmp.m_ValidFields = ICMP_TYPE;
        pFilters->m_StaticFilters[0].m_TransportFilter.m_Icmp.m_TypeRange.m_StartRange = 128; // ICMP PING REQUEST
        pFilters->m_StaticFilters[0].m_TransportFilter.m_Icmp.m_TypeRange.m_EndRange = 128;

        //***************************************************************************************
        // 2. Pass all packets (skipped by previous filters) without processing in user mode
        // Common values
        pFilters->m_StaticFilters[1].m_Adapter.QuadPart = 0; // applied to all adapters
        pFilters->m_StaticFilters[1].m_ValidFields = 0;
        pFilters->m_StaticFilters[1].m_FilterAction = FILTER_PACKET_PASS;
        pFilters->m_StaticFilters[1].m_dwDirectionFlags = PACKET_FLAG_ON_RECEIVE | PACKET_FLAG_ON_SEND;

        break;

    default:
        printf("Unknown test scenario specified. Exiting. \n");
        return 0;
    }

    api.SetPacketFilterTable(pFilters);

    // Initialize Request
    ZeroMemory(&Request, sizeof(ETH_REQUEST));
    ZeroMemory(&PacketBuffer, sizeof(INTERMEDIATE_BUFFER));
    Request.EthPacket.Buffer = &PacketBuffer;
    Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

    api.SetAdapterMode(&Mode);

    while (TRUE)
    {
        WaitForSingleObject(hEvent, INFINITE);

        while (api.ReadPacket(&Request))
        {
            pEtherHdr = reinterpret_cast<ether_header_ptr>(PacketBuffer.m_IBuffer);

            if (ntohs(pEtherHdr->h_proto) == ETH_P_IP)
            {
                pIpHdr = reinterpret_cast<iphdr*>(PacketBuffer.m_IBuffer + sizeof(ether_header));

                if (pIpHdr->ip_p == IPPROTO_TCP)
                {
                    pTcpHdr = reinterpret_cast<tcphdr_ptr>(reinterpret_cast<PUCHAR>(pIpHdr) + sizeof(DWORD) * pIpHdr->ip_hl);
                }
                else
                {
                    pTcpHdr = NULL;
                }

                if (pIpHdr->ip_p == IPPROTO_UDP)
                {
                    pUdpHdr = reinterpret_cast<udphdr_ptr>(reinterpret_cast<PUCHAR>(pIpHdr) + sizeof(DWORD) * pIpHdr->ip_hl);
                }
                else
                {
                    pUdpHdr = NULL;
                }
            }

            if (ntohs(pEtherHdr->h_proto) == ETH_P_IPV6)
            {
                pIpv6Hdr = reinterpret_cast<ipv6hdr*>(PacketBuffer.m_IBuffer + ETHER_HEADER_LENGTH);

                pIpv6ProtoHdr = IPHLP_FindLastHeader(reinterpret_cast<iphdr_ptr>(pIpv6Hdr), PacketBuffer.m_Length - ETHER_HEADER_LENGTH, &Ipv6Proto);

                if (Ipv6Proto == IPPROTO_TCP)
                {
                    pTcpHdr = static_cast<tcphdr_ptr>(pIpv6ProtoHdr);
                }
                else
                {
                    pTcpHdr = NULL;
                }

                if (Ipv6Proto == IPPROTO_UDP)
                {
                    pUdpHdr = static_cast<udphdr_ptr>(pIpv6ProtoHdr);
                }
                else
                {
                    pUdpHdr = NULL;
                }
            }

            if (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
            {
                printf("\nMSTCP --> Interface\n");
                printf("FilterID = %d \n", PacketBuffer.m_FilterID);
            }
            else
            {
                printf("\nInterface --> MSTCP\n");
                printf("FilterID = %d \n", PacketBuffer.m_FilterID);
            }

            printf("\tPacket size = %d\n", PacketBuffer.m_Length);

            printf(
                "\tETHERNET %.2X%.2X%.2X%.2X%.2X%.2X --> %.2X%.2X%.2X%.2X%.2X%.2X\n",
                pEtherHdr->h_source[0],
                pEtherHdr->h_source[1],
                pEtherHdr->h_source[2],
                pEtherHdr->h_source[3],
                pEtherHdr->h_source[4],
                pEtherHdr->h_source[5],
                pEtherHdr->h_dest[0],
                pEtherHdr->h_dest[1],
                pEtherHdr->h_dest[2],
                pEtherHdr->h_dest[3],
                pEtherHdr->h_dest[4],
                pEtherHdr->h_dest[5]
            );

            if (ntohs(pEtherHdr->h_proto) == ETH_P_IP)
            {
                printf("\tIPv4 %.3d.%.3d.%.3d.%.3d --> %.3d.%.3d.%.3d.%.3d PROTOCOL: %d\n",
                    pIpHdr->ip_src.S_un.S_un_b.s_b1,
                    pIpHdr->ip_src.S_un.S_un_b.s_b2,
                    pIpHdr->ip_src.S_un.S_un_b.s_b3,
                    pIpHdr->ip_src.S_un.S_un_b.s_b4,
                    pIpHdr->ip_dst.S_un.S_un_b.s_b1,
                    pIpHdr->ip_dst.S_un.S_un_b.s_b2,
                    pIpHdr->ip_dst.S_un.S_un_b.s_b3,
                    pIpHdr->ip_dst.S_un.S_un_b.s_b4,
                    pIpHdr->ip_p
                    );

                if (pUdpHdr)
                {
                    printf("\tUDP SRC PORT: %d DST PORT: %d\n",
                        ntohs(pUdpHdr->th_sport),
                        ntohs(pUdpHdr->th_dport)
                        );
                }

                if (pTcpHdr)
                {
                    printf("\tTCP SRC PORT: %d DST PORT: %d\n",
                        ntohs(pTcpHdr->th_sport),
                        ntohs(pTcpHdr->th_dport)
                        );
                }
            }

            if (ntohs(pEtherHdr->h_proto) == ETH_P_IPV6)
            {
                printf("\tIPv6 %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X --> %.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X:%.4X PROTOCOL: %d\n",
                    htons(pIpv6Hdr->ip6_src.u.Word[0]),
                    htons(pIpv6Hdr->ip6_src.u.Word[1]),
                    htons(pIpv6Hdr->ip6_src.u.Word[2]),
                    htons(pIpv6Hdr->ip6_src.u.Word[3]),
                    htons(pIpv6Hdr->ip6_src.u.Word[4]),
                    htons(pIpv6Hdr->ip6_src.u.Word[5]),
                    htons(pIpv6Hdr->ip6_src.u.Word[6]),
                    htons(pIpv6Hdr->ip6_src.u.Word[7]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[0]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[1]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[2]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[3]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[4]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[5]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[6]),
                    htons(pIpv6Hdr->ip6_dst.u.Word[7]),
                    Ipv6Proto
                    );

                if (pUdpHdr)
                {
                    printf("\tUDP SRC PORT: %d DST PORT: %d\n",
                        ntohs(pUdpHdr->th_sport),
                        ntohs(pUdpHdr->th_dport)
                        );
                }

                if (pTcpHdr)
                {
                    printf("\tTCP SRC PORT: %d DST PORT: %d\n",
                        ntohs(pTcpHdr->th_sport),
                        ntohs(pTcpHdr->th_dport)
                        );
                }
            }

            if (ntohs(pEtherHdr->h_proto) == ETH_P_RARP)
                printf("\tReverse Addr Res packet\n");

            if (ntohs(pEtherHdr->h_proto) == ETH_P_ARP)
                printf("\tAddress Resolution packet\n");


            if (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
            {
                // Place packet on the network interface
                api.SendPacketToAdapter(&Request);
            }
            else
            {
                // Indicate packet to MSTCP
                api.SendPacketToMstcp(&Request);
            }
        }

        ResetEvent(hEvent);

    }

    return 0;
}

