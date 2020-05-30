/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  PacketSniffer.cpp                                       */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

// Packet filter definitions from DDK
#define NDIS_PACKET_TYPE_DIRECTED				0x00000001
#define NDIS_PACKET_TYPE_MULTICAST				0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST			0x00000004
#define NDIS_PACKET_TYPE_BROADCAST				0x00000008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING			0x00000010
#define NDIS_PACKET_TYPE_PROMISCUOUS			0x00000020
#define NDIS_PACKET_TYPE_SMT					0x00000040
#define NDIS_PACKET_TYPE_ALL_LOCAL				0x00000080
#define NDIS_PACKET_TYPE_GROUP					0x00001000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL			0x00002000
#define NDIS_PACKET_TYPE_FUNCTIONAL				0x00004000
#define NDIS_PACKET_TYPE_MAC_FRAME				0x00008000

TCP_AdapterList	AdList;
DWORD			iIndex;
CNdisApi		api;
BOOL			bSetPromisc = FALSE;
DWORD			dwFilter = 0;

USHORT htons( USHORT hostshort )
{
	PUCHAR	pBuffer;
	USHORT	nResult;

	nResult = 0;
	pBuffer = (PUCHAR )&hostshort;

	nResult = ( (pBuffer[ 0 ] << 8) & 0xFF00 )
		| ( pBuffer[ 1 ] & 0x00FF );

	return( nResult );
}

ULONG htonl( ULONG hostlong )
{
	ULONG    nResult = hostlong >> 16;
	USHORT	upper = (USHORT) nResult & 0x0000FFFF;
	USHORT	lower = (USHORT) hostlong & 0x0000FFFF;

	upper = htons( upper );
	lower = htons( lower );

    nResult = 0x10000 * lower + upper;
	return( nResult );
}

#define ntohs(X) htons(X)
#define ntohl(X) htonl(X)

void ReleaseInterface()
{
	// This function releases packets in the adapter queue and stops listening the interface

	// Restore old packet filter
	if (bSetPromisc)
	{
		api.SetHwPacketFilter ( AdList.m_nAdapterHandle[iIndex], dwFilter );
	}
		
	// Reset adapter mode and flush the packet queue
	ADAPTER_MODE Mode;

	Mode.dwFlags = 0;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
	api.SetAdapterMode(&Mode);
	api.FlushAdapterPacketQueue (AdList.m_nAdapterHandle[iIndex]);
}

//
// IPHLP_FindLastHeader parses IP headers until the payload.
// Returnes pointer to IP packet payload (TCP, UDP, ICMP, ICMPv6 and etc..)
//
PVOID 
	IPHLP_FindLastHeader (
		iphdr_ptr IPHdrPtr,		// pointer to IP header
		unsigned PacketSize,	// size of IP packet in octets
		unsigned char *IPProto	// returnes IPPROTO_ value
		)
{
	unsigned char nextHeader = 0;
	ipv6hdr_ptr IPv6HdrPtr = (ipv6hdr_ptr)IPHdrPtr;
	ipv6ext_ptr pHeader = NULL;
	void *theHeader = NULL;

	//
	// Parse IPv4 headers
	//
	if (IPHdrPtr->ip_v == 4)
	{
		nextHeader = IPHdrPtr->ip_p;
		theHeader = ((char *)IPHdrPtr + IPHdrPtr->ip_hl*4);
	
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
	pHeader = (ipv6ext_ptr)(IPv6HdrPtr + 1);

	// Loop until we find the last IP header
	while (TRUE) 
	{
		// Ensure that current header is still within the packet
		if ((char *)pHeader > (char *)IPv6HdrPtr + PacketSize - sizeof(ipv6ext)) 
		{
			*IPProto = nextHeader;
			return NULL;
		}

		switch (nextHeader) 
		{
			// Fragmentation
			case IPPROTO_FRAGMENT:
			{
				ipv6ext_frag_ptr pfrag = (ipv6ext_frag_ptr)pHeader;

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
				pHeader = (ipv6ext_ptr)((char *)pHeader + sizeof(ipv6ext_frag));

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
		  
			pHeader = (ipv6ext_ptr)((char *)pHeader + 8 + (pHeader->ip6_len)*8);
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
	ETH_REQUEST			Request;
	INTERMEDIATE_BUFFER PacketBuffer;
	UINT				counter = 0;
	ether_header*		pEthHeader = NULL;
	iphdr_ptr			pIpHdr		= NULL;
	tcphdr_ptr			pTcpHdr		= NULL;
	udphdr_ptr			pUdpHdr		= NULL;
	ipv6hdr_ptr			pIpv6Hdr		= NULL;
	unsigned char		Ipv6Proto		= 0;
	void*				pIpv6ProtoHdr	= NULL;

	if (argc < 3)
	{
		printf ("Command line syntax:\n\tPacketSniffer.exe index num [-promisc]\n\tindex - network interface index.\n\tnum - number or packets to capture\n\t-promisc - optional parameter. \n\tWhen specified network interface is switched to the promiscuous mode.\n\tYou can use ListAdapters to determine correct index.\n");
		return 0;
	}

	iIndex = atoi(argv[1]) - 1;
	counter = atoi(argv[2]);

	if (argc == 4)
	{
		// Check if promiscuous mode was specified correct
		if (!strcmp(argv[3], "-promisc"))
		{
			bSetPromisc = TRUE;
		}
		else
		{
			printf ("Parameter %s is not recognized.\n", argv[3]);
			return 0;
		}
	}

	// Check if driver us loaded properly
	if(!api.IsDriverLoaded())
	{
		printf ("Driver not installed on this system of failed to load.\n");
		return 0;
	}
	
	// Get TCP/IP bound adapters information
	api.GetTcpipBoundAdaptersInfo ( &AdList );

	if ( iIndex + 1 > AdList.m_nAdapterCount )
	{
		printf("There is no network interface with such index on this system.\n");
		return 0;
	}
	
	// Set atexit handler
	atexit (ReleaseInterface);

	// Read current packet filter and set NDIS_PACKET_TYPE_PROMISCUOUS 
	// if promiscuous mode is to be set
	if (bSetPromisc)
	{
		HANDLE hAdapter = AdList.m_nAdapterHandle[iIndex];

		if(!api.GetHwPacketFilter ( hAdapter, &dwFilter ))
			printf ("Failed to get current packet filter from the network interface.\n");

		if(!api.SetHwPacketFilter ( hAdapter, NDIS_PACKET_TYPE_PROMISCUOUS ))
			printf ("Failed to set promiscuous mode for the network interface.\n");
	}
	
	// Set passive listening mode
	ADAPTER_MODE Mode;

	// If promiscuous mode specified then set TCP/IP direct filter to prevent TCP/IP
	// from receiving non-directed packets and set block loopback filter to prevent
	// packet loop
	if (bSetPromisc)
		Mode.dwFlags = MSTCP_FLAG_SENT_LISTEN|MSTCP_FLAG_RECV_LISTEN|MSTCP_FLAG_FILTER_DIRECT|MSTCP_FLAG_LOOPBACK_BLOCK;
	else
		Mode.dwFlags = MSTCP_FLAG_SENT_LISTEN|MSTCP_FLAG_RECV_LISTEN;

	
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

	api.SetAdapterMode(&Mode);

	// Initialize Read Packet Request
	ZeroMemory ( &Request, sizeof(ETH_REQUEST) );
	ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER) );
	Request.EthPacket.Buffer = &PacketBuffer;
	Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

	// Read 'counter' packets from the interface
	while (counter != 0)
	{
		if(api.ReadPacket(&Request))
		{
			counter--;

			// Dump packet direction
			if (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
			{
				printf("\nMSTCP --> Interface\n");
			}
			else
			{
				printf("\nInterface --> MSTCP\n");
			}

			// Dump packet size
			printf ("\tPacket size = %d\n", PacketBuffer.m_Length);

			// Get protocol headers
			pEthHeader = (ether_header*)PacketBuffer.m_IBuffer;

			if (ntohs(pEthHeader->h_proto) == ETH_P_IP)
			{
				pIpHdr = (iphdr*)(PacketBuffer.m_IBuffer + sizeof(ether_header));

				if(pIpHdr->ip_p == IPPROTO_TCP)
				{
					pTcpHdr = (tcphdr_ptr)(((PUCHAR)pIpHdr) + sizeof(DWORD)*pIpHdr->ip_hl);
				}
				else
				{
					pTcpHdr = NULL;
				}

				if(pIpHdr->ip_p == IPPROTO_UDP)
				{
					pUdpHdr = (udphdr_ptr)(((PUCHAR)pIpHdr) + sizeof(DWORD)*pIpHdr->ip_hl);
				}
				else
				{
					pUdpHdr = NULL;
				}
			}

			if (ntohs(pEthHeader->h_proto) == ETH_P_IPV6)
			{
				pIpv6Hdr = (ipv6hdr*)(PacketBuffer.m_IBuffer + ETHER_HEADER_LENGTH);

				pIpv6ProtoHdr = IPHLP_FindLastHeader((iphdr_ptr)pIpv6Hdr, PacketBuffer.m_Length - ETHER_HEADER_LENGTH, &Ipv6Proto);

				if(Ipv6Proto == IPPROTO_TCP)
				{
					pTcpHdr = (tcphdr_ptr)pIpv6ProtoHdr;
				}
				else
				{
					pTcpHdr = NULL;
				}

				if(Ipv6Proto == IPPROTO_UDP)
				{
					pUdpHdr = (udphdr_ptr)pIpv6ProtoHdr;
				}
				else
				{
					pUdpHdr = NULL;
				}
			}

			// Dump MAC address information
			printf (
				"\tSource MAC:\t\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
				pEthHeader->h_source[0],
				pEthHeader->h_source[1],
				pEthHeader->h_source[2],
				pEthHeader->h_source[3],
				pEthHeader->h_source[4],
				pEthHeader->h_source[5]
				);
			
			printf (
				"\tDestination MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
				pEthHeader->h_dest[0],
				pEthHeader->h_dest[1],
				pEthHeader->h_dest[2],
				pEthHeader->h_dest[3],
				pEthHeader->h_dest[4],
				pEthHeader->h_dest[5]
				);

			// Dump next protocol
			if(ntohs(pEthHeader->h_proto) == ETH_P_IP)
			{
				printf("\tIP %.3d.%.3d.%.3d.%.3d --> %.3d.%.3d.%.3d.%.3d PROTOCOL: %d\n",
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
					printf ("\tUDP SRC PORT: %d DST PORT: %d\n",
						ntohs(pUdpHdr->th_sport),
						ntohs(pUdpHdr->th_dport)
						);
				}

				if (pTcpHdr)
				{
					printf ("\tTCP SRC PORT: %d DST PORT: %d\n",
						ntohs(pTcpHdr->th_sport),
						ntohs(pTcpHdr->th_dport)
						);
				}
			}

			if(ntohs(pEthHeader->h_proto) == ETH_P_IPV6)
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
					printf ("\tUDP SRC PORT: %d DST PORT: %d\n",
						ntohs(pUdpHdr->th_sport),
						ntohs(pUdpHdr->th_dport)
						);
				}

				if (pTcpHdr)
				{
					printf ("\tTCP SRC PORT: %d DST PORT: %d\n",
						ntohs(pTcpHdr->th_sport),
						ntohs(pTcpHdr->th_dport)
						);
				}
			}

			if(ntohs(pEthHeader->h_proto) == ETH_P_RARP)
				printf("\tReverse Addr Res packet\n");

			if(ntohs(pEthHeader->h_proto) == ETH_P_ARP)
				printf("\tAddress Resolution packet\n");

			// Renitialize Request
			ZeroMemory ( &Request, sizeof(ETH_REQUEST) );
			ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER) );
			Request.EthPacket.Buffer = &PacketBuffer;
			Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
		}
		else
		{
			// No packet in the queue, sleep for 100 milliseconds
			printf (".");
			Sleep(100);
		}
	}

	return 0;
}

