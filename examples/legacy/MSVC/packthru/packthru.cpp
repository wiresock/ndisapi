/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  PackThru.cpp                                            */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

#define PACKET_CHUNK 10

TCP_AdapterList		AdList;
DWORD				iIndex;
CNdisApi			api;

PETH_M_REQUEST		ReadRequest;
PETH_M_REQUEST		ToMstcpRequest;
PETH_M_REQUEST		ToAdapterRequest;

INTERMEDIATE_BUFFER PacketBuffer[PACKET_CHUNK];
HANDLE				hEvent;

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
	ADAPTER_MODE Mode;

	Mode.dwFlags = 0;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

	// Set NULL event to release previously set event object
	api.SetPacketEvent(AdList.m_nAdapterHandle[iIndex], NULL);

	// Close Event
	if (hEvent)
		CloseHandle ( hEvent );

	// Set default adapter mode
	api.SetAdapterMode(&Mode);

	// Empty adapter packets queue
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
	int					counter = 0;
	ether_header*		pEthHeader = NULL;
	iphdr_ptr			pIpHdr		= NULL;
	tcphdr_ptr			pTcpHdr		= NULL;
	udphdr_ptr			pUdpHdr		= NULL;
	ipv6hdr_ptr			pIpv6Hdr		= NULL;
	unsigned char		Ipv6Proto		= 0;
	void*				pIpv6ProtoHdr	= NULL;

	if (argc < 3)
	{
		printf ("Command line syntax:\n\tPackThru.exe index num\n\tindex - network interface index.\n\tnum - number or packets to filter\n\tYou can use ListAdapters to determine correct index.\n");
		return 0;
	}

	iIndex = atoi(argv[1]) - 1;
	counter = atoi(argv[2]);

	if(!api.IsDriverLoaded())
	{
		printf ("Driver not installed on this system of failed to load.\n");
		return 0;
	}
	
	api.GetTcpipBoundAdaptersInfo ( &AdList );

	if ( iIndex + 1 > AdList.m_nAdapterCount )
	{
		printf("There is no network interface with such index on this system.\n");
		return 0;
	}
	
	ADAPTER_MODE Mode;

	Mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL|MSTCP_FLAG_RECV_TUNNEL;
	Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];

	// Create notification event
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	// Set event for helper driver
	if ((!hEvent)||(!api.SetPacketEvent((HANDLE)AdList.m_nAdapterHandle[iIndex], hEvent)))
	{
		printf ("Failed to create notification event or set it for driver.\n");
		return 0;
	}

	atexit (ReleaseInterface);
	
	// Initialize Request
	ReadRequest = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + sizeof (NDISRD_ETH_Packet)*(PACKET_CHUNK - 1));
	ToMstcpRequest = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + sizeof (NDISRD_ETH_Packet)*(PACKET_CHUNK - 1));
	ToAdapterRequest = (PETH_M_REQUEST)malloc(sizeof(ETH_M_REQUEST) + sizeof (NDISRD_ETH_Packet)*(PACKET_CHUNK - 1));

	ZeroMemory ( ReadRequest, sizeof(ETH_M_REQUEST) + sizeof (NDISRD_ETH_Packet)*(PACKET_CHUNK - 1) );
	ZeroMemory ( ToMstcpRequest, sizeof(ETH_M_REQUEST) + sizeof (NDISRD_ETH_Packet)*(PACKET_CHUNK - 1) );
	ZeroMemory ( ToAdapterRequest, sizeof(ETH_M_REQUEST) + sizeof (NDISRD_ETH_Packet)*(PACKET_CHUNK - 1) );

	ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER)*PACKET_CHUNK );
	ReadRequest->hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
	ToMstcpRequest->hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
	ToAdapterRequest->hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
	ReadRequest->dwPacketsNumber = PACKET_CHUNK;

	for (unsigned i = 0; i < PACKET_CHUNK; ++i)
	{
		ReadRequest->EthPacket[i].Buffer = &PacketBuffer[i];
	}	
		
	api.SetAdapterMode(&Mode);

	while (counter > 0)
	{
		WaitForSingleObject ( hEvent, INFINITE );
		
		while(api.ReadPackets(ReadRequest))
		{
			printf ("%d packet received from the driver\n", ReadRequest->dwPacketsSuccess);
			
			for (unsigned i = 0; i < ReadRequest->dwPacketsSuccess; ++i)
			{
				counter--;

				if (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				{
					printf("\n%d - MSTCP --> Interface\n", counter);
				}
				else
				{
					printf("\n%d - Interface --> MSTCP\n", counter);
				}

				printf ("\tPacket size = %d\n", PacketBuffer[i].m_Length);

				// Get protocol headers
				pEthHeader = (ether_header*)PacketBuffer[i].m_IBuffer;

				if (ntohs(pEthHeader->h_proto) == ETH_P_IP)
				{
					pIpHdr = (iphdr*)(PacketBuffer[i].m_IBuffer + sizeof(ether_header));

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
					pIpv6Hdr = (ipv6hdr*)(PacketBuffer[i].m_IBuffer + ETHER_HEADER_LENGTH);

					pIpv6ProtoHdr = IPHLP_FindLastHeader((iphdr_ptr)pIpv6Hdr, PacketBuffer[i].m_Length - ETHER_HEADER_LENGTH, &Ipv6Proto);

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
			
			
				if (PacketBuffer[i].m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				{
					ToAdapterRequest->EthPacket[ToAdapterRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
					ToAdapterRequest->dwPacketsNumber++;
				}
				else
				{
					ToMstcpRequest->EthPacket[ToMstcpRequest->dwPacketsNumber].Buffer = &PacketBuffer[i];
					ToMstcpRequest->dwPacketsNumber++;
				}
			}

			if (ToAdapterRequest->dwPacketsNumber)
			{
				printf ("Sending %d packets to network \n", ToAdapterRequest->dwPacketsNumber);
				api.SendPacketsToAdapter(ToAdapterRequest);
				ToAdapterRequest->dwPacketsNumber = 0;
			}

			if (ToMstcpRequest->dwPacketsNumber)
			{
				printf ("Sending %d packets to protocols \n", ToMstcpRequest->dwPacketsNumber);
				api.SendPacketsToMstcp(ToMstcpRequest);
				ToMstcpRequest->dwPacketsNumber = 0;
			}

			ReadRequest->dwPacketsSuccess = 0;

			if (counter < 0)
			{
				printf ("Filtering complete\n");
				break;
			}

		}

		ResetEvent(hEvent);
	
	}

	return 0;
}

