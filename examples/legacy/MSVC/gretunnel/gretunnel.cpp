/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  GRETunnel.cpp                                           */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"
TCP_AdapterList		AdList;
DWORD				iIndex;
CNdisApi			api;
ETH_REQUEST			Request;
INTERMEDIATE_BUFFER PacketBuffer;
HANDLE				hEvent;

USHORT ntohs( USHORT netshort )
{
	PUCHAR	pBuffer;
	USHORT	nResult;

	nResult = 0;
	pBuffer = (PUCHAR )&netshort;

	nResult = ( (pBuffer[ 0 ] << 8) & 0xFF00 )
		| ( pBuffer[ 1 ] & 0x00FF );

	return( nResult );
}

#define htons ntohs

//
// Function recalculates IP checksum
//
VOID
	RecalculateIPChecksum (
		iphdr_ptr pIpHeader 
		)
{
	unsigned short word16;
	unsigned int sum = 0;
	unsigned int i = 0;
	PUCHAR buff;

	// Initialize checksum to zero
	pIpHeader->ip_sum = 0;
	buff = (PUCHAR)pIpHeader;

	// Calculate IP header checksum
	for (i = 0; i < pIpHeader->ip_hl*sizeof(DWORD); i=i+2)
	{
		word16 = ((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		sum = sum+word16; 
	}

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
    while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;

	pIpHeader->ip_sum = htons((unsigned short) sum);
}

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

int main(int argc, char* argv[])
{
	UINT				counter = 0;
	ether_header*		pEthHeader = NULL;
	iphdr*				pIpHeader = NULL;
	ipgre_hdr*			pIpGreHeader = NULL;

	if (argc < 3)
	{
		printf ("Command line syntax:\n\tGreTunnel.exe index num\n\tindex - network interface index.\n\tnum - number or packets to passthru the tunnel\n\tYou can use ListAdapters to determine correct index.\n");
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

	DWORD dwMTUDec = api.GetMTUDecrement();
	if (dwMTUDec != sizeof(ipgre_hdr))
	{
		api.SetMTUDecrement(sizeof(ipgre_hdr));
		printf ("Incorrect MTU decrement was set for the system. New MTU decrement is %d bytes. Please reboot the system for the changes to take the effect.\n", sizeof(ipgre_hdr));
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
	ZeroMemory ( &Request, sizeof(ETH_REQUEST) );
	ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER) );
	Request.EthPacket.Buffer = &PacketBuffer;
	Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[iIndex];
		
	api.SetAdapterMode(&Mode);

	while (counter != 0)
	{
		WaitForSingleObject ( hEvent, INFINITE );
		
		while(api.ReadPacket(&Request))
		{
			counter--;

			if (PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
			{
				printf("\n%d - MSTCP --> Interface\n", counter);
			}
			else
			{
				printf("\n%d - Interface --> MSTCP\n", counter);
			}

			printf ("\tPacket size = %d\n", PacketBuffer.m_Length);
			pEthHeader = (ether_header*)PacketBuffer.m_IBuffer;

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

			if((ntohs(pEthHeader->h_proto) == ETH_P_IP)&&
				(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND)
				)
			{
				printf("\t Outgoing IP packet to be GRE tunneled \n");
				if (PacketBuffer.m_Length <= (MAX_ETHER_FRAME - sizeof(ipgre_hdr)))
				{
					// We have got enough space in the packet to attach GRE header
					// Get IP header pointer
					pIpHeader = (iphdr*)(pEthHeader + 1);
					
					// Move IP packet body by sizeof(ipgre_hdr) bytes
					// Previous IP header stays unchanged
					memmove(((unsigned char*)pIpHeader) + sizeof (ipgre_hdr), pIpHeader, PacketBuffer.m_Length - sizeof(ether_header));

					// Change the length field of the new IP header
					pIpGreHeader = (ipgre_hdr*)pIpHeader;
					pIpHeader->ip_len = ntohs(ntohs(pIpHeader->ip_len) + sizeof(ipgre_hdr));

					// Set next protocol to GRE
					pIpHeader->ip_p = IPPROTO_GRE;

					// Recalculate IP checksum
					RecalculateIPChecksum(pIpHeader);

					// Initialize GRE header
					pIpGreHeader->gre_header.flags = 0;
					pIpGreHeader->gre_header.protocol = ntohs(ETH_P_IP);

					// Adjust packet length 
					PacketBuffer.m_Length += sizeof(ipgre_hdr); 

				}
				else
				{
					printf("\t Packet length = %d bytes. Not enough space to attach GRE header. Check MTU decrement. \n", PacketBuffer.m_Length);
				}
			}

			if((ntohs(pEthHeader->h_proto) == ETH_P_IP)&&
				(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)
				)
			{
				// Get IP header pointer
				pIpHeader = (iphdr*)(pEthHeader + 1);

				if (pIpHeader->ip_p == IPPROTO_GRE)
				{
					printf("\t Incoming IP packet with GRE header \n");

					pIpGreHeader = (ipgre_hdr*)pIpHeader;

					// We process only simple GRE tunnels
					if (pIpGreHeader->gre_header.flags == 0)
					{
						// Remove GRE header and adjust packet length
						memmove(pIpHeader, ((unsigned char*)pIpHeader) + sizeof (ipgre_hdr), PacketBuffer.m_Length - sizeof(ether_header) - sizeof(ipgre_hdr));
						PacketBuffer.m_Length -= sizeof(ipgre_hdr); 
					}
					else
					{
						printf("\tThis is not SIMPLE GRE packet, skip it . \n");
					}
				}
				else
				{
					printf("\tThis is not GRE packet, skip it . \n");
				}
			}

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

			if (counter == 0)
			{
				printf ("Filtering complete\n");
				break;
			}

		}

		ResetEvent(hEvent);
	
	}

	return 0;
}

