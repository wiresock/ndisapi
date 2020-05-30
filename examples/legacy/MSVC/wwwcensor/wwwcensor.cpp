/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  wwwcensor.cpp                                           */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

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

ULONG ntohl( ULONG netlong )
{
	ULONG    nResult = netlong >> 16;
	USHORT   upper = (USHORT) nResult & 0x0000FFFF;
	USHORT	lower = (USHORT) netlong & 0x0000FFFF;

	upper = htons( upper );
	lower = htons( lower );

    nResult = 0x10000 * lower + upper;
	return( nResult );
}

#define htonl ntohl


int main(int argc, char* argv[])
{
	TCP_AdapterList		AdList;
	CNdisApi			api;
	ETH_REQUEST			Request;
	INTERMEDIATE_BUFFER PacketBuffer;
	ether_header_ptr	pEthHeader = NULL;
	iphdr_ptr			pIpHeader = NULL;
	tcphdr_ptr			pTcpHeader = NULL;
	HANDLE				hEvent[256];
	DWORD				dwAdIndex = 0;
	char				szTempString[1500];
	char				szPattern[256];
	BOOL				bDrop = FALSE;


	if (argc < 2)
	{
		printf ("Command line syntax:\n\twwwcensor.exe pattern \n\tpattern - phrase or word to block HTTP packets with.\n");
		return 0;
	}

	if(!api.IsDriverLoaded())
	{
		printf ("Driver not installed on this system of failed to load.\n");
		return 0;
	}

	if ( strlen(argv[1]) > 255 )
	{
		printf ("Pattern is too,long, please use one with maximum of 255 characters.\n");
		return 0;
	}

	//
	// Get pattern in upper case
	//
	ZeroMemory ( szPattern, 256 );
	strcpy ( szPattern, argv[1] );
	for ( unsigned i = 0; i < strlen (szPattern); ++i )
	{
		if (isalpha(((UCHAR)szPattern[i])))
			szPattern[i] = (char)toupper((UCHAR)szPattern[i]);
	}

	//
	// Get system installed network interfaces
	//
	api.GetTcpipBoundAdaptersInfo ( &AdList );

	//
	// Initialize common ADAPTER_MODE structure (all network interfaces will operate in the same mode)
	//
	ADAPTER_MODE Mode;
	Mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL|MSTCP_FLAG_RECV_TUNNEL;

	//
	// Create notification events and initialize the driver to pass packets thru us
	//
	for (dwAdIndex = 0; dwAdIndex < AdList.m_nAdapterCount; ++dwAdIndex)
	{
		hEvent[dwAdIndex] = CreateEvent(NULL, TRUE, FALSE, NULL);

		if (!hEvent[dwAdIndex])
		{
			printf("Failed to create notification event for network interface \n");
			return 0;
		}

		Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[dwAdIndex];

		//
		// Set MSTCP_FLAG_SENT_TUNNEL|MSTCP_FLAG_RECV_TUNNEL for the network interface
		//
		api.SetAdapterMode(&Mode);

		//
		// Set packet notification event for the network interface
		//
		api.SetPacketEvent((HANDLE)AdList.m_nAdapterHandle[dwAdIndex], hEvent[dwAdIndex]);
	}

	
	// Initialize common part of ETH_REQUEST
	ZeroMemory ( &Request, sizeof(ETH_REQUEST) );
	ZeroMemory ( &PacketBuffer, sizeof(INTERMEDIATE_BUFFER) );
	Request.EthPacket.Buffer = &PacketBuffer;

	//
	// Go into the endless loop (this is just a sample application)
	//
	while (TRUE)
	{
		//
		// Wait before any of the interfaces is ready to indicate the packet
		//
		dwAdIndex = WaitForMultipleObjects ( AdList.m_nAdapterCount, hEvent, FALSE, INFINITE ) - WAIT_OBJECT_0;

		//
		// Complete initialization of ETH_REQUEST
		//

		Request.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[dwAdIndex];
		
		//
		// Read packet from the interface until there are any
		//
		while(api.ReadPacket(&Request))
		{
			//
			// Get Ethernet header
			//
			pEthHeader = (ether_header_ptr)PacketBuffer.m_IBuffer;
			
			//
			// Check if Ethernet frame contains IP packet
			//
			if(ntohs(pEthHeader->h_proto) == ETH_P_IP)
			{
				//
				// Get IP header
				//
				pIpHeader = (iphdr_ptr)(pEthHeader + 1);

				//
				// Check if IP packet contains TCP packet
				//
				if (pIpHeader->ip_p == IPPROTO_TCP)
				{
					//
					// Get TCP header pointer
					//
					pTcpHeader = (tcphdr_ptr)((PUCHAR)pIpHeader + pIpHeader->ip_hl*4);

					//
					// Check if this HTTP packet (destined to remote system port 80, or received from it)
					//

					if (((pTcpHeader->th_dport == htons (80))&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND))|| 
						((pTcpHeader->th_sport == htons (80))&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_RECEIVE)))
					{
						//
						// Get data size in the packet and pointer to the data
						//

						DWORD dwDataLength = PacketBuffer.m_Length - (sizeof(ether_header) + pIpHeader->ip_hl*4 + pTcpHeader->th_off*4);
						PCHAR pData = (PCHAR)pEthHeader + (sizeof(ether_header) + pIpHeader->ip_hl*4 + pTcpHeader->th_off*4);

						// If packet contains any data - process it
						if (dwDataLength)
						{
							//
							// Copy packet payload into the temporary string, replace all 0 bytes with 0x20, convert string to upper case and place \0 at the end
							//
							memcpy (szTempString, pData, dwDataLength);
							for (unsigned t = 0; t < dwDataLength; ++t)
							{
								if (szTempString[t] == 0)
									szTempString[t] = 0x20;

								if (isalpha((UCHAR)szTempString[t]))
									szTempString[t] = (char)toupper((UCHAR)szTempString[t]);
							}
							szTempString[dwDataLength] = 0;

							//
							// Base functionality:
							// Check if this packet payload contains user supplied pattern in ASCII code
							// 

							if (strstr ( szTempString, szPattern ))
								bDrop = TRUE;

							//
							// Demonstrate how to modify search request with safe search parameter for google, bing, yahoo
							//

							// Check if this is HTTP GET
							if (0 == _strnicmp(szTempString, "GET ", strlen("GET ")))
							{
								PCHAR pPage = szTempString + strlen("GET ");
								PCHAR pEndPage = strchr (pPage, ' ');
								PCHAR pHost = NULL;
								PCHAR pUserAgent = NULL;
								PCHAR pUserAgentEnd = NULL;

								if (pEndPage)
								{
									*pEndPage = 0;
									pHost = strstr (pEndPage + 1, "HOST: ");
									pUserAgent = strstr(pEndPage + 1, "USER-AGENT: ");
								}
								else
								{
									pHost = strstr (szTempString, "HOST: ");
									pUserAgent = strstr(szTempString, "USER-AGENT: ");
								}
								
								PCHAR pEnd = NULL;
								
								if (pHost)
								{
									pHost += strlen("HOST: ");
									pEnd = strchr ( pHost, 0x0D );
								}

								if (pEnd)
								{
									*pEnd = 0;
								}

								if (pUserAgent)
								{
									pUserAgent += strlen("USER-AGENT: ");
									pUserAgentEnd = strchr ( pUserAgent, 0x0D );
								}

								if(pHost && pPage)
								{

									if(strstr(pHost, "GOOGLE")&&strstr(pPage,"Q="))
									{
										// This is a google query
										if(pUserAgent && pUserAgentEnd && ((unsigned)(pUserAgentEnd - pUserAgent) > strlen("&safe=active")))
										{
											// Move data for the space from UserAgent
											memmove(pData + (pEndPage - szTempString) + strlen("&safe=active"), pData + (pEndPage - szTempString), pUserAgentEnd - pEndPage - strlen("&safe=active"));
											memmove(pData + (pEndPage - szTempString), "&safe=active", strlen("&safe=active"));
											RecalculateTCPChecksum (&PacketBuffer);
											RecalculateIPChecksum (&PacketBuffer);

											printf ("TCP %d.%d.%d.%d:%d  ->  %d.%d.%d.%d:%d Google query found and safe mode activated for the request\n", 
												pIpHeader->ip_src.S_un.S_un_b.s_b1, pIpHeader->ip_src.S_un.S_un_b.s_b2, pIpHeader->ip_src.S_un.S_un_b.s_b3, pIpHeader->ip_src.S_un.S_un_b.s_b4, ntohs(pTcpHeader->th_sport),
												pIpHeader->ip_dst.S_un.S_un_b.s_b1, pIpHeader->ip_dst.S_un.S_un_b.s_b2, pIpHeader->ip_dst.S_un.S_un_b.s_b3, pIpHeader->ip_dst.S_un.S_un_b.s_b4, ntohs (pTcpHeader->th_dport));
										}
									}

									if(strstr(pHost, "BING")&&strstr(pPage,"Q="))
									{
										// This is a bing query
										if(pUserAgent && pUserAgentEnd && ((unsigned)(pUserAgentEnd - pUserAgent) > strlen("&adlt=strict")))
										{
											// Move data for the space from UserAgent
											memmove(pData + (pEndPage - szTempString) + strlen("&adlt=strict"), pData + (pEndPage - szTempString), pUserAgentEnd - pEndPage - strlen("&adlt=strict"));
											memmove(pData + (pEndPage - szTempString), "&adlt=strict", strlen("&adlt=strict"));
											RecalculateTCPChecksum (&PacketBuffer);
											RecalculateIPChecksum (&PacketBuffer);

											printf ("TCP %d.%d.%d.%d:%d  ->  %d.%d.%d.%d:%d Bing query found and safe mode activated for the request\n", 
												pIpHeader->ip_src.S_un.S_un_b.s_b1, pIpHeader->ip_src.S_un.S_un_b.s_b2, pIpHeader->ip_src.S_un.S_un_b.s_b3, pIpHeader->ip_src.S_un.S_un_b.s_b4, ntohs(pTcpHeader->th_sport),
												pIpHeader->ip_dst.S_un.S_un_b.s_b1, pIpHeader->ip_dst.S_un.S_un_b.s_b2, pIpHeader->ip_dst.S_un.S_un_b.s_b3, pIpHeader->ip_dst.S_un.S_un_b.s_b4, ntohs (pTcpHeader->th_dport));
										}
									}

									if(strstr(pHost, "YAHOO")&&strstr(pPage,"P="))
									{
										// This is a yahoo query
										if(pUserAgent && pUserAgentEnd && ((unsigned)(pUserAgentEnd - pUserAgent) > strlen("&vm=r")))
										{
											// Move data for the space from UserAgent
											memmove(pData + (pEndPage - szTempString) + strlen("&vm=r"), pData + (pEndPage - szTempString), pUserAgentEnd - pEndPage - strlen("&vm=r"));
											memmove(pData + (pEndPage - szTempString), "&vm=r", strlen("&vm=r"));
											RecalculateTCPChecksum (&PacketBuffer);
											RecalculateIPChecksum (&PacketBuffer);

											printf ("TCP %d.%d.%d.%d:%d  ->  %d.%d.%d.%d:%d Yahoo query found and safe mode activated for the request\n", 
												pIpHeader->ip_src.S_un.S_un_b.s_b1, pIpHeader->ip_src.S_un.S_un_b.s_b2, pIpHeader->ip_src.S_un.S_un_b.s_b3, pIpHeader->ip_src.S_un.S_un_b.s_b4, ntohs(pTcpHeader->th_sport),
												pIpHeader->ip_dst.S_un.S_un_b.s_b1, pIpHeader->ip_dst.S_un.S_un_b.s_b2, pIpHeader->ip_dst.S_un.S_un_b.s_b3, pIpHeader->ip_dst.S_un.S_un_b.s_b4, ntohs (pTcpHeader->th_dport));
										}
									}
								}
							}
						}
					}

					// Session is supposed to be dropped according keyword criteria
					if(bDrop)
					{
						printf ("TCP %d.%d.%d.%d:%d  ->  %d.%d.%d.%d:%d pattern found & packet dropped & redirect HTTP packet injected\n", 
							pIpHeader->ip_src.S_un.S_un_b.s_b1, pIpHeader->ip_src.S_un.S_un_b.s_b2, pIpHeader->ip_src.S_un.S_un_b.s_b3, pIpHeader->ip_src.S_un.S_un_b.s_b4, ntohs(pTcpHeader->th_sport),
							pIpHeader->ip_dst.S_un.S_un_b.s_b1, pIpHeader->ip_dst.S_un.S_un_b.s_b2, pIpHeader->ip_dst.S_un.S_un_b.s_b3, pIpHeader->ip_dst.S_un.S_un_b.s_b4, ntohs (pTcpHeader->th_dport));

						if ((pTcpHeader->th_dport == htons (80))&&(PacketBuffer.m_dwDeviceFlags == PACKET_FLAG_ON_SEND))
						{
							//
							// Outgoing HTTP request we convert into incoming HTTP response
							//

							// 1. Change packet direction
							PacketBuffer.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;

							// 2. Swap Ethernet addresses
							UCHAR ucaSwapMAC[ETHER_ADDR_LENGTH];
							memmove(ucaSwapMAC, pEthHeader->h_dest, ETHER_ADDR_LENGTH);
							memmove(pEthHeader->h_dest, pEthHeader->h_source, ETHER_ADDR_LENGTH);
							memmove(pEthHeader->h_source, ucaSwapMAC, ETHER_ADDR_LENGTH);

							// 3. Swap IP addresses
							ULONG ulSwapIp = pIpHeader->ip_dst.S_un.S_addr;
							pIpHeader->ip_dst.S_un.S_addr = pIpHeader->ip_src.S_un.S_addr;
							pIpHeader->ip_src.S_un.S_addr = ulSwapIp;

							// 4. Swap TCP ports
							USHORT usSwapPort = pTcpHeader->th_dport;
							pTcpHeader->th_dport = pTcpHeader->th_sport;
							pTcpHeader->th_sport = usSwapPort;

							// 5.Swap SEQ/ACK
							tcp_seq tsSwap = pTcpHeader->th_ack;
							pTcpHeader->th_ack = pTcpHeader->th_seq;
							pTcpHeader->th_seq = tsSwap;

							// 6. Update ACK on the sent packet length
							DWORD dwTcpDataLength = PacketBuffer.m_Length - (sizeof(ether_header) + pIpHeader->ip_hl*4 + pTcpHeader->th_off*4);
							pTcpHeader->th_ack = htonl(ntohl(pTcpHeader->th_ack) + dwTcpDataLength);
						}

						// Form the TCP packet payload

						// 1. Form the HTTP date & time string
						SYSTEMTIME today;
						char date_time_str[256];
						GetSystemTime ( &today );
						GetDateFormat(LOCALE_INVARIANT, 0, &today, "ddd',' dd MMM yyyy ", date_time_str, 256);
						GetTimeFormat(0, TIME_FORCE24HOURFORMAT, &today, "hh':'mm':'ss GMT\r\n", date_time_str + strlen(date_time_str), 256 - (int)strlen(date_time_str));


						// 2. Get pointer to TCP data and fill HTTP response packet
						PCHAR pTcpData = (PCHAR)pEthHeader + (sizeof(ether_header) + pIpHeader->ip_hl*4 + pTcpHeader->th_off*4);
						sprintf(pTcpData, "HTTP/1.1 "); // Protocol version
						sprintf(pTcpData + strlen(pTcpData), "200 ");  // Status code
						sprintf(pTcpData + strlen(pTcpData), "OK\r\n");  // Reason
						sprintf(pTcpData + strlen(pTcpData), "Date: %s", date_time_str);  // Date
						sprintf(pTcpData + strlen(pTcpData), "Server: Apache/2.2.22 (Win32) PHP/5.4.7\r\n");  // Server
						sprintf(pTcpData + strlen(pTcpData), "Last-Modified: %s", date_time_str);  // Last-Modified
						//sprintf(pTcpData + strlen(pTcpData), "ETag: \"1500000000f77e-d4-4d044c2c087d6\"\r\n");  // ETag
						sprintf(pTcpData + strlen(pTcpData), "Accept-Ranges: bytes\r\n");  // Accept-Ranges
						sprintf(pTcpData + strlen(pTcpData), "Content-Length: 212\r\n");  // ContentLength
						sprintf(pTcpData + strlen(pTcpData), "Keep-Alive: timeout=5, max=100\r\n");  // Keep-Alive
						sprintf(pTcpData + strlen(pTcpData), "Connection: Keep-Alive\r\n");  // Connection
						sprintf(pTcpData + strlen(pTcpData), "Content-Type: text/html\r\n");  // ContentType
						sprintf(pTcpData + strlen(pTcpData), "\r\n");  // HeaderEnd: CRLF
						sprintf(pTcpData + strlen(pTcpData), "<html>\r\n");  //
						sprintf(pTcpData + strlen(pTcpData), "<head>\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "<title>WWWCENSOR</title>\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"0;URL=http://www.google.com/\">\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "</head>\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "<BODY>\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "<H3>Blocked by wwwcensor. Redirecting to http://www.google.com</H3>\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "</BODY>\r\n");  // 
						sprintf(pTcpData + strlen(pTcpData), "</html>");  // 

						// 3. Set new packet buffer length
						PacketBuffer.m_Length = sizeof(ether_header) + pIpHeader->ip_hl*4 + pTcpHeader->th_off*4 + (ULONG)strlen(pTcpData);

						// 4. Set IP total length
						pIpHeader->ip_len = htons((short)(PacketBuffer.m_Length - sizeof(ether_header)));

						// 5. Set TTL
						pIpHeader->ip_ttl = 128;

						RecalculateTCPChecksum (&PacketBuffer);
						RecalculateIPChecksum (&PacketBuffer);

						bDrop = FALSE;
					}
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
		}

		//
		// Reset signalled event
		//
		ResetEvent(hEvent[dwAdIndex]);
	
	}

	return 0;
}

