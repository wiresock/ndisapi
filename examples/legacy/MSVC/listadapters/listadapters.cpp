/*************************************************************************/
/*                    Copyright (c) 2000-2024 NT KERNEL.                 */
/*                           All Rights Reserved.                        */
/*                          https://www.ntkernel.com                     */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ListAdapters.cpp                                        */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/

#include "stdafx.h"

int main(int argc, char* argv[])
{
	CNdisApi			api;
	TCP_AdapterList		AdList;
	OSVERSIONINFO		verInfo;
	char				szFriendlyName[MAX_PATH*4];
	ADAPTER_MODE		Mode;

	verInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx ( &verInfo );

	DWORD dwMTUDec = api.GetMTUDecrement();
	DWORD dwAdapterStartupMode = api.GetAdaptersStartupMode();

	if(api.IsDriverLoaded())
	{
		printf("The following network interfaces are available to MSTCP:\n");
		api.GetTcpipBoundAdaptersInfo (&AdList);

		for (UINT i = 0; i < AdList.m_nAdapterCount; ++i)
		{
			if (verInfo.dwPlatformId == VER_PLATFORM_WIN32_NT)
			{
				if (verInfo.dwMajorVersion > 4)
				{
					// Windows 2000 or XP
					CNdisApi::ConvertWindows2000AdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH*4);
				}
				else if (verInfo.dwMajorVersion == 4)
				{
					// Windows NT 4.0	
					CNdisApi::ConvertWindowsNTAdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH*4);
				}
			}
			else
			{
				// Windows 9x/ME
				CNdisApi::ConvertWindows9xAdapterName((const char*)AdList.m_szAdapterNameList[i], szFriendlyName, MAX_PATH*4);
			}

			printf ("%d) %s.\n",i+1, szFriendlyName);
			printf ("\tInternal Name:\t %s\n", AdList.m_szAdapterNameList[i]);
			
			printf (
				"\tCurrent MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
				AdList.m_czCurrentAddress[i][0],
				AdList.m_czCurrentAddress[i][1],
				AdList.m_czCurrentAddress[i][2],
				AdList.m_czCurrentAddress[i][3],
				AdList.m_czCurrentAddress[i][4],
				AdList.m_czCurrentAddress[i][5]
				);
			printf ("\tMedium:\t 0x%.8X\n", AdList.m_nAdapterMediumList[i]);
			printf ("\tCurrent MTU:\t %d\n", AdList.m_usMTU[i]);

			RtlZeroMemory(&Mode, sizeof(ADAPTER_MODE));
			Mode.hAdapterHandle = AdList.m_nAdapterHandle[i];
			if (api.GetAdapterMode (&Mode))
				printf("\tCurrent adapter mode = 0x%X\n", Mode.dwFlags);

			DWORD dwAdapterHwFilter = 0;
			if(api.GetHwPacketFilter(AdList.m_nAdapterHandle[i], &dwAdapterHwFilter))
				printf("\tCurrent adapter hardware filter = 0x%X\n", dwAdapterHwFilter);

			if ((CNdisApi::IsNdiswanIp((LPCSTR)AdList.m_szAdapterNameList[i]))||
				(CNdisApi::IsNdiswanIpv6((LPCSTR)AdList.m_szAdapterNameList[i])))
			{
				RAS_LINKS RasLinks;
				if(api.GetRasLinks(AdList.m_nAdapterHandle[i], &RasLinks))
				{
					printf("Number of active WAN links: %d \n", RasLinks.nNumberOfLinks);

					for ( unsigned k = 0; k < RasLinks.nNumberOfLinks; ++k )
					{
						printf ("\t%d) LinkSpeed = %d MTU = %d \n", k, RasLinks.RasLinks[k].LinkSpeed, RasLinks.RasLinks[k].MaximumTotalSize);
						printf (
								"\t\tLocal MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
								RasLinks.RasLinks[k].LocalAddress[0],
								RasLinks.RasLinks[k].LocalAddress[1],
								RasLinks.RasLinks[k].LocalAddress[2],
								RasLinks.RasLinks[k].LocalAddress[3],
								RasLinks.RasLinks[k].LocalAddress[4],
								RasLinks.RasLinks[k].LocalAddress[5]
							);

							printf (
								"\t\tRemote MAC:\t %.2X%.2X%.2X%.2X%.2X%.2X\n",
								RasLinks.RasLinks[k].RemoteAddress[0],
								RasLinks.RasLinks[k].RemoteAddress[1],
								RasLinks.RasLinks[k].RemoteAddress[2],
								RasLinks.RasLinks[k].RemoteAddress[3],
								RasLinks.RasLinks[k].RemoteAddress[4],
								RasLinks.RasLinks[k].RemoteAddress[5]
							);

							if(CNdisApi::IsNdiswanIp((LPCSTR)AdList.m_szAdapterNameList[i]))
							{
								// IP v.4
								if (verInfo.dwMajorVersion == 4)
								{
									printf (
										"\t\tIP address:\t %.3d.%.3d.%.3d.%.3d\n",
										RasLinks.RasLinks[k].ProtocolBuffer[4],
										RasLinks.RasLinks[k].ProtocolBuffer[5],
										RasLinks.RasLinks[k].ProtocolBuffer[6],
										RasLinks.RasLinks[k].ProtocolBuffer[7]
										);

								}
								else if (verInfo.dwMajorVersion < 6)
								{
									printf (
										"\t\tIP address:\t %.3d.%.3d.%.3d.%.3d mask %.3d.%.3d.%.3d.%.3d\n",
										RasLinks.RasLinks[k].ProtocolBuffer[8],
										RasLinks.RasLinks[k].ProtocolBuffer[9],
										RasLinks.RasLinks[k].ProtocolBuffer[10],
										RasLinks.RasLinks[k].ProtocolBuffer[11],
										RasLinks.RasLinks[k].ProtocolBuffer[4],
										RasLinks.RasLinks[k].ProtocolBuffer[5],
										RasLinks.RasLinks[k].ProtocolBuffer[6],
										RasLinks.RasLinks[k].ProtocolBuffer[7]
										);
								}
								else
								{
									// Windows Vista
									printf (
										"\t\tIP address:\t %.3d.%.3d.%.3d.%.3d mask %.3d.%.3d.%.3d.%.3d\n",
										RasLinks.RasLinks[k].ProtocolBuffer[584],
										RasLinks.RasLinks[k].ProtocolBuffer[585],
										RasLinks.RasLinks[k].ProtocolBuffer[586],
										RasLinks.RasLinks[k].ProtocolBuffer[587],
										RasLinks.RasLinks[k].ProtocolBuffer[588],
										RasLinks.RasLinks[k].ProtocolBuffer[589],
										RasLinks.RasLinks[k].ProtocolBuffer[590],
										RasLinks.RasLinks[k].ProtocolBuffer[591]
										);
								}
							}
							else
							{
								// IP v.6
								if (verInfo.dwMajorVersion > 5)
								{
									printf (
										"\t\tIPv6 address (without prefix):\t %.2X%.2X:%.2X%.2X:%.2X%.2X:%.2X%.2X\n",
										RasLinks.RasLinks[k].ProtocolBuffer[588],
										RasLinks.RasLinks[k].ProtocolBuffer[589],
										RasLinks.RasLinks[k].ProtocolBuffer[590],
										RasLinks.RasLinks[k].ProtocolBuffer[591],
										RasLinks.RasLinks[k].ProtocolBuffer[592],
										RasLinks.RasLinks[k].ProtocolBuffer[593],
										RasLinks.RasLinks[k].ProtocolBuffer[594],
										RasLinks.RasLinks[k].ProtocolBuffer[595]
										);
								}
							}
							
					}
				}
				else
				{
					printf ("Failed to query active WAN links information.\n");
				}
			}

		}
		printf ("\nCurrent system wide MTU decrement = %d\n", dwMTUDec);
		printf ("\nDefault adapter startup mode = 0x%X", dwAdapterStartupMode);
	}
	else
		printf("Helper driver failed to load or was not installed.\n");

	return 0;
}
