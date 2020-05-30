/*************************************************************************/
/*				Copyright (c) 2000-2016 NT Kernel Resources.		     */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  filterstats.cpp                                         */
/*                                                                       */
/* Abstract: Defines the entry point for the console application         */
/*                                                                       */
/*************************************************************************/
#include "stdafx.h"

int main(int argc, char* argv[])
{
	CNdisApi api;

	if (argc < 2)
	{
		printf ("Command line syntax:\n\tfilterstats.exe [DoReset] \n\tDoReset - 1 to reset filters counters / 0 - query counters without reset.\n");
		
		return 0;
	}

	DWORD bReset = atoi(argv[1]);
	
	if(!api.IsDriverLoaded())
	{
		printf ("Driver not installed on this system of failed to load.\n");
		return 0;
	}
	
	// Get number of filters loaded
	DWORD dwFilterNum = 0;
	api.GetPacketFilterTableSize(&dwFilterNum);

	printf ("%d filters loaded into the driver \n", dwFilterNum);

	if (dwFilterNum)
	{
		DWORD dwTableSize = sizeof (STATIC_FILTER_TABLE) + (dwFilterNum - ANY_SIZE)*sizeof(STATIC_FILTER);

		PSTATIC_FILTER_TABLE pFilterTable = (PSTATIC_FILTER_TABLE)malloc(dwTableSize);

		if (pFilterTable)
		{
			// Initialize table size
			pFilterTable->m_TableSize = dwFilterNum;

			// if reset flag is set then query filters table with reset and without reset otherwise
			if (!bReset)
				api.GetPacketFilterTable (pFilterTable);
			else
				api.GetPacketFilterTableResetStats (pFilterTable);

			printf ("Statistics for the loaded filters:\n");
			
			for (unsigned i = 0; i < pFilterTable->m_TableSize; ++i)
			{
				printf ("Filter %d: \n", i);
				printf ("\tIncoming packets counter = %d \n", pFilterTable->m_StaticFilters[i].m_PacketsIn.QuadPart);
				printf ("\tIncoming bytes counter = %d \n", pFilterTable->m_StaticFilters[i].m_BytesIn.QuadPart);
				printf ("\tOutgoing packets counter = %d \n", pFilterTable->m_StaticFilters[i].m_PacketsOut.QuadPart);
				printf ("\tOutgoing bytes counter = %d \n", pFilterTable->m_StaticFilters[i].m_BytesOut.QuadPart);
				printf ("\tLast reset = %d \n", pFilterTable->m_StaticFilters[i].m_LastReset);
			}

			free (pFilterTable);
		}
	}

	return 0;
}

