// lfnemu.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "lfnemu.h"
#include <time.h>

int mainLoop(void);

int main(int argc, LPCTSTR argv[])
{
	int result;

	if ((result = initialize(argc, argv)) != 0)
		return result;

	return mainLoop();
}


int mainLoop()
{
	DWORD				dwEvent;
	PETH_REQUEST		pRequest;
	PINTERMEDIATE_BUFFER aux;

	pRequest = (PETH_REQUEST) malloc(sizeof(ETH_REQUEST));
	ZeroMemory(pRequest, sizeof(ETH_REQUEST));
	pRequest->EthPacket.Buffer = (PINTERMEDIATE_BUFFER) 
			malloc(sizeof(INTERMEDIATE_BUFFER));
	ZeroMemory(pRequest->EthPacket.Buffer, sizeof(INTERMEDIATE_BUFFER));

	while (!bExitSignal)
	{
		dwEvent = WaitForMultipleObjects (dwAdapterCount, hEvent, FALSE, 
				INFINITE );

		ResetEvent(hEvent[dwEvent]);

		if (bExitSignal)	// Are we exiting?
			break;

		if (!dwEvent)
		{
			/* Excerpt from WinpkFilter documentation:
				"This event when TCP/IP bound adapter's list changes (an 
				example this happens on plug/unplug network card, 
				disable/enable network connection or etc.). Usually you 
				should call GetTcpipBoundAdaptersInfo and renew your adapter 
				associated structures on this event."

				In this code, dwEvent = 0 holds the event mentioned above.
			*/
			ReleaseHandles();

			if(!InitHandles())
				return E_INITHANDLES;

			continue;
		}

		pRequest->hAdapterHandle = (HANDLE) AdList.m_nAdapterHandle[dwEvent-1];
		while(api.ReadPacket(pRequest))
		{
			if (pRequest->EthPacket.Buffer->m_dwDeviceFlags ==
					PACKET_FLAG_ON_SEND){

				// Give packet to the topmost layer
				topLayerDownward(pRequest);
			}
			else {

				// Packet is headed up. Hand it to the bottom layer of our stack
				bottomLayerUpward(pRequest);
			}

			// Initialize pRequest for next use
			pRequest = (PETH_REQUEST) malloc(sizeof(ETH_REQUEST));
			aux = (PINTERMEDIATE_BUFFER) malloc(sizeof(INTERMEDIATE_BUFFER));
			ZeroMemory(pRequest, sizeof(ETH_REQUEST));
			ZeroMemory(aux, sizeof(INTERMEDIATE_BUFFER));
			pRequest->EthPacket.Buffer = aux;
			pRequest->hAdapterHandle = 
					(HANDLE) AdList.m_nAdapterHandle[dwEvent-1];
		} // while
	} // while

	free(pRequest->EthPacket.Buffer);
	free(pRequest);

	return 0;
}
