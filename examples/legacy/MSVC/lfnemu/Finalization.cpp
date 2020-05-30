#include "stdafx.h"
#include "Finalization.h"

//
// Function sends n (if specified) or all buffered TCP stream. If count was 
// used, it returns Count - Sent, that is the remaining packets that could've
// been sent.
//
DWORD FlushNBufferedPackets(BOOL bSend, UINT count)
{
	std::vector<PETH_REQUEST>::iterator theIterator;
	
	for (theIterator = vFlushBuffer.begin(); theIterator != 
			vFlushBuffer.end(); theIterator++)
	{
		if(bSend)
		{
			// Place packet on the network interface
			api.SendPacketToAdapter((PETH_REQUEST)(*theIterator));
		}

		if (bUsePAcketCount && (!--count))
		{
			vFlushBuffer.erase(vFlushBuffer.begin(), ++theIterator);
			return 0;
		}

		delete (*theIterator);
	}

	vFlushBuffer.clear();
	return (bUsePAcketCount? 0: count);
}


void ReleaseHandles()
{
	// This function releases packets in the adapter queue and stops listening the interface
	ADAPTER_MODE Mode;

	for(UINT nCount = 0; nCount < dwAdapterCount - 1; nCount++)
	{
		Mode.dwFlags = 0;
		Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[nCount];

		// Set NULL event to release previously set event object
		api.SetPacketEvent(AdList.m_nAdapterHandle[nCount], NULL);

		// Close Event
		if (hEvent[nCount+1])
			CloseHandle ( hEvent[nCount+1] );

		// Set default adapter mode
		api.SetAdapterMode(&Mode);

		// Empty adapter packets queue
		api.FlushAdapterPacketQueue (AdList.m_nAdapterHandle[nCount]);
	}

}

void ReleaseInterface()
{
	if (usePacketDropperLayer){
		_tprintf(_T("Halting Packet dropper..."));
		_tprintf(_T("%s"), pdropl::haltLayer()? _T("Ok\n"): _T("FAILED\n"));
	}

	if (usePacketDelayerLayer){
		_tprintf(_T("Halting Packet Delayer..."));
		_tprintf(_T("%s"), pdl::haltLayer()? _T("Ok\n"): _T("FAILED\n"));
	}

	ReleaseHandles();

	if (hEvent[0])
		CloseHandle ( hEvent[0] );

	if (hCountPktsSentEv)
		CloseHandle(hCountPktsSentEv);
	
	std::vector<PETH_REQUEST>::iterator theIterator;

	::EnterCriticalSection(&csMapLock);
	
	for (theIterator = vFlushBuffer.begin(); theIterator != vFlushBuffer.end();
			theIterator++)
	{
		FlushNBufferedPackets(FALSE, ALL_PACKETS);
	}

	vFlushBuffer.clear();
	
	::LeaveCriticalSection(&csMapLock);

	::DeleteCriticalSection(&csMapLock);
}

