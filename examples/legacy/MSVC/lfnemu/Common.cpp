#include "StdAfx.h"
#include "Common.h"

TCP_AdapterList		AdList;
CNdisApi			api;
DWORD				dwAdapterCount;
HANDLE				hEvent[33];
BOOL				bPausing = false;
BOOL				bExitSignal = false;
BOOL				bUsePAcketCount = false;

DWORD				dwDelayFrecuency = 0;	
DWORD				dwDelayPktCount = 0;
DWORD				dwDelayLength;		
DWORD				dwDelayDelta;		
DWORD				dwPktRemaining;
HANDLE				hCountPktsSentEv;
std::vector <PETH_REQUEST> vFlushBuffer;

bool usePacketDropperLayer	= false;
bool usePacketDelayerLayer	= false;
bool useAckTimerLayer		= false;

void (*topLayerDownward)(PETH_REQUEST pRequest) = 0;
void (*bottomLayerUpward)(PETH_REQUEST pRequest) = 0;

CRITICAL_SECTION	csMapLock;
