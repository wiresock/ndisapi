#ifndef _COMMON_DEFINITIONS_H
#define _COMMON_DEFINITIONS_H

#define E_INITHANDLES		0x00000001
#define E_INVALIDOPTION		0x00000002
#define E_DRIVERNOTPRESENT	0x00000003
#define E_INITEVENT			0x00000004
#define E_ATENTIONTHREAD	0x00000005

#define ALL_PACKETS INFINITE

extern TCP_AdapterList		AdList;
extern CNdisApi				api;
extern DWORD				dwAdapterCount;
extern HANDLE				hEvent[33];
extern BOOL					bPausing;
extern BOOL					bExitSignal;
extern BOOL					bUsePAcketCount;

extern DWORD				dwDelayFrecuency;
extern DWORD				dwDelayPktCount;
extern DWORD				dwDelayLength;		
extern DWORD				dwDelayDelta;		
extern DWORD				dwPktRemaining;
extern HANDLE				hCountPktsSentEv;
extern std::vector <PETH_REQUEST> vFlushBuffer;

extern CRITICAL_SECTION	csMapLock;

extern bool usePacketDropperLayer;
extern bool usePacketDelayerLayer;
//extern bool useAckTimerLayer;

extern void (*topLayerDownward)(PETH_REQUEST pRequest);
extern void (*bottomLayerUpward)(PETH_REQUEST pRequest);

extern void ReleaseInterface();
extern DWORD FlushNBufferedPackets(BOOL bSend, UINT count);

#endif //_COMMON_DEFINITIONS_H