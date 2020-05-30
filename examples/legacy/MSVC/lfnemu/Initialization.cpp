#include "stdafx.h"
#include "Initialization.h"

void initPacketDropper(LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR);
void initPacketDelayer(LPCTSTR, LPCTSTR);
void usage(LPCTSTR argv[]);
void HandleCtrlC(int);
int InitHandles();
void selectLayers(LPCTSTR argv[]);

int initialize(int argc, LPCTSTR argv[])
{
	if (argc != 7){
		usage(argv);
		return E_INVALIDOPTION;
	}

	selectLayers(argv);

	initPacketDropper(argv[1], argv[2], argv[4], argv[5]);
	if (usePacketDropperLayer){
		if (!topLayerDownward)
			topLayerDownward = pdropl::PacketDropperLayer;
		if (!bottomLayerUpward)
			bottomLayerUpward = pdropl::PacketDropperLayer;
	 }

	initPacketDelayer(argv[3], argv[6]);
	if (usePacketDelayerLayer) {
		if (!topLayerDownward)
			topLayerDownward = pdl::PacketDelayerLayer;
		bottomLayerUpward = pdl::PacketDelayerLayer;
	 }

	if (!topLayerDownward)
		topLayerDownward = ndisBottomLayer;

	if (!bottomLayerUpward)
		bottomLayerUpward = ndisTopLayer;

	if(!api.IsDriverLoaded()){
		_tprintf(_T("Driver not installed on this system or failed to load.\n"));
		return E_DRIVERNOTPRESENT;
	}

	InitHandles();

	// Set adapter event for helper driver
	hEvent[0] = CreateEvent(NULL, TRUE, FALSE, NULL);

	if ((!hEvent[0]) || (!api.SetAdapterListChangeEvent(hEvent[0]))){
		_tprintf(_T("Failed to create notification event for adapter or"
			" set it for driver.\n"));
			return E_INITEVENT;
	}

	signal(SIGINT, HandleCtrlC);
	atexit(ReleaseInterface);
	
	::InitializeCriticalSection(&csMapLock);

	return 0;
}

void usage(LPCTSTR argv[])
{
	TCHAR *name = NULL;
	
	name = _tcsrchr(const_cast<TCHAR*>(argv[0]), _T('\\'));

	if(!name)
	{
		name = const_cast<TCHAR*>(argv[0]);
	}
	else
	{
		name++;
	}

	_tprintf(_T("Simulates a long-fat-network.\n"
	" USAGE: %s  idc idt id odc odt od\n"
	" OPTIONS:\n"
	" idc: IncomingDropCount. How many incoming packets will be dropped in a row.\n"
	" idt: IncomingDropThreshold. Incoming packets that will not be dropped.\n"
	" id:  IncomingDelay. How long incoming packets will be delayed, in ms.\n"
	" idc: OutgoingDropCount. How many outgoing packets will be dropped in a row.\n"
	" idt: OutgoingDropThreshold. Outgoing packets that will not be dropped.\n"
	" od:  OutgoingDelay. How long outgoing packets will be delayed, in ms.\n"
	" All parameters are required. A zero(0) disables the function\n"
	" Example: %s 2 8 0 0 0 100. This setting will drop to 2 incoming\n"
	" packets, then 8 will be let trough. All outgoing packets will be \n"
	" delayed 100 ms.\n"
	"\n"),
	name, name);

}

void HandleCtrlC(int)
{
	bExitSignal = true;
	SetEvent(hEvent[0]);
	SetEvent(hCountPktsSentEv);
}

int InitHandles()
{
	api.GetTcpipBoundAdaptersInfo ( &AdList );

	ADAPTER_MODE Mode;

	Mode.dwFlags = MSTCP_FLAG_SENT_TUNNEL|MSTCP_FLAG_RECV_TUNNEL;
	
	dwAdapterCount	=	AdList.m_nAdapterCount + 1;

	// Create notification events
	for(UINT nCount = 1; nCount < dwAdapterCount; nCount++)
	{
		hEvent[nCount] = CreateEvent(NULL, TRUE, FALSE, NULL);

		Mode.hAdapterHandle = (HANDLE)AdList.m_nAdapterHandle[nCount-1];

		// Set event for helper driver
		if ((!hEvent[nCount]) ||
				(!api.SetPacketEvent((HANDLE)AdList.m_nAdapterHandle[nCount-1], 
						hEvent[nCount])))
		{
			_tprintf(_T("Failed to create notification event or"
					" set it for driver.\n"));
			return 0;
		}

		api.SetAdapterMode(&Mode);
	}

	return 1;
}

void initPacketDropper(LPCTSTR idc, LPCTSTR idt, LPCTSTR odc, LPCTSTR odt)
{
	int result;
	void *nextLayerDown, *nextLayerUp;

	// PacketDroper Layer initialization
	_tprintf(_T("Initializing Packet dropper..."));
	int incomingDropCount = _ttoi(idc);
	int incomingDropThreshold = _ttoi(idt);
	int outgoingDropCount = _ttoi(odc);
	int outgoingDropThreshold = _ttoi(odt);

	// We don't allow negative values
	if ((incomingDropCount < 0) || (outgoingDropCount < 0) ||
			(incomingDropThreshold < 0) || (outgoingDropThreshold < 0)){
		_tprintf(_T("FAILED\n"));
		_tprintf(_T("Error. Negative values are not allowed\n"));
		exit(E_INVALIDOPTION);
	}

	// Check if the conversions from string to integer worked properly
	if (incomingDropThreshold == 0){

		if (_tcsncmp(idt, _T("0"), sizeof(TCHAR) * 3)){
			_tprintf(_T("FAILED\n"));
			exit(E_INVALIDOPTION);
		}
	}

	if (incomingDropCount == 0){

		if (_tcsncmp(idc, _T("0"), sizeof(TCHAR) * 3)){
			_tprintf(_T("FAILED\n"));
			exit(E_INVALIDOPTION);
		}
	}

	if (outgoingDropThreshold == 0){

		if (_tcsncmp(odt, _T("0"), sizeof(TCHAR) * 3)){
			_tprintf(_T("FAILED\n"));
			exit(E_INVALIDOPTION);
		}
	}

	if (outgoingDropCount == 0){

		if (_tcsncmp(odc, _T("0"), sizeof(TCHAR) * 3)){
			_tprintf(_T("FAILED\n"));
			exit(E_INVALIDOPTION);
		}
	}
	// All conversions are ok.

	if ((incomingDropCount ==0) && (incomingDropThreshold == 0) &&
			(outgoingDropCount == 0) && (outgoingDropThreshold == 0)){
		_tprintf(_T("Disabled\n"));
		return;
	}

	// Now link this layer in into our stack. First the upward stack
	nextLayerUp = ndisTopLayer;

	// Now downward stack
	if (usePacketDelayerLayer)
		nextLayerDown = pdl::PacketDelayerLayer;
	else
		nextLayerDown = ndisBottomLayer;

	// Check if layer will run properly.
	result = pdropl::initLayer((UINT) incomingDropThreshold, incomingDropCount,
			(UINT) outgoingDropThreshold, outgoingDropCount, nextLayerDown,
			nextLayerUp);

	if (result)
		_tprintf(_T("Ok\n"));
	else
		_tprintf(_T("FAILED\n"));
}

void initPacketDelayer(LPCTSTR arg1, LPCTSTR arg2)
{
	int result;
	void *nextLayerDown, *nextLayerUp;

	// PacketDelayer Layer initialization
	_tprintf(_T("Initializing Packet Delayer..."));
	int incomingDelay = _ttoi(arg1);
	int outgoingDelay = _ttoi(arg2);

	if ((incomingDelay < 0) || (outgoingDelay < 0)){
		_tprintf(_T("FAILED\n"));
		_tprintf(_T("Error. Negative values are not allowed\n"));
		exit(E_INVALIDOPTION);
	}

	if (incomingDelay == 0) {

		if (_tcsncmp(arg1,_T("0"),sizeof(TCHAR) * 3)){
			_tprintf(_T("FAILED\n\n"));
			exit(E_INVALIDOPTION);
		}
	}

	if (outgoingDelay == 0) {

		if (_tcsncmp(arg2,_T("0"),sizeof(TCHAR) * 3)){
			_tprintf(_T("FAILED\n\n"));
			exit(E_INVALIDOPTION);
		}
	}

	if ((incomingDelay == 0) && (outgoingDelay == 0)){
		_tprintf(_T("Disabled\n"));
		return;
	}

	nextLayerDown = ndisBottomLayer;

	if (usePacketDropperLayer)
		nextLayerUp = pdropl::PacketDropperLayer;
	else
		nextLayerUp = ndisTopLayer;

	result = pdl::initLayer((UINT) outgoingDelay, (UINT) incomingDelay,
			nextLayerDown, nextLayerUp);

	if (result)
		_tprintf(_T("Ok\n"));
	else
		_tprintf(_T("FAILED\n"));
}

void selectLayers(LPCTSTR argv[])
{
	int aux = _ttoi(argv[1]);
	if (aux != 0)
		usePacketDropperLayer = true;

	aux = _ttoi(argv[2]);
	if (aux != 0)
		usePacketDropperLayer = true;

	aux = _ttoi(argv[3]);
	if (aux != 0)
		usePacketDelayerLayer = true;

	aux = _ttoi(argv[4]);
	if (aux != 0)
		usePacketDropperLayer = true;

	aux = _ttoi(argv[5]);
	if (aux != 0)
		usePacketDropperLayer = true;

	aux = _ttoi(argv[6]);
	if (aux != 0)
		usePacketDelayerLayer = true;
}
