#include "stdafx.h"
#include "PacketDelayerLayer.h"

namespace pdl {

// PacketDelayer Layer variables

typedef struct _TIME_STAMPED_PACKET
{
	PETH_REQUEST	pRequest;
	DWORD			arrivalTime;
} TIME_STAMPED_PACKET, *PTIME_STAMPED_PACKET;

std::vector<PTIME_STAMPED_PACKET>	downwardDelayedPktsQueue;
std::vector<PTIME_STAMPED_PACKET>	upwardDelayedPktsQueue;
CRITICAL_SECTION	downwardQueueLock;
CRITICAL_SECTION	upwardQueueLock;
HANDLE				newDownwardPktQueued;
HANDLE				newUpwardPktQueued;
UINT				downwardDelayLapse;
UINT				upwardDelayLapse;
bool				exitSignal = false;

void (*nextLayerDown)(PETH_REQUEST pRequest) = 0;
void (*nextLayerUp)(PETH_REQUEST pRequest) = 0;

// End of RandomDroper Layer variables

void downwardDelayedPktsSender(void*)
{
	PTIME_STAMPED_PACKET pkt;
	std::vector<PTIME_STAMPED_PACKET>::iterator i;
	DWORD waitResult, now = 0;
	DWORD wakeupTime = 0;

	do {
		if (wakeupTime > now)
			Sleep(wakeupTime - now);

		::EnterCriticalSection(&downwardQueueLock);
		if (downwardDelayedPktsQueue.empty()){
			::LeaveCriticalSection(&downwardQueueLock);

			waitResult = ::WaitForSingleObject(newDownwardPktQueued, INFINITE);

			if ((waitResult == WAIT_ABANDONED) || (waitResult == WAIT_FAILED)
					|| exitSignal)
				return;

			::EnterCriticalSection(&downwardQueueLock);
		}

		now = ::GetTickCount();
		i = downwardDelayedPktsQueue.begin();
		while (i != downwardDelayedPktsQueue.end()){
			pkt = (PTIME_STAMPED_PACKET) *i;

			// Should I add 10 or 5 to avoid sleeping for very short periods?
			wakeupTime = pkt->arrivalTime + downwardDelayLapse;
			if (wakeupTime <= now){
				if (nextLayerDown)
					nextLayerDown(pkt->pRequest);
				i = downwardDelayedPktsQueue.erase(i);
				free(pkt);
			}
			else
				break;
		} // while

		::LeaveCriticalSection(&downwardQueueLock);

	} while (!exitSignal);
}

void upwardDelayedPktsSender(void*)
{
	PTIME_STAMPED_PACKET pkt;
	std::vector<PTIME_STAMPED_PACKET>::iterator i;
	DWORD waitResult, now = 0;
	DWORD wakeupTime = 0;

	do {
		if (wakeupTime > now)
			Sleep(wakeupTime - now);

		::EnterCriticalSection(&upwardQueueLock);
		if (upwardDelayedPktsQueue.empty()){
			::LeaveCriticalSection(&upwardQueueLock);

			waitResult = ::WaitForSingleObject(newUpwardPktQueued, INFINITE);

			if ((waitResult == WAIT_ABANDONED) || (waitResult == WAIT_FAILED)
					|| exitSignal)
				return;

			::EnterCriticalSection(&upwardQueueLock);
		}

		now = ::GetTickCount();
		i = upwardDelayedPktsQueue.begin();
		while (i != upwardDelayedPktsQueue.end()){
			pkt = (PTIME_STAMPED_PACKET) *i;

			// Should I add 10 or 5 to avoid sleeping for very short periods?
			wakeupTime = pkt->arrivalTime + upwardDelayLapse;
			if (wakeupTime <= now){
				if (nextLayerUp)
					nextLayerUp(pkt->pRequest);
				i = upwardDelayedPktsQueue.erase(i);
				free(pkt);
			}
			else
				break;
		} // while

		::LeaveCriticalSection(&upwardQueueLock);

	} while (!exitSignal);
}

int initLayer(UINT aDownwardDelayLapse, UINT anUpwardDelayLapse,
		void* aNextLayerDown, void* aNextLayerUp)
{
	if ((!aNextLayerDown) || (!aNextLayerUp))
		return false;

	downwardDelayedPktsQueue.clear();
	upwardDelayedPktsQueue.clear();

	::InitializeCriticalSection(&downwardQueueLock);
	::InitializeCriticalSection(&upwardQueueLock);

	newDownwardPktQueued = ::CreateEvent(NULL, FALSE, FALSE, NULL);
	newUpwardPktQueued = ::CreateEvent(NULL, FALSE, FALSE, NULL);

	downwardDelayLapse = aDownwardDelayLapse;
	upwardDelayLapse = anUpwardDelayLapse;

	nextLayerDown = (void (*) (PETH_REQUEST)) aNextLayerDown;
	nextLayerUp = (void (*) (PETH_REQUEST)) aNextLayerUp;

	if ((LONG) _beginthread(downwardDelayedPktsSender, 0, NULL) == -1)
		return false;
	if ((LONG) _beginthread(upwardDelayedPktsSender, 0, NULL) == -1)
		return false;

	return true;
}

int haltLayer(void)
{
	exitSignal = true;
	::SetEvent(newDownwardPktQueued);
	::SetEvent(newUpwardPktQueued);
	Sleep(100);
	int result = ::CloseHandle(newDownwardPktQueued);
	result &= ::CloseHandle(newUpwardPktQueued);
	::DeleteCriticalSection(&downwardQueueLock);
	::DeleteCriticalSection(&upwardQueueLock);

	for (std::vector<PTIME_STAMPED_PACKET>::iterator i =
			downwardDelayedPktsQueue.begin();
			i != downwardDelayedPktsQueue.end();
			i++){
		free(((PTIME_STAMPED_PACKET) *i)->pRequest->EthPacket.Buffer);
		free(((PTIME_STAMPED_PACKET) *i)->pRequest);
	}

	for (std::vector<PTIME_STAMPED_PACKET>::iterator j =
			upwardDelayedPktsQueue.begin();
			j != upwardDelayedPktsQueue.end();
			j++){
		free(((PTIME_STAMPED_PACKET) *j)->pRequest->EthPacket.Buffer);
		free(((PTIME_STAMPED_PACKET) *j)->pRequest);
	}

	downwardDelayedPktsQueue.clear();
	upwardDelayedPktsQueue.clear();

	return result;
}

void PacketDelayerLayer(PETH_REQUEST pRequest)
{
	PTIME_STAMPED_PACKET pkt;
	DWORD direction;

	if ((!pRequest) ||							// invalid structure
			(!pRequest->EthPacket.Buffer))		// invalid packet
		return; // ignore packet

	direction = pRequest->EthPacket.Buffer->m_dwDeviceFlags;

	// Are we delaying outgoing packets?
	if ((direction == PACKET_FLAG_ON_SEND) && (downwardDelayLapse == 0)) {
		if (nextLayerDown)
			nextLayerDown(pRequest); // No, send it now
		return;
	}

	// Are we delaying incoming packets?
	if ((direction == PACKET_FLAG_ON_RECEIVE) && (upwardDelayLapse == 0)) {
		if (nextLayerUp)
			nextLayerUp(pRequest); // No, send it now
		return;
	}

	pkt = (PTIME_STAMPED_PACKET) malloc(sizeof(TIME_STAMPED_PACKET));

	if (!pkt){			// insufficient memory

		free(pRequest->EthPacket.Buffer);
		free(pRequest);
		return; // ignore packet
	}

	pkt->pRequest = pRequest;
	pkt->arrivalTime = ::GetTickCount();

	switch (direction)
	{
	  case PACKET_FLAG_ON_SEND:
		::EnterCriticalSection(&downwardQueueLock);

		if (downwardDelayedPktsQueue.empty())
			::SetEvent(newDownwardPktQueued);

		downwardDelayedPktsQueue.push_back(pkt);
		::LeaveCriticalSection(&downwardQueueLock);
	  break;
	  case PACKET_FLAG_ON_RECEIVE:
		::EnterCriticalSection(&upwardQueueLock);

		if (upwardDelayedPktsQueue.empty())
			::SetEvent(newUpwardPktQueued);

		upwardDelayedPktsQueue.push_back(pkt);
		::LeaveCriticalSection(&upwardQueueLock);
	  break;
	  default:	//error: invalid direction
		free(pRequest->EthPacket.Buffer);
		free(pRequest);
		free(pkt);
	}
}

} // namespace pdl