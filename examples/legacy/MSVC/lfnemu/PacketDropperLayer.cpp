#include "StdAfx.h"
#include "PacketDropperLayer.h"

namespace pdropl {

// PacketDropper Layer variables
UINT incomingDropThreshold 		= 0;
UINT incomingDropCount 			= 0;
UINT incomingDropped 			= 0;
UINT incomingAllowedThru		= 0;
bool incomingBeingDropped 		= false;

UINT outgoingDropThreshold 		= 0;
UINT outgoingDropCount 			= 0;
UINT outgoingDropped 			= 0;
UINT outgoingAllowedThru		= 0;
bool outgoingBeingDropped 		= false;

void (*nextLayerDown)(PETH_REQUEST pRequest) = 0;
void (*nextLayerUp)(PETH_REQUEST pRequest) = 0;

// End of PacketDropper Layer variables


void PacketDropperLayer(PETH_REQUEST pRequest)
{
	DWORD pktDirection = pRequest->EthPacket.Buffer->m_dwDeviceFlags;
	void (*nextLayer)(PETH_REQUEST pRequest) = 0;

	if (pktDirection & PACKET_FLAG_ON_SEND){

		// Have we dropped all packets we are supposed to?
		if (outgoingDropped == outgoingDropCount){
			outgoingBeingDropped = false;
			outgoingDropped = 0;
		}

		// Have we let thru all pkts we are supposed to?
		if (outgoingAllowedThru == outgoingDropThreshold){
			outgoingBeingDropped = true;
			outgoingAllowedThru = 0;
		}

		// Is our presence required?
		if ((outgoingDropCount == 0) && (outgoingDropThreshold == 0)){
			outgoingBeingDropped = false;
		}

		// If we have to drop the pkt, do it.
		if (outgoingBeingDropped){
			outgoingDropped++;
			free(pRequest->EthPacket.Buffer);
			free(pRequest);
			return;
		} else
			outgoingAllowedThru++;

		nextLayer = nextLayerDown;
	}
	else if (pktDirection & PACKET_FLAG_ON_RECEIVE){

		// Have we dropped all packets we are supposed to?
		if (incomingDropped == incomingDropCount){
			incomingBeingDropped = false;
			incomingDropped = 0;
		}

		// Have we let thru all pkts we are supposed to?
		if (incomingAllowedThru == incomingDropThreshold){
			incomingBeingDropped = true;
			incomingAllowedThru = 0;
		}

		// Is our presence required?
		if ((incomingDropCount == 0) && (incomingDropThreshold == 0)){
			incomingBeingDropped = false;
		}

		// If we have to drop the pkt, do it.
		if (incomingBeingDropped){
			incomingDropped++;
			free(pRequest->EthPacket.Buffer);
			free(pRequest);
			return;
		} else
			incomingAllowedThru++;

		nextLayer = nextLayerUp;
	}
	else {
		_tprintf(_T("ERROR: Invalid packet direction flag.\n"));
	}

	if (nextLayer)
		nextLayer(pRequest);
}

int initLayer(UINT anIncomingDropThreshold, UINT anIncomingDropCount,
		UINT anOutgoingDropThreshold, UINT anOutgoingDropCount,
		void* aNextLayerDown, void* aNextLayerUp)
{
	if (!aNextLayerDown || !aNextLayerUp)
		return false;

	if ((anIncomingDropCount == 0) && (anIncomingDropThreshold == 0) &&
			(anOutgoingDropThreshold == 0) && (anOutgoingDropCount == 0))
		return false;

	incomingDropCount = anIncomingDropCount;
	incomingDropThreshold = anIncomingDropThreshold;
	outgoingDropCount = anOutgoingDropCount;
	outgoingDropThreshold = anOutgoingDropThreshold;

	nextLayerDown = (void (*) (PETH_REQUEST)) aNextLayerDown;
	nextLayerUp   = (void (*) (PETH_REQUEST)) aNextLayerUp;

	return true;
}

int haltLayer(void)
{
	return true;
}

} // namespace pdropl
