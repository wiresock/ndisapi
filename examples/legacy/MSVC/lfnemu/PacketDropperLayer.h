#ifndef _PACKETDROPPERLAYER_H
#define _PACKETDROPPERLAYER_H

#include "Common.h"

namespace pdropl {

	int initLayer(UINT anIncomingDropThreshold, UINT anIncomingDropCount,
		UINT anOutgoingDropThreshold, UINT anOutgoingDropCount,
		void* aNextLayerDown, void* aNextLayerUp);
	int haltLayer(void);
	void PacketDropperLayer(PETH_REQUEST pRequest);
}

#endif //_PACKETDROPPERLAYER_H