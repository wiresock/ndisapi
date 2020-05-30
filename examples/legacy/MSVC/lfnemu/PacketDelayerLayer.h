#ifndef _PACKET_DELAYER_LAYER_H
#define _PACKET_DELAYER_LAYER_H

#include "Common.h"

namespace pdl {

	int initLayer(UINT aDownwardDelayLapse, UINT anUpwardDelayLapse,
		void* aNextLayerDown, void* aNextLayerUp);
	int haltLayer(void);
	void PacketDelayerLayer(PETH_REQUEST pRequest);
}

#endif //_PACKET_DELAYER_LAYER_H