#ifndef _ACKTIMERLAYER_H
#define _ACKTIMERLAYER_H

#include "Common.h"

namespace acktl {

	int initLayer(UINT aTimeout, void* aNextLayer, void* aNextLayerUp);
	int haltLayer(void);
	void AckTimerLayer(PETH_REQUEST pRequest);
}

#endif //_ACKTIMERLAYER_H