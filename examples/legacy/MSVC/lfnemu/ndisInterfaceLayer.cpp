#include "stdafx.h"
#include "ndisInterfaceLayer.h"

void ndisBottomLayer(PETH_REQUEST pRequest)
{
	api.SendPacketToAdapter(pRequest);
	free(pRequest->EthPacket.Buffer);
	free(pRequest);
}

void ndisTopLayer(PETH_REQUEST pRequest)
{
	api.SendPacketToMstcp(pRequest);
	free(pRequest->EthPacket.Buffer);
	free(pRequest);
}
