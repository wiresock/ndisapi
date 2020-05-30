#ifndef _INITIALIZATION_H
#define _INITIALIZATION_H

#include "Common.h"
#include "ndisInterfaceLayer.h"
#include "PacketDelayerLayer.h"
#include "PacketDropperLayer.h"

int initialize(int argc, LPCTSTR argv[]);
int InitHandles();

#endif //_INITIALIZATION_H