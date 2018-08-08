/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  stdafx.h                                                */
/*                                                                       */
/* Abstract: include file for standard system include files,             */
/*  or project specific include files that are used frequently, but      */
/*  are changed infrequently                                             */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#pragma once

#include "targetver.h"

#include <winsock2.h>
#include <tchar.h>
#include <ws2ipdef.h>
#include <IPHlpApi.h>
#include <conio.h>

#include <utility>
#include <vector>
#include <array>
#include <unordered_map>
#include <memory>
#include <tuple>
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <shared_mutex>
#include <optional>

using namespace std;

#include "..\..\include\common.h"
#include "..\..\include\ndisapi.h"
#include "iphlp.h"
#include "dhcp_typedefs.h"
#include "NetworkAdapter.h"
#include "EthernetBridge.h"

