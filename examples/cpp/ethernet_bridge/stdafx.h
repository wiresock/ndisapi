// --------------------------------------------------------------------------------
/// <summary>
/// include file for standard system include files,or project specific include 
/// files that are used frequently, but are changed infrequently 
/// </summary>
// --------------------------------------------------------------------------------

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
#include <map>
#include <fstream>
#include <charconv>
#include <gsl/gsl>

using namespace std;

#include "../../../include/common.h"
#include "../../../include/ndisapi.h"
#include "../common/iphlp.h"
#include "../common/dhcp_typedefs.h"
#include "../common/net/ip_address.h"
#include "../common/net/mac_address.h"
#include "../common/winsys/object.h"
#include "../common/winsys/event.h"
#include "../common/pcap/pcap.h"
#include "../common/pcap/pcap_file_storage.h"
#include "NetworkAdapter.h"
#include "EthernetBridge.h"

