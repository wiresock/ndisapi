// pch.h: pre-compiled header for the packet_owner example

#ifndef PCH_H
#define PCH_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>
#include <tchar.h>
#include <ws2ipdef.h>
#include <IPHlpApi.h>
#include <Mstcpip.h>
#include <conio.h>

#include <memory>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <limits>
#include <atomic>
#include <string>
#include <functional>
#include <vector>
#include <deque>
#include <cassert>
#include <array>
#include <map>
#include <unordered_map>
#include <cctype>
#include <cmath>
#include <cwctype>
#include <shared_mutex>
#include <mutex>
#include <condition_variable>
#include <set>
#include <algorithm>
#include <optional>
#include <variant>
#include <bitset>
#include <charconv>
#include <gsl/gsl>

#include "../../../include/common.h"
#include "../../../include/ndisapi.h"
#include "../common/iphlp.h"
#include "../common/winsys/object.h"
#include "../common/winsys/event.h"
#include "../common/net/mac_address.h"
#include "../common/net/ip_address.h"
#include "../common/net/ip_subnet.h"
#include "../common/net/ip_endpoint.h"
#include "../common/iphelper/network_adapter_info.h"
#include "../common/ndisapi/network_adapter.h"
#include "../common/ndisapi/simple_packet_filter.h"
#include "../common/iphelper/process_lookup.h"
#include "../common/iphelper/etw_packet_attributor.h"

#endif //PCH_H
