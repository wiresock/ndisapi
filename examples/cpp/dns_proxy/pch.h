// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

#ifndef PCH_H
#define PCH_H

#include <winsock2.h>
#include <in6addr.h>
#include <tchar.h>
#include <ws2ipdef.h>
#include <IPHlpApi.h>
#include <Mstcpip.h>
#include <conio.h>
#include <WinDNS.h>

#include <memory>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <limits>
#include <atomic>
#include <string>
#include <functional>
#include <vector>
#include <cassert>
#include <array>
#include <map>
#include <cctype>
#include <mutex>
#include <shared_mutex>
#include <variant>
#include <bitset>
#include <optional>
#include <algorithm>

#include "../../../include/common.h"
#include "../../../include/ndisapi.h"
#include "../common/iphlp.h"
#include "../common/winsys/object.h"
#include "../common/winsys/event.h"
#include "../common/net/mac_address.h"
#include "../common/net/ip_address.h"
#include "../common/net/ipv6_helper.h"
#include "../common/net/ip_subnet.h"
#include "../common/iphelper/network_adapter_info.h"
#include "../common/ndisapi/network_adapter.h"
#include "../common/ndisapi/simple_packet_filter.h"
#include "../common/proxy/proxy_common.h"
#include "../common/ndisapi/udp_proxy.h"

#endif //PCH_H
