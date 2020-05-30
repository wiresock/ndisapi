{                 Windows Packet Filter Kit 3.0 interface             }
{                 Copyright(C) 2000-2013 NT Kernel Resources          }
{                         mailto: ndisrd@ntkernel.com                 }
{                                                                     }
{                 Delphi import unit fixed on 2003-02-21 by           }
{                 Federico Simonetti (aka BackDream)                  }
{                 Reworked to load library dinamically on 2006-06-23  }
{                 by Alex Shakhaylo                                   }

unit winpkf;

interface

uses
  Windows, SysUtils;

const

// Some size constants
  ADAPTER_NAME_SIZE = 256;
  ADAPTER_LIST_SIZE = 32;
  ETHER_ADDR_LENGTH = 6;
  MAX_ETHER_FRAME = 1514;

// Adapter flags
  MSTCP_FLAG_SENT_TUNNEL = $1;    // Receive packets sent by MSTCP
  MSTCP_FLAG_RECV_TUNNEL = $2;    // Receive packets instead MSTCP
  MSTCP_FLAG_SENT_LISTEN = $4;    // Receive packets sent by MSTCP, original ones delivered to the network
  MSTCP_FLAG_RECV_LISTEN = $8;    // Receive packets received by MSTCP
  MSTCP_FLAG_FILTER_DIRECT = $10; // In promiscuous mode TCP/IP stack receives all
			          // packets in the ethernet segment, to prevent this set this flag
			          // All packets with destination MAC different from FF-FF-FF-FF-FF-FF and
			          // network interface current MAC will be blocked

// By default loopback packets are passed to original MSTCP handlers without processing,
// to change this behavior use the flags below
  MSTCP_FLAG_LOOPBACK_FILTER = $20;  // Pass loopback packet for processing
  MSTCP_FLAG_LOOPBACK_BLOCK  = $40;  // Silently drop loopback packets, this flag
				     // is recommended for usage in combination with
			             // promiscuous mode

// Device flags for intermediate buffer
  PACKET_FLAG_ON_SEND = 1;
  PACKET_FLAG_ON_RECEIVE = 2;

// RAS connections relative definitions
  RAS_LINK_BUFFER_LENGTH = 1024;
  RAS_LINKS_MAX = 256;

// filter flags
  FILTER_PACKET_PASS = 1;     // Pass packet if if matches the filter
  FILTER_PACKET_DROP = 2;     // Drop packet if it matches the filter
  FILTER_PACKET_REDIRECT = 3; // Redirect packet to WinpkFilter client application

  DATA_LINK_LAYER_VALID = 1;  // Match packet against data link layer filter
  NETWORK_LAYER_VALID = 2;    // Match packet against network layer filter
  TRANSPORT_LAYER_VALID = 4;  // Match packet against transport layer filter

  ETH_802_3 = 1;

  ETH_802_3_SRC_ADDRESS = 1;
  ETH_802_3_DEST_ADDRESS = 2;
  ETH_802_3_PROTOCOL = 4;

  IPV4 = 1;
  IPV6 = 2;

  IP_V4_FILTER_SRC_ADDRESS = 1;
  IP_V4_FILTER_DST_ADDRESS = 2;
  IP_V4_FILTER_PROTOCOL = 4;

  IP_SUBNET_V4_TYPE = 1;
  IP_RANGE_V4_TYPE = 2;

  IP_V6_FILTER_SRC_ADDRESS = 1;
  IP_V6_FILTER_DST_ADDRESS = 2;
  IP_V6_FILTER_PROTOCOL = 4;

  IP_SUBNET_V6_TYPE = 1;
  IP_RANGE_V6_TYPE = 2;

  TCPUDP = 1;

  TCPUDP_SRC_PORT = 1;
  TCPUDP_DST_PORT = 2;
  TCPUDP_TCP_FLAGS = 4;

type

  PTCP_AdapterList = ^TCP_AdapterList;
  TCP_AdapterList = packed record
    m_nAdapterCount: DWORD; // Number of adapters
    m_szAdapterNameList: array[1..ADAPTER_LIST_SIZE, 1..ADAPTER_NAME_SIZE] of AnsiChar; // Array of adapter names
    m_nAdapterHandle: array[1..ADAPTER_LIST_SIZE] of THANDLE; // Array of adapter handles, this are key handles for any adapter relative operation
    m_nAdapterMediumList: array[1..ADAPTER_LIST_SIZE] of DWORD; // List of adapter mediums
    m_czCurrentAddress: array[1..ADAPTER_LIST_SIZE, 1..ETHER_ADDR_LENGTH] of Byte; // current (configured) ethernet address
    m_usMTU: array[1..ADAPTER_LIST_SIZE] of Word; // current adapter MTU
  end;

  PLIST_ENTRY = ^LIST_ENTRY;
  LIST_ENTRY = record
    Flink: PLIST_ENTRY;
    Blink: PLIST_ENTRY;
  end;

  PINTERMEDIATE_BUFFER = ^INTERMEDIATE_BUFFER;
  INTERMEDIATE_BUFFER = packed record
    m_qLink: LIST_ENTRY;
    m_dwDeviceFlags: DWORD;
    m_Length: DWORD;
    m_Flags: DWORD;
    m_8021q: DWORD;
    m_FilterID: DWORD;
    m_Reserved: array[1..4] of DWORD;
    m_IBuffer: array[1..MAX_ETHER_FRAME] of Byte;
  end;

  PNDISRD_ETH_Packet = ^NDISRD_ETH_Packet;
  NDISRD_ETH_Packet = packed record
    Buffer: PINTERMEDIATE_BUFFER;
  end;

  PETH_REQUEST = ^ETH_REQUEST;
  ETH_REQUEST = packed record
    hAdapterHandle: THANDLE;
    EthPacket: NDISRD_ETH_Packet;
  end;

  PETH_M_REQUEST = ^ETH_M_REQUEST;
  ETH_M_REQUEST = packed record 
    hAdapterHandle: THANDLE;
    dwPacketsNumber: DWORD;
    dwPacketsSuccess: DWORD;
    EthPacket: array[0..0] of NDISRD_ETH_Packet;
  end;

  PADAPTER_MODE = ^ADAPTER_MODE;
  ADAPTER_MODE = packed record
    hAdapterHandle: THANDLE;
    dwFlags: DWORD;
  end;

  PADAPTER_EVENT = ^ADAPTER_EVENT;
  ADAPTER_EVENT = packed record
    hAdapterHandle: THANDLE;
    hEvent: THANDLE;
  end;

  PPACKET_OID_DATA = ^PACKET_OID_DATA;
  PACKET_OID_DATA = packed record
    hAdapterHandle: THANDLE;
    Oid: DWORD;
    Length: DWORD;
    Data: array[0..0] of Byte;
  end;

  PRAS_LINK_INFO = ^RAS_LINK_INFO;
  RAS_LINK_INFO = packed record
    LinkSpeed: DWORD;
    RemoteAddress: array[1..ETHER_ADDR_LENGTH] of byte;
    LocalAddress: array[1..ETHER_ADDR_LENGTH] of byte;
    ProtocolBufferLength: DWORD;
    ProtocolBuffer: array[1..RAS_LINK_BUFFER_LENGTH] of byte;
  end;

  PRAS_LINKS = ^RAS_LINKS;
  RAS_LINKS = packed record
    nNumberOfLinks: DWORD;
    RasLinks: array[1..RAS_LINKS_MAX] of RAS_LINK_INFO;
  end;

  TETH_802_3_FILTER = packed record
	  m_ValidFields: Cardinal;                            // Specifies which of the fileds below contain valid values and should be matched against the packet
	  m_SrcAddress: array[1..ETHER_ADDR_LENGTH] of byte;	// Source MAC address
	  m_DstAddress: array[1..ETHER_ADDR_LENGTH] of byte;	// Destination MAC address
	  m_Protocol: system.Word;                            // EtherType
	  Padding:system.Word;
  end;

  TDATA_LINK_LAYER_FILTER = packed record
    m_dwUnionSelector: Cardinal;
	  m_Eth8023Filter: TETH_802_3_FILTER;
  end;

  TIP_SUBNET_V4 = packed record
    m_Ip: Cardinal;     // IPv4 address expressed as ULONG
	  m_IpMask: Cardinal; // IPv4 mask expressed as ULONG
  end;

  TIP_RANGE_V4 = packed record
	  m_StartIp: Cardinal; // IPv4 address expressed as ULONG
	  m_EndIp: Cardinal;   // IPv4 address expressed as ULONG
  end;

  TIP_ADDRESS_V4 = packed record
	  m_AddressType: Cardinal; // Specifies which of the IP v4 address types is used below
    case integer of
      0: (m_IpSubnet: TIP_SUBNET_V4);
      1: (m_IpRange: TIP_RANGE_V4);
  end;

  TIP_V4_FILTER = packed record
	  m_ValidFields: Cardinal;	     // Specifies which of the fileds below contain valid values and should be matched against the packet
	  m_SrcAddress: TIP_ADDRESS_V4;	 // IP v4 source address
	  m_DstAddress: TIP_ADDRESS_V4;  // IP v4 destination address
	  m_Protocol: byte;         		 // Specifies next protocol
	  Padding: array[1..3] of byte;
  end;

  TIP_IN6_ADDR = packed record
	m_Byte: array[1..16] of byte; // IPv6 address 
  end;

  TIP_SUBNET_V6 = packed record
    m_Ip: TIP_IN6_ADDR;     // IPv6 address
    m_IpMask: TIP_IN6_ADDR; // IPv6 mask
  end;

  TIP_RANGE_V6 = packed record
	  m_StartIp: TIP_IN6_ADDR; // IPv6 address 
	  m_EndIp: TIP_IN6_ADDR;   // IPv6 address 
  end;

  TIP_ADDRESS_V6 = packed record
	  m_AddressType: Cardinal; // Specifies which of the IP v6 address types is used below
    case integer of
      0: (m_IpSubnet: TIP_SUBNET_V6);
      1: (m_IpRange: TIP_RANGE_V6);
  end;

  TIP_V6_FILTER = packed record
	  m_ValidFields: Cardinal;	     // Specifies which of the fileds below contain valid values and should be matched against the packet
	  m_SrcAddress: TIP_ADDRESS_V6;	 // IP v6 source address
	  m_DstAddress: TIP_ADDRESS_V6;  // IP v6 destination address
	  m_Protocol: byte;         		 // Specifies next protocol
	  Padding: array[1..3] of byte;
  end;


  TNETWORK_LAYER_FILTER = packed record
  m_dwUnionSelector: Cardinal;
    case integer of
      0: (m_IPv4: TIP_V4_FILTER);
      1: (m_IPv6: TIP_V6_FILTER);
  end;

  TPORT_RANGE = packed record
	  m_StartRange: System.Word;
	  m_EndRange: System.Word;
  end;

  TTCPUDP_FILTER = packed record
	  m_ValidFields: Cardinal; // Specifies which of the fileds below contain valid values and should be matched against the packet
	  m_SrcPort: TPORT_RANGE;	 // Source port
	  m_DstPort: TPORT_RANGE;	 // Destination port
          m_TcpFalgs: byte;              // TCP flags combination
  end;

  TRANSPORT_LAYER_FILTER = packed record
	  m_dwUnionSelector: Cardinal;
		m_TcpUdp: TTCPUDP_FILTER;
  end;

  TSTATIC_FILTER = packed record
    m_Adapter: Int64;             // Adapter handle extended to 64 bit size for structure compatibility across x64 and x86
	  m_dwDirectionFlags: Cardinal;	// PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE
	  m_FilterAction: Cardinal;	    // FILTER_PACKET_XXX
	  m_ValidFields: Cardinal;  		// Specifies which of the fileds below contain valid values and should be matched against the packet

    m_LastReset: Cardinal;    		// Time of the last counters reset (in seconds passed since 1 Jan 1980)
	  m_PacketsIn: Int64;       			// Incoming packets passed through this filter
	  m_BytesIn: Int64;         			// Incoming bytes passed through this filter
	  m_PacketsOut: Int64;       			// Outgoing packets passed through this filter
	  m_BytesOut: Int64;         			// Outgoing bytes passed through this filter
	  m_DataLinkFilter: TDATA_LINK_LAYER_FILTER;
	  m_NetworkFilter: TNETWORK_LAYER_FILTER;
	  m_TransportFilter: TRANSPORT_LAYER_FILTER;
  end;

  PSTATIC_FILTER_TABLE =^TSTATIC_FILTER_TABLE;
  TSTATIC_FILTER_TABLE = packed record
 	m_TableSize: Cardinal; // number of STATIC_FILTER entries
	m_StaticFilters: array[0..0] of TSTATIC_FILTER;
  end;

procedure InitNDISAPI;
procedure FreeNDISAPI;

var
  NDISAPIHandle: THandle = 0;

  OpenFilterDriver: function(pszFileName : Pchar): THANDLE; stdcall;
  CloseFilterDriver: procedure(hOpen: THANDLE); stdcall;
  GetDriverVersion: function(hOpen: THANDLE): DWORD; stdcall;
  GetTcpipBoundAdaptersInfo: function(hOpen: THANDLE; pAdapters: PTCP_AdapterList): DWORD; stdcall;
  SendPacketToMstcp: function(hOpen: THANDLE; pPacket: PETH_REQUEST): DWORD; stdcall;
  SendPacketToAdapter: function(hOpen: THANDLE; pPacket: PETH_REQUEST): DWORD; stdcall;
  ReadPacket: function(hOpen: THANDLE; pPacket: PETH_REQUEST): DWORD; stdcall;
  SendPacketsToMstcp: function(hOpen: THANDLE; pPackets: PETH_M_REQUEST): DWORD; stdcall;
  SendPacketsToAdapter: function(hOpen: THANDLE; pPackets: PETH_M_REQUEST): DWORD; stdcall;
  ReadPackets: function(hOpen: THANDLE; pPackets: PETH_M_REQUEST): DWORD; stdcall;
  SetAdapterMode: function(hOpen: THANDLE; pMode: PADAPTER_MODE): DWORD; stdcall;
  GetAdapterMode: function(hOpen: THANDLE; pMode: PADAPTER_MODE): DWORD; stdcall;
  FlushAdapterPacketQueue: function(hOpen: THANDLE; hAdapter: THANDLE): DWORD; stdcall;
  GetAdapterPacketQueueSize: function(hOpen: THANDLE; hAdapter: THANDLE; pdwSize: PDWORD): DWORD; stdcall;
  SetPacketEvent: function(hOpen: THANDLE; hAdapter: THANDLE; hWin32Event: THANDLE): DWORD; stdcall;
  SetWANEvent: function(hOpen: THANDLE; hWin32Event: THANDLE): DWORD; stdcall;
  SetAdapterListChangeEvent: function(hOpen: THANDLE; hWin32Event: THANDLE): DWORD; stdcall;
  NdisrdRequest: function(hOpen: THANDLE; OidData: PPACKET_OID_DATA; dwSet: DWORD): DWORD; stdcall;
  GetRasLinks: function(hOpen: THANDLE; hAdapter: THANDLE; pLinks: PRAS_LINKS): DWORD; stdcall;
  SetHwPacketFilter: function(hOpen: THANDLE; hAdapter: THANDLE; dwFilter: DWORD):DWORD; stdcall;
  GetHwPacketFilter: function(hOpen: THANDLE; hAdapter: THANDLE; var dwFilter: DWORD):DWORD; stdcall;
  SetMTUDecrement: function(dwMTUDecrement: DWORD): DWORD; stdcall;
  GetMTUDecrement: function(): DWORD; stdcall;
  SetAdaptersStartupMode : function(dwStartupMode: DWORD): DWORD; stdcall;
  GetAdaptersStartupMode: function(): DWORD; stdcall;
  IsDriverLoaded: function(hOpen: THANDLE): Boolean; stdcall;
  GetBytesReturned: function(hOpen: THANDLE): DWORD; stdcall;
  SetPacketFilterTable: function(hOpen: THANDLE; pFilterList: PSTATIC_FILTER_TABLE): Boolean; stdcall;
  GetPacketFilterTable: function(hOpen: THANDLE; pFilterList: PSTATIC_FILTER_TABLE): Boolean; stdcall;
  GetPacketFilterTableResetStats: function(hOpen: THANDLE; pFilterList: PSTATIC_FILTER_TABLE): Boolean; stdcall;
  ResetPacketFilterTable: function(hOpen: THANDLE): Boolean; stdcall;
  GetPacketFilterTableSize: function(hOpen: THANDLE; pSize: PDWORD): Boolean; stdcall;
  ConvertWindowsNTAdapterName: function(szAdapterName: Pchar; szUserFriendlyName: Pchar; dwUserFriendlyNameLength: DWORD): DWORD; stdcall;
  ConvertWindows2000AdapterName: function(szAdapterName: Pchar; szUserFriendlyName: Pchar; dwUserFriendlyNameLength: DWORD): DWORD; stdcall;
  ConvertWindows9xAdapterName: function(szAdapterName: Pchar; szUserFriendlyName: Pchar; dwUserFriendlyNameLength: DWORD): DWORD; stdcall;

implementation

procedure InitNDISAPI;
begin
  if NDISAPIHandle = 0 then
  begin
    NDISAPIHandle := LoadLibrary('NdisApi.dll');
    if NDISAPIHandle <> 0 then
    begin
      OpenFilterDriver := GetProcAddress(NDISAPIHandle, 'OpenFilterDriver');
      CloseFilterDriver := GetProcAddress(NDISAPIHandle, 'CloseFilterDriver');
      GetDriverVersion := GetProcAddress(NDISAPIHandle, 'GetDriverVersion');
      GetTcpipBoundAdaptersInfo := GetProcAddress(NDISAPIHandle, 'GetTcpipBoundAdaptersInfo');
      SendPacketToMstcp := GetProcAddress(NDISAPIHandle, 'SendPacketToMstcp');
      SendPacketToAdapter := GetProcAddress(NDISAPIHandle, 'SendPacketToAdapter');
      ReadPacket := GetProcAddress(NDISAPIHandle, 'ReadPacket');
      SendPacketsToMstcp := GetProcAddress(NDISAPIHandle, 'SendPacketsToMstcp');
      SendPacketsToAdapter := GetProcAddress(NDISAPIHandle, 'SendPacketsToAdapter');
      ReadPackets := GetProcAddress(NDISAPIHandle, 'ReadPackets');
      SetAdapterMode := GetProcAddress(NDISAPIHandle, 'SetAdapterMode');
      GetAdapterMode := GetProcAddress(NDISAPIHandle, 'GetAdapterMode');
      FlushAdapterPacketQueue := GetProcAddress(NDISAPIHandle, 'FlushAdapterPacketQueue');
      GetAdapterPacketQueueSize := GetProcAddress(NDISAPIHandle, 'GetAdapterPacketQueueSize');
      SetPacketEvent := GetProcAddress(NDISAPIHandle, 'SetPacketEvent');
      SetWANEvent := GetProcAddress(NDISAPIHandle, 'SetWANEvent');
      SetAdapterListChangeEvent := GetProcAddress(NDISAPIHandle, 'SetAdapterListChangeEvent');
      NdisrdRequest := GetProcAddress(NDISAPIHandle, 'NdisrdRequest');
      GetRasLinks := GetProcAddress(NDISAPIHandle, 'GetRasLinks');
      SetHwPacketFilter := GetProcAddress(NDISAPIHandle, 'SetHwPacketFilter');
      GetHwPacketFilter := GetProcAddress(NDISAPIHandle, 'GetHwPacketFilter');
      SetMTUDecrement := GetProcAddress(NDISAPIHandle, 'SetMTUDecrement');
      GetMTUDecrement := GetProcAddress(NDISAPIHandle, 'GetMTUDecrement');
      SetAdaptersStartupMode := GetProcAddress(NDISAPIHandle, 'SetAdaptersStartupMode');
      GetAdaptersStartupMode := GetProcAddress(NDISAPIHandle, 'GetAdaptersStartupMode');
      IsDriverLoaded := GetProcAddress(NDISAPIHandle, 'IsDriverLoaded');
      GetBytesReturned := GetProcAddress(NDISAPIHandle, 'GetBytesReturned');
      SetPacketFilterTable := GetProcAddress(NDISAPIHandle, 'SetPacketFilterTable');
      GetPacketFilterTable := GetProcAddress(NDISAPIHandle, 'GetPacketFilterTable');
      GetPacketFilterTableResetStats := GetProcAddress(NDISAPIHandle, 'GetPacketFilterTableResetStats');
      ResetPacketFilterTable := GetProcAddress(NDISAPIHandle, 'ResetPacketFilterTable');
      GetPacketFilterTableSize := GetProcAddress(NDISAPIHandle, 'GetPacketFilterTableSize');
      ConvertWindowsNTAdapterName := GetProcAddress(NDISAPIHandle, 'ConvertWindowsNTAdapterName');
      ConvertWindows2000AdapterName := GetProcAddress(NDISAPIHandle, 'ConvertWindows2000AdapterName');
      ConvertWindows9xAdapterName := GetProcAddress(NDISAPIHandle, 'ConvertWindows9xAdapterName');
    end
    else
    begin
      raise Exception.Create('Cannot load library "NDISAPI.DLL"');
    end;
  end;
end;

procedure FreeNDISAPI;
begin
  if NDISAPIHandle <> 0 then
  begin
    FreeLibrary(NDISAPIHandle);
    NDISAPIHandle := 0;
  end;
end;

end.

