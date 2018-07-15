/*************************************************************************/
/*                Copyright (c) 2000-2018 NT Kernel Resources.           */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  ndisapicl.h                                             */
/*                                                                       */
/* Abstract: .NET NdisApi interface                                      */
/*                                                                       */
/* Environment:                                                          */
/*   .NET User mode                                                      */
/*                                                                       */
/*************************************************************************/

#pragma once

using namespace System;
using namespace System::Net;
using namespace System::Net::NetworkInformation;
using namespace System::Net::Sockets; 
using namespace System::Collections::Generic;
using namespace System::Runtime::InteropServices;
using namespace System::Threading;
using namespace msclr::interop;

// Forward declaration of CNdisApi class
class CNdisApi;
struct _INTERMEDIATE_BUFFER;
struct _ETH_REQUEST;
struct _ETH_M_REQUEST;
struct _STATIC_FILTER_TABLE;

namespace NdisApi {
	
	[FlagsAttribute]
	public enum class MSTCP_FLAGS : UInt32
	{
		/// <summary>
		/// Receive packets sent by MSTCP to network interface.
		/// The original packet is dropped.
		/// </summary>
		MSTCP_FLAG_SENT_TUNNEL = 0x00000001,

		/// <summary>
		/// Receive packets sent from network interface to MSTCP.
		/// The original packet is dropped.
		/// </summary>
		MSTCP_FLAG_RECV_TUNNEL = 0x00000002,

		/// <summary>
		/// Receive packets sent from and to MSTCP and network interface.
		/// The original packet is dropped.
		/// </summary>
		MSTCP_FLAG_TUNNEL = MSTCP_FLAG_SENT_TUNNEL | MSTCP_FLAG_RECV_TUNNEL,

		/// <summary>
		/// Receive packets sent by MSTCP to network interface.
		/// The original packet is still delivered to the network.
		/// </summary>
		MSTCP_FLAG_SENT_LISTEN = 0x00000004,

		/// <summary>
		/// Receive packets sent from network interface to MSTCP
		/// The original packet is still delivered to the network.
		/// </summary>
		MSTCP_FLAG_RECV_LISTEN = 0x00000008,

		/// <summary>
		/// Receive packets sent from and to MSTCP and network interface.
		/// The original packet is dropped.
		/// </summary>
		MSTCP_FLAG_LISTEN = MSTCP_FLAG_SENT_LISTEN | MSTCP_FLAG_RECV_LISTEN,

		/// <summary>
		/// In promiscuous mode TCP/IP stack receives all.
		/// </summary>
		MSTCP_FLAG_FILTER_DIRECT = 0x00000010,

		/// <summary>
		/// Passes loopback packet for processing.
		/// </summary>
		MSTCP_FLAG_LOOPBACK_FILTER = 0x00000020,

		/// <summary>
		/// Silently drop loopback packets.
		/// </summary>
		MSTCP_FLAG_LOOPBACK_BLOCK = 0x00000040

	};

	[FlagsAttribute]
	public enum struct PACKET_FLAG : UInt32
	{
		/// <summary>
		/// The packet was intercepted from MSTCP.
		/// </summary>
		PACKET_FLAG_ON_SEND = 0x00000001,

		/// <summary>
		/// The packet was intercepted from the network interface.
		/// </summary>
		PACKET_FLAG_ON_RECEIVE = 0x00000002,

		/// <summary>
		/// Directional flag, can be applied in filter
		/// </summary>
		PACKET_FLAG_ON_SEND_RECEIVE = PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE
	};

	public enum struct NDIS_MEDIUM : UInt32
	{
		NdisMediumDefault, // Extra added default value
		NdisMedium802_3,
		NdisMedium802_5,
		NdisMediumFddi,
		NdisMediumWan,
		NdisMediumLocalTalk,
		NdisMediumDix,
		NdisMediumArcnetRaw,
		NdisMediumArcnet878_2,
		NdisMediumAtm,
		NdisMediumWirelessWan,
		NdisMediumIrda,
		NdisMediumBpc,
		NdisMediumCoWan,
		NdisMedium1394,
		NdisMediumInfiniBand,
		NdisMediumTunnel,
		NdisMediumNative802_11,
		NdisMediumLoopback,
		NdisMediumWiMAX,
		NdisMediumIP,
		NdisMediumMax
	};

	public ref class NetworkAdapter
	{
		String^				_adapterName;
		String^				_adapterFriendlyName;
		IntPtr				_adapterHandle;
		NDIS_MEDIUM			_adapterMedium;
		PhysicalAddress^	_adapterCurrentAddress;
		UInt16				_adapterMtu;

	public:
		NetworkAdapter(
			String^	adapterName,
			String^ adapterFriendlyName,
			IntPtr	adapterHandle,
			NDIS_MEDIUM	adapterMedium,
			PhysicalAddress^ adapterCurrentAddress,
			UInt16	adapterMtu) : 
				_adapterName(adapterName),
				_adapterFriendlyName(adapterFriendlyName),
				_adapterHandle(adapterHandle),
				_adapterMedium(adapterMedium),
				_adapterCurrentAddress(adapterCurrentAddress),
				_adapterMtu(adapterMtu) {}

		property String^			Name { String^ get() { return _adapterName; } }
		property String^			FriendlyName { String^ get() { return _adapterFriendlyName; } }
		property IntPtr				Handle { IntPtr get() { return _adapterHandle; } }
		property NDIS_MEDIUM		Medium { NDIS_MEDIUM get() { return _adapterMedium; } }
		property PhysicalAddress^	CurrentAddress { PhysicalAddress^ get() { return _adapterCurrentAddress; } }
		property UInt16				Mtu { UInt16 get() { return _adapterMtu; } }
	};

	public ref class RawPacket
	{
	public:
		[FlagsAttribute]
		enum struct CHECKSUM_FLAG : UInt32 
		{
			/// <summary>
			/// Recalculate IP version 4 checksum
			/// </summary>
			RECALCULATE_IP_V4 = 0x00000001,
			/// <summary>
			/// Recalculate ICMP checksum for IP version 4 packet
			/// </summary>
			RECALCULATE_ICMP_V4 = 0x00000002,
			/// <summary>
			/// Recalculate TCP checksum for IP version 4 packet
			/// </summary>
			RECALCULATE_TCP_V4 = 0x00000004,
			/// <summary>
			/// Recalculate UDP checksum for IP version 4 packet
			/// </summary>
			RECALCULATE_UDP_V4 = 0x00000008
		};
	private:
		PACKET_FLAG		_deviceFlags;
		UInt32			_flags; // NDIS_PACKET flags
		UInt32			_dot1q; // 802.1q info
		UInt32			_filterId;
		CHECKSUM_FLAG	_checksums;
		array<Byte>^ 	_buffer;

	public:
		property PACKET_FLAG DeviceFlags {
			PACKET_FLAG get() { return _deviceFlags; }
			void set(PACKET_FLAG deviceFlags) { _deviceFlags = deviceFlags; }
		}

		property UInt32	NdisFlags {
			UInt32 get() { return _flags; } 
			void set(UInt32 flags) { _flags = flags; }
		}

		property UInt32	Dot1q {
			UInt32 get() { return _dot1q; }
			void set(UInt32 dot1q) { _dot1q = dot1q;	}
		}

		property UInt32	FilterId {
			UInt32 get() { return _filterId; } 
			void set(UInt32 filterId) { _filterId = filterId; }
		}

		property CHECKSUM_FLAG Checksums {
			CHECKSUM_FLAG get() { return _checksums; }
			void set(CHECKSUM_FLAG checksums) { _checksums = checksums; }
		}

		property array<Byte>^ Data { 
			array<Byte>^ get() { return _buffer; } 
			void set(array<Byte>^ buffer) { _buffer = buffer; }
		}
	};

	public ref class NdisBufferResource
	{
		static const Int32 defaultBufferSize = 32;
	public:
		NdisBufferResource() : NdisBufferResource(defaultBufferSize) {}
		NdisBufferResource(Int32 size);
		!NdisBufferResource();
		~NdisBufferResource();
		property _INTERMEDIATE_BUFFER* Buffer {_INTERMEDIATE_BUFFER* get() { return _intermediateBufferPtr; }}
		property _ETH_M_REQUEST* Request {_ETH_M_REQUEST* get() { return reinterpret_cast<_ETH_M_REQUEST*>(_dataRequest); }}
		property Int32 Size {Int32 get() { return _size; }}
	private:
		_INTERMEDIATE_BUFFER* _intermediateBufferPtr;
		uint8_t* _dataRequest;
		Int32	_size;
	};

	//
	// PACKET_OID_DATA used for passing NDIS_REQUEST to driver
	//
	public ref class PacketOidData
	{
	private:
		IntPtr			_hAdapter;
		UInt32			_oid;
		array<Byte>^ 	_buffer;
	public:
		property IntPtr Adapter {
			IntPtr get() { return _hAdapter; }
			void set(IntPtr value) { _hAdapter = value; }
		}

		property UInt32 Oid {
			UInt32 get() { return _oid; }
			void set(UInt32 value) { _oid = value; }
		}

		property array<Byte>^ Data {
			array<Byte>^ get() { return _buffer; }
			void set(array<Byte>^ buffer) { _buffer = buffer; }
		}
	};

	public ref class RasLinkInfo{
	private:
		UInt32				_linkSpeed;
		UInt32				_maximumTotalSize;
		PhysicalAddress^	_remoteAddress;
		PhysicalAddress^	_localAddress;		
		array<Byte>^ 		_buffer;

	public:
		RasLinkInfo(
			UInt32				linkSpeed,
			UInt32				maximumTotalSize,
			PhysicalAddress^	remoteAddress,
			PhysicalAddress^	localAddress,
			array<Byte>^ 		buffer) :
			_linkSpeed(linkSpeed),
			_maximumTotalSize(maximumTotalSize),
			_remoteAddress(remoteAddress),
			_localAddress(localAddress),
			_buffer(buffer) {}

		// Specifies the speed of the link, in units of 100 bps.
		// Zero indicates no change from the speed returned when the protocol called NdisRequest with OID_GEN_LINK_SPEED. 
		property UInt32  LinkSpeed {UInt32 get() { return _linkSpeed; }}

		// Specifies the maximum number of bytes per packet that the protocol can send over the network.
		// Zero indicates no change from the value returned when the protocol called NdisRequest with OID_GEN_MAXIMUM_TOTAL_SIZE. 
		property UInt32  MaximumTotalSize {UInt32 get() { return _maximumTotalSize; }}

		// Represents the address of the remote node on the link in Ethernet-style format. NDISWAN supplies this value.
		property PhysicalAddress^  RemoteAddress {PhysicalAddress^ get() { return _remoteAddress; }}
		
		// Represents the protocol-determined context for indications on this link in Ethernet-style format.
		property PhysicalAddress^  LocalAddress {PhysicalAddress^ get() { return _localAddress; }}
	
		// Containing protocol-specific information supplied by a higher-level component that makes connections through NDISWAN
		// to the appropriate protocol(s). Maximum observed size is 600 bytes on Windows Vista, 1200 on Windows 10
		property array<Byte>^  ProtocolBuffer {array<Byte>^ get() { return _buffer; }} 
	};

	// Represents 802.3 header filter
	public ref class Eth802dot3Filter
	{
	public:
		[FlagsAttribute]
		enum struct ETH_802_3_FLAGS : UInt32
		{
			/// <summary>
			/// The eth 802 3 source address.
			/// </summary>
			ETH_802_3_SRC_ADDRESS = 0x00000001,

			/// <summary>
			/// The eth 802 3 destination address.
			/// </summary>
			ETH_802_3_DEST_ADDRESS = 0x00000002,

			/// <summary>
			/// The eth 802 3 protocol.
			/// </summary>
			ETH_802_3_PROTOCOL = 0x00000004
		};

	private:
		ETH_802_3_FLAGS		_validFields;
		PhysicalAddress^	_sourceAddress;
		PhysicalAddress^	_destinationAddress;
		UInt16				_networkProtocol;

	public:

		String^ ToString() override
		{
			return "Eth802dot3Filter [ " + ((_sourceAddress != nullptr) ? ("SourceAddress = " + _sourceAddress->ToString()):"") +
				((_destinationAddress != nullptr) ? (" DestinationAddress = " + _destinationAddress->ToString()):"") +
				(((_validFields & ETH_802_3_FLAGS::ETH_802_3_PROTOCOL) == ETH_802_3_FLAGS::ETH_802_3_PROTOCOL) ? 
				(" Protocol = " + _sourceAddress->ToString()):"") + " ]";
		}

		// Specifies which of the fileds below contain valid values and should be matched against the packet
		property ETH_802_3_FLAGS ValidFields {
			ETH_802_3_FLAGS get() { return _validFields; }
			void set(ETH_802_3_FLAGS value) { _validFields = value; }
		};

		// Source MAC address
		property PhysicalAddress^ SrcAddress {
			PhysicalAddress^ get() { return _sourceAddress; }
			void set(PhysicalAddress^ value) { _sourceAddress = value; }
		}

		// Destination MAC address
		property PhysicalAddress^ DestAddress {
			PhysicalAddress^ get() { return _destinationAddress; }
			void set(PhysicalAddress^ value) { _destinationAddress = value; }
		}

		// EtherType
		property UInt16 Protocol {
			UInt16 get() { return _networkProtocol; }
			void set(UInt16 value) { _networkProtocol = value; }
		}

		Eth802dot3Filter(
			ETH_802_3_FLAGS	validFields,
			PhysicalAddress^ sourceAddress,
			PhysicalAddress^ destinationAddress,
			UInt16	networkProtocol) :
			_validFields(validFields),
			_sourceAddress(sourceAddress),
			_destinationAddress(destinationAddress),
			_networkProtocol(networkProtocol) {}
	};

	// Represents IP subnet or range of IP addresses
	public ref class IpNetRange
	{
	public:
		enum struct ADDRESS_TYPE : UInt32
		{
			IP_SUBNET_TYPE = 0x00000001,
			IP_RANGE_TYPE = 0x00000002
		};

	private:
		ADDRESS_TYPE	_addressType;
		IPAddress^		_firstIp;
		IPAddress^		_secondIp;

	public:
		String^ ToString() override
		{
			if (_addressType == ADDRESS_TYPE::IP_SUBNET_TYPE)
			{
				return "IpNetRange [ " + "network: " + _firstIp->ToString() + " mask: " + _secondIp->ToString() + " ]";
			}
			else if (_addressType == ADDRESS_TYPE::IP_RANGE_TYPE)
			{
				return "IpNetRange [ " + "start IP: " + _firstIp->ToString() + " end IP: " + _secondIp->ToString() + " ]";
			}
			else
			{
				return "IpNetRange: UNDEFINED TYPE";
			}
		}
		
		// Specifies which of the IP v4 address types is used below
		property ADDRESS_TYPE AddressType {
			ADDRESS_TYPE get() { return _addressType; }
			void set(ADDRESS_TYPE value) { _addressType = value; }
		}

		property IPAddress^	NetworkAddress {
			IPAddress^ get() { return _firstIp; }
			void set(IPAddress^ value) { _firstIp = value; }
		}

		property IPAddress^	NetworkMask {
			IPAddress^ get() { return _secondIp; }
			void set(IPAddress^ value) { _secondIp = value; }
		}

		property IPAddress^	StartRange {
			IPAddress^ get() { return _firstIp; }
			void set(IPAddress^ value) { _firstIp = value; }
		}

		property IPAddress^	EndRange {
			IPAddress^ get() { return _secondIp; }
			void set(IPAddress^ value) { _secondIp = value; }
		}

		IpNetRange(
			ADDRESS_TYPE addressType,
			IPAddress^ firstIp,
			IPAddress^ secondIp) :
			_addressType(addressType),
			_firstIp(firstIp),
			_secondIp(secondIp) {}
	};

	// Represent IP level filter
	public ref class IpAddressFilter
	{
	public:
		[FlagsAttribute]
		enum struct IP_FILTER_FIELDS : UInt32
		{
			IP_FILTER_SRC_ADDRESS = 0x00000001,
			IP_FILTER_DEST_ADDRESS = 0x00000002,
			IP_FILTER_PROTOCOL = 0x00000004
		};
	private:
		AddressFamily		_addressFamily;
		IP_FILTER_FIELDS	_validFields;
		IpNetRange^			_sourceAddress;
		IpNetRange^			_destinationAddress;
		Byte				_nextProtocol;		
	public:
		String^ ToString() override
		{
			return "IpAddressFilter [ " + ((_sourceAddress != nullptr) ? ("SourceAddress = " + _sourceAddress->ToString()) : "") +
				((_destinationAddress != nullptr) ? (" DestinationAddress = " + _destinationAddress->ToString()) : "") +
				(((_validFields & IP_FILTER_FIELDS::IP_FILTER_PROTOCOL) == IP_FILTER_FIELDS::IP_FILTER_PROTOCOL) ? 
				(" Protocol = " + _nextProtocol.ToString()) : "") + " ]";
		}

		// Specifies IP address family (IPv6/IPv4)
		property AddressFamily	IpAddressFamily {
			AddressFamily get() { return _addressFamily; }
			void set(AddressFamily value) { _addressFamily = value; }
		}

		// Specifies which of the fileds below contain valid values and should be matched against the packet
		property IP_FILTER_FIELDS	ValidFields {
			IP_FILTER_FIELDS get() { return _validFields; }
			void set(IP_FILTER_FIELDS value) { _validFields = value; }
		}

		// Source IP address
		property IpNetRange^ SrcAddress {
			IpNetRange^ get() { return _sourceAddress; }
			void set(IpNetRange^ value) { _sourceAddress = value; }
		}

		// Destination IP address	
		property IpNetRange^ DestAddress {
			IpNetRange^ get() { return _destinationAddress; }
			void set(IpNetRange^ value) { _destinationAddress = value; }
		}

		// Specifies next protocol
		property Byte Protocol {
			Byte get() { return _nextProtocol; }
			void set(Byte value) { _nextProtocol = value; }
		}

		IpAddressFilter(
			AddressFamily addressFamily,
			IP_FILTER_FIELDS	validFields,
			IpNetRange^	sourceAddress,
			IpNetRange^ destinationAddress,
			Byte nextProtocol):
			_addressFamily(addressFamily),
			_validFields(validFields),
			_sourceAddress(sourceAddress),
			_destinationAddress(destinationAddress),
			_nextProtocol(nextProtocol){}
	};

	// Represents TCP/UDP level filter
	public ref class TcpUdpFilter
	{
	public:
		[FlagsAttribute]
		enum struct TCPUDP_FILTER_FIELDS
		{
			/// <summary>
			/// The TCP/UDP source port.
			/// </summary>
			TCPUDP_SRC_PORT = 0x00000001,

			/// <summary>
			/// The TCP/UDP destination port.
			/// </summary>
			TCPUDP_DEST_PORT = 0x00000002,

			/// <summary>
			/// The TCP flags.
			/// </summary>
			TCPUDP_TCP_FLAGS = 0x00000004
		};

		value struct PortRange {
			UInt16 startRange;
			UInt16 endRange;

			String^ ToString() override
			{
				return "PortRange [ start = " + startRange.ToString() + " end = " + endRange.ToString() + " ]";
			}
		};

	private:
		TCPUDP_FILTER_FIELDS	_validFields;
		PortRange				_sourcePort;
		PortRange				_destPort;
		Byte					_tcpFlags;
	
	public:
		String^ ToString() override
		{
			return "TcpUdpFilter [ " + (((_validFields & TCPUDP_FILTER_FIELDS::TCPUDP_SRC_PORT) == TCPUDP_FILTER_FIELDS::TCPUDP_SRC_PORT) ? 
				("Source Port = " + _sourcePort.ToString()) : "") +
				(((_validFields & TCPUDP_FILTER_FIELDS::TCPUDP_DEST_PORT) == TCPUDP_FILTER_FIELDS::TCPUDP_DEST_PORT) ? 
				(" Destination Port = " + _destPort.ToString()) : "") +
				(((_validFields & TCPUDP_FILTER_FIELDS::TCPUDP_TCP_FLAGS) == TCPUDP_FILTER_FIELDS::TCPUDP_TCP_FLAGS) ? 
				(" Protocol = " + _tcpFlags.ToString()) : "") + " ]";
		}

		// Specifies which of the fileds below contain valid values and should be matched against the packet
		property TCPUDP_FILTER_FIELDS ValidFields {
			TCPUDP_FILTER_FIELDS get() { return _validFields; }
			void set(TCPUDP_FILTER_FIELDS value) { _validFields = value; }
		};

		// Source port
		property PortRange	SrcPort {
			PortRange get() { return _sourcePort; }
			void set(PortRange value) { _sourcePort = value; }
		};

		// Destination port
		property PortRange	DestPort {
			PortRange get() { return _destPort; }
			void set(PortRange value) { _destPort = value; }
		};

		// TCP flags combination
		property Byte TCPFlags {
			Byte get() { return _tcpFlags; }
			void set(Byte value) { _tcpFlags = value; }
		}

		TcpUdpFilter(
			TCPUDP_FILTER_FIELDS validFields,
			PortRange sourcePort,
			PortRange destPort,
			Byte tcpFlags):
			_validFields(validFields),
			_sourcePort(sourcePort),
			_destPort(destPort),
			_tcpFlags(tcpFlags){}
	};

	public ref class StaticFilter
	{
	public:
		enum struct FILTER_PACKET_ACTION : UInt32
		{
			/// <summary>
			/// Pass packet if if matches the filter
			/// </summary>
			FILTER_PACKET_PASS = 0x00000001, 
			/// <summary>
			/// Drop packet if it matches the filter
			/// </summary>
			FILTER_PACKET_DROP = 0x00000002,
			/// <summary>
			/// Redirect packet to WinpkFilter client application
			/// </summary>
			FILTER_PACKET_REDIRECT = 0x00000003, 
			/// <summary>
			/// Redirect packet to WinpkFilter client application and pass over network (listen mode)
			/// </summary>
			FILTER_PACKET_PASS_RDR = 0x00000004, 
			/// <summary>
			/// Redirect packet to WinpkFilter client application and drop it, e.g. log but remove from the flow (listen mode)
			/// </summary>
			FILTER_PACKET_DROP_RDR = 0x00000005
		};

		[FlagsAttribute]
		enum struct STATIC_FILTER_FIELDS : UInt32
		{
			/// <summary>
			/// Match packet against data link layer filter.
			/// </summary>
			DATA_LINK_LAYER_VALID = 0x00000001,

			/// <summary>
			/// Match packet against network layer filter.
			/// </summary>
			NETWORK_LAYER_VALID = 0x00000002,

			/// <summary>
			/// Match packet against transport layer filter.
			/// </summary>
			TRANSPORT_LAYER_VALID = 0x00000004
		};
	
	private:
		IntPtr					_adapterHandle; 
		PACKET_FLAG				_directionFlags;
		FILTER_PACKET_ACTION	_filterAction;
		STATIC_FILTER_FIELDS	_validFields;
												
		UInt32				_lastReset;		
		UInt64				_packetsIn;		
		UInt64				_bytesIn;			
		UInt64				_packetsOut;		
		UInt64				_bytesOut;			

		Eth802dot3Filter^	_dataLinkFilter;
		IpAddressFilter^	_networkFilter;
		TcpUdpFilter^		_transportFilter;

	public:
		StaticFilter() {}

		StaticFilter(
			IntPtr adapterHandle,
			PACKET_FLAG directionFlags,
			FILTER_PACKET_ACTION filterAction,
			STATIC_FILTER_FIELDS validFields,
			Eth802dot3Filter^ dataLinkFilter,
			IpAddressFilter^ networkFilter,
			TcpUdpFilter^ transportFilter
			):	_adapterHandle(adapterHandle),
				_directionFlags(directionFlags),
				_filterAction(filterAction),
				_validFields(validFields),
				_dataLinkFilter(dataLinkFilter),
				_networkFilter(networkFilter),
				_transportFilter(transportFilter){}

		String^ ToString() override
		{
			return "StaticFilter [ adapter = " + _adapterHandle.ToString("x") + " direction = " + _directionFlags.ToString() +
				" action = " + _filterAction.ToString() + " reset_timestamp = " + _lastReset.ToString("x") +
				" packets_in = " + _packetsIn.ToString() + " bytes_in = " + _bytesIn.ToString() +
				" packets_out = " + _packetsOut.ToString() + " bytes_out = " + _bytesOut.ToString() + " " +
				((_dataLinkFilter != nullptr) ? (_dataLinkFilter->ToString() + " ") : "")  +
				((_networkFilter != nullptr) ? (_networkFilter->ToString() + " ") : "") + 
				((_transportFilter != nullptr) ? _transportFilter->ToString() : "") + " ]";
		}

		// Adapter handle extended to 64 bit size for structure compatibility across x64 and x86
		property IntPtr	Adapter {
			IntPtr get() { return _adapterHandle; }
			void set(IntPtr value) { _adapterHandle = value; }
		}

		// PACKET_FLAG_ON_SEND or/and PACKET_FLAG_ON_RECEIVE
		property PACKET_FLAG DirectionFlags {
			PACKET_FLAG get() { return _directionFlags; }
			void set(PACKET_FLAG value) { _directionFlags = value; }
		}

		// FILTER_PACKET_XXX
		property FILTER_PACKET_ACTION FilterAction {
			FILTER_PACKET_ACTION get() { return _filterAction; }
			void set(FILTER_PACKET_ACTION value) { _filterAction = value; }
		}

		// Specifies which of the fileds below contain valid values and should be matched against the packet
		property STATIC_FILTER_FIELDS ValidFields {
			STATIC_FILTER_FIELDS get() { return _validFields; }
			void set(STATIC_FILTER_FIELDS value) { _validFields = value; }
		};
		
		// Statistics for the filter:
		// Time of the last counters reset (in seconds passed since 1 Jan 1980)
		property UInt32 LastReset {
			UInt32 get() { return _lastReset; }
			void set(UInt32 value) { _lastReset = value; }
		};

		// Incoming packets passed through this filter
		property UInt64	PacketsIn {
			UInt64 get() { return _packetsIn; }
			void set(UInt64 value) { _packetsIn = value; }
		};

		// Incoming bytes passed through this filter
		property UInt64	BytesIn {
			UInt64 get() { return _bytesIn; }
			void set(UInt64 value) { _bytesIn = value; }
		};

		// Outgoing packets passed through this filter
		property UInt64	PacketsOut {
			UInt64 get() { return _packetsOut; }
			void set(UInt64 value) { _packetsOut = value; }
		};

		// Outgoing bytes passed through this filter
		property UInt64	BytesOut {
			UInt64 get() { return _bytesOut; }
			void set(UInt64 value) { _bytesOut = value; }
		};

		property Eth802dot3Filter^	DataLinkFilter {
			Eth802dot3Filter^ get() { return _dataLinkFilter; }
			void set(Eth802dot3Filter^ value) { _dataLinkFilter = value; }
		}

		property IpAddressFilter^ NetworkFilter {
			IpAddressFilter^ get() { return _networkFilter; }
			void set(IpAddressFilter^ value) { _networkFilter = value; }
		}

		property TcpUdpFilter^ TransportFilter {
			TcpUdpFilter^ get() { return _transportFilter; }
			void set(TcpUdpFilter^ value) { _transportFilter = value; }
		}
	};

	public ref class NdisApiDotNet
	{
	private:
		CNdisApi * m_pNdisApi;

	public:
		NdisApiDotNet(String^ deviceName);
		!NdisApiDotNet();
		~NdisApiDotNet();

		UInt32									GetVersion();
		Tuple<Boolean, List<NetworkAdapter^>^>^	GetTcpipBoundAdaptersInfo();
		Boolean									SendPacketToMstcp(IntPtr hAdapter, RawPacket^ packet);
		Boolean									SendPacketToAdapter(IntPtr hAdapter, RawPacket^ packet);
		RawPacket^								ReadPacket(IntPtr hAdapter);
		Boolean									SendPacketsToMstcp(IntPtr hAdapter, NdisBufferResource^ packetBuffer, List<RawPacket^>^ packetList);
		Boolean									SendPacketsToAdapter(IntPtr hAdapter, NdisBufferResource^ packetBuffer, List<RawPacket^>^ packetList);
		Tuple<Boolean, List<RawPacket^>^>^		ReadPackets(IntPtr hAdapter, NdisBufferResource^ packetBuffer);
		Boolean									SetAdapterMode(IntPtr hAdapter, MSTCP_FLAGS filterFlags);
		Boolean									GetAdapterMode(IntPtr hAdapter, [Out]MSTCP_FLAGS% filterFlags);
		Boolean									FlushAdapterPacketQueue(IntPtr hAdapter);
		Boolean									GetAdapterPacketQueueSize(IntPtr hAdapter, [Out]UInt32% queueSize);
		Boolean									SetPacketEvent(IntPtr hAdapter, ManualResetEvent^ eventObject);
		Boolean									SetWANEvent(ManualResetEvent^ eventObject);
		Boolean									SetAdapterListChangeEvent(ManualResetEvent^ eventObject);
		Boolean									NdisrdRequest(PacketOidData^ oidData, Boolean bSet);
		Tuple<Boolean, List<RasLinkInfo^>^>^	GetRasLinks(IntPtr hAdapter);
		Boolean									SetHwPacketFilter(IntPtr hAdapter, UInt32 hwFilter);
		Boolean									GetHwPacketFilter(IntPtr hAdapter, [Out]UInt32% hwFilter);
		Boolean									SetHwPacketFilterEvent(IntPtr hAdapter, ManualResetEvent^ eventObject);
		Boolean									SetPacketFilterTable(List<StaticFilter^>^ filterList);
		Boolean									ResetPacketFilterTable();
		Boolean									GetPacketFilterTableSize(UInt32 % dwTableSize);
		Tuple<Boolean, List<StaticFilter^>^>^	GetPacketFilterTable();
		Tuple<Boolean, List<StaticFilter^>^>^	GetPacketFilterTableResetStats();
		Boolean									IsDriverLoaded();

		static Boolean							SetMTUDecrement(UInt32 dwMTUDecrement);
		static UInt32							GetMTUDecrement();

		static Boolean							SetAdaptersStartupMode(UInt32 dwStartupMode);
		static UInt32							GetAdaptersStartupMode();

		static Boolean							IsNdiswanIp(String^ adapterName);
		static Boolean							IsNdiswanIpv6(String^ adapterName);
		static Boolean							IsNdiswanBh(String^ adapterName);

	private:
		static String^					GetAdapterFriendlyName(std::string const& adapterName);
		static void						InitializeSendPacketRequest(IntPtr hAdapter, RawPacket ^ packet, _ETH_REQUEST& sendRequest, _INTERMEDIATE_BUFFER& intermediateBuffer);
		static void						InitializeSendPacketRequestList(IntPtr hAdapter, NdisBufferResource^ packetBuffer, List<RawPacket^>^ packetList);
		static void						ConvertToStaticFilterTable(_STATIC_FILTER_TABLE& staticFilterTable, List<StaticFilter^>^ filterList);
		static List<StaticFilter^>^		ConvertFromStaticFilterTable(_STATIC_FILTER_TABLE& staticFilterTable);
	};
}
