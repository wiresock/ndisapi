{                        Windows Packet Filter Kit 3.0                }
{                 Copyright(C) 2000-2010 NT Kernel Resources          }
{                         mailto: ndisrd@ntkernel.com                 }

unit iphlp;

interface

uses Windows;

const
ETH_ALEN      = 6;		  // Octets in one ethernet addr
ARPHRD_ETHER  = $01;
ARPOP_REQUEST =	$01;
ARPOP_REPLY	  = $02;

ETH_P_IP		= $0800;	// Internet Protocol packet
ETH_P_RARP    		= $8035;	// Reverse Addr Res packet
ETH_P_ARP		= $0806;	// Address Resolution packet

// Protocols

IPPROTO_IP    = 0;      // dummy for IP
IPPROTO_ICMP  = 1;      // control message protocol
IPPROTO_IGMP  = 2;      // group management protocol
IPPROTO_GGP   = 3;      // gateway^2 (deprecated)
IPPROTO_TCP   = 6;      // tcp
IPPROTO_PUP   = 12;     // pup
IPPROTO_UDP   = 17;     // user datagram protocol
IPPROTO_IDP   = 22;     // xns idp
IPPROTO_ND    = 77;     // UNOFFICIAL net disk proto

IPPROTO_RAW   = 255;    // raw IP packet
IPPROTO_MAX   = 256;

//
// Ethernet Header
//
type
  TEtherHeaderPtr = ^TEtherHeader;
  TEtherHeader = packed record
      h_dest: array [1..ETH_ALEN] of Byte;	{ destination eth addr	}
	    h_source: array [1..ETH_ALEN] of Byte;	{ source ether addr	}
	    h_proto: Word;		{ packet type ID field }
end;

//
// IP header
//
type
  TIPHeaderPtr = ^TIPHeader;
  TIPHeader = packed record
      VerLen: Byte;
      TOS: Byte;
      TotalLen: Word;
      Identifer: Word;
      FragOffsets: Word;
      TTL: Byte;
      Protocol: Byte;
      CheckSum: Word;
      SourceIp: DWORD;
      DestIp: DWORD;
      Options: DWORD;
end;

//
// TCP header
//
TTCPHeaderPtr = ^TTCPHeader;
  TTCPHeader = packed record
       SourcePort:Word;
       DestPort:Word;
       SequenceNumber:DWord;
       AcknowledgementNumber:DWord;
       Offset:Byte; //only left 4 bits. Header length in 32-bit segments
       Flags:Byte;
       Window:Word;
       Checksum:Word;  //includes speudo header instead of TCP header.
       UrgentPointer:Word;
  end; 

//
// UDP header
//
TUDPHeaderPtr = ^TUDPHeader;
  TUDPHeader = packed record
       SourcePort:Word;
       DestPort:Word;
       Length:Word;
       Checksum:Word;  
  end; 


implementation

end.
