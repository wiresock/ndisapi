{                        Windows Packet Filter Kit 3.0                }
{                 Copyright(C) 2000-2010 NT Kernel Resources          }
{                         mailto: ndisrd@ntkernel.com                 }

program ndisrequest;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  winpkf in '..\winpkf.pas';

const

// Network interface current address
OID_802_3_CURRENT_ADDRESS	=	$01010102;

//	Required network interface statistics
OID_GEN_XMIT_OK	      = $00020101;
OID_GEN_RCV_OK        = $00020102;
OID_GEN_XMIT_ERROR    = $00020103;
OID_GEN_RCV_ERROR	    = $00020104;
OID_GEN_RCV_NO_BUFFER	= $00020105;

type
    TEtherAddrPtr = ^TEtherAddr;
    TEtherAddr = packed record
      Data: array[1..6] of Byte;
    end;

var
  hFilt: THANDLE;
  Adapts: TCP_AdapterList;
  pCurrentMacRequest, pStatRequest: PPACKET_OID_DATA;
  i: DWORD;
  ethAddr: TEtherAddrPtr;
  pdwStat: ^DWORD;

begin
  // Initialize NDISAPI
  InitNDISAPI();

  // Create driver object
  hFilt := OpenFilterDriver('NDISRD');

  // Allocate request structures
  GetMem( pCurrentMacRequest, SizeOf(PACKET_OID_DATA) + 5);
  GetMem( pStatRequest, SizeOf(PACKET_OID_DATA) + SizeOf(DWORD) - 1);

  // Get TCP/IP bound interfaces
  GetTcpipBoundAdaptersInfo (hFilt, @Adapts);

  // Pre-initialize requests
  pCurrentMacRequest.Length := 6;
	pCurrentMacRequest.Oid := OID_802_3_CURRENT_ADDRESS;
  pStatRequest.Length := sizeof(DWORD);

  for i:=1 to Adapts.m_nAdapterCount do begin
    // Set handle field
    pCurrentMacRequest.hAdapterHandle := Adapts.m_nAdapterHandle[i];
		pStatRequest.hAdapterHandle := Adapts.m_nAdapterHandle[i];

    NdisrdRequest ( hFilt, pCurrentMacRequest, 0 );

    ethAddr := @pCurrentMacRequest.Data;
    Writeln(Format('%d) Current MAC is %.2x-%.2x-%.2x-%.2x-%.2x-%.2x', [i, ethAddr.Data[1], ethAddr.Data[2], ethAddr.Data[3], ethAddr.Data[4], ethAddr.Data[5], ethAddr.Data[6]]));

    pdwStat := @pStatRequest.Data;
    pStatRequest.Oid := OID_GEN_XMIT_OK;

		if NdisrdRequest(hFilt, pStatRequest, 0) <> 0 then
			Writeln(Format('     Frames transmitted without errors = %d', [pdwStat^]));

		pStatRequest.Oid := OID_GEN_RCV_OK;

    if NdisrdRequest(hFilt, pStatRequest, 0) <> 0 then
			Writeln(Format('     Frames received without errors = %d', [pdwStat^]));

		pStatRequest.Oid := OID_GEN_XMIT_ERROR;

    if NdisrdRequest(hFilt, pStatRequest, 0) <> 0 then
			Writeln(Format('     Frames that a NIC failed to transmit = %d', [pdwStat^]));

		pStatRequest.Oid := OID_GEN_RCV_ERROR;

    if NdisrdRequest(hFilt, pStatRequest, 0) <> 0 then
			Writeln(Format('     Frames that a NIC have not indicated due to errors = %d', [pdwStat^]));

  end;

  // Deallocate request structures
  FreeMem (pCurrentMacRequest);
  FreeMem (pStatRequest);

  // Close driver object
  CloseFilterDriver (hFilt);

  // Release NDISAPI
  FreeNDISAPI();
end.
