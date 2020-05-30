{                        Windows Packet Filter Kit 3.0                }
{                 Copyright(C) 2000-2010 NT Kernel Resources          }
{                         mailto: ndisrd@ntkernel.com                 }

program PacketSniffer;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  Winsock,
  winpkf in '..\winpkf.pas',
  iphlp in '..\iphlp.pas';

const
// Packet filter definitions from DDK
NDIS_PACKET_TYPE_DIRECTED         = $1;
NDIS_PACKET_TYPE_MULTICAST        = $2;
NDIS_PACKET_TYPE_ALL_MULTICAST    = $4;
NDIS_PACKET_TYPE_BROADCAST	      = $8;
NDIS_PACKET_TYPE_SOURCE_ROUTING   = $10;
NDIS_PACKET_TYPE_PROMISCUOUS	    = $20;
NDIS_PACKET_TYPE_SMT	            = $40;
NDIS_PACKET_TYPE_ALL_LOCAL        = $80;
NDIS_PACKET_TYPE_GROUP            = $1000;
NDIS_PACKET_TYPE_ALL_FUNCTIONAL   = $2000;
NDIS_PACKET_TYPE_FUNCTIONAL				= $4000;
NDIS_PACKET_TYPE_MAC_FRAME				= $8000;

var
  iIndex, counter: DWORD;
  hFilt: THANDLE;
  Adapts: TCP_AdapterList;
  AdapterMode: ADAPTER_MODE;
  Buffer: INTERMEDIATE_BUFFER;
  ReadRequest: ETH_REQUEST;
  hAdapter: THANDLE;
  pEtherHeader: TEtherHeaderPtr;
  bSetPromisc: Boolean;
  dwFilter: DWORD;
  pIPHeader: TIPHeaderPtr;
  pTcpHeader: TTCPHeaderPtr;
  pUdpHeader: TUDPHeaderPtr;
  SourceIP, DestIP: TInAddr;

procedure ReleaseInterface();
begin
  // Restore old packet filter
	if bSetPromisc then
			SetHwPacketFilter ( hFilt, hAdapter, dwFilter );

  // Restore default mode
  AdapterMode.dwFlags := 0;
  AdapterMode.hAdapterHandle := hAdapter;
  SetAdapterMode ( hFilt, @AdapterMode );

  // Close driver object
  CloseFilterDriver (hFilt);

  // Release NDISAPI
  FreeNDISAPI();
end;

begin
  bSetPromisc := False;

  // Check the number of parameters
  if ParamCount() < 2 then begin
    Writeln('Command line syntax:');
    Writeln('   PacketSniffer.exe index num [-promisc]');
    Writeln('   index - network interface index.');
    Writeln('   num - number or packets to capture');
    Writeln('   -promisc - optional parameter. ');
    Writeln('   When specified network interface is switched to the promiscuous mode.');
    Writeln('You can use ListAdapters to determine correct index.');
    Exit;
  end;

  // Initialize NDISAPI
  InitNDISAPI();

  // Create driver object
  hFilt := OpenFilterDriver('NDISRD');

  if IsDriverLoaded(hFilt) then begin

      // Get parameters from command line
      iIndex := StrToInt(ParamStr(1));
      counter := StrToInt(ParamStr(2));

      if ParamCount() = 3 then begin
          if StrComp(Pchar(ParamStr(3)), '-promisc') = 0 then bSetPromisc := True;
      end;

      // Set exit procedure
      ExitProcessProc := ReleaseInterface;

      // Get TCP/IP bound interfaces
      GetTcpipBoundAdaptersInfo (hFilt, @Adapts);

      // Check paramer values
      if iIndex > Adapts.m_nAdapterCount then begin
        Writeln ('There is no network interface with such index on this system.');
        Exit;
      end;

      hAdapter := Adapts.m_nAdapterHandle[iIndex];

      // Set promiscuous mode if specified from command line
      if bSetPromisc then begin
        if GetHwPacketFilter ( hFilt, hAdapter, dwFilter ) = 0 then
            Writeln ('Failed to get current packet filter from the network interface.');
        if SetHwPacketFilter ( hFilt, hAdapter, NDIS_PACKET_TYPE_PROMISCUOUS ) = 0 then
            Writeln('Failed to set promiscuous mode fro the network interface.');
      end;

      // Initialize adapter mode
      if bSetPromisc then
          AdapterMode.dwFlags := MSTCP_FLAG_SENT_LISTEN or MSTCP_FLAG_RECV_LISTEN or MSTCP_FLAG_FILTER_DIRECT or MSTCP_FLAG_LOOPBACK_BLOCK
      else
          AdapterMode.dwFlags := MSTCP_FLAG_SENT_LISTEN or MSTCP_FLAG_RECV_LISTEN;

      AdapterMode.hAdapterHandle := hAdapter;

       // Initialize request
       ReadRequest.EthPacket.Buffer := @Buffer;
       ReadRequest.hAdapterHandle := hAdapter;

       // Set adapter mode
       SetAdapterMode ( hFilt, @AdapterMode );

       // Capture 'counter' packets from the interface
       while counter <> 0 do begin
            while ReadPacket (hFilt, @ReadRequest) <> 0 do begin
              Dec (counter);
              Writeln;
              if Buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND then
                  Writeln(counter, ') - MSTCP --> Interface' )
              else
                  Writeln(counter, ') - Interface --> MSTCP' );

              Writeln ('     Packet size =    ', Buffer.m_Length);
              pEtherHeader := TEtherHeaderPtr (@Buffer.m_IBuffer);

              Writeln (Format('     Source MAC:      %.2x%.2x%.2x%.2x%.2x%.2x',
				        [pEtherHeader.h_source[1],
				        pEtherHeader.h_source[2],
				        pEtherHeader.h_source[3],
				        pEtherHeader.h_source[4],
				        pEtherHeader.h_source[5],
				        pEtherHeader.h_source[6]]));

              Writeln (Format('     Destination MAC: %.2x%.2x%.2x%.2x%.2x%.2x',
				        [pEtherHeader.h_dest[1],
				        pEtherHeader.h_dest[2],
				        pEtherHeader.h_dest[3],
				        pEtherHeader.h_dest[4],
				        pEtherHeader.h_dest[5],
				        pEtherHeader.h_dest[6]]));

              if ntohs(pEtherHeader.h_proto) = ETH_P_IP then
                begin
                  pIPHeader := TIPHeaderPtr(Integer(pEtherHeader) +
                    SizeOf(TEtherHeader));

                  SourceIP.S_addr := pIPHeader.SourceIp;
                  DestIP.S_addr := pIPHeader.DestIp;

                  Writeln (Format('     IP %.3u.%.3u.%.3u.%.3u --> %.3u.%.3u.%.3u.%.3u PROTOCOL: %u',
					          [byte(SourceIP.S_un_b.s_b1),
					          byte(SourceIP.S_un_b.s_b2),
					          byte(SourceIP.S_un_b.s_b3),
					          byte(SourceIP.S_un_b.s_b4),
					          byte(DestIP.S_un_b.s_b1),
					          byte(DestIP.S_un_b.s_b2),
					          byte(DestIP.S_un_b.s_b3),
					          byte(DestIP.S_un_b.s_b4),
					          byte(pIPHeader.Protocol)]
					          ));

                    if pIPHeader.Protocol = IPPROTO_TCP then
                      begin
                        pTcpHeader  := TTCPHeaderPtr(Integer(pIPHeader) + (pIPHeader.VerLen and $F) * 4);
                        Writeln (Format('     TCP SRC PORT: %d DST PORT: %d',
                            [ntohs(pTcpHeader.SourcePort),
						                ntohs(pTcpHeader.DestPort)]));
                      end;

                    if pIPHeader.Protocol = IPPROTO_UDP then
                      begin
                        pUdpHeader  := TUDPHeaderPtr(Integer(pIPHeader) + (pIPHeader.VerLen and $F) * 4);
                        Writeln (Format('     UDP SRC PORT: %d DST PORT: %d',
                            [ntohs(pUdpHeader.SourcePort),
						                ntohs(pUdpHeader.DestPort)]));
                      end;
                end;

              if ntohs(pEtherHeader.h_proto) = ETH_P_RARP then
                  Writeln('     Reverse Addr Res packet');

			        if ntohs(pEtherHeader.h_proto) = ETH_P_ARP  then
                  Writeln('     Address Resolution packet');

              Writeln;

              if counter = 0 then begin
				        Writeln ('Filtering complete');
				        break;
              end;
            end;
            Write ('.');
			      Sleep(100);
       end;
  end;
end.
