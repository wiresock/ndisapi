{                        Windows Packet Filter Kit 3.0                }
{                 Copyright(C) 2000-2010 NT Kernel Resources          }
{                         mailto: ndisrd@ntkernel.com                 }

program PassThru;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  Winsock,
  winpkf in '..\winpkf.pas',
  iphlp in '..\iphlp.pas';

var
  iIndex, counter: DWORD;
  hFilt: THANDLE;
  Adapts: TCP_AdapterList;
  AdapterMode: ADAPTER_MODE;
  Buffer: INTERMEDIATE_BUFFER;
  ReadRequest: ETH_REQUEST;
  hEvent: THANDLE;
  hAdapter: THANDLE;
  pEtherHeader: TEtherHeaderPtr;
  pIPHeader: TIPHeaderPtr;
  pTcpHeader: TTCPHeaderPtr;
  pUdpHeader: TUDPHeaderPtr;
  SourceIP, DestIP: TInAddr;

procedure ReleaseInterface();
begin
  // Restore default mode
  AdapterMode.dwFlags := 0;
  AdapterMode.hAdapterHandle := hAdapter;
  SetAdapterMode ( hFilt, @AdapterMode );

  // Set NULL event to release previously set event object
  SetPacketEvent (hFilt, hAdapter, 0);

  // Close Event
  if hEvent <> 0 then CloseHandle(hEvent);

  // Close driver object
  CloseFilterDriver (hFilt);

  // Release NDISAPI
  FreeNDISAPI();
end;

begin

  // Check the number of parameters
  if ParamCount() < 2 then begin
    Writeln('Command line syntax:');
    Writeln('   PassThru.exe index num');
    Writeln('   index - network interface index.');
    Writeln('   num - number or packets to filter');
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

      AdapterMode.dwFlags := MSTCP_FLAG_SENT_TUNNEL or MSTCP_FLAG_RECV_TUNNEL;
      AdapterMode.hAdapterHandle := hAdapter;

      // Create notification event
	    hEvent := CreateEvent(Nil, TRUE, FALSE, Nil);

      if hEvent <> 0 then
        if SetPacketEvent (hFilt, hAdapter, hEvent) <> 0 then begin
          // Initialize request
          ReadRequest.EthPacket.Buffer := @Buffer;
	        ReadRequest.hAdapterHandle := hAdapter;

          SetAdapterMode ( hFilt, @AdapterMode );

          while counter <> 0 do begin
            WaitForSingleObject ( hEvent, INFINITE );
            while ReadPacket (hFilt, @ReadRequest) <> 0 do begin
              Dec (counter);
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

              if Buffer.m_dwDeviceFlags = PACKET_FLAG_ON_SEND then
                  // Place packet on the network interface
				          SendPacketToAdapter(hFilt, @ReadRequest)
              else
                  // Indicate packet to MSTCP
				          SendPacketToMstcp(hFilt, @ReadRequest);

              if counter = 0 then begin
				        Writeln ('Filtering complete');
				        break;
              end;
            end;
            ResetEvent(hEvent);
          end;
        end;
  end;
end.
