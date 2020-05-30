{                        Windows Packet Filter Kit 3.0                }
{                 Copyright(C) 2000-2010 NT Kernel Resources          }
{                         mailto: ndisrd@ntkernel.com                 }

program ListAdapters;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows,
  winpkf in '..\winpkf.pas';

var
  i: integer;
  hFilt: THANDLE;
  Adapts: PTCP_AdapterList;
  Mode: PADAPTER_MODE;
  aname: array[0..1023] of char;
  VerInfo: TOSVersionInfo;
  dwMTUDec: DWORD;
  dwAdapterStartupMode: DWORD;
begin
  // Allocate TCP_AdapterList record
  new(Adapts);

  // Allocate ADAPTER_MODE
  new(Mode);

  VerInfo.dwOSVersionInfoSize := SizeOf(TOSVersionInfo);
  GetVersionEx(VerInfo);

  // Initialize NDISAPI
  InitNDISAPI();

  dwMTUDec := GetMTUDecrement();
  dwAdapterStartupMode := GetAdaptersStartupMode();

  // Create driver object
  hFilt := OpenFilterDriver('NDISRD');

  // Check if driver loaded
  if IsDriverLoaded(hFilt) then begin

    GetTcpipBoundAdaptersInfo (hFilt, Adapts);
    for i := 1 to Adapts.m_nAdapterCount do begin
          // Convert internal network interface name to user-friendly one depending of the OS
          if VerInfo.dwPlatformId = VER_PLATFORM_WIN32_NT then
              if VerInfo.dwMajorVersion = 4 then
                ConvertWindowsNTAdapterName(PAnsiChar(string(Adapts.m_szAdapterNameList[i])), aname, 1024)
              else
                ConvertWindows2000AdapterName(PAnsiChar(string(Adapts.m_szAdapterNameList[i])), aname, 1024)
          else
            ConvertWindows9xAdapterName(PAnsiChar(string(Adapts.m_szAdapterNameList[i])), aname, 1024);

          // Dump some network interface information
          Writeln(i, ') ', string(aname));
          Writeln('     Internal Name: ', Pchar(string(Adapts.m_szAdapterNameList[i])));
          Writeln(Format('     Current MAC:   %.2x%.2x%.2x%.2x%.2x%.2x', [Adapts.m_czCurrentAddress[i][1], Adapts.m_czCurrentAddress[i][2], Adapts.m_czCurrentAddress[i][3], Adapts.m_czCurrentAddress[i][4], Adapts.m_czCurrentAddress[i][5], Adapts.m_czCurrentAddress[i][6]]));
          Writeln(Format('     Medium:        0x%.8X', [Adapts.m_nAdapterMediumList[i]]));
			    Writeln(Format('     Current MTU:   %d', [Adapts.m_usMTU[i]]));

          Mode.hAdapterHandle := Adapts.m_nAdapterHandle[i];
          GetAdapterMode(hFilt, Mode);

          Writeln(Format('     Current adapter mode:   %d', [Mode.dwFlags]));

          Writeln;
    end;
    Writeln('Current system wide MTU decrement = ', dwMTUDec);
    Writeln('Default adapter startup mode = ', dwAdapterStartupMode);
  end
  else
    Writeln('Helper driver failed to load or was not installed.');

  // Perform cleanup
  dispose(Adapts);
  CloseFilterDriver (hFilt);

  // Release NDISAPI
  FreeNDISAPI();
end.
