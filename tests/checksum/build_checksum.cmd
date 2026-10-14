@echo off
setlocal
set "TESTS=%~dp0"
set "ARCH=%~1"
set "LAYOUT=%~2"
set "CODEC=%~3"
set "SRC=%~4"
set "OUT=%~5"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%OUT%\temp" mkdir "%OUT%\temp"
set "TEMP=%OUT%\temp"
set "TMP=%OUT%\temp"
set "CL="
set "_CL_="
set "LINK="
set "_LINK_="
pushd "%OUT%"
if not defined VCVARSALL set "VCVARSALL=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARSALL%" exit /b 2
call "%VCVARSALL%" %ARCH% > "%OUT%\environment.log" 2>&1
if errorlevel 1 exit /b 2
set "DEFINES=/D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /D_CRT_SECURE_NO_WARNINGS"
if "%LAYOUT%"=="jumbo" set "DEFINES=%DEFINES% /DJUMBO_FRAME_SUPPORTED"
if "%CODEC%"=="legacy" set "DEFINES=%DEFINES% /DINET_CHECKSUM_FORCE_LEGACY_COMPAT"
cl /nologo /W4 /EHsc /std:c++17 /Od %DEFINES% /I"%SRC%\ndisapi" /I"%SRC%\include" /Fo"%OUT%\\" /Fe"%OUT%\checksum_ceiling_test.exe" "%TESTS%checksum_ceiling_test.cpp" "%SRC%\ndisapi\ndisapi.cpp" /link ws2_32.lib iphlpapi.lib advapi32.lib > "%OUT%\build.log" 2>&1
exit /b %ERRORLEVEL%
