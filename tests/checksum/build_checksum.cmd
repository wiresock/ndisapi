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
call :find_vcvarsall > "%OUT%\toolchain-discovery.log" 2>&1
if errorlevel 1 exit /b 2
call :clean_vc_environment > "%OUT%\toolchain-clean.log" 2>&1
if errorlevel 1 exit /b 2
echo Toolchain: "%VCVARSALL%" >> "%OUT%\toolchain-discovery.log"
call "%VCVARSALL%" %ARCH% > "%OUT%\environment.log" 2>&1
if errorlevel 1 exit /b 2
where cl > "%OUT%\compiler-path.log" 2>&1
if errorlevel 1 exit /b 2
set "DEFINES=/D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /D_CRT_SECURE_NO_WARNINGS"
if "%LAYOUT%"=="jumbo" set "DEFINES=%DEFINES% /DJUMBO_FRAME_SUPPORTED"
if "%CODEC%"=="legacy" set "DEFINES=%DEFINES% /DINET_CHECKSUM_FORCE_LEGACY_COMPAT"
cl /Bv /nologo /W4 /EHsc /std:c++17 /Od %DEFINES% /I"%SRC%\ndisapi" /I"%SRC%\include" /Fo"%OUT%\\" /Fe"%OUT%\checksum_ceiling_test.exe" "%TESTS%checksum_ceiling_test.cpp" "%SRC%\ndisapi\ndisapi.cpp" /link ws2_32.lib iphlpapi.lib advapi32.lib > "%OUT%\build.log" 2>&1
set "BUILD_RC=%ERRORLEVEL%"
echo SDK_CHECKSUM_COMPILER_RECEIPT arch=%ARCH% layout=%LAYOUT% codec=%CODEC%
type "%OUT%\compiler-path.log"
findstr /C:"cl.exe" /C:"Compiler Version" "%OUT%\build.log"
echo SDK_CHECKSUM_COMPILER_RECEIPT_END arch=%ARCH% layout=%LAYOUT% codec=%CODEC%
exit /b %BUILD_RC%

:find_vcvarsall
if defined VCVARSALL (
 if exist "%VCVARSALL%" exit /b 0
 echo Invalid VCVARSALL override: "%VCVARSALL%"
 exit /b 1
)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" for /f "usebackq tokens=*" %%I in (`call "%VSWHERE%" -latest -products * -version "[16.0,18.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
 if exist "%%I\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%%I\VC\Auxiliary\Build\vcvarsall.bat"
)
if defined VCVARSALL exit /b 0
echo Could not locate VS2019/2022 C++ tools; set VCVARSALL to a valid vcvarsall.bat.
exit /b 1

:clean_vc_environment
if not defined VSCMD_VER exit /b 0
if not exist "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvarsall.bat" (
 echo Cannot clean the inherited Visual Studio environment; run from a fresh prompt.
 exit /b 1
)
call "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvarsall.bat" /clean_env
exit /b %ERRORLEVEL%
