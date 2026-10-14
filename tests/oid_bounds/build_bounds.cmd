@echo off
setlocal
set "HERE=%~dp0"
set "ARCH=%~1"
if not "%ARCH%"=="x64" if not "%ARCH%"=="x86" exit /b 2
set "SRC=%~2"
set "OUT=%~3"
if "%SRC%"=="" set "SRC=%HERE%..\.."
if "%OUT%"=="" set "OUT=%HERE%out\%ARCH%"
if not exist "%OUT%" mkdir "%OUT%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VCVARS=%%I\VC\Auxiliary\Build\vcvarsall.bat"
if not defined VCVARS exit /b 2
call "%VCVARS%" %ARCH% > "%OUT%\environment.log" 2>&1
if errorlevel 1 exit /b 2
cl /nologo /c /W4 /EHa /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /DBOUNDS_SDK_SOURCE /I"%HERE%." /I"%SRC%\ndisapi" /I"%SRC%\include" /FIbounds_shim.h /Fo"%OUT%\sdk.obj" "%SRC%\ndisapi\ndisapi.cpp" > "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
cl /nologo /c /W4 /EHa /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%HERE%." /I"%SRC%\include" /Fo"%OUT%\\" "%HERE%bounds_test.cpp" "%HERE%bounds_shim.cpp" >> "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
link /nologo /out:"%OUT%\bounds_test.exe" "%OUT%\sdk.obj" "%OUT%\bounds_test.obj" "%OUT%\bounds_shim.obj" ws2_32.lib iphlpapi.lib advapi32.lib >> "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
exit /b 0
