@echo off
setlocal
set "TESTS=%~dp0"
set "TESTS=%TESTS:~0,-1%"
set "ROOT=%TESTS%\..\.."
set "ARCH=%~1"
set "SRC=%~2"
set "OUT=%~3"
if "%SRC%"=="" set "SRC=%ROOT%"
if "%OUT%"=="" set "OUT=%ROOT%\tests\bin\handles\%ARCH%"
if not exist "%OUT%" mkdir "%OUT%"
if not defined VCVARSALL call :find_vcvarsall
if not defined VCVARSALL exit /b 2
call "%VCVARSALL%" %ARCH% > "%OUT%\environment.log" 2>&1
if errorlevel 1 exit /b 2
cl /nologo /c /W4 /EHa /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /DSDK_HANDLES_SOURCE /I"%TESTS%" /I"%SRC%\ndisapi" /I"%SRC%\include" /FIhandles_shim.h /Fo"%OUT%\sdk.obj" "%SRC%\ndisapi\ndisapi.cpp" > "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
cl /nologo /c /W4 /EHa /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TESTS%" /I"%SRC%\include" /Fo"%OUT%\\" "%TESTS%\handles_test.cpp" "%TESTS%\handles_shim.cpp" >> "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
link /nologo /out:"%OUT%\handles_test.exe" "%OUT%\sdk.obj" "%OUT%\handles_test.obj" "%OUT%\handles_shim.obj" ws2_32.lib iphlpapi.lib advapi32.lib >> "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
exit /b 0
:find_vcvarsall
set "VCVARSALL="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :eof
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%I\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%%I\VC\Auxiliary\Build\vcvarsall.bat"
)
goto :eof
