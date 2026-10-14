@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "ARCH=%~1"
if not "%ARCH%"=="x86" if not "%ARCH%"=="x64" exit /b 2
set "ROOT=%~dp0"
set "OUT=%~4"
if not defined OUT set "OUT=%ROOT%red-%ARCH%"
if not exist "%OUT%" mkdir "%OUT%"
set "S=%~2"
if not defined S set "S=%ROOT%source\sdk"
set "K=%~3"
if not defined K set "K=%ROOT%source\kernel"
if not defined VCVARSALL call :find_vcvarsall
if not defined VCVARSALL exit /b 2
call "%VCVARSALL%" %ARCH% >"%OUT%\environment.log" 2>&1
if errorlevel 1 exit /b 2
set "GSL=%~5"
set "COMMON=/nologo /c /W4 /EHsc /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%ROOT%.""
cl %COMMON% /I"%S%\include" /I"%S%\ndisapi" /FI"%ROOT%r5_hooks.h" /Fo"%OUT%\sdk.obj" "%S%\ndisapi\ndisapi.cpp" >"%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
cl %COMMON% /D_ENABLE_EXTENDED_ALIGNED_STORAGE /I"%GSL%" /I"%S%" /I"%S%\include" /I"%S%\ndisapi" /Fo"%OUT%\\" "%ROOT%r5_hooks.cpp" "%ROOT%r5_lifecycle_test.cpp" >>"%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
cl /nologo /c /W4 /wd4100 /I"%ROOT%." /I"%K%\tests\shim_lwf" /FI"%K%\tests\shim_lwf\precomp.h" /Fo"%OUT%\\" "%ROOT%r5_driver_bridge.c" "%K%\tests\shim_lwf\shim_lwf.c" "%K%\LWF\fastio.c" "%K%\LWF\lifecycle.c" >>"%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
link /nologo /OUT:"%OUT%\r5_lifecycle_test.exe" "%OUT%\sdk.obj" "%OUT%\r5_hooks.obj" "%OUT%\r5_lifecycle_test.obj" "%OUT%\r5_driver_bridge.obj" "%OUT%\shim_lwf.obj" "%OUT%\fastio.obj" "%OUT%\lifecycle.obj" ws2_32.lib iphlpapi.lib advapi32.lib >>"%OUT%\build.log" 2>&1
set "BUILD_EXIT=!ERRORLEVEL!"
>"%OUT%\build.exit.txt" echo !BUILD_EXIT!
if not !BUILD_EXIT!==0 exit /b 2
exit /b 0

:find_vcvarsall
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :eof
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
 if exist "%%I\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%%I\VC\Auxiliary\Build\vcvarsall.bat"
)
goto :eof
