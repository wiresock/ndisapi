@echo off
setlocal EnableExtensions
set "TESTS=%~dp0"
set "TESTS=%TESTS:~0,-1%"
set "ARCH=%~1"
set "LAYOUT=%~2"
set "SRC=%~3"
set "OUT=%~4"
set "MODE=%~5"
if /i not "%ARCH%"=="x64" if /i not "%ARCH%"=="x86" exit /b 2
if /i not "%LAYOUT%"=="standard" if /i not "%LAYOUT%"=="jumbo" exit /b 2
if "%SRC%"=="" set "SRC=%TESTS%\..\.."
if "%OUT%"=="" set "OUT=%SRC%\tests\bin\fastio_reader\%ARCH%-%LAYOUT%"
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%OUT%\temp" mkdir "%OUT%\temp"
set "TEMP=%OUT%\temp"
set "TMP=%OUT%\temp"
pushd "%OUT%"
if not defined VCVARSALL call :find_vcvarsall
if not defined VCVARSALL exit /b 2
call "%VCVARSALL%" %ARCH% > "%OUT%\environment.log" 2>&1
if errorlevel 1 exit /b 2
set "DEFINES=/D_ENABLE_EXTENDED_ALIGNED_STORAGE"
if /i "%LAYOUT%"=="jumbo" set "DEFINES=%DEFINES% /DJUMBO_FRAME_SUPPORTED"
if /i "%MODE%"=="worker-only" set "DEFINES=%DEFINES% /DFASTIO_WORKER_ONLY"
cl /nologo /W4 /WX /EHsc /std:c++17 %DEFINES% /I"%SRC%\include" /I"%SRC%\examples\cpp\common\ndisapi" /Fo"%OUT%\fastio_reader_test.obj" /Fe"%OUT%\fastio_reader_test.exe" "%TESTS%\fastio_reader_test.cpp" /link > "%OUT%\build.log" 2>&1
if errorlevel 1 exit /b 2
exit /b 0
:find_vcvarsall
set "VCVARSALL="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :eof
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%I\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%%I\VC\Auxiliary\Build\vcvarsall.bat"
)
goto :eof
