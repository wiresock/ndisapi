@echo off
rem run_all.cmd - build and run the SDK's offline regressions.
rem
rem   run_all.cmd                 build + run for x64 and x86; exit code 0 iff every test passed
rem   run_all.cmd ablation        additionally run exact checksum/FastIO ablations and the SAME historical OID tests and
rem                               require them to FAIL, which is what makes them a regression
rem                               rather than a description of the current code
rem   run_all.cmd ablation <rev>  use <rev> instead of the default pre-fix commit
rem
rem Both architectures matter and neither substitutes for the other: the 32-bit build running on
rem 64-bit Windows is genuinely a WOW64 process, so it takes CNdisApi's WOW64 conversion branch for
rem real. The test asserts which branch it took rather than assuming.
rem
rem Every exit code is captured the moment the child returns, and any nonzero value - including an
rem access violation's 0xC0000005 - fails the run. No output is filtered before a status is read.
setlocal EnableDelayedExpansion
rem Explicit maintained selection exits before every historical suite.
if /i "%~1"=="safe-gates" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0handles\Run-SafeGates.ps1" -OutputDirectory "%~2"
    exit /b !ERRORLEVEL!
)

set "TESTS=%~dp0"
set "TESTS=%TESTS:~0,-1%"
set "ROOT=%TESTS%\.."
set "OUT=%TESTS%\bin"
if not exist "%OUT%" mkdir "%OUT%"

rem the SDK commit that still had the defect; see tests\README.md
set "PREFIX_REV=20aa90f"

set RESULT=0
set ABLATION=0
if /i "%~1"=="ablation" set ABLATION=1
if not "%~2"=="" set "PREFIX_REV=%~2"

call :find_vcvarsall
if errorlevel 1 exit /b 2
echo SDK_TOOLCHAIN vcvarsall="%VCVARSALL%"
rem Clear an inherited developer environment before children enter the selected toolchain.
call :clean_vc_environment
if errorlevel 1 exit /b 2

call :arch x64
call :arch x86
call :oid_bounds x64
call :oid_bounds x86
call :handles x64
call :handles x86
call :packets x64
call :packets x86
call :fastio x64 standard
call :fastio x64 jumbo
call :fastio x86 standard
call :fastio x86 jumbo
call :checksum x64 standard modern
call :checksum x64 standard legacy
call :checksum x64 jumbo modern
call :checksum x64 jumbo legacy
call :checksum x86 standard modern
call :checksum x86 standard legacy
call :checksum x86 jumbo modern
call :checksum x86 jumbo legacy

if "%ABLATION%"=="1" (
    call :fastio_ablate x64 standard
    call :fastio_ablate x64 jumbo
    call :fastio_ablate x86 standard
    call :fastio_ablate x86 jumbo
    call :checksum_ablate x64 standard modern
    call :checksum_ablate x64 standard legacy
    call :checksum_ablate x64 jumbo modern
    call :checksum_ablate x64 jumbo legacy
    call :checksum_ablate x86 standard modern
    call :checksum_ablate x86 standard legacy
    call :checksum_ablate x86 jumbo modern
    call :checksum_ablate x86 jumbo legacy
    call :stage_prefix
    if not "!ERRORLEVEL!"=="0" (
        echo ABLATION RESULT: SETUP_FAILED - the pre-fix sources could not be staged
        set RESULT=1
    ) else (
        call :ablate x64
        call :ablate x86
    )
)

echo.
echo ===== OVERALL RESULT=%RESULT% =====
exit /b %RESULT%

rem ---------------------------------------------------------------- the current SDK
:arch
echo.
echo === oid_test %~1 ^(ndisapi\ndisapi.cpp as shipped^)
call :build_and_run "%~1" "%ROOT%" "%OUT%\%~1" oid_test
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

rem ---------------------------------------------------------------- checked OID request extents
:oid_bounds
echo.
echo === oid_bounds %~1
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\oid_bounds\Run-Bounds.ps1" -Arch "%~1"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

rem ---------------------------------------------------------------- handle/table regressions
:handles
echo.
echo === handles_test %~1
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\handles\Run-Handles.ps1" -Arch "%~1"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

rem ---------------------------------------------------------------- packet result/staging regressions
:packets
echo.
echo === packets_test %~1
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\packets\Run-Packets.ps1" -Arch "%~1"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

rem ---------------------------------------------------------------- actual FastIO header/worker/helper
:fastio
echo.
echo === fastio_reader %~1 %~2
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\fastio_reader\Run-Reader.ps1" -Arch "%~1" -Layout "%~2"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

:fastio_ablate
echo.
echo === fastio_reader ablation %~1 %~2
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\fastio_reader\Run-Ablation.ps1" -Arch "%~1" -Layout "%~2"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

rem ---------------------------------------------------------------- actual checksum methods and exports
:checksum
echo.
echo === checksum %~1 %~2 %~3
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\checksum\Run-Checksum.ps1" -Arch "%~1" -Layout "%~2" -Codec "%~3"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

:checksum_ablate
echo.
echo === checksum ablation %~1 %~2 %~3
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\checksum\Run-Ablation.ps1" -Arch "%~1" -Layout "%~2" -Codec "%~3"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof

rem ---------------------------------------------------------------- the pre-fix SDK
:ablate
rem B-ABLATE-01. Whether an ablation proved anything is decided by Classify-Ablation.ps1,
rem not by "the exit code was nonzero". A compile error, a crash - including a crash AFTER
rem the footer was printed - and a test that failed for an unrelated reason all look like
rem success from here.
echo.
echo === ablation %~1 ^(ndisapi.cpp at %PREFIX_REV%: these tests MUST fail^)
set "AO=%OUT%\%~1_prefix"
if not exist "!AO!" mkdir "!AO!"
set "BUILDOUTCOME=OK"
set "ABRC="
if not exist "%OUT%\prefix\ndisapi\ndisapi.cpp" set "BUILDOUTCOME=SETUP_FAILED"
if "!BUILDOUTCOME!"=="OK" (
    call :build_only "%~1" "%OUT%\prefix" "!AO!" oid_test
    if not "!ERRORLEVEL!"=="0" set "BUILDOUTCOME=COMPILE_FAILED"
)
if "!BUILDOUTCOME!"=="OK" (
    "!AO!\oid_test.exe" > "!AO!\ablation.log" 2>&1
    set "ABRC=!ERRORLEVEL!"
    findstr /C:"checks," "!AO!\ablation.log"
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%TESTS%\Classify-Ablation.ps1" -BuildOutcome "!BUILDOUTCOME!" -ExitCode "!ABRC!" -LogPath "!AO!\ablation.log" -ExpectedExitCode 1 -VerdictPattern "(?m)^^RESULT=" -FailFooterPattern "(?m)^^RESULT=1" -SignaturePattern "\[FAIL\] pending failure: GET returns FALSE" -Label "%~1"
if not "!ERRORLEVEL!"=="0" set RESULT=1
goto :eof
rem %1 arch, %2 sdk root, %3 output dir, %4 exe name - builds only, so the ablation can tell
rem a build failure apart from a test failure
:build_only
set "A=%~1"
set "SRC=%~2"
set "O=%~3"
set "EXE=%~4"
if not exist "%O%" mkdir "%O%"
cmd /c ""%VCVARSALL%" %A% >nul 2>&1 && echo SDK_COMPILER_PATH arch=%A% && where cl && cl /Bv /nologo /W4 /EHsc /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TESTS%" /I"%SRC%\ndisapi" /I"%SRC%\include" /FIoidshim.h /Fo"%O%\\" /Fe"%O%\%EXE%.exe" "%TESTS%\oid_test.cpp" "%TESTS%\oidshim.c" "%SRC%\ndisapi\ndisapi.cpp" /link ws2_32.lib iphlpapi.lib advapi32.lib" > "%O%\build.log" 2>&1
if not "!ERRORLEVEL!"=="0" (
    findstr /C:"error " "%O%\build.log"
    exit /b 2
)
echo SDK_COMPILER_RECEIPT arch=%A%
findstr /C:"SDK_COMPILER_PATH" /C:"cl.exe" /C:"Compiler Version" "%O%\build.log"
echo SDK_COMPILER_RECEIPT_END arch=%A%
exit /b 0

rem %1 arch, %2 sdk root, %3 output dir, %4 exe name
:build_and_run
set "A=%~1"
set "SRC=%~2"
set "O=%~3"
set "EXE=%~4"
if not exist "%O%" mkdir "%O%"
cmd /c ""%VCVARSALL%" %A% >nul 2>&1 && echo SDK_COMPILER_PATH arch=%A% && where cl && cl /Bv /nologo /W4 /EHsc /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TESTS%" /I"%SRC%\ndisapi" /I"%SRC%\include" /FIoidshim.h /Fo"%O%\\" /Fe"%O%\%EXE%.exe" "%TESTS%\oid_test.cpp" "%TESTS%\oidshim.c" "%SRC%\ndisapi\ndisapi.cpp" /link ws2_32.lib iphlpapi.lib advapi32.lib" > "%O%\build.log" 2>&1
if not "!ERRORLEVEL!"=="0" (
    echo BUILD FAILED ^(%A%^); see "%O%\build.log"
    findstr /C:"error " "%O%\build.log"
    exit /b 2
)
echo SDK_COMPILER_RECEIPT arch=%A%
findstr /C:"SDK_COMPILER_PATH" /C:"cl.exe" /C:"Compiler Version" "%O%\build.log"
echo SDK_COMPILER_RECEIPT_END arch=%A%
"%O%\%EXE%.exe"
exit /b !ERRORLEVEL!

rem ---------------------------------------------------------------- pre-fix source tree
:stage_prefix
set "P=%OUT%\prefix"
if exist "%P%" rmdir /s /q "%P%"
mkdir "%P%\ndisapi" "%P%\include" 2>nul
pushd "%ROOT%"
git show %PREFIX_REV%:ndisapi/ndisapi.cpp > "%P%\ndisapi\ndisapi.cpp" 2>nul
if not "!ERRORLEVEL!"=="0" ( popd & echo cannot read ndisapi.cpp at %PREFIX_REV% & exit /b 1 )
git show %PREFIX_REV%:include/ndisapi.h > "%P%\include\ndisapi.h" 2>nul
if not "!ERRORLEVEL!"=="0" ( popd & echo cannot read include/ndisapi.h at %PREFIX_REV% & exit /b 1 )
popd
copy /y "%ROOT%\ndisapi\precomp.h"  "%P%\ndisapi\" >nul
copy /y "%ROOT%\ndisapi\iphlp.h"    "%P%\ndisapi\" >nul
copy /y "%ROOT%\ndisapi\resource.h" "%P%\ndisapi\" >nul
for %%F in ("%ROOT%\include\*.h") do if /i not "%%~nxF"=="ndisapi.h" copy /y "%%F" "%P%\include\" >nul
exit /b 0

rem ---------------------------------------------------------------- toolchain
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
