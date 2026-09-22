@echo off
rem run_all.cmd - build and run the SDK's offline regressions.
rem
rem   run_all.cmd                 build + run for x64 and x86; exit code 0 iff every test passed
rem   run_all.cmd ablation        additionally compile the SAME tests against the PRE-FIX SDK and
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
if not defined VCVARSALL (
    echo Could not locate vcvarsall.bat; install the C++ build tools or run from a Developer prompt.
    exit /b 2
)

call :arch x64
call :arch x86

if "%ABLATION%"=="1" (
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
cmd /c ""%VCVARSALL%" %A% >nul 2>&1 && cl /nologo /W4 /EHsc /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TESTS%" /I"%SRC%\ndisapi" /I"%SRC%\include" /FIoidshim.h /Fo"%O%\\" /Fe"%O%\%EXE%.exe" "%TESTS%\oid_test.cpp" "%TESTS%\oidshim.c" "%SRC%\ndisapi\ndisapi.cpp" /link ws2_32.lib iphlpapi.lib advapi32.lib" > "%O%\build.log" 2>&1
if not "!ERRORLEVEL!"=="0" (
    findstr /C:"error " "%O%\build.log"
    exit /b 2
)
exit /b 0

rem %1 arch, %2 sdk root, %3 output dir, %4 exe name
:build_and_run
set "A=%~1"
set "SRC=%~2"
set "O=%~3"
set "EXE=%~4"
if not exist "%O%" mkdir "%O%"
cmd /c ""%VCVARSALL%" %A% >nul 2>&1 && cl /nologo /W4 /EHsc /std:c++17 /D_LIB /DUNICODE /D_UNICODE /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TESTS%" /I"%SRC%\ndisapi" /I"%SRC%\include" /FIoidshim.h /Fo"%O%\\" /Fe"%O%\%EXE%.exe" "%TESTS%\oid_test.cpp" "%TESTS%\oidshim.c" "%SRC%\ndisapi\ndisapi.cpp" /link ws2_32.lib iphlpapi.lib advapi32.lib" > "%O%\build.log" 2>&1
if not "!ERRORLEVEL!"=="0" (
    echo BUILD FAILED ^(%A%^); see "%O%\build.log"
    findstr /C:"error " "%O%\build.log"
    exit /b 2
)
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
set "VCVARSALL="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :eof
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%I\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL=%%I\VC\Auxiliary\Build\vcvarsall.bat"
)
goto :eof
