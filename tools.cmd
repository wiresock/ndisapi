@echo off
mkdir tools
mkdir tools\i386
mkdir tools\amd64
mkdir tools\arm64
mkdir tools\vs2012
mkdir tools\vs2012\i386
mkdir tools\vs2012\amd64
mkdir tools\vc6

copy /Y .\bin\examples\native\Win32\Release\*.exe tools\i386\
for %%f in (tools\i386\*.exe) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\i386\*.exe) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

copy /Y .\bin\examples\native\x64\Release\*.exe tools\amd64\
for %%f in (tools\amd64\*.exe) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\amd64\*.exe) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

copy /Y .\bin\examples\native\arm64\Release\*.exe tools\arm64\
copy /Y .\bin\dll\ARM64\Release\*.dll tools\arm64\
for %%f in (tools\arm64\*.exe tools\arm64\*.dll) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\arm64\*.exe tools\arm64\*.dll) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

copy /Y .\bin\dll\Win32\Release\*.dll tools\i386\
for %%f in (tools\i386\*.dll) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\i386\*.dll) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

copy /Y .\bin\dll\x64\Release\*.dll tools\amd64\
for %%f in (tools\amd64\*.dll) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\amd64\*.dll) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

copy /Y .\examples\legacy\MSVC\bin\dll.vs2012\i386\ndisapi.dll tools\vs2012\i386\
copy /Y .\examples\legacy\MSVC\bin\dll.vs2012\amd64\ndisapi.dll tools\vs2012\amd64\
copy /Y .\examples\legacy\MSVC\bin\i386\*.exe tools\vs2012\i386\
copy /Y .\examples\legacy\MSVC\bin\amd64\*.exe tools\vs2012\amd64\
for %%f in (tools\vs2012\i386\*.exe tools\vs2012\i386\*.dll tools\vs2012\amd64\*.exe tools\vs2012\amd64\*.dll) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\vs2012\i386\*.exe tools\vs2012\i386\*.dll tools\vs2012\amd64\*.exe tools\vs2012\amd64\*.dll) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

copy /Y .\examples\legacy\MSVC\bin\vc6\*.exe tools\vc6\
copy /Y .\bin\dll.vc6\i386\ndisapi.dll tools\vc6\
for %%f in (tools\vc6\*.exe tools\vc6\*.dll) do signtool sign /fd sha1 /t http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"
for %%f in (tools\vc6\*.exe tools\vc6\*.dll) do signtool sign /as /td sha256 /fd sha256 /tr http://timestamp.digicert.com /n "IP SMIRNOV VADIM VALERIEVICH" "%%f"

pushd tools\i386
"C:\Program Files\7-Zip\7z.exe" a ..\..\tools_bin_x86.zip *
popd

pushd tools\amd64
"C:\Program Files\7-Zip\7z.exe" a ..\..\tools_bin_x64.zip *
popd

pushd tools\arm64
"C:\Program Files\7-Zip\7z.exe" a ..\..\tools_bin_arm64.zip *
popd

pushd tools\vs2012
"C:\Program Files\7-Zip\7z.exe" a ..\..\tools_bin_x86_x64_vs2012.zip *
popd

pushd tools\vc6
"C:\Program Files\7-Zip\7z.exe" a ..\..\tools_bin_x86_vc6.zip *
popd

rmdir tools /s /q
