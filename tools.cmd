mkdir tools
mkdir tools\i386
mkdir tools\amd64
mkdir tools\arm64
mkdir tools\vc6
copy /Y .\bin\examples\native\Win32\Release\*.exe tools\i386\
copy /Y .\bin\examples\native\x64\Release\*.exe tools\amd64\
copy /Y .\bin\examples\native\arm64\Release\*.exe tools\arm64\
copy /Y .\examples\legacy\MSVC\bin\dll.vs2012\i386\ndisapi.dll tools\i386\
copy /Y .\examples\legacy\MSVC\bin\dll.vs2012\amd64\ndisapi.dll tools\amd64\
copy /Y .\bin\dll\ARM64\Release\*.dll tools\arm64\
copy /Y .\examples\legacy\MSVC\bin\i386\*.exe tools\i386\
copy /Y .\examples\legacy\MSVC\bin\amd64\*.exe tools\amd64\
copy /Y .\examples\legacy\MSVC\bin\vc6\*.exe tools\vc6\
copy /Y .\bin\dll.vc6\i386\ndisapi.dll tools\vc6\
"C:\Program Files\7-Zip\7z.exe" a tools_bin_x86.zip tools\i386
"C:\Program Files\7-Zip\7z.exe" a tools_bin_x64.zip tools\amd64
"C:\Program Files\7-Zip\7z.exe" a tools_bin_arm64.zip tools\arm64
"C:\Program Files\7-Zip\7z.exe" a tools_bin_x86_vc6.zip tools\vc6
rmdir tools /s /q
