@echo off
SETLOCAL

ECHO Building for x86 Debug...
make ARCH=x86 CONFIG=Debug

ECHO Building for x86 Release...
make ARCH=x86 CONFIG=Release

ECHO Building for x64 Debug...
make ARCH=x64 CONFIG=Debug

ECHO Building for x64 Release...
make ARCH=x64 CONFIG=Release

ENDLOCAL
ECHO Build process completed.
