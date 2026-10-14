#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <winternl.h>
#include <tchar.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <string>
#include <algorithm>
#include "Common.h"
#include "r5_bridge.h"
struct R5Hooks {
 bool failEvent=false, failMode=false, failOwnerEvent=false, ownerEventPending=false;
 int failOpenAt=0, modeCalls=0, eventCalls=0, openCalls=0, closeCalls=0, flushCalls=0, registrations=0;
 long status=0;
 HANDLE base=nullptr, lastRegistrationOwner=nullptr, lastModeOwner=nullptr, lastEventOwner=nullptr, attachedEvent=nullptr;
 HANDLE registrationOwners[32]{};
};
extern R5Hooks r5;
HANDLE WINAPI R5CreateFile(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
HANDLE WINAPI R5CreateEvent(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCTSTR);
BOOL WINAPI R5Ioctl(HANDLE,DWORD,void*,DWORD,void*,DWORD,DWORD*,OVERLAPPED*);
BOOL WINAPI R5CloseHandle(HANDLE);
FARPROC WINAPI R5GetProcAddress(HMODULE,LPCSTR);
#ifndef R5_HOOK_IMPL
#undef CreateFile
#define CreateFile R5CreateFile
#undef CreateEvent
#define CreateEvent R5CreateEvent
#define DeviceIoControl R5Ioctl
#define CloseHandle R5CloseHandle
#define GetProcAddress R5GetProcAddress
#endif
