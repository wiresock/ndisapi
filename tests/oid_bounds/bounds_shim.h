#pragma once
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include "Common.h"
struct BOUNDS_STATE {
    unsigned allocations, copies, ioctls, events, completions, faults, frees, closes;
    size_t requestedBytes;
    DWORD inputBytes, outputBytes;
    bool pending, failIo, boundary, replyLengthSet, clobberCleanup;
    DWORD replyLength;
};
extern BOUNDS_STATE g_bounds;
bool BoundsWow64();
void BoundsReset();
void BoundsCleanup();
void BoundsWatchCaller(void*,size_t);
HANDLE WINAPI BoundsCreateFile(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
HANDLE WINAPI BoundsCreateEvent(LPSECURITY_ATTRIBUTES,BOOL,BOOL,LPCTSTR);
BOOL WINAPI BoundsCloseHandle(HANDLE);
BOOL WINAPI BoundsIoctl(HANDLE,DWORD,void*,DWORD,void*,DWORD,DWORD*,OVERLAPPED*);
BOOL WINAPI BoundsCompletion(HANDLE,OVERLAPPED*,DWORD*,BOOL);
void* BoundsMalloc(size_t);
void BoundsFree(void*);
void* BoundsMemmove(void*,const void*,size_t);
#ifndef BOUNDS_SHIM_IMPL
#undef CreateFile
#define CreateFile BoundsCreateFile
#undef CreateEvent
#define CreateEvent BoundsCreateEvent
#define CloseHandle BoundsCloseHandle
#define DeviceIoControl BoundsIoctl
#define GetOverlappedResult BoundsCompletion
#ifdef BOUNDS_SDK_SOURCE
#define malloc BoundsMalloc
#define free BoundsFree
#define memmove BoundsMemmove
#endif
#endif
