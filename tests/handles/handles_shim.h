#ifndef SDK_HANDLES_SHIM_H
#define SDK_HANDLES_SHIM_H
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <stddef.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <string>
#include <algorithm>
#include "Common.h"

// Only the actual SDK TU is compiled with SDK_HANDLES_SOURCE, so allocation
// observation cannot intercept the test's containers or shim bookkeeping.
enum TEST_IO_MODE { TestImmediate, TestFailure, TestPending };
struct TEST_SHIM_STATE {
    TEST_IO_MODE mode;
    DWORD immediateError, immediateBytes, terminalError, terminalBytes;
    BOOL terminalSuccess, writeResponse, delayResponse, cleanupClobbersError;
    DWORD responseLength, captureInputLimit;
    unsigned char response[8192], input[8192];
    DWORD capturedInput, code, inLength, outLength, ioctlCalls, completions, waits;
    DWORD pendingReturns, freedWhilePending, closedWhilePending, completionInputChanged;
    DWORD allocationCalls, freeCalls, outstandingAllocations, failAllocationAt;
    DWORD resetStatsSideEffects, enumerationCalls, enumerationCompletions;
    TEST_IO_MODE enumerationMode;
    DWORD enumerationBytes, enumerationError, enumerationTerminalError;
    BOOL enumerationTerminalSuccess, enumerationPending;
    OVERLAPPED* enumerationOverlap;
    BOOL pending, validServiceResponse;
    void* inputPointer;
    void* outputPointer;
    OVERLAPPED* overlap;
    HANDLE pendingEvent;
};
extern TEST_SHIM_STATE g_Test;
extern ULONGLONG g_Adapters[ADAPTER_LIST_SIZE];
extern unsigned g_AdapterCount;
void TestReset();
void TestAbandonPending();
bool TestWow64();
HANDLE WINAPI TestCreateFile(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL WINAPI TestIoctl(HANDLE, DWORD, void*, DWORD, void*, DWORD, DWORD*, OVERLAPPED*);
BOOL WINAPI TestCompletion(HANDLE, OVERLAPPED*, DWORD*, BOOL);
BOOL WINAPI TestCloseHandle(HANDLE);
void* TestMalloc(size_t);
void TestFree(void*);
extern void (*g_AfterMapUnlock)();
BOOL WINAPI TestReleaseMutex(HANDLE);

#ifndef SDK_HANDLES_SHIM_IMPL
#undef CreateFile
#define CreateFile TestCreateFile
#define DeviceIoControl TestIoctl
#define GetOverlappedResult TestCompletion
#define CloseHandle TestCloseHandle
#ifdef SDK_HANDLES_SOURCE
#define malloc TestMalloc
#define free TestFree
#define ReleaseMutex TestReleaseMutex
#endif
#endif
#endif