#ifndef SDK_PACKETS_SHIM_H
#define SDK_PACKETS_SHIM_H
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
enum PACKET_IO_MODE { PacketImmediate, PacketFailure, PacketPending };
struct PACKET_SHIM_STATE {
    PACKET_IO_MODE mode;
    DWORD immediateError, immediateBytes, terminalError, terminalBytes;
    BOOL terminalSuccess, delayResponse, cleanupClobbersError, writePackets, writeCount;
    DWORD resultCount, lengths[4], packetWrites;
    DWORD submittedLengths[4], submittedHashes[4];
    DWORD code, inLength, outLength, submittedCount, ioctlCalls, completions, waits;
    DWORD pendingReturns, freedWhilePending, closedWhilePending, completionInputChanged;
    DWORD allocationCalls, freeCalls, outstandingAllocations, failAllocationAt;
    DWORD oversizedCopies, copyCalls, copyBytes, enumerationCalls, oversizedInputs;
    BOOL pending;
    void* inputPointer;
    void* outputPointer;
    OVERLAPPED* overlap;
    HANDLE pendingEvent;
    unsigned char input[128];
    DWORD capturedInput;
};
extern PACKET_SHIM_STATE g_Packet;
void PacketReset();
void PacketAbandonPending();
bool PacketWow64();
HANDLE WINAPI PacketCreateFile(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL WINAPI PacketIoctl(HANDLE, DWORD, void*, DWORD, void*, DWORD, DWORD*, OVERLAPPED*);
BOOL WINAPI PacketCompletion(HANDLE, OVERLAPPED*, DWORD*, BOOL);
BOOL WINAPI PacketCloseHandle(HANDLE);
void* PacketMalloc(size_t);
void PacketFree(void*);
void* PacketMemmove(void*, const void*, size_t);
#ifndef SDK_PACKETS_SHIM_IMPL
#undef CreateFile
#define CreateFile PacketCreateFile
#define DeviceIoControl PacketIoctl
#define GetOverlappedResult PacketCompletion
#define CloseHandle PacketCloseHandle
#ifdef SDK_PACKETS_SOURCE
#define malloc PacketMalloc
#define free PacketFree
#define memmove PacketMemmove
#endif
#endif
#endif
