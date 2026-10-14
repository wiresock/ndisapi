#define SDK_HANDLES_SHIM_IMPL
#include "handles_shim.h"
TEST_SHIM_STATE g_Test = {};
ULONGLONG g_Adapters[ADAPTER_LIST_SIZE] = { 0x1234567887650000ULL, 0x2345678998760000ULL };
unsigned g_AdapterCount = 2;
struct ALLOCATION { void* p; size_t bytes; };
static ALLOCATION allocations[128] = {};

bool TestWow64() {
#ifdef _WIN64
    return false;
#else
    BOOL wow = FALSE;
    return IsWow64Process(GetCurrentProcess(), &wow) && wow != FALSE;
#endif
}
void TestAbandonPending() { g_Test.pending = FALSE; g_Test.overlap = NULL; }
void TestReset() {
    TestAbandonPending();
    // Release only allocations stranded by a baseline SEH probe; no production
    // code executes outside each guarded invocation in this deterministic fixture.
    for (unsigned i = 0; i != 128; ++i) {
        if (allocations[i].p) ::free(allocations[i].p);
        allocations[i].p = NULL; allocations[i].bytes = 0;
    }
    memset(&g_Test, 0, sizeof(g_Test));
    g_Test.mode = TestImmediate;
    g_Test.immediateError = ERROR_NOT_SUPPORTED;
    g_Test.terminalSuccess = TRUE;
    g_Test.terminalError = ERROR_ACCESS_DENIED;
    g_Test.captureInputLimit = sizeof(g_Test.input);
    SetLastError(ERROR_SUCCESS);
}
HANDLE WINAPI TestCreateFile(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) {
    WCHAR dir[MAX_PATH], path[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, dir) || !GetTempFileNameW(dir, L"nha", 0, path)) return INVALID_HANDLE_VALUE;
    return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
}
static BOOL Enumerate(void* out, DWORD outLen, DWORD* bytes) {
    ++g_Test.enumerationCalls;
    if (TestWow64()) {
        if (outLen != sizeof(TCP_AdapterList_WOW64)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        TCP_AdapterList_WOW64* a = static_cast<TCP_AdapterList_WOW64*>(out);
        memset(a, 0, sizeof(*a)); a->m_nAdapterCount = g_AdapterCount;
        for (unsigned i = 0; i < g_AdapterCount && i < ADAPTER_LIST_SIZE; ++i) {
            a->m_nAdapterHandle[i].QuadPart = g_Adapters[i];
            a->m_usMTU[i] = 1500;
        }
    } else {
        if (outLen != sizeof(TCP_AdapterList)) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
        TCP_AdapterList* a = static_cast<TCP_AdapterList*>(out);
        memset(a, 0, sizeof(*a)); a->m_nAdapterCount = g_AdapterCount;
        for (unsigned i = 0; i < g_AdapterCount && i < ADAPTER_LIST_SIZE; ++i) {
            a->m_nAdapterHandle[i] = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(g_Adapters[i]));
            a->m_usMTU[i] = 1500;
        }
    }
    if (bytes) *bytes = outLen;
    return TRUE;
}
static void WriteValidServiceResponse() {
    if (!g_Test.validServiceResponse || !g_Test.outputPointer) return;
    if (g_Test.code == IOCTL_NDISRD_READ_PACKET) {
        if (TestWow64()) {
            ETH_REQUEST_WOW64* r = static_cast<ETH_REQUEST_WOW64*>(g_Test.outputPointer);
            INTERMEDIATE_BUFFER_WOW64* b = reinterpret_cast<INTERMEDIATE_BUFFER_WOW64*>(static_cast<ULONG_PTR>(r->EthPacket.Buffer.QuadPart));
            memset(b, 0, sizeof(*b)); b->m_Length = 64;
        } else {
            ETH_REQUEST* r = static_cast<ETH_REQUEST*>(g_Test.outputPointer);
            memset(r->EthPacket.Buffer, 0, sizeof(*r->EthPacket.Buffer)); r->EthPacket.Buffer->m_Length = 64;
        }
    } else if (g_Test.code == IOCTL_NDISRD_READ_PACKETS) {
        if (TestWow64()) {
            ETH_M_REQUEST_WOW64* r = static_cast<ETH_M_REQUEST_WOW64*>(g_Test.outputPointer);
            INTERMEDIATE_BUFFER_WOW64* b = reinterpret_cast<INTERMEDIATE_BUFFER_WOW64*>(static_cast<ULONG_PTR>(r->EthPacket[0].Buffer.QuadPart));
            memset(b, 0, sizeof(*b)); b->m_Length = 64; r->dwPacketsSuccess = 1;
        } else {
            ETH_M_REQUEST* r = static_cast<ETH_M_REQUEST*>(g_Test.outputPointer);
            memset(r->EthPacket[0].Buffer, 0, sizeof(*r->EthPacket[0].Buffer));
            r->EthPacket[0].Buffer->m_Length = 64; r->dwPacketsSuccess = 1;
        }
    } else if (g_Test.code == IOCTL_NDISRD_GET_ADAPTER_MODE) {
        if (TestWow64()) static_cast<ADAPTER_MODE_WOW64*>(g_Test.outputPointer)->dwFlags = 0;
        else static_cast<ADAPTER_MODE*>(g_Test.outputPointer)->dwFlags = 0;
    } else if (g_Test.code == IOCTL_NDISRD_NDIS_GET_REQUEST || g_Test.code == IOCTL_NDISRD_NDIS_SET_REQUEST) {
        if (TestWow64()) {
            PACKET_OID_DATA_WOW64* r = static_cast<PACKET_OID_DATA_WOW64*>(g_Test.outputPointer);
            r->Length = 4; memset(r->Data, 0x53, 4);
        } else {
            PACKET_OID_DATA* r = static_cast<PACKET_OID_DATA*>(g_Test.outputPointer);
            r->Length = 4; memset(r->Data, 0x53, 4);
        }
    } else if (g_Test.code == IOCTL_NDISRD_ADAPTER_QUEUE_SIZE || g_Test.code == IOCTL_NDISRD_GET_RAS_LINKS) {
        memset(g_Test.outputPointer, 0, g_Test.outLength);
    }
}
static void WriteResponse() {
    WriteValidServiceResponse();
    if (g_Test.writeResponse && g_Test.outputPointer) {
        DWORD n = (std::min)(g_Test.outLength, g_Test.responseLength);
        memcpy(g_Test.outputPointer, g_Test.response, n);
        if (g_Test.code == IOCTL_NDISRD_GET_PACKET_FILTERS_RESET_STATS)
            ++g_Test.resetStatsSideEffects;
    }
}
BOOL WINAPI TestIoctl(HANDLE, DWORD code, void* in, DWORD inLen, void* out, DWORD outLen,
                      DWORD* bytes, OVERLAPPED* ov) {
    if (code == IOCTL_NDISRD_GET_TCPIP_INTERFACES) return Enumerate(out, outLen, bytes);
    ++g_Test.ioctlCalls;
    g_Test.code = code; g_Test.inLength = inLen; g_Test.outLength = outLen;
    g_Test.inputPointer = in; g_Test.outputPointer = out; g_Test.overlap = ov;
    g_Test.capturedInput = (std::min)(inLen, (std::min)(g_Test.captureInputLimit, static_cast<DWORD>(sizeof(g_Test.input))));
    if (in && g_Test.capturedInput) memcpy(g_Test.input, in, g_Test.capturedInput);
    if (bytes) *bytes = g_Test.validServiceResponse ? outLen : g_Test.immediateBytes;
    // This reproduces the coordinated drivers' established empty-SET refusal.
    if (code == IOCTL_NDISRD_SET_PACKET_FILTERS &&
        (inLen < sizeof(STATIC_FILTER_TABLE) || !in || !static_cast<PSTATIC_FILTER_TABLE>(in)->m_TableSize)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    if (g_Test.mode == TestPending) {
        g_Test.pending = TRUE; ++g_Test.pendingReturns;
        g_Test.pendingEvent = ov ? ov->hEvent : NULL;
        if (!g_Test.delayResponse) WriteResponse();
        SetLastError(ERROR_IO_PENDING); return FALSE;
    }
    WriteResponse();
    if (g_Test.mode == TestFailure) { SetLastError(g_Test.immediateError); return FALSE; }
    return TRUE;
}
BOOL WINAPI TestCompletion(HANDLE, OVERLAPPED* ov, DWORD* bytes, BOOL wait) {
    ++g_Test.completions;
    if (wait) ++g_Test.waits;
    if (g_Test.pending && ov != g_Test.overlap) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (g_Test.pending && g_Test.inputPointer && g_Test.capturedInput &&
        memcmp(g_Test.input, g_Test.inputPointer, g_Test.capturedInput) != 0)
        ++g_Test.completionInputChanged;
    if (g_Test.pending && g_Test.delayResponse) WriteResponse();
    g_Test.pending = FALSE;
    if (bytes) *bytes = g_Test.terminalBytes;
    if (!g_Test.terminalSuccess) { SetLastError(g_Test.terminalError); return FALSE; }
    return TRUE;
}
BOOL WINAPI TestCloseHandle(HANDLE h) {
    if (g_Test.pending && h == g_Test.pendingEvent) ++g_Test.closedWhilePending;
    const BOOL result = ::CloseHandle(h);
    if (g_Test.cleanupClobbersError) SetLastError(ERROR_INVALID_DATA);
    return result;
}
void* TestMalloc(size_t bytes) {
    ++g_Test.allocationCalls;
    if (g_Test.allocationCalls == g_Test.failAllocationAt || bytes > 16 * 1024 * 1024) return NULL;
    void* p = ::malloc(bytes);
    if (p) {
        for (unsigned i = 0; i != 128; ++i) if (!allocations[i].p) {
            allocations[i].p = p; allocations[i].bytes = bytes;
            ++g_Test.outstandingAllocations; break;
        }
    }
    return p;
}
void TestFree(void* p) {
    if (p) {
        for (unsigned i = 0; i != 128; ++i) if (allocations[i].p == p) {
            const ULONG_PTR begin = reinterpret_cast<ULONG_PTR>(p);
            const ULONG_PTR end = begin + allocations[i].bytes;
            const ULONG_PTR in = reinterpret_cast<ULONG_PTR>(g_Test.inputPointer);
            const ULONG_PTR out = reinterpret_cast<ULONG_PTR>(g_Test.outputPointer);
            if (g_Test.pending && ((in >= begin && in < end) || (out >= begin && out < end)))
                ++g_Test.freedWhilePending;
            allocations[i].p = NULL; allocations[i].bytes = 0;
            --g_Test.outstandingAllocations; break;
        }
        ++g_Test.freeCalls; ::free(p);
    }
    if (g_Test.cleanupClobbersError) SetLastError(ERROR_INVALID_DATA);
}