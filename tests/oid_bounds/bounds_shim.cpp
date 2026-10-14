#define BOUNDS_SHIM_IMPL
#include "bounds_shim.h"
BOUNDS_STATE g_bounds = {};
namespace {
struct Allocation { void* p; void* base; } blocks[16] = {};
HANDLE events[16] = {};
}
bool BoundsWow64() {
#ifdef _WIN64
    return false;
#else
    BOOL wow=FALSE; IsWow64Process(GetCurrentProcess(), &wow); return wow != FALSE;
#endif
}
void BoundsCleanup() {
    for (auto& a : blocks) if (a.base) { VirtualFree(a.base,0,MEM_RELEASE); a={}; }
    for (auto& e : events) if (e) { ::CloseHandle(e); e=NULL; }
}
void BoundsReset() { BoundsCleanup(); g_bounds={}; }
HANDLE WINAPI BoundsCreateFile(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) {
    // A real closable handle; all device I/O is substituted.
    return ::CreateEvent(NULL,TRUE,FALSE,NULL);
}
HANDLE WINAPI BoundsCreateEvent(LPSECURITY_ATTRIBUTES sa,BOOL manual,BOOL initial,LPCTSTR name) {
    ++g_bounds.events;
    HANDLE h=::CreateEvent(sa,manual,initial,name);
    for (auto& e: events) if(!e) { e=h; return h; }
    abort();
}
BOOL WINAPI BoundsCloseHandle(HANDLE h) {
    for(auto& e:events) if(e==h) e=NULL;
    return ::CloseHandle(h);
}
void* BoundsMalloc(size_t bytes) {
    ++g_bounds.allocations; g_bounds.requestedBytes=bytes;
    // Fail large allocations deterministically, without reserving gigabytes.
    if(bytes>1024*1024) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    const size_t physical=bytes?bytes:1;
    const size_t rounded=(physical+4095)&~static_cast<size_t>(4095);
    unsigned char* base=static_cast<unsigned char*>(VirtualAlloc(NULL,rounded+4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!base) abort();
    DWORD old;
    if(!VirtualProtect(base+rounded,4096,PAGE_NOACCESS,&old)) abort();
    void* p=base+rounded-physical;
    memset(p,0,physical);
    for(auto& a:blocks) if(!a.p) { a={p,base}; return p; }
    abort();
}
void BoundsFree(void* p) {
    for(auto& a:blocks) if(a.p==p && p) { VirtualFree(a.base,0,MEM_RELEASE); a={}; return; }
}
void* BoundsMemmove(void* out,const void* in,size_t bytes) {
    ++g_bounds.copies;
    // A baseline oversized copy is explicit failure evidence and is intercepted before access.
    if(bytes>64) { ++g_bounds.faults; return out; }
    return ::memmove(out,in,bytes);
}
BOOL WINAPI BoundsIoctl(HANDLE,DWORD code,void*,DWORD inBytes,void* out,DWORD outBytes,DWORD* returned,OVERLAPPED*) {
    if(code==IOCTL_NDISRD_GET_TCPIP_INTERFACES) {
        if(BoundsWow64()) {
            if(outBytes!=sizeof(TCP_AdapterList_WOW64)) abort();
            auto* p=static_cast<PTCP_AdapterList_WOW64>(out); memset(p,0,sizeof(*p));
            p->m_nAdapterCount=1; p->m_nAdapterHandle[0].QuadPart=0x1122334455667788ULL;
        } else {
            if(outBytes!=sizeof(TCP_AdapterList)) abort();
            auto* p=static_cast<PTCP_AdapterList>(out); memset(p,0,sizeof(*p));
            p->m_nAdapterCount=1; p->m_nAdapterHandle[0]=reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x1122334455667788ULL));
        }
        if(returned)*returned=outBytes; return TRUE;
    }
    ++g_bounds.ioctls; g_bounds.inputBytes=inBytes; g_bounds.outputBytes=outBytes;
    if(g_bounds.boundary) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    const DWORD prefix=BoundsWow64()?offsetof(PACKET_OID_DATA_WOW64,Data):offsetof(PACKET_OID_DATA,Data);
    if(inBytes<=prefix || inBytes!=outBytes) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    DWORD* length=reinterpret_cast<DWORD*>(static_cast<unsigned char*>(out)+prefix-sizeof(DWORD));
    const DWORD n=(*length<4)?*length:4;
    *length=n;
    if(code==IOCTL_NDISRD_NDIS_GET_REQUEST) memset(static_cast<unsigned char*>(out)+prefix,0x5A,n);
    if(returned)*returned=prefix+n;
    if(g_bounds.pending) { SetLastError(ERROR_IO_PENDING); return FALSE; }
    if(g_bounds.failIo) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}
BOOL WINAPI BoundsCompletion(HANDLE,OVERLAPPED*,DWORD* bytes,BOOL) {
    ++g_bounds.completions;
    if(bytes)*bytes=0;
    if(g_bounds.failIo) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

void BoundsForgetSetupEvents() { for(auto& e:events) e=NULL; }
