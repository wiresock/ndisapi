#define BOUNDS_SHIM_IMPL
#include "bounds_shim.h"
BOUNDS_STATE g_bounds = {};
namespace {
struct Allocation { void* p; void* base; size_t bytes; } blocks[16] = {};
HANDLE events[16] = {};
void* caller = NULL;
size_t callerBytes = 0;
bool strictCopies = false;
void* pendingReply = NULL;
DWORD pendingCapacity = 0, pendingCode = 0;
bool Contains(const void* base,size_t size,const void* p,size_t bytes) {
    const ULONG_PTR begin=reinterpret_cast<ULONG_PTR>(base), address=reinterpret_cast<ULONG_PTR>(p);
    return base && address>=begin && address-begin<=size && bytes<=size-(address-begin);
}
bool KnownRange(const void* p,size_t bytes) {
    if(Contains(caller,callerBytes,p,bytes)) return true;
    for(const auto& a:blocks) if(Contains(a.p,a.bytes,p,bytes)) return true;
    return false;
}
void WriteReply(void* out,DWORD capacity,DWORD code) {
    const DWORD prefix=BoundsWow64()?offsetof(PACKET_OID_DATA_WOW64,Data):offsetof(PACKET_OID_DATA,Data);
    const DWORD length=g_bounds.replyLengthSet?g_bounds.replyLength:((capacity<4)?capacity:4);
    // Malformed metadata must never make the fake driver itself perform an unsafe access.
    if(!KnownRange(out,static_cast<size_t>(prefix)+capacity)) { ++g_bounds.faults; return; }
    *reinterpret_cast<DWORD*>(static_cast<unsigned char*>(out)+prefix-sizeof(DWORD))=length;
    const DWORD written=(length<capacity)?length:capacity;
    if(code==IOCTL_NDISRD_NDIS_GET_REQUEST) memset(static_cast<unsigned char*>(out)+prefix,0x5A,written);
}
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
void BoundsReset() {
    BoundsCleanup(); g_bounds={}; caller=NULL; callerBytes=0; strictCopies=true;
    pendingReply=NULL; pendingCapacity=0; pendingCode=0;
}
void BoundsWatchCaller(void* p,size_t bytes) { caller=p; callerBytes=bytes; }
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
    ++g_bounds.closes;
    for(auto& e:events) if(e==h) e=NULL;
    const BOOL result=::CloseHandle(h);
    if(g_bounds.clobberCleanup) SetLastError(ERROR_INVALID_HANDLE);
    return result;
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
    for(auto& a:blocks) if(!a.p) { a={p,base,physical}; return p; }
    abort();
}
void BoundsFree(void* p) {
    for(auto& a:blocks) if(a.p==p && p) {
        ++g_bounds.frees; VirtualFree(a.base,0,MEM_RELEASE); a={};
        if(g_bounds.clobberCleanup) SetLastError(ERROR_ACCESS_DENIED);
        return;
    }
}
void* BoundsMemmove(void* out,const void* in,size_t bytes) {
    ++g_bounds.copies;
    // Once OID tests start, both ranges must be known and fully bounded before any access.
    // Unknown ranges fail closed, including copies smaller than a fixed-size threshold.
    if(strictCopies && (!KnownRange(out,bytes) || !KnownRange(in,bytes))) {
        ++g_bounds.faults; return out;
    }
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
    if(inBytes<=prefix || inBytes!=outBytes || !KnownRange(out,outBytes)) {
        ++g_bounds.faults; SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    const DWORD capacity=outBytes-prefix;
    if(g_bounds.pending) {
        pendingReply=out; pendingCapacity=capacity; pendingCode=code;
        SetLastError(ERROR_IO_PENDING); return FALSE;
    }
    WriteReply(out,capacity,code);
    if(returned)*returned=outBytes;
    if(g_bounds.failIo) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}
BOOL WINAPI BoundsCompletion(HANDLE,OVERLAPPED*,DWORD* bytes,BOOL) {
    ++g_bounds.completions;
    if(!pendingReply) { ++g_bounds.faults; SetLastError(ERROR_INVALID_DATA); return FALSE; }
    WriteReply(pendingReply,pendingCapacity,pendingCode); pendingReply=NULL;
    if(bytes)*bytes=0;
    if(g_bounds.failIo) { SetLastError(ERROR_GEN_FAILURE); return FALSE; }
    return TRUE;
}

void BoundsForgetSetupEvents() { for(auto& e:events) e=NULL; }
