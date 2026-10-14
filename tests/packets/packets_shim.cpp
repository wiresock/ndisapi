#ifndef SDK_PACKETS_SHIM_IMPL
#define SDK_PACKETS_SHIM_IMPL
#endif
#include "packets_shim.h"
PACKET_SHIM_STATE g_Packet = {};
struct ALLOCATION { void* p; void* base; size_t bytes; };
static ALLOCATION allocations[128] = {};
bool PacketWow64() {
#ifdef _WIN64
    return false;
#else
    BOOL wow = FALSE;
    return IsWow64Process(GetCurrentProcess(), &wow) && wow != FALSE;
#endif
}
void PacketAbandonPending() { g_Packet.pending = FALSE; g_Packet.overlap = NULL; }
void PacketReset() {
    PacketAbandonPending();
    for (unsigned i=0;i!=128;++i) {
        if (allocations[i].base) VirtualFree(allocations[i].base,0,MEM_RELEASE);
        allocations[i].p=NULL; allocations[i].base=NULL; allocations[i].bytes=0;
    }
    memset(&g_Packet,0,sizeof(g_Packet));
    g_Packet.mode=PacketImmediate; g_Packet.immediateError=ERROR_ACCESS_DENIED;
    g_Packet.terminalSuccess=TRUE; g_Packet.terminalError=ERROR_DEVICE_NOT_CONNECTED;
    g_Packet.lengths[0]=64; g_Packet.lengths[1]=65; g_Packet.resultCount=1;
    SetLastError(ERROR_SUCCESS);
}
HANDLE WINAPI PacketCreateFile(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) {
    WCHAR dir[MAX_PATH],path[MAX_PATH];
    if (!GetTempPathW(MAX_PATH,dir)||!GetTempFileNameW(dir,L"npb",0,path)) return INVALID_HANDLE_VALUE;
    return CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED|FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);
}
static BOOL Enumerate(void* out,DWORD outLen,DWORD* bytes) {
    ++g_Packet.enumerationCalls;
    const ULONGLONG raw=0x1234567887650000ULL;
    if (PacketWow64()) {
        if (!out||outLen!=sizeof(TCP_AdapterList_WOW64)) {SetLastError(ERROR_BAD_LENGTH);return FALSE;}
        TCP_AdapterList_WOW64* a=static_cast<TCP_AdapterList_WOW64*>(out);
        memset(a,0,sizeof(*a));a->m_nAdapterCount=1;a->m_nAdapterHandle[0].QuadPart=raw;a->m_usMTU[0]=1500;
    } else {
        if (!out||outLen!=sizeof(TCP_AdapterList)) {SetLastError(ERROR_BAD_LENGTH);return FALSE;}
        TCP_AdapterList* a=static_cast<TCP_AdapterList*>(out);
        memset(a,0,sizeof(*a));a->m_nAdapterCount=1;a->m_nAdapterHandle[0]=reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(raw));a->m_usMTU[0]=1500;
    }
    if(bytes)*bytes=outLen;return TRUE;
}
static bool Sorted(DWORD c) {return c==IOCTL_NDISRD_READ_PACKETS||c==IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER||c==IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP;}
static bool Unsorted(DWORD c) {return c==IOCTL_NDISRD_READ_PACKETS_UNSORTED||c==IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER_UNSORTED||c==IOCTL_NDISRD_SEND_PACKET_TO_MSTCP_UNSORTED;}
static void FillPacket(void* p,DWORD length,unsigned index,bool wow) {
    if (!p)return;
    const DWORD copied=(std::min)(length,static_cast<DWORD>(MAX_ETHER_FRAME));
    if(wow) {
        INTERMEDIATE_BUFFER_WOW64* b=static_cast<INTERMEDIATE_BUFFER_WOW64*>(p);
        memset(b,0,sizeof(*b));b->m_dwDeviceFlags=0x71+index;b->m_Flags=0x91+index;b->m_8021q=0x123+index;b->m_FilterID=0x321+index;
        b->m_Length=length;memset(b->m_Reserved,0x6B,sizeof(b->m_Reserved));memset(b->m_IBuffer,0x40+index,copied);
    } else {
        INTERMEDIATE_BUFFER* b=static_cast<INTERMEDIATE_BUFFER*>(p);
        memset(b,0,sizeof(*b));b->m_dwDeviceFlags=0x71+index;b->m_Flags=0x91+index;b->m_8021q=0x123+index;b->m_FilterID=0x321+index;
        b->m_Length=length;memset(b->m_Reserved,0x6B,sizeof(b->m_Reserved));memset(b->m_IBuffer,0x40+index,copied);
    }
    ++g_Packet.packetWrites;
}
static void ObservePacket(const void* p,unsigned index,bool wow) {
    const DWORD length=wow?static_cast<const INTERMEDIATE_BUFFER_WOW64*>(p)->m_Length:static_cast<const INTERMEDIATE_BUFFER*>(p)->m_Length;
    const UCHAR* data=wow?static_cast<const INTERMEDIATE_BUFFER_WOW64*>(p)->m_IBuffer:static_cast<const INTERMEDIATE_BUFFER*>(p)->m_IBuffer;
    g_Packet.submittedLengths[index]=length;
    for(DWORD i=0;i<(std::min)(length,static_cast<DWORD>(MAX_ETHER_FRAME));++i)g_Packet.submittedHashes[index]+=data[i];
}
static void ObserveSendPackets() {
    const DWORD code=g_Packet.code;const bool wow=PacketWow64();void* in=g_Packet.inputPointer;
    if(code==IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER||code==IOCTL_NDISRD_SEND_PACKET_TO_MSTCP) {
        if(wow)ObservePacket(reinterpret_cast<void*>(static_cast<ULONG_PTR>(static_cast<ETH_REQUEST_WOW64*>(in)->EthPacket.Buffer.QuadPart)),0,true);
        else ObservePacket(static_cast<ETH_REQUEST*>(in)->EthPacket.Buffer,0,false);
    } else if(code==IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER||code==IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP) {
        for(unsigned i=0;i<(std::min)(g_Packet.submittedCount,4UL);++i) {
            if(wow)ObservePacket(reinterpret_cast<void*>(static_cast<ULONG_PTR>(static_cast<ETH_M_REQUEST_WOW64*>(in)->EthPacket[i].Buffer.QuadPart)),i,true);
            else ObservePacket(static_cast<ETH_M_REQUEST*>(in)->EthPacket[i].Buffer,i,false);
        }
    }
}
static void WriteResponse() {
    void* out=g_Packet.outputPointer;
    if(!out)return;
    const bool wow=PacketWow64();
    if(g_Packet.code==IOCTL_NDISRD_READ_PACKET && g_Packet.writePackets) {
        if(wow) { ETH_REQUEST_WOW64* r=static_cast<ETH_REQUEST_WOW64*>(out);FillPacket(reinterpret_cast<void*>(static_cast<ULONG_PTR>(r->EthPacket.Buffer.QuadPart)),g_Packet.lengths[0],0,true); }
        else FillPacket(static_cast<ETH_REQUEST*>(out)->EthPacket.Buffer,g_Packet.lengths[0],0,false);
    } else if(g_Packet.code==IOCTL_NDISRD_READ_PACKETS) {
        const DWORD writeN=(std::min)((std::min)(g_Packet.resultCount,g_Packet.submittedCount),4UL);
        if(wow) {
            ETH_M_REQUEST_WOW64* r=static_cast<ETH_M_REQUEST_WOW64*>(out);
            if(g_Packet.writePackets)for(DWORD i=0;i<writeN;++i)FillPacket(reinterpret_cast<void*>(static_cast<ULONG_PTR>(r->EthPacket[i].Buffer.QuadPart)),g_Packet.lengths[i],i,true);
            if(g_Packet.writeCount)r->dwPacketsSuccess=g_Packet.resultCount;
        } else {
            ETH_M_REQUEST* r=static_cast<ETH_M_REQUEST*>(out);
            if(g_Packet.writePackets)for(DWORD i=0;i<writeN;++i)FillPacket(r->EthPacket[i].Buffer,g_Packet.lengths[i],i,false);
            if(g_Packet.writeCount)r->dwPacketsSuccess=g_Packet.resultCount;
        }
    } else if(Unsorted(g_Packet.code)) {
        UNSORTED_READ_SEND_REQUEST* r=static_cast<UNSORTED_READ_SEND_REQUEST*>(out);
        if(g_Packet.writePackets && g_Packet.code==IOCTL_NDISRD_READ_PACKETS_UNSORTED)
            for(DWORD i=0;i<(std::min)((std::min)(g_Packet.resultCount,g_Packet.submittedCount),4UL);++i)FillPacket(r->packets[i],g_Packet.lengths[i],i,false);
        if(g_Packet.writeCount)r->packets_num=g_Packet.resultCount;
    }
}
BOOL WINAPI PacketIoctl(HANDLE,DWORD code,void* in,DWORD inLen,void* out,DWORD outLen,DWORD* bytes,OVERLAPPED* ov) {
    if(code==IOCTL_NDISRD_GET_TCPIP_INTERFACES)return Enumerate(out,outLen,bytes);
    ++g_Packet.ioctlCalls;g_Packet.code=code;g_Packet.inLength=inLen;g_Packet.outLength=outLen;
    g_Packet.inputPointer=in;g_Packet.outputPointer=out;g_Packet.overlap=ov;
    if(inLen>1024*1024||outLen>1024*1024) {++g_Packet.oversizedInputs;SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    g_Packet.capturedInput=(std::min)(inLen,static_cast<DWORD>(sizeof(g_Packet.input)));
    if(in&&g_Packet.capturedInput)memcpy(g_Packet.input,in,g_Packet.capturedInput);
    if(bytes)*bytes=g_Packet.immediateBytes;
    if(Sorted(code)) {
        const DWORD prefix=PacketWow64()?static_cast<DWORD>(offsetof(ETH_M_REQUEST_WOW64,EthPacket)):static_cast<DWORD>(offsetof(ETH_M_REQUEST,EthPacket));
        const DWORD stride=PacketWow64()?sizeof(NDISRD_ETH_Packet_WOW64):sizeof(NDISRD_ETH_Packet);
        if(!in||inLen<prefix) {SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
        g_Packet.submittedCount=PacketWow64()?static_cast<ETH_M_REQUEST_WOW64*>(in)->dwPacketsNumber:static_cast<ETH_M_REQUEST*>(in)->dwPacketsNumber;
        if(!g_Packet.submittedCount||inLen<prefix+stride||g_Packet.submittedCount>(inLen-prefix)/stride) {SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    } else if(Unsorted(code))g_Packet.submittedCount=static_cast<UNSORTED_READ_SEND_REQUEST*>(in)->packets_num;
    ObserveSendPackets();
    if(g_Packet.mode==PacketPending) {
        g_Packet.pending=TRUE;++g_Packet.pendingReturns;g_Packet.pendingEvent=ov?ov->hEvent:NULL;
        if(!g_Packet.delayResponse)WriteResponse();SetLastError(ERROR_IO_PENDING);return FALSE;
    }
    WriteResponse();
    if(g_Packet.mode==PacketFailure) {SetLastError(g_Packet.immediateError);return FALSE;}
    return TRUE;
}
BOOL WINAPI PacketCompletion(HANDLE,OVERLAPPED* ov,DWORD* bytes,BOOL wait) {
    ++g_Packet.completions;if(wait)++g_Packet.waits;
    if(g_Packet.pending&&ov!=g_Packet.overlap) {SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    if(g_Packet.pending&&g_Packet.inputPointer&&g_Packet.capturedInput&&memcmp(g_Packet.input,g_Packet.inputPointer,g_Packet.capturedInput)!=0)++g_Packet.completionInputChanged;
    if(g_Packet.pending&&g_Packet.delayResponse)WriteResponse();
    g_Packet.pending=FALSE;if(bytes)*bytes=g_Packet.terminalBytes;
    if(!g_Packet.terminalSuccess) {SetLastError(g_Packet.terminalError);return FALSE;}return TRUE;
}
BOOL WINAPI PacketCloseHandle(HANDLE h) {
    if(g_Packet.pending&&h==g_Packet.pendingEvent)++g_Packet.closedWhilePending;
    const BOOL result=::CloseHandle(h);if(g_Packet.cleanupClobbersError)SetLastError(ERROR_INVALID_DATA);return result;
}
void* PacketMalloc(size_t bytes) {
    ++g_Packet.allocationCalls;
    if(g_Packet.allocationCalls==g_Packet.failAllocationAt||bytes>16*1024*1024)return NULL;
    const size_t physical=bytes?bytes:1;
    const size_t rounded=(physical+4095)&~static_cast<size_t>(4095);
    unsigned char* base=static_cast<unsigned char*>(VirtualAlloc(NULL,rounded+4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!base)return NULL;
    DWORD old;if(!VirtualProtect(base+rounded,4096,PAGE_NOACCESS,&old)) {VirtualFree(base,0,MEM_RELEASE);return NULL;}
    void* p=base+rounded-physical;
    for(unsigned i=0;i!=128;++i)if(!allocations[i].p) {allocations[i].p=p;allocations[i].base=base;allocations[i].bytes=bytes;++g_Packet.outstandingAllocations;return p;}
    VirtualFree(base,0,MEM_RELEASE);return NULL;
}
void PacketFree(void* p) {
    if(p)for(unsigned i=0;i!=128;++i)if(allocations[i].p==p) {
        if(g_Packet.pending)++g_Packet.freedWhilePending;
        VirtualFree(allocations[i].base,0,MEM_RELEASE);allocations[i].p=NULL;allocations[i].base=NULL;allocations[i].bytes=0;
        --g_Packet.outstandingAllocations;++g_Packet.freeCalls;break;
    }
    if(g_Packet.cleanupClobbersError)SetLastError(ERROR_INVALID_DATA);
}
void* PacketMemmove(void* out,const void* in,size_t bytes) {
    ++g_Packet.copyCalls;
    // Explicit modeled unsafe-copy evidence: do not corrupt a baseline stack frame.
    // Exact-ceiling and all ordinary copies execute the real CRT operation.
    if(bytes>MAX_ETHER_FRAME) {++g_Packet.oversizedCopies;return out;}
    g_Packet.copyBytes+=static_cast<DWORD>(bytes);return ::memmove(out,in,bytes);
}
