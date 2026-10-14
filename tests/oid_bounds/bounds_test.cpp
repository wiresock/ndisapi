#include "bounds_shim.h"
#include "ndisapi.h"
#include <stdio.h>
#include <initializer_list>
static unsigned checks=0,failures=0;
static void Check(bool ok,const char* name,const char* property) {
    ++checks; if(!ok)++failures;
    printf("[%s] %s: %s\n",ok?"PASS":"FAIL",name,property);
}
static BOOL Invoke(CNdisApi& api,PPACKET_OID_DATA oid,BOOL set,bool exported,DWORD& error) {
    BOOL result=FALSE;
    // Every call uses a caller array with at least 16 payload bytes. Register only the
    // offered capacity (or that physical bound for intentionally impossible lengths).
    const DWORD capacity=oid->Length<16?oid->Length:16;
    BoundsWatchCaller(oid,offsetof(PACKET_OID_DATA,Data)+capacity);
    __try { result=exported?::NdisrdRequest(&api,oid,set):api.NdisrdRequest(oid,set); error=GetLastError(); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++g_bounds.faults; error=GetExceptionCode(); }
    return result;
}
static void CheckCopyGuard() {
    for(size_t bytes:{static_cast<size_t>(9),static_cast<size_t>(MAXDWORD)}) for(unsigned source=0;source<2;++source) {
        unsigned char caller[16]; memset(caller,0xA7,sizeof(caller));
        BoundsReset(); BoundsWatchCaller(caller,source?16:8);
        auto* staging=static_cast<unsigned char*>(BoundsMalloc(source?8:16));
        char name[100]; sprintf_s(name,"copy guard %s bytes=%zu",source?"source":"destination",bytes);
        BoundsMemmove(caller,staging,bytes);
        Check(g_bounds.faults==1 && g_bounds.copies==1,name,"rejects before unsafe memory access");
        bool unchanged=true; for(unsigned char value:caller) if(value!=0xA7) unchanged=false;
        Check(unchanged,name,"destination remains unchanged");
    }
    unsigned char caller[8]; memset(caller,0xA7,sizeof(caller));
    BoundsReset(); BoundsWatchCaller(caller,sizeof(caller));
    auto* staging=static_cast<unsigned char*>(BoundsMalloc(sizeof(caller)));
    BoundsMemmove(caller,staging,sizeof(caller));
    Check(!g_bounds.faults && g_bounds.copies==1,"copy guard exact","allows a fully bounded copy");
    bool copied=true; for(unsigned char value:caller) if(value) copied=false;
    Check(copied,"copy guard exact","valid copy writes the expected bytes");
    BoundsReset();
}
int main() {
    CNdisApi api;
    TCP_AdapterList list={};
    if(!api.IsDriverLoaded() || !api.GetTcpipBoundAdaptersInfo(&list) || list.m_nAdapterCount!=1) return 2;
    const HANDLE adapter=list.m_nAdapterHandle[0];
    // Preserve the actual constructor event; Reset owns only per-request events.
    extern void BoundsForgetSetupEvents();
    BoundsForgetSetupEvents();
    CheckCopyGuard();
    const DWORD prefix=BoundsWow64()?offsetof(PACKET_OID_DATA_WOW64,Data):offsetof(PACKET_OID_DATA,Data);
    const DWORD maxLength=INT_MAX-prefix;
    printf("branch=%s header=%lu maxLength=%lu\n",BoundsWow64()?"WOW64":"native",prefix,maxLength);
    const DWORD bad[]={0,maxLength+1,static_cast<DWORD>(INT_MAX),MAXDWORD-prefix,MAXDWORD-prefix+1,MAXDWORD-1,MAXDWORD};
    for(unsigned exported=0;exported<2;++exported) for(unsigned set=0;set<2;++set) {
        for(DWORD n:bad) {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16]; memset(bytes,0xA7,sizeof(bytes));
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes);
            oid->hAdapterHandle=adapter; oid->Oid=0xFEDC0123; oid->Length=n;
            unsigned char before[sizeof(bytes)]; memcpy(before,bytes,sizeof(bytes));
            BoundsReset(); SetLastError(ERROR_SUCCESS);
            DWORD error=0; char name[100]; sprintf_s(name,"%s %s length=%lu",exported?"C":"C++",set?"SET":"GET",n);
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            Check(!got,name,"rejects invalid extent");
            Check(!g_bounds.faults,name,"no guarded access fault or oversized copy");
            Check(!g_bounds.events,name,"rejects before event creation");
            Check(!g_bounds.allocations,name,"rejects before allocation");
            Check(!g_bounds.copies,name,"rejects before payload copy");
            Check(!g_bounds.ioctls,name,"rejects before IOCTL");
            Check(!memcmp(before,bytes,sizeof(bytes)),name,"caller bytes unchanged");
            Check(error==(n?ERROR_ARITHMETIC_OVERFLOW:ERROR_INVALID_PARAMETER),name,"reports extent error");
        }
        {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16]={};
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes); oid->hAdapterHandle=adapter;oid->Oid=0xFEDC0123;oid->Length=maxLength;
            BoundsReset();g_bounds.boundary=true;DWORD error=0;char name[100];
            sprintf_s(name,"%s %s exact INT_MAX envelope",exported?"C":"C++",set?"SET":"GET");
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            Check(!got,name,"controlled downstream refusal");
            Check(!g_bounds.faults && !g_bounds.copies,name,"no payload access for controlled refusal");
            Check(g_bounds.events==1,name,"valid extent reaches event creation");
            Check(BoundsWow64()?(g_bounds.allocations==1 && g_bounds.requestedBytes==INT_MAX && !g_bounds.ioctls):
                (!g_bounds.allocations && g_bounds.ioctls==1 && g_bounds.inputBytes==INT_MAX && g_bounds.outputBytes==INT_MAX),
                name,"exact checked envelope reaches allocation or native IOCTL");
        }
        for(DWORD n:{1UL,4UL,8UL}) for(unsigned pending=0;pending<2;++pending) {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16];memset(bytes,0xA7,sizeof(bytes));
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes);oid->hAdapterHandle=adapter;oid->Oid=0xFEDC0123;oid->Length=n;
            BoundsReset();g_bounds.pending=pending!=0;DWORD error=0;char name[100];
            sprintf_s(name,"%s %s valid=%lu pending=%u",exported?"C":"C++",set?"SET":"GET",n,pending);
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            const DWORD shortLength=n<4?n:4;
            Check(got!=FALSE,name,"valid generic OID terminal success");
            Check(!g_bounds.faults,name,"no guarded access fault");
            Check(g_bounds.ioctls==1 && g_bounds.inputBytes==prefix+n && g_bounds.outputBytes==prefix+n,name,"exact selected-layout extent");
            Check(g_bounds.completions==pending,name,"pending completion consumed once");
            Check(oid->Length==((BoundsWow64()&&set)?n:shortLength),name,"short reply accounting preserved");
            Check(set || oid->Data[0]==0x5A,name,"GET payload copied back");
            Check(bytes[offsetof(PACKET_OID_DATA,Data)+n]==0xA7,name,"caller tail remains unchanged");
        }
        for(DWORD capacity:{1UL,8UL}) for(DWORD reply:{capacity+1,static_cast<DWORD>(MAXDWORD)}) for(unsigned pending=0;pending<2;++pending) {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16]; memset(bytes,0xA7,sizeof(bytes));
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes);
            oid->hAdapterHandle=adapter; oid->Oid=0xFEDC0123; oid->Length=capacity;
            unsigned char before[sizeof(bytes)]; memcpy(before,bytes,sizeof(bytes));
            BoundsReset(); g_bounds.pending=pending!=0; g_bounds.replyLengthSet=true;
            g_bounds.replyLength=reply; g_bounds.clobberCleanup=true;
            DWORD error=0; char name[120];
            sprintf_s(name,"%s %s malformed success capacity=%lu reply=%lu pending=%u",exported?"C":"C++",set?"SET":"GET",capacity,reply,pending);
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            Check(!got,name,"rejects malformed successful length");
            Check(error==ERROR_INVALID_DATA,name,"validation error survives cleanup");
            Check(g_bounds.ioctls==1 && g_bounds.inputBytes==prefix+capacity && g_bounds.outputBytes==prefix+capacity,name,"uses captured request extent");
            Check(g_bounds.completions==pending,name,"pending completion consumed once");
            Check(!g_bounds.faults,name,"rejects before any unsafe copy or access");
            Check(!BoundsWow64() || !memcmp(before,bytes,sizeof(bytes)),name,"WOW64 caller bytes and Length unchanged");
            Check(g_bounds.copies==((BoundsWow64() && set)?1U:0U),name,"no reply payload copy");
            Check(g_bounds.closes==1 && g_bounds.frees==(BoundsWow64()?1U:0U),name,"request resources released once");
        }
        for(DWORD reply:{0UL,1UL,8UL}) for(unsigned pending=0;pending<2;++pending) {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16]; memset(bytes,0xA7,sizeof(bytes));
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes);
            oid->hAdapterHandle=adapter; oid->Oid=0xFEDC0123; oid->Length=8;
            BoundsReset(); g_bounds.pending=pending!=0; g_bounds.replyLengthSet=true; g_bounds.replyLength=reply;
            DWORD error=0; char name[120];
            sprintf_s(name,"%s %s valid reply=%lu pending=%u",exported?"C":"C++",set?"SET":"GET",reply,pending);
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            Check(got!=FALSE,name,"accepts zero short or exact successful reply");
            Check(!g_bounds.faults,name,"all copy ranges remain bounded");
            Check(g_bounds.completions==pending,name,"pending completion consumed once");
            Check(oid->Length==((BoundsWow64() && set)?8:reply),name,"preserves GET and SET length semantics");
            bool payload=true; for(DWORD i=0;i<8;++i) if(oid->Data[i]!=((!set && i<reply)?0x5A:0xA7)) payload=false;
            Check(payload,name,"only returned GET payload is published");
            Check(bytes[offsetof(PACKET_OID_DATA,Data)+8]==0xA7,name,"caller tail remains unchanged");
            Check(g_bounds.copies==(BoundsWow64()?1U:0U),name,"only the existing GET or SET copy occurs");
            Check(g_bounds.closes==1 && g_bounds.frees==(BoundsWow64()?1U:0U),name,"request resources released once");
        }
        for(DWORD reply:{9UL,static_cast<DWORD>(MAXDWORD)}) for(unsigned pending=0;pending<2;++pending) {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16]; memset(bytes,0xA7,sizeof(bytes));
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes);
            oid->hAdapterHandle=adapter; oid->Oid=0xFEDC0123; oid->Length=8;
            unsigned char before[sizeof(bytes)]; memcpy(before,bytes,sizeof(bytes));
            BoundsReset(); g_bounds.pending=pending!=0; g_bounds.failIo=true;
            g_bounds.replyLengthSet=true; g_bounds.replyLength=reply; g_bounds.clobberCleanup=true;
            DWORD error=0; char name[120];
            sprintf_s(name,"%s %s terminal failure reply=%lu pending=%u",exported?"C":"C++",set?"SET":"GET",reply,pending);
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            Check(!got,name,"terminal failure remains failure");
            Check(error==ERROR_GEN_FAILURE,name,"terminal error wins over metadata and cleanup errors");
            Check(g_bounds.completions==pending,name,"pending completion consumed once");
            Check(!g_bounds.faults,name,"no unsafe copy or access");
            Check(!BoundsWow64() || !memcmp(before,bytes,sizeof(bytes)),name,"WOW64 caller bytes and Length unchanged");
            Check(g_bounds.copies==((BoundsWow64() && set)?1U:0U),name,"failed completion is never copied back");
            Check(g_bounds.closes==1 && g_bounds.frees==(BoundsWow64()?1U:0U),name,"request resources released once");
        }
    }
    BoundsCleanup();
    printf("%u checks, %u failures\nRESULT=%u\n",checks,failures,failures?1:0);
    return failures?1:0;
}
