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
    __try { result=exported?::NdisrdRequest(&api,oid,set):api.NdisrdRequest(oid,set); error=GetLastError(); }
    __except(EXCEPTION_EXECUTE_HANDLER) { ++g_bounds.faults; error=GetExceptionCode(); }
    return result;
}
int main() {
    CNdisApi api;
    TCP_AdapterList list={};
    if(!api.IsDriverLoaded() || !api.GetTcpipBoundAdaptersInfo(&list) || list.m_nAdapterCount!=1) return 2;
    const HANDLE adapter=list.m_nAdapterHandle[0];
    // Preserve the actual constructor event; Reset owns only per-request events.
    extern void BoundsForgetSetupEvents();
    BoundsForgetSetupEvents();
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
        {
            unsigned char bytes[sizeof(PACKET_OID_DATA)+16]={};
            auto* oid=reinterpret_cast<PPACKET_OID_DATA>(bytes);oid->hAdapterHandle=adapter;oid->Oid=0xFEDC0123;oid->Length=8;
            BoundsReset();g_bounds.pending=true;g_bounds.failIo=true;DWORD error=0;char name[100];
            sprintf_s(name,"%s %s pending failure",exported?"C":"C++",set?"SET":"GET");
            BOOL got=Invoke(api,oid,set!=0,exported!=0,error);
            Check(!got && error==ERROR_GEN_FAILURE,name,"terminal error preserved");
            Check(g_bounds.completions==1 && !g_bounds.faults,name,"one safe terminal completion");
        }
    }
    BoundsCleanup();
    printf("%u checks, %u failures\nRESULT=%u\n",checks,failures,failures?1:0);
    return failures?1:0;
}
