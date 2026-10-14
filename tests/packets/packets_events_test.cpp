#include "packets_shim.h"
#include "ndisapi.h"
static unsigned checks=0,failures=0;
static void Check(bool ok,const char* label){++checks;if(!ok){++failures;printf("[FAIL] %s\n",label);}}
static BOOL Invoke(const CNdisApi& api,DWORD* error=NULL){STATIC_FILTER filter={};filter.m_FilterAction=FILTER_PACKET_PASS;const BOOL result=api.AddStaticFilterFront(&filter);if(error)*error=GetLastError();return result;}
struct WORKER {const CNdisApi* api;BOOL result;DWORD error;};
static DWORD WINAPI Worker(void* value){WORKER* w=static_cast<WORKER*>(value);w->result=Invoke(*w->api,&w->error);return 0;}
static HANDLE Start(WORKER& worker){return CreateThread(NULL,0,Worker,&worker,0,NULL);}
static void Join(HANDLE thread){Check(thread!=NULL,"worker thread started");if(thread){Check(WaitForSingleObject(thread,15000)==WAIT_OBJECT_0,"worker reaches terminal completion");CloseHandle(thread);}}
static void PendingMode(const CNdisApi& api,bool success){
    const PACKET_EVENT_STATS before=PacketEventsStats();
    PacketEventsConfigure(true,success,ERROR_DEVICE_NOT_CONNECTED,true);
    WORKER worker={&api,FALSE,0};HANDLE thread=Start(worker);
    Check(PacketEventsWaitActive(1),"pending call remains outstanding until explicit completion");
    const PACKET_EVENT_STATS held=PacketEventsStats();
    Check(held.closes==before.closes,"pending event remains open");
    PacketEventsRelease();Join(thread);
    Check((worker.result!=FALSE)==success,"pending terminal status returned");
    if(!success)Check(worker.error==ERROR_DEVICE_NOT_CONNECTED,"pending terminal error survives event cleanup");
    Check(PacketEventsStats().completions==before.completions+1,"pending call waits exactly once");
}
int main(){
    setvbuf(stdout,NULL,_IONBF,0);PacketReset();
    PacketEventsBegin();
    // WOW64 construction enumerates through the same convenience helper.
    // Fail that first lazy creation so explicit failure tests start empty.
    if(PacketWow64())PacketEventsFailCreate();
    CNdisApi* apis[18]={};apis[0]=new CNdisApi;
#ifdef _WIN64
    Check(!PacketWow64(),"native x64 control");
#else
    Check(PacketWow64(),"genuine WOW64 control");
#endif
    PacketEventsConfigure(false,true,ERROR_SUCCESS,true);
    // Creation failure must free the claimed slot without losing its error.
    for(unsigned i=0;i<3;++i){PacketEventsFailCreate();DWORD error=0;Check(!Invoke(*apis[0],&error),"event creation failure returned");Check(error==ERROR_NOT_ENOUGH_MEMORY,"event creation error preserved");}
    Check(PacketEventsStats().ioctls==0,"event creation failure never submits I/O");
    Check(Invoke(*apis[0])!=FALSE,"slot reusable after event creation failures");
    const PACKET_EVENT_STATS warm=PacketEventsStats();
    bool sequential=true;for(unsigned i=0;i<1000;++i)if(!Invoke(*apis[0]))sequential=false;
    PACKET_EVENT_STATS after=PacketEventsStats();
    Check(sequential,"1000 sequential convenience calls succeed");
    Check(after.creates==warm.creates,"1000 sequential calls create no additional events");
    Check(after.closes==warm.closes,"1000 sequential calls close no cached events");
    Check(after.resets==warm.resets+1000,"every sequential reuse resets the cached event");
    Check(after.live==1,"one sequential event retained");
    PacketEventsFailReset();DWORD error=0;
    Check(!Invoke(*apis[0],&error),"cached event reset failure returned");
    Check(error==ERROR_INVALID_HANDLE,"reset error survives invalid-event close");
    PACKET_EVENT_STATS reset=PacketEventsStats();
    Check(reset.ioctls==after.ioctls,"reset failure never submits I/O");
    Check(reset.live==0&&reset.closes==after.closes+1,"failed reset invalidates and closes cached event");
    Check(Invoke(*apis[0])!=FALSE,"slot reusable after reset failure");
    Check(PacketEventsStats().live==1,"replacement event retained");
    PacketEventsConfigure(false,false,ERROR_ACCESS_DENIED,true);
    Check(!Invoke(*apis[0],&error),"immediate I/O failure returned");
    Check(error==ERROR_ACCESS_DENIED,"immediate I/O error survives release");
    PendingMode(*apis[0],true);PendingMode(*apis[0],false);
    printf("CONTROL sequential_and_errors checks=%u failures=%u\n",checks,failures);

    // Sixteen distinct instances hold all pool slots. Overflow calls must use
    // independent fresh events without waiting for or disturbing those leases.
    for(unsigned i=1;i<18;++i)apis[i]=new CNdisApi;
    PacketEventsConfigure(true,true,ERROR_SUCCESS,true);
    WORKER workers[17]={};HANDLE threads[17]={};
    for(unsigned i=0;i<16;++i){workers[i].api=apis[i];threads[i]=Start(workers[i]);}
    Check(PacketEventsWaitActive(16),"sixteen overlapping pending calls reach I/O");
    PACKET_EVENT_STATS full=PacketEventsStats();
    Check(full.live==16,"pool saturation retains exactly sixteen events");
    Check(full.activeRequests==16,"all pool leases remain outstanding");
    PacketEventsConfigure(false,true,ERROR_SUCCESS,true);
    PacketEventsFailCreate();
    Check(!Invoke(*apis[16],&error),"saturated fallback creation failure returned");
    Check(error==ERROR_NOT_ENOUGH_MEMORY,"saturated fallback creation error preserved");
    Check(PacketEventsStats().activeRequests==16,"fallback creation failure leaves all leases intact");
    const PACKET_EVENT_STATS failedFallback=PacketEventsStats();
    Check(Invoke(*apis[16])!=FALSE,"saturated immediate fallback succeeds");
    after=PacketEventsStats();
    Check(after.creates==failedFallback.creates+1&&after.closes==failedFallback.closes+1,"fresh fallback create/close balanced");
    Check(after.live==16,"immediate fallback does not grow idle pool");
    PacketEventsConfigure(false,false,ERROR_ACCESS_DENIED,true);
    Check(!Invoke(*apis[16],&error),"saturated immediate fallback failure returned");
    Check(error==ERROR_ACCESS_DENIED,"fallback close preserves immediate failure");
    PacketEventsConfigure(true,false,ERROR_DEVICE_NOT_CONNECTED,true);
    workers[16].api=apis[16];threads[16]=Start(workers[16]);
    Check(PacketEventsWaitActive(17),"pending fallback overlaps sixteen leased calls");
    const PACKET_EVENT_STATS held=PacketEventsStats();
    Check(held.live==17,"live handles are sixteen leases plus one pending fallback");
    Check(held.identityConflicts==0,"pending OVERLAPPED/event/request identities are distinct");
    Check(held.earlyResetOrClose==0,"no pending event reset or close before terminal result");
    PacketEventsRelease();
    for(unsigned i=0;i<17;++i){Join(threads[i]);Check((workers[i].result!=FALSE)==(i<16),"overlapping call returns its own terminal status");}
    Check(workers[16].error==ERROR_DEVICE_NOT_CONNECTED,"pending fallback close preserves terminal error");
    after=PacketEventsStats();
    Check(after.activeRequests==0,"all pending requests completed");
    Check(after.live==16,"pending fallback closes while cached leases remain");
    Check(after.creates==full.creates+3&&after.closes==full.closes+3,"all three overflow event handles close exactly once");
    Check(after.peakLive==17,"peak live event count bounded by active overflow");
    Check(after.changedInput==0&&after.identityConflicts==0,"pending request storage remains unchanged and private");
    Check(after.earlyResetOrClose==0&&after.waitFailures==0,"no early reuse or terminal wait failure");
    printf("CONTROL saturation_and_parallel checks=%u failures=%u\n",checks,failures);

    PacketEventsConfigure(false,true,ERROR_SUCCESS,true);
    const PACKET_EVENT_STATS manyBefore=PacketEventsStats();bool many=true;
    for(unsigned i=0;i<128;++i){CNdisApi another;if(!Invoke(another))many=false;}
    after=PacketEventsStats();
    Check(many,"128 later SDK instances can reuse the module pool");
    Check(after.creates==manyBefore.creates&&after.closes==manyBefore.closes,"instance count does not grow cache or close retained events");
    Check(after.live==16,"retained handle bound independent of instance count");
    Check(after.signaledOnSubmit==0,"reused events are nonsignaled before every I/O");
    for(unsigned i=0;i<18;++i)delete apis[i];
    Check(PacketEventsStats().live==16,"instance destruction leaves cache for module teardown");
    printf("CONTROL bounds_and_teardown checks=%u failures=%u\n",checks,failures);
    PacketEventsFinish(checks,failures);
    return failures?1:0;
}