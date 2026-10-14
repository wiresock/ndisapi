#define SDK_PACKETS_SHIM_IMPL
#include "packets_shim.h"

namespace {
struct EVENT_ENTRY { HANDLE handle; bool active; } events[64] = {};
struct REQUEST_ENTRY {
    OVERLAPPED* overlap; HANDLE event; void* input; DWORD length;
    unsigned char before[1024]; bool active, success; DWORD error;
} requests[32] = {};
CRITICAL_SECTION eventLock;
HANDLE releaseRequests;
PACKET_EVENT_STATS stats = {};
bool enabled=false, pendingMode=false, successMode=true, clobberError=false;
bool failCreate=false, failReset=false, finishArmed=false;
DWORD resultError=ERROR_DEVICE_NOT_CONNECTED;
unsigned finalChecks=0, finalFailures=0;
struct Lock { Lock(){EnterCriticalSection(&eventLock);} ~Lock(){LeaveCriticalSection(&eventLock);} };
void Finish() {
    ++finalChecks;
    if(stats.live!=0 || stats.closes!=stats.creates || stats.closeFailures) {
        ++finalFailures;printf("[FAIL] static teardown: every tracked event closes exactly once\n");
    }
    printf("EVENTS creates=%lu create_failures=%lu resets=%lu reset_failures=%lu closes=%lu live=%lu peak_live=%lu ioctls=%lu completions=%lu peak_pending=%lu conflicts=%lu early_cleanup=%lu changed_input=%lu signaled_submission=%lu wait_failures=%lu close_failures=%lu\n",
        stats.creates,stats.createFailures,stats.resets,stats.resetFailures,stats.closes,stats.live,stats.peakLive,stats.ioctls,stats.completions,stats.peakRequests,stats.identityConflicts,stats.earlyResetOrClose,stats.changedInput,stats.signaledOnSubmit,stats.waitFailures,stats.closeFailures);
    printf("%u checks, %u failures, 0 guarded faults, %u scoped checks\nRESULT=%u\n",finalChecks,finalFailures,finalChecks,finalFailures?1U:0U);
    finishArmed=false;
}
}
bool PacketEventsEnabled() {return enabled;}
void PacketEventsBegin() {
    InitializeCriticalSection(&eventLock);
    releaseRequests=::CreateEvent(NULL,TRUE,FALSE,NULL);
    enabled=true;
}
void PacketEventsConfigure(bool pending,bool success,DWORD error,bool clobber) {
    Lock lock;pendingMode=pending;successMode=success;resultError=error;clobberError=clobber;
    if(!stats.activeRequests)::ResetEvent(releaseRequests);
}
void PacketEventsFailCreate(){Lock lock;failCreate=true;}
void PacketEventsFailReset(){Lock lock;failReset=true;}
PACKET_EVENT_STATS PacketEventsStats(){Lock lock;return stats;}
bool PacketEventsWaitActive(DWORD count) {
    for(unsigned i=0;i<5000;++i){if(PacketEventsStats().activeRequests==count)return true;Sleep(1);}return false;
}
void PacketEventsRelease(){::SetEvent(releaseRequests);}
void PacketEventsFinish(unsigned checks,unsigned failures) {
    Lock lock;finalChecks=checks;finalFailures=failures;
    ++finalChecks;
    if(stats.live!=16){++finalFailures;printf("[FAIL] static teardown: exactly sixteen retained events before teardown\n");}
    ::CloseHandle(releaseRequests);releaseRequests=NULL;
    finishArmed=true;
    // Baseline fresh-per-call code has nothing retained. A pool must reach
    // Finish through its real static destructor; a leaked handle gives no footer.
    if(!stats.live)Finish();
}
HANDLE WINAPI PacketCreateEvent(LPSECURITY_ATTRIBUTES sa,BOOL manual,BOOL initial,LPCTSTR name) {
    if(!enabled || manual)return ::CreateEvent(sa,manual,initial,name);
    Lock lock;
    if(failCreate){failCreate=false;++stats.createFailures;SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}
    HANDLE event=::CreateEvent(sa,manual,initial,name);
    if(!event)return NULL;
    for(unsigned i=0;i<64;++i)if(!events[i].active){events[i].handle=event;events[i].active=true;++stats.creates;++stats.live;stats.peakLive=(std::max)(stats.live,stats.peakLive);return event;}
    ::CloseHandle(event);SetLastError(ERROR_TOO_MANY_OPEN_FILES);return NULL;
}
BOOL WINAPI PacketResetEvent(HANDLE event) {
    if(!enabled)return ::ResetEvent(event);
    Lock lock;
    bool tracked=false;for(unsigned i=0;i<64;++i)if(events[i].active&&events[i].handle==event)tracked=true;
    if(!tracked)return ::ResetEvent(event);
    ++stats.resets;
    for(unsigned i=0;i<32;++i)if(requests[i].active&&requests[i].event==event)++stats.earlyResetOrClose;
    if(failReset){failReset=false;++stats.resetFailures;SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
    return ::ResetEvent(event);
}
void PacketEventsObserveClose(HANDLE event,BOOL result) {
    if(!enabled)return;
    Lock lock;
    for(unsigned i=0;i<32;++i)if(requests[i].active&&requests[i].event==event)++stats.earlyResetOrClose;
    for(unsigned i=0;i<64;++i)if(events[i].active&&events[i].handle==event){events[i].active=false;++stats.closes;--stats.live;if(!result)++stats.closeFailures;break;}
    if(clobberError)SetLastError(ERROR_INVALID_DATA);
    if(finishArmed&&!stats.live)Finish();
}
BOOL PacketEventsIoctl(void* input,DWORD length,DWORD* bytes,OVERLAPPED* overlap) {
    Lock lock;++stats.ioctls;
    if(bytes)*bytes=pendingMode?0x71717171UL:0;
    if(!overlap||!overlap->hEvent||length>1024){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    if(::WaitForSingleObject(overlap->hEvent,0)!=WAIT_TIMEOUT)++stats.signaledOnSubmit;
    for(unsigned i=0;i<32;++i)if(requests[i].active &&
        (requests[i].overlap==overlap||requests[i].event==overlap->hEvent||requests[i].input==input))++stats.identityConflicts;
    if(pendingMode){
        for(unsigned i=0;i<32;++i)if(!requests[i].active){
            REQUEST_ENTRY& r=requests[i];r.overlap=overlap;r.event=overlap->hEvent;r.input=input;r.length=length;
            if(input&&length)memcpy(r.before,input,length);
            r.success=successMode;r.error=resultError;r.active=true;++stats.activeRequests;
            stats.peakRequests=(std::max)(stats.peakRequests,stats.activeRequests);
            SetLastError(ERROR_IO_PENDING);return FALSE;
        }
        SetLastError(ERROR_TOO_MANY_CMDS);return FALSE;
    }
    ::SetEvent(overlap->hEvent);
    if(!successMode){SetLastError(resultError);return FALSE;}return TRUE;
}
BOOL PacketEventsCompletion(OVERLAPPED* overlap,DWORD* bytes,BOOL wait) {
    REQUEST_ENTRY* request=NULL;
    {Lock lock;++stats.completions;for(unsigned i=0;i<32;++i)if(requests[i].active&&requests[i].overlap==overlap)request=&requests[i];}
    if(!request){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    const DWORD waited=wait?::WaitForSingleObject(releaseRequests,10000):WAIT_FAILED;
    Lock lock;
    if(waited!=WAIT_OBJECT_0)++stats.waitFailures;
    if(request->input&&request->length&&memcmp(request->before,request->input,request->length))++stats.changedInput;
    if(request->event!=overlap->hEvent)++stats.identityConflicts;
    request->active=false;--stats.activeRequests;
    if(bytes)*bytes=0;
    ::SetEvent(overlap->hEvent);
    if(waited!=WAIT_OBJECT_0){SetLastError(ERROR_TIMEOUT);return FALSE;}
    if(!request->success){SetLastError(request->error);return FALSE;}return TRUE;
}