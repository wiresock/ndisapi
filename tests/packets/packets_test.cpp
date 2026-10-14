#include "packets_shim.h"
#include "ndisapi.h"
static unsigned checks=0,failures=0,guardedFaults=0;
static HANDLE mappedAdapter=NULL;
static void Check(bool ok,const std::string& label) {++checks;if(!ok) {++failures;printf("[FAIL] %s\n",label.c_str());}}
enum OP {SendOneMstcp,SendOneAdapter,ReadOne,SendManyMstcp,SendManyAdapter,ReadMany,ReadUnsorted,SendUnsortedAdapter,SendUnsortedMstcp};
static const char* Name(OP op) {static const char* names[]={"SEND_ONE_MSTCP","SEND_ONE_ADAPTER","READ_ONE","SEND_MANY_MSTCP","SEND_MANY_ADAPTER","READ_MANY","READ_UNSORTED","SEND_UNSORTED_ADAPTER","SEND_UNSORTED_MSTCP"};return names[op];}
static bool Many(OP op) {return op>=SendManyMstcp&&op<=ReadMany;}
static bool Unsorted(OP op) {return op>=ReadUnsorted;}
static bool Read(OP op) {return op==ReadOne||op==ReadMany||op==ReadUnsorted;}
static bool CountOutput(OP op) {return op==ReadMany||Unsorted(op);}
static DWORD Metadata(OP op,unsigned capacity) {
    if(Unsorted(op))return sizeof(UNSORTED_READ_SEND_REQUEST);
    if(op==ReadOne)return PacketWow64()?sizeof(ETH_REQUEST_WOW64):sizeof(ETH_REQUEST);
    if(op==ReadMany)return PacketWow64()?static_cast<DWORD>(offsetof(ETH_M_REQUEST_WOW64,EthPacket)+capacity*sizeof(NDISRD_ETH_Packet_WOW64)):
        static_cast<DWORD>(offsetof(ETH_M_REQUEST,EthPacket)+capacity*sizeof(NDISRD_ETH_Packet));
    return 0;
}
struct Fixture {
    std::vector<unsigned char> request;
    INTERMEDIATE_BUFFER packets[3];
    INTERMEDIATE_BUFFER before[3];
    PINTERMEDIATE_BUFFER pointers[3];
    ETH_REQUEST one;
    DWORD count;
    unsigned capacity;
    explicit Fixture(unsigned n=2):request(offsetof(ETH_M_REQUEST,EthPacket)+3*sizeof(NDISRD_ETH_Packet),0),count(0xCCCCCCCC),capacity(n) {
        memset(packets,0xA5,sizeof(packets));
        for(unsigned i=0;i!=3;++i) {packets[i].m_Length=64+i;pointers[i]=&packets[i];}
        memcpy(before,packets,sizeof(before));one.hAdapterHandle=mappedAdapter;one.EthPacket.Buffer=&packets[0];
        many()->hAdapterHandle=mappedAdapter;many()->dwPacketsNumber=n;many()->dwPacketsSuccess=0xCCCCCCCC;
        for(unsigned i=0;i!=3;++i)many()->EthPacket[i].Buffer=pointers[i];
    }
    PETH_M_REQUEST many() {return reinterpret_cast<PETH_M_REQUEST>(&request[0]);}
    DWORD Result(OP op) {return op==ReadMany?many()->dwPacketsSuccess:count;}
    bool Unchanged() const {return memcmp(before,packets,sizeof(before))==0;}
};
struct CALL {const CNdisApi* api;OP op;Fixture* f;DWORD error;BOOL nullCount;BOOL nullRequest;};
static BOOL Execute(CALL* c) {
    Fixture* f=c->f;
    switch(c->op) {
    case SendOneMstcp:return c->api->SendPacketToMstcp(c->nullRequest?NULL:&f->one);
    case SendOneAdapter:return c->api->SendPacketToAdapter(c->nullRequest?NULL:&f->one);
    case ReadOne:return c->api->ReadPacket(c->nullRequest?NULL:&f->one);
    case SendManyMstcp:return c->api->SendPacketsToMstcp(c->nullRequest?NULL:f->many());
    case SendManyAdapter:return c->api->SendPacketsToAdapter(c->nullRequest?NULL:f->many());
    case ReadMany:return c->api->ReadPackets(c->nullRequest?NULL:f->many());
    case ReadUnsorted:return c->api->ReadPacketsUnsorted(f->pointers,f->capacity,c->nullCount?NULL:&f->count);
    case SendUnsortedAdapter:return c->api->SendPacketsToAdaptersUnsorted(f->pointers,f->capacity,c->nullCount?NULL:&f->count);
    case SendUnsortedMstcp:return c->api->SendPacketsToMstcpUnsorted(f->pointers,f->capacity,c->nullCount?NULL:&f->count);
    }
    return FALSE;
}
static DWORD Guarded(CALL* c,BOOL* answer) {
    __try {*answer=Execute(c);c->error=GetLastError();return 0;}
    __except(EXCEPTION_EXECUTE_HANDLER) {*answer=FALSE;c->error=ERROR_NOACCESS;return GetExceptionCode();}
}
static BOOL Run(CALL& c,const std::string& label) {
    BOOL result=FALSE;const DWORD exception=Guarded(&c,&result);
    if(exception) {++guardedFaults;printf("[FAULT] %s code=0x%08lX\n",label.c_str(),exception);}
    Check(exception==0,label+": no guarded access violation");return result;
}
static void Setup(OP op,unsigned capacity,bool success=true) {
    PacketReset();g_Packet.writePackets=Read(op);g_Packet.writeCount=CountOutput(op);
    g_Packet.resultCount=capacity?1:0;
    g_Packet.immediateBytes=success?Metadata(op,capacity):0;
    g_Packet.terminalBytes=g_Packet.immediateBytes;
}
static void CheckPacket(const INTERMEDIATE_BUFFER& p,unsigned index,DWORD length,const std::string& label) {
    Check(p.m_Length==length,label+": exact frame length");
    Check(p.m_dwDeviceFlags==0x71+index&&p.m_Flags==0x91+index&&p.m_8021q==0x123+index&&p.m_FilterID==0x321+index,label+": packet metadata");
    bool bytes=true;for(DWORD i=0;i<length&&i<MAX_ETHER_FRAME;++i)if(p.m_IBuffer[i]!=0x40+index)bytes=false;
    Check(bytes,label+": every payload byte copied");
}
static void Modes(const CNdisApi& api) {
    for(unsigned value=0;value!=9;++value) {
        const OP op=static_cast<OP>(value);
        for(unsigned scenario=0;scenario!=4;++scenario) {
            const unsigned controlChecks=checks,controlFailures=failures;
            Fixture f;Setup(op,f.capacity);
            g_Packet.mode=scenario<2?(scenario==0?PacketImmediate:PacketFailure):PacketPending;
            g_Packet.terminalSuccess=scenario!=3;g_Packet.delayResponse=TRUE;
            if(scenario>=2)g_Packet.immediateBytes=0x71717171UL;
            g_Packet.cleanupClobbersError=scenario==1||scenario==3;
            if(scenario==1) {g_Packet.writePackets=FALSE;g_Packet.writeCount=FALSE;}
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/mode"+std::to_string(scenario);
            const BOOL ok=Run(c,label);
            if(Unsorted(op)&&PacketWow64()) {
                Check(!ok,label+": genuine WOW64 refusal");Check(f.count==0,label+": unsupported count zero");
                Check(c.error==ERROR_NOT_SUPPORTED,label+": meaningful unsupported error");Check(g_Packet.ioctlCalls==0,label+": unsupported no submission");continue;
            }
            const bool expected=scenario==0||scenario==2;
            Check((ok!=FALSE)==expected,label+": terminal success/failure");
            Check(g_Packet.ioctlCalls==1,label+": exactly one submission");
            if(CountOutput(op))Check(f.Result(op)==static_cast<DWORD>(expected?1:0),label+": count published only on valid success");
            if(expected&&Read(op))CheckPacket(f.packets[0],0,64,label);
            if(expected)Check(api.GetBytesReturned()==Metadata(op,f.capacity),label+": fresh actual returned bytes");
            else Check(c.error==static_cast<DWORD>(scenario==1?ERROR_ACCESS_DENIED:ERROR_DEVICE_NOT_CONNECTED),label+": terminal error survives cleanup");
            if(scenario>=2) {
                Check(g_Packet.completions==1&&g_Packet.waits==1&&!g_Packet.pending,label+": waited for terminal completion");
                Check(g_Packet.freedWhilePending==0&&g_Packet.closedWhilePending==0,label+": staging/event retained through completion");
                Check(g_Packet.completionInputChanged==0,label+": pending input stable");
            }
            Check(g_Packet.outstandingAllocations==0,label+": balanced staging allocations");
            Check(g_Packet.oversizedCopies==0,label+": no unsafe copy request");
            if(scenario==0)printf("CONTROL %s checks=%u failures=%u\n",label.c_str(),checks-controlChecks,failures-controlFailures);
        }
    }
}
static void Counts(const CNdisApi& api) {
    const OP ops[]={ReadMany,ReadUnsorted,SendUnsortedAdapter,SendUnsortedMstcp};
    for(unsigned o=0;o!=4;++o) {
        const OP op=ops[o];if(Unsorted(op)&&PacketWow64())continue;
        for(unsigned scenario=0;scenario!=7;++scenario) {
            Fixture f;Setup(op,2);const DWORD full=Metadata(op,2);
            const DWORD prefix=op==ReadMany?(PacketWow64()?offsetof(ETH_M_REQUEST_WOW64,EthPacket):offsetof(ETH_M_REQUEST,EthPacket)):sizeof(UNSORTED_READ_SEND_REQUEST);
            if(scenario==0)g_Packet.resultCount=3;
            if(scenario==1)g_Packet.resultCount=0xFFFFFFFF;
            if(scenario==2)g_Packet.immediateBytes=0;
            if(scenario==3)g_Packet.immediateBytes=prefix-1;
            if(scenario==4)g_Packet.immediateBytes=full+1;
            if(scenario==5) {g_Packet.mode=PacketPending;g_Packet.delayResponse=TRUE;g_Packet.terminalBytes=prefix-1;}
            if(scenario==6) {g_Packet.mode=PacketFailure;g_Packet.writeCount=FALSE;g_Packet.writePackets=FALSE;}
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/invalid-result"+std::to_string(scenario);
            const BOOL ok=Run(c,label);Check(!ok,label+": malformed or failed output rejected");Check(f.Result(op)==0,label+": rejected count zero");
            if(scenario!=6)Check(c.error==ERROR_INVALID_DATA||c.error==ERROR_BAD_LENGTH,label+": meaningful malformed response error");
            if(PacketWow64())Check(f.Unchanged(),label+": no WOW64 prefix published");
            Check(g_Packet.outstandingAllocations==0,label+": malformed result releases staging");
        }
        for(unsigned scenario=0;scenario!=2;++scenario) {
            const unsigned controlChecks=checks,controlFailures=failures;
            Fixture f;Setup(op,2);g_Packet.resultCount=scenario?2:0;
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/valid-count"+std::to_string(g_Packet.resultCount);
            Check(Run(c,label)!=FALSE,label+": bounded successful result accepted");Check(f.Result(op)==g_Packet.resultCount,label+": exact bounded count");
            if(Read(op)&&scenario) {CheckPacket(f.packets[0],0,64,label);CheckPacket(f.packets[1],1,65,label);}
            printf("CONTROL %s checks=%u failures=%u\n",label.c_str(),checks-controlChecks,failures-controlFailures);
        }
    }
    for(unsigned scenario=0;scenario!=2;++scenario) {
        const unsigned controlChecks=checks,controlFailures=failures;
        Fixture f(1);Setup(ReadMany,1);g_Packet.resultCount=scenario?2:1;
        CALL c={&api,ReadMany,&f,0,FALSE,FALSE};const std::string label=std::string("READ_MANY/capacity-one-result")+std::to_string(g_Packet.resultCount);
        const BOOL ok=Run(c,label);
        if(!scenario) {Check(ok!=FALSE,label+": one packet accepted");Check(f.many()->dwPacketsSuccess==1,label+": one packet count");CheckPacket(f.packets[0],0,64,label);printf("CONTROL %s checks=%u failures=%u\n",label.c_str(),checks-controlChecks,failures-controlFailures);}
        else {Check(!ok,label+": over-capacity result refused");Check(f.many()->dwPacketsSuccess==0,label+": rejected result count zero");if(PacketWow64())Check(f.Unchanged(),label+": no WOW64 packet prefix published");}
    }
    for(unsigned value=ReadUnsorted;value<=SendUnsortedMstcp;++value) {
        Fixture f;const OP op=static_cast<OP>(value);Setup(op,2);CALL c={&api,op,&f,0,TRUE,FALSE};
        const std::string label=std::string(Name(op))+"/null-output-count";
        Check(!Run(c,label),label+": rejected");Check(c.error==ERROR_INVALID_PARAMETER,label+": explicit invalid parameter");Check(g_Packet.ioctlCalls==0,label+": no submission");
    }
}
static void Lengths(const CNdisApi& api) {
    // A native API does not copy its indirect payload in this TU; these oracles
    // intentionally test the genuine WOW64 conversion rather than claiming rollback.
    if(!PacketWow64())return;
    for(unsigned value=SendOneMstcp;value<=ReadMany;++value) {
        const OP op=static_cast<OP>(value);
        for(unsigned scenario=0;scenario!=3;++scenario) {
            const unsigned controlChecks=checks,controlFailures=failures;
            Fixture f;Setup(op,2);const DWORD length=scenario==0?MAX_ETHER_FRAME:(scenario==1?MAX_ETHER_FRAME+1:0xFFFFFFFFUL);
            if(Read(op)) {g_Packet.resultCount=Many(op)?2:1;g_Packet.lengths[Many(op)?1:0]=length;}
            else f.packets[Many(op)?1:0].m_Length=length;
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/frame-length"+std::to_string(length);
            const BOOL ok=Run(c,label);
            if(scenario==0) {
                Check(ok!=FALSE,label+": exact ceiling accepted");Check(g_Packet.ioctlCalls==1,label+": exact ceiling submitted");
                    Check(g_Packet.copyBytes>=MAX_ETHER_FRAME,label+": full real ceiling copy executed");
                if(Read(op))CheckPacket(f.packets[Many(op)?1:0],Many(op)?1:0,MAX_ETHER_FRAME,label);
                else Check(g_Packet.submittedLengths[Many(op)?1:0]==MAX_ETHER_FRAME&&g_Packet.submittedHashes[Many(op)?1:0]==MAX_ETHER_FRAME*0xA5UL,label+": entire ceiling send payload reached IOCTL");
            } else {
                Check(!ok,label+": oversized frame rejected");Check(g_Packet.oversizedCopies==0,label+": no modeled unsafe copy request");
                Check(c.error==ERROR_INVALID_PARAMETER||c.error==ERROR_INVALID_DATA||c.error==ERROR_BAD_LENGTH,label+": meaningful length error");
                if(Read(op)) {Check(f.Unchanged(),label+": entire WOW64 output transaction withheld");if(op==ReadMany)Check(f.many()->dwPacketsSuccess==0,label+": bad later frame count zero");}
                else Check(g_Packet.ioctlCalls==0,label+": oversized source not submitted");
            }
            Check(g_Packet.outstandingAllocations==0,label+": frame validation releases staging");
            if(scenario==0)printf("CONTROL %s checks=%u failures=%u\n",label.c_str(),checks-controlChecks,failures-controlFailures);
        }
    }
    // A short single read response must not publish even a well-formed staged frame.
    Fixture f;Setup(ReadOne,2);g_Packet.immediateBytes=sizeof(ETH_REQUEST_WOW64)-1;
    CALL c={&api,ReadOne,&f,0,FALSE,FALSE};Check(!Run(c,"READ_ONE/short-metadata"),"READ_ONE/short-metadata: rejected");
    Check(f.Unchanged(),"READ_ONE/short-metadata: caller unchanged");
}
static void Requests(const CNdisApi& api) {
    for(unsigned value=SendManyMstcp;value<=ReadMany;++value) {
        const OP op=static_cast<OP>(value);
        const unsigned counts[]={0,0xFFFFFFFFU,0x40000000U};
        for(unsigned i=0;i!=3;++i) {
            Fixture f(counts[i]);Setup(op,counts[i]);g_Packet.writePackets=FALSE;g_Packet.writeCount=FALSE;
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/capacity"+std::to_string(counts[i]);
            Check(!Run(c,label),label+": invalid capacity rejected");
            if(op==ReadMany)Check(f.many()->dwPacketsSuccess==0,label+": failure count zero");
            if(i)Check(g_Packet.ioctlCalls==0&&g_Packet.allocationCalls==0,label+": arithmetic rejected before allocation/submission");
            Check(c.error!=ERROR_SUCCESS,label+": meaningful capacity error");Check(g_Packet.outstandingAllocations==0,label+": capacity failure storage balanced");
        }
        if(PacketWow64()) {
            // This count fits ETH_M_REQUEST_WOW64's signed byte boundary but
            // independently overflows the private INTERMEDIATE_BUFFER array.
            const size_t stagingLimit=static_cast<size_t>(-1)/sizeof(INTERMEDIATE_BUFFER_WOW64);
            const unsigned stagingOverflow=static_cast<unsigned>(stagingLimit+1);
            const ULONGLONG requestBytes=offsetof(ETH_M_REQUEST_WOW64,EthPacket)+static_cast<ULONGLONG>(stagingOverflow)*sizeof(NDISRD_ETH_Packet_WOW64);
            Check(requestBytes<=0x7FFFFFFFULL,std::string(Name(op))+"/staging-overflow: metadata still fits signed IOCTL size");
            Fixture f(stagingOverflow);Setup(op,stagingOverflow);g_Packet.writePackets=FALSE;g_Packet.writeCount=FALSE;
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/independent-staging-array-overflow";
            Check(!Run(c,label),label+": overflow rejected");
            Check(g_Packet.allocationCalls==0&&g_Packet.ioctlCalls==0,label+": rejected before any allocation or submission");
            Check(c.error==ERROR_ARITHMETIC_OVERFLOW,label+": explicit arithmetic error");
            if(op==ReadMany)Check(f.many()->dwPacketsSuccess==0,label+": read failure count zero");
        }
        if(PacketWow64())for(unsigned failure=1;failure<=2;++failure) {
            Fixture f;Setup(op,2);g_Packet.failAllocationAt=failure;
            CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/allocation-failure"+std::to_string(failure);
            Check(!Run(c,label),label+": allocation refusal reported");Check(c.error==ERROR_NOT_ENOUGH_MEMORY,label+": allocation error");
            Check(g_Packet.ioctlCalls==0,label+": allocation failure not submitted");Check(g_Packet.outstandingAllocations==0,label+": earlier allocation released");
            if(op==ReadMany)Check(f.many()->dwPacketsSuccess==0,label+": allocation failure count zero");
        }
    }
    for(unsigned value=ReadUnsorted;value<=SendUnsortedMstcp;++value) {
        Fixture f(0);const OP op=static_cast<OP>(value);Setup(op,0);g_Packet.mode=PacketFailure;g_Packet.writeCount=FALSE;
        CALL c={&api,op,&f,0,FALSE,FALSE};const std::string label=std::string(Name(op))+"/zero-request-failure";
        Check(!Run(c,label),label+": failure preserved");Check(f.count==0,label+": zero output on failure");
    }
}
static void PublicAsyncControl(const CNdisApi& api) {
    const unsigned controlChecks=checks,controlFailures=failures;
    PacketReset();g_Packet.mode=PacketPending;g_Packet.immediateBytes=0x2222;g_Packet.terminalBytes=4;
    DWORD value=0,bytes=0;OVERLAPPED overlap={};overlap.hEvent=CreateEvent(NULL,TRUE,FALSE,NULL);
    Check(overlap.hEvent!=NULL,"public async wrapper: caller event created");
    const BOOL initial=api.DeviceIoControl(0x12345678UL,&value,sizeof(value),&value,sizeof(value),&bytes,&overlap);
    const DWORD error=GetLastError();
    Check(!initial&&error==ERROR_IO_PENDING,"public async wrapper: pending remains visible");
    Check(g_Packet.completions==0&&g_Packet.pending,"public async wrapper: no implicit wait");
    Check(api.CompleteOverlappedRequest(initial,&overlap,&bytes)!=FALSE,"public async wrapper: caller can finish request");
    Check(bytes==4&&g_Packet.completions==1&&g_Packet.waits==1&&!g_Packet.pending,"public async wrapper: explicit terminal result");
    CloseHandle(overlap.hEvent);
    printf("CONTROL public_async_wrapper checks=%u failures=%u\n",checks-controlChecks,failures-controlFailures);
}
static void SeedCompletedPendingError(const CNdisApi& api,const std::string& label) {
    // Execute a real convenience-helper pending path before testing the invalid
    // instance. The I/O mock completes safely and leaves ERROR_IO_PENDING stale.
    g_Packet.mode=PacketPending;g_Packet.terminalSuccess=TRUE;
    STATIC_FILTER filter={};filter.m_FilterAction=FILTER_PACKET_PASS;
    const BOOL completed=api.AddStaticFilterFront(&filter);
    const DWORD error=GetLastError();
    Check(completed!=FALSE,label+": valid pending request reaches success");
    Check(g_Packet.ioctlCalls==1&&g_Packet.completions==1&&g_Packet.waits==1&&!g_Packet.pending,label+": valid request submits and waits exactly once");
    Check(error==ERROR_IO_PENDING,label+": successful pending call leaves the stale error");
}
static void InvalidHandle(const CNdisApi& validApi) {
    const unsigned controlChecks=checks,controlFailures=failures;
    PacketReset();g_Packet.failCreateFile=TRUE;CNdisApi invalidApi;
    Check(!invalidApi.IsDriverLoaded(),"invalid handle: constructor reports failed driver open");
    g_Packet.failCreateFile=FALSE;
    for(unsigned callerOverlap=0;callerOverlap!=2;++callerOverlap) {
        PacketReset();const std::string label=std::string("invalid handle/direct-wrapper/")+std::to_string(callerOverlap);
        SeedCompletedPendingError(validApi,label);
        DWORD value=0,bytes=0xCCCCCCCC;OVERLAPPED overlap={};
        const BOOL result=invalidApi.DeviceIoControl(0x12345678UL,&value,sizeof(value),&value,sizeof(value),&bytes,callerOverlap?&overlap:NULL);
        const DWORD error=GetLastError();
        Check(!result,label+": invalid handle remains FALSE");
        Check(error==ERROR_INVALID_HANDLE,label+": exact invalid-handle error replaces stale pending");
        Check(g_Packet.ioctlCalls==1&&g_Packet.completions==1&&g_Packet.waits==1&&!g_Packet.pending,label+": no invalid submission or completion/wait");
    }
    for(unsigned value=0;value!=9;++value) {
        const OP op=static_cast<OP>(value);if(Unsorted(op)&&PacketWow64())continue;
        Fixture f;Setup(op,f.capacity);const std::string label=std::string("invalid handle/")+Name(op);
        SeedCompletedPendingError(validApi,label);
        g_Packet.cleanupClobbersError=TRUE;
        CALL c={&invalidApi,op,&f,0,FALSE,FALSE};
        Check(!Run(c,label),label+": no bogus successful completion");
        Check(c.error==ERROR_INVALID_HANDLE,label+": exact error survives staging/event cleanup");
        Check(g_Packet.ioctlCalls==1&&g_Packet.completions==1&&g_Packet.waits==1&&!g_Packet.pending,label+": no invalid submission or completion/wait");
        Check(invalidApi.GetBytesReturned()==0,label+": no fabricated returned bytes");
        if(CountOutput(op))Check(f.Result(op)==0,label+": failed count remains zero");
        Check(g_Packet.outstandingAllocations==0,label+": staging allocations balanced");
    }
    PacketReset();SeedCompletedPendingError(validApi,"invalid handle/static-filter");
    STATIC_FILTER filter={};filter.m_FilterAction=FILTER_PACKET_PASS;
    const BOOL result=invalidApi.AddStaticFilterFront(&filter);const DWORD error=GetLastError();
    Check(!result,"invalid handle/static-filter: no bogus successful completion");
    Check(error==ERROR_INVALID_HANDLE,"invalid handle/static-filter: exact invalid-handle error");
    Check(g_Packet.ioctlCalls==1&&g_Packet.completions==1&&g_Packet.waits==1&&!g_Packet.pending,"invalid handle/static-filter: no invalid submission or completion/wait");
    printf("CONTROL invalid_handle_after_pending checks=%u failures=%u\n",checks-controlChecks,failures-controlFailures);
}
int main() {
    setvbuf(stdout,NULL,_IONBF,0);
    PacketReset();CNdisApi api;TCP_AdapterList adapters={};
    Check(api.GetTcpipBoundAdaptersInfo(&adapters)!=FALSE,"real enumeration succeeds");Check(adapters.m_nAdapterCount==1,"one real mapped adapter");
    mappedAdapter=adapters.m_nAdapterHandle[0];Check(mappedAdapter!=NULL,"mapped nonzero adapter");
#ifdef _WIN64
    Check(!PacketWow64(),"genuine native x64 branch");
#else
    Check(PacketWow64(),"genuine WOW64 branch");
#endif
    printf("CONTROL enumeration_and_real_arch checks=%u failures=%u\n",checks,failures);
    PublicAsyncControl(api);
    const unsigned start=checks;
    InvalidHandle(api);
    Modes(api);printf("GROUP modes cumulative_checks=%u cumulative_failures=%u\n",checks,failures);
    Counts(api);printf("GROUP counts cumulative_checks=%u cumulative_failures=%u\n",checks,failures);
    Lengths(api);printf("GROUP lengths cumulative_checks=%u cumulative_failures=%u\n",checks,failures);
    Requests(api);printf("GROUP requests cumulative_checks=%u cumulative_failures=%u\n",checks,failures);
    PacketReset();
    printf("%u checks, %u failures, %u guarded faults, %u scoped checks\n",checks,failures,guardedFaults,checks-start);
    printf("RESULT=%u\n",failures?1U:0U);return failures?1:0;
}
