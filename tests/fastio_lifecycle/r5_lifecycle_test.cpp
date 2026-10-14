#include "r5_hooks.h"
#include "ndisapi.h"
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <type_traits>
#include <new>
#include <array>
#include <map>
#include <variant>
#include <optional>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <charconv>
#include <cassert>
#include <system_error>
#include <malloc.h>
#include <gsl/gsl>
#include "examples/cpp/common/iphlp.h"
#include "examples/cpp/common/winsys/object.h"
#include "examples/cpp/common/winsys/event.h"
#include "examples/cpp/common/net/mac_address.h"
#include "examples/cpp/common/net/ip_address.h"
#include "examples/cpp/common/net/ip_subnet.h"
#include "examples/cpp/common/iphelper/network_adapter_info.h"
#include "examples/cpp/common/ndisapi/network_adapter.h"

struct Allocation {void* p;size_t n;bool retired;};static Allocation allocated[128]{};
static int alignedCalls=0, failAlignedAt=0;
static int unsafeFrees=0;static long retainedAtFree=0;
void* operator new(size_t n,std::align_val_t a){if(++alignedCalls==failAlignedAt)throw std::bad_alloc();void*p=_aligned_malloc(n,static_cast<size_t>(a));if(!p)throw std::bad_alloc();for(auto&x:allocated)if(!x.p){x={p,n,false};return p;}_aligned_free(p);throw std::bad_alloc();}
void* operator new[](size_t n,std::align_val_t a){return ::operator new(n,a);}
static void alignedFree(void*p) noexcept{if(!p)return;for(auto&x:allocated)if(x.p==p){long owned=R5OwnedInRange(p,x.n);if(owned){++unsafeFrees;retainedAtFree+=owned;printf("OBSERVE storage-release owned-sections=%ld bytes=%zu\n",owned,x.n);x.retired=true;return;}x={};_aligned_free(p);return;}abort();}
void operator delete(void*p,std::align_val_t)noexcept{alignedFree(p);}void operator delete[](void*p,std::align_val_t)noexcept{alignedFree(p);}void operator delete(void*p,size_t,std::align_val_t)noexcept{alignedFree(p);}void operator delete[](void*p,size_t,std::align_val_t)noexcept{alignedFree(p);}

namespace scheduler {static HANDLE gate=nullptr;static bool failThread=false;static std::atomic<int> entered{0};}
namespace r5_std {using namespace std;
class thread {std::thread native_;public:thread()=default;thread(thread&&)=default;thread&operator=(thread&&)=default;
 template<class F,class P>thread(F f,P p){if(scheduler::failThread)throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));native_=std::thread([f,p]{if(WaitForSingleObject(scheduler::gate,10000)!=WAIT_OBJECT_0)ExitProcess(2);++scheduler::entered;std::invoke(f,p);});}
 bool joinable()const noexcept{return native_.joinable();}void join(){native_.join();}
};}
// Only access visibility and std::thread scheduling are substituted in the exact header.
#define private public
#define std r5_std
#include "examples/cpp/common/ndisapi/fastio_packet_filter.h"
#undef std
#undef private
using Filter=ndisapi::fastio_packet_filter;
static int checks=0,failures=0,cases=0;static const char*caseName="";
static void check(bool ok,const char*label){++checks;if(!ok){++failures;printf("FAIL %s: %s\n",caseName,label);}else printf("PASS %s: %s\n",caseName,label);}
static void require(bool ok,const char*label){if(!ok){printf("HARNESS-ERROR %s: %s\n",caseName,label);ExitProcess(2);}}
static void begin(const char*n){caseName=n;++cases;r5={};alignedCalls=failAlignedAt=0;unsafeFrees=0;retainedAtFree=0;R5FailRegistration(0);scheduler::failThread=false;scheduler::entered=0;scheduler::gate=CreateEvent(nullptr,TRUE,FALSE,nullptr);require(scheduler::gate!=nullptr,"thread gate");}
static void end(){check(R5Sections()==0&&R5Mdls()==0&&R5Locked()==0&&R5Clients()==0,"scope teardown clears registry, MDLs, pages and clients");for(auto&x:allocated)if(x.retired){_aligned_free(x.p);x={};}CloseHandle(scheduler::gate);scheduler::gate=nullptr;}
static void adapter(Filter&f){unsigned char mac[6]={};f.network_interfaces_.push_back(std::make_unique<ndisapi::network_adapter>(&f,reinterpret_cast<HANDLE>(1),mac,"fixture","fixture",0,1500));}
static void releaseWorker(Filter&f){SetEvent(scheduler::gate);if(!f.working_thread_.joinable())return;for(int i=0;i<5000&&f.get_filter_state()==Filter::filter_state::starting;++i)Sleep(1);require(f.get_filter_state()!=Filter::filter_state::starting,"worker reaches running");}
static void cleanupWorker(Filter&f){releaseWorker(f);if(f.working_thread_.joinable()){if(f.get_filter_state()==Filter::filter_state::running)f.stop_filter();else{f.filter_state_=Filter::filter_state::stopping;f.network_interfaces_[0]->release();f.working_thread_.join();}}}
static bool start(Filter&f,bool&threw){threw=false;try{return f.start_filter(0);}catch(const std::exception&e){threw=true;printf("OBSERVE start exception=%s\n",e.what());return false;}}
static void normal(bool destroy){begin(destroy?"destructor-owner-order":"start-stop-restart");{
 Filter f(nullptr,nullptr,true);adapter(f);bool threw=false;bool ok=start(f,threw);require(ok&&!threw,"baseline normal start");check(f.get_filter_state()==Filter::filter_state::running,"successful start reports running before worker executes");check(R5Sections()==4&&R5Mdls()==4&&R5Locked()==4,"four live registrations while storage is retained");check(r5.registrations==4&&r5.registrationOwners[0]!=r5.base&&std::all_of(r5.registrationOwners,r5.registrationOwners+4,[](HANDLE h){return h==r5.lastRegistrationOwner;}),"all four sections share a dedicated owner distinct from base");check(r5.lastModeOwner==r5.base&&r5.lastEventOwner==r5.base,"adapter mode and event use inherited base handle");{CNdisApi unrelated;check(R5Sections()==4,"unrelated handle open preserves registration owner");}check(R5Sections()==4,"unrelated handle close preserves registration owner");releaseWorker(f);
 if(!destroy){check(f.stop_filter(),"stop succeeds");printf("OBSERVE after-stop sections=%ld mdls=%ld locked=%ld\n",R5Sections(),R5Mdls(),R5Locked());check(R5Sections()==0&&R5Mdls()==0&&R5Locked()==0,"stop closes registration owner");check(unsafeFrees==0,"stop closes registrations before storage release");check(R5Clients()==1&&f.IsDriverLoaded(),"base handle remains open after stop");check(r5.attachedEvent==nullptr,"stop unregisters acquired packet event");ResetEvent(scheduler::gate);ok=start(f,threw);printf("OBSERVE restart returned=%d status=%08lx state=%d\n",ok,r5.status,int(f.get_filter_state()));check(ok&&!threw,"restart succeeds with fresh ownership");if(ok)cleanupWorker(f);else check(f.get_filter_state()==Filter::filter_state::stopped,"failed restart restores stopped state");}
 }check(unsafeFrees==0,"destruction never frees registered backing storage");end();}
static void failureCase(int stage,int kind){char name[80];const char* names[]={"registration", "packet-event", "adapter-mode", "thread-construction", "owner-open", "owner-event-init", "partial-aligned-allocation"};sprintf_s(name,"%s stage=%d",names[kind],stage);begin(name);{
 Filter f(nullptr,nullptr,true);adapter(f);if(kind==0)R5FailRegistration(stage);if(kind==1)r5.failEvent=true;if(kind==2)r5.failMode=true;if(kind==3)scheduler::failThread=true;if(kind==4)r5.failOpenAt=r5.openCalls+1;if(kind==5)r5.failOwnerEvent=true;if(kind==6){alignedCalls=0;failAlignedAt=stage;}
 bool threw=false;bool ok=start(f,threw);printf("OBSERVE failed-start returned=%d threw=%d state=%d sections=%ld mdls=%ld locked=%ld status=%08lx\n",ok,threw,int(f.get_filter_state()),R5Sections(),R5Mdls(),R5Locked(),r5.status);
 check(!ok&&!threw,"failed startup returns false without escaping exception");check(f.get_filter_state()==Filter::filter_state::stopped,"failed startup restores stopped state");check(R5Sections()==0&&R5Mdls()==0&&R5Locked()==0,"failed startup closes partial registration ownership");check(unsafeFrees==0,"failed startup does not free registered backing storage");
 check(!f.packet_buffer_&&!f.write_adapter_request_ptr_&&!f.write_mstcp_request_ptr_&&!f.fast_io_ptr_,"failed startup releases every partially allocated buffer");
 check(R5Clients()==1&&f.IsDriverLoaded(),"failed startup preserves only the inherited base handle");
 check(r5.attachedEvent==nullptr,"failed startup unregisters any acquired packet event");
 if(kind>=4)check(r5.modeCalls==0&&r5.eventCalls==0&&r5.flushCalls==0,"early failure leaves adapter configuration untouched");
 if(ok)cleanupWorker(f);R5FailRegistration(0);r5.failEvent=r5.failMode=r5.failOwnerEvent=false;r5.failOpenAt=0;failAlignedAt=0;scheduler::failThread=false;ResetEvent(scheduler::gate);
 bool retry=start(f,threw);check(retry&&!threw,"retry after startup failure succeeds");if(retry)cleanupWorker(f);
 }check(unsafeFrees==0,"failure/retry scope preserves storage ownership through destruction");end();}

static void stopBeforeWorker(){begin("stop-before-worker-scheduled");{
 Filter f(nullptr,nullptr,true);adapter(f);bool threw=false;require(start(f,threw)&&!threw,"normal start before delayed stop");
 check(f.get_filter_state()==Filter::filter_state::running,"successful start is running before worker scheduling");
 std::atomic<bool> done{false};bool stopped=false;std::thread closer([&]{stopped=f.stop_filter();done=true;});
 for(int i=0;i<5000&&!done&&f.get_filter_state()!=Filter::filter_state::stopping;++i)Sleep(1);
 require(done||f.get_filter_state()==Filter::filter_state::stopping,"stop reaches return or stopping before worker starts");
 bool stoppingSeen=!done&&f.get_filter_state()==Filter::filter_state::stopping;SetEvent(scheduler::gate);
 for(int i=0;i<5000&&!done&&f.get_filter_state()!=Filter::filter_state::running;++i)Sleep(1);
 bool resurrected=stoppingSeen&&f.get_filter_state()==Filter::filter_state::running;
 check(!resurrected,"late worker never restores running after stop begins");
 // Recovery only after recording a violated invariant keeps a negative run bounded.
 if(resurrected){f.filter_state_=Filter::filter_state::stopping;f.network_interfaces_[0]->release();}
 for(int i=0;i<5000&&!done;++i)Sleep(1);
 check(done,"stop completes after delayed worker is released");
 if(!done){f.filter_state_=Filter::filter_state::stopping;f.network_interfaces_[0]->release();for(int i=0;i<5000&&!done;++i)Sleep(1);}
 require(done,"bounded failed-case cleanup");closer.join();check(stopped,"stop succeeds before worker receives CPU time");
 check(f.get_filter_state()==Filter::filter_state::stopped,"delayed-worker stop leaves stopped state");
 if(!stopped)cleanupWorker(f);
 check(R5Sections()==0&&R5Mdls()==0&&R5Locked()==0,"delayed-worker stop closes owner resources");check(unsafeFrees==0,"delayed-worker stop closes ownership before storage release");
 }check(unsafeFrees==0,"delayed-worker destruction preserves storage ownership");end();}

int main(){R5DriverInit();normal(false);normal(true);stopBeforeWorker();for(int i=1;i<=4;++i)failureCase(i,0);failureCase(0,1);failureCase(0,2);failureCase(0,3);failureCase(0,4);failureCase(0,5);for(int i=1;i<=3;++i)failureCase(i,6);printf("RESULT arch=%zu cases=%d checks=%d failures=%d\n",8*sizeof(void*),cases,checks,failures);return failures?1:0;}
