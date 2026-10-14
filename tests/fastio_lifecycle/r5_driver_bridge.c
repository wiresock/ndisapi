#include "precomp.h"
#include "r5_bridge.h"
static FILE_OBJECT files[256];
static int opened[256], nextFile, registrationCall, failRegistration;
void R5DriverInit(void) { LC_InitializeLifecycle(); }
void* R5DriverOpen(void) { int i=nextFile++; if(i>=256) abort(); files[i].id=i+1; opened[i]=1; LC_OnCreate(); return &files[i]; }
int R5DriverClose(void* p) { int i; for(i=0;i<nextFile;i++) if(p==&files[i]) { if(!opened[i]) abort(); opened[i]=0; LC_OnClose(&files[i]); return 1; } return 0; }
long R5DriverRegister(void* owner,void* section,unsigned long bytes,int first) {
 INITIALIZE_FAST_IO_PARAMS p; ++registrationCall; if(failRegistration==registrationCall) g_ShimFailAllocateMdl=1;
 p.header_ptr=(PFAST_IO_SECTION)section;p.data_size=bytes;
 return first?FIO_InitializeSection((PFILE_OBJECT)owner,&p):FIO_AddSection((PFILE_OBJECT)owner,&p);
}
long R5Sections(void){return g_lFastIoNum;}
long R5Mdls(void){return g_ShimMdlsAllocated;}
long R5Locked(void){return g_ShimPagesLocked;}
long R5Clients(void){return LC_ActiveClients();}
long R5OwnedInRange(void* p,size_t bytes){long i,n=0;ULONG_PTR a=(ULONG_PTR)p;for(i=0;i<g_lFastIoNum;i++){ULONG_PTR q=(ULONG_PTR)g_FastIoSection[i];if(q>=a&&q-a<bytes)++n;}return n;}
void R5FailRegistration(int n){registrationCall=0;failRegistration=n;g_ShimFailAllocateMdl=0;}
VOID IB_FreeIntermediateBuffer(PINTERMEDIATE_BUFFER p){(void)p;abort();}
VOID IB_FreeIntermediateBufferSpecial(PINTERMEDIATE_BUFFER p){(void)p;abort();}
VOID EXT_ResetRDForAllAdapters(void){}
VOID FLT_ResetStaticFilters(void){}
