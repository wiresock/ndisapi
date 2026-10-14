#define R5_HOOK_IMPL
#include "r5_hooks.h"
R5Hooks r5;
HANDLE WINAPI R5CreateFile(LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) {
 ++r5.openCalls;
 if(r5.openCalls==r5.failOpenAt){SetLastError(ERROR_ACCESS_DENIED);return INVALID_HANDLE_VALUE;}
 HANDLE p=R5DriverOpen();
 if(!r5.base)r5.base=p;
 else if(r5.failOwnerEvent)r5.ownerEventPending=true;
 return p;
}
HANDLE WINAPI R5CreateEvent(LPSECURITY_ATTRIBUTES a,BOOL manual,BOOL initial,LPCTSTR name) {
 if(r5.ownerEventPending){r5.ownerEventPending=false;SetLastError(ERROR_NOT_ENOUGH_MEMORY);return nullptr;}
 return ::CreateEvent(a,manual,initial,name);
}
BOOL WINAPI R5CloseHandle(HANDLE h){if(R5DriverClose(h)){++r5.closeCalls;return TRUE;}return ::CloseHandle(h);}
static BOOL WINAPI NativeProcess(HANDLE,PBOOL value){*value=FALSE;return TRUE;}
FARPROC WINAPI R5GetProcAddress(HMODULE m,LPCSTR s){if(s&&strcmp(s,"IsWow64Process")==0)return reinterpret_cast<FARPROC>(&NativeProcess);return ::GetProcAddress(m,s);}
BOOL WINAPI R5Ioctl(HANDLE owner,DWORD code,void* in,DWORD inBytes,void* out,DWORD outBytes,DWORD* returned,OVERLAPPED*){
 if(returned)*returned=0;
 if(code==IOCTL_NDISRD_GET_TCPIP_INTERFACES){if(out&&outBytes>=sizeof(TCP_AdapterList)){memset(out,0,sizeof(TCP_AdapterList));if(returned)*returned=sizeof(TCP_AdapterList);return TRUE;}SetLastError(ERROR_BAD_LENGTH);return FALSE;}
 if(code==IOCTL_NDISRD_INITIALIZE_FAST_IO||code==IOCTL_NDISRD_ADD_SECOND_FAST_IO_SECTION){
  if(inBytes!=sizeof(INITIALIZE_FAST_IO_PARAMS))abort();auto* p=static_cast<PINITIALIZE_FAST_IO_PARAMS>(in);r5.lastRegistrationOwner=owner;
  if(r5.registrations>=32)abort();r5.registrationOwners[r5.registrations++]=owner;
  r5.status=R5DriverRegister(owner,p->header_ptr,p->data_size,code==IOCTL_NDISRD_INITIALIZE_FAST_IO);
  if(r5.status<0){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return FALSE;}return TRUE;
 }
 if(code==IOCTL_NDISRD_SET_ADAPTER_MODE){++r5.modeCalls;r5.lastModeOwner=owner;auto*p=static_cast<PADAPTER_MODE>(in);if(r5.failMode&&p->dwFlags){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;}
 if(code==IOCTL_NDISRD_SET_EVENT){++r5.eventCalls;r5.lastEventOwner=owner;auto*p=static_cast<PADAPTER_EVENT>(in);if(r5.failEvent&&p->hEvent){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}r5.attachedEvent=p->hEvent;return TRUE;}
 if(code==IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE){++r5.flushCalls;return TRUE;}
 SetLastError(ERROR_NOT_SUPPORTED);return FALSE;
}
