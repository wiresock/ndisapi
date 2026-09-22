/*************************************************************************/
/*                                                                       */
/* Module Name:  oidshim.h                                               */
/*                                                                       */
/* Description: force-included ahead of the SDK translation unit so that  */
/*              the REAL CNdisApi::NdisrdRequest can be driven            */
/*              deterministically, with no driver present.                */
/*                                                                       */
/* Environment:                                                          */
/*   User mode test                                                       */
/*                                                                       */
/*************************************************************************/

/*
 * Three Win32 entry points are redirected, and only three. The macros are defined AFTER
 * <windows.h> has declared the real functions, so the platform declarations are untouched and only
 * the SDK's own CALLS are diverted:
 *
 *   CreateFile            gives CNdisApi a VALID overlapped handle without a driver present, so
 *                         that the request path is reached at all.
 *   DeviceIoControl       programmable: immediate success, immediate failure, or ERROR_IO_PENDING.
 *   GetOverlappedResult   programmable terminal status of the COMPLETED request - the thing the
 *                         old code never asked for.
 *
 * CNdisApi has a member named DeviceIoControl as well; the macro renames it too, consistently
 * across the class declaration, its definition and its call sites. The member's own call is
 * written ::DeviceIoControl, so it reaches the global shim.
 *
 * Everything else about the object is genuine, including m_bIsWow64Process: a 32-bit build of this
 * test on 64-bit Windows really does take the WOW64 conversion branch, so that path is exercised as
 * itself rather than simulated. oid_test asserts which branch ran instead of assuming.
 */
#ifndef NDISAPI_TEST_OIDSHIM_H
#define NDISAPI_TEST_OIDSHIM_H

#include <winsock2.h>   /* before windows.h: the SDK's precomp.h expects Winsock 2 */
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _SHIM_IOCTL_MODE
{
    ShimIoImmediateSuccess = 0,   /* DeviceIoControl returns TRUE */
    ShimIoImmediateFailure,       /* returns FALSE with g_ShimIoImmediateError */
    ShimIoPending                 /* returns FALSE with ERROR_IO_PENDING */
} SHIM_IOCTL_MODE;

extern SHIM_IOCTL_MODE g_ShimIoMode;
extern DWORD g_ShimIoImmediateError;      /* the error an immediate failure reports */

/* the terminal status GetOverlappedResult reports for the completed request */
extern BOOL  g_ShimTerminalSuccess;
extern DWORD g_ShimTerminalError;
extern DWORD g_ShimTerminalBytes;

/*
 * What the "driver" writes back into the output buffer before completing. A driver that succeeds
 * sets Length to the bytes it actually transferred; a driver that fails reports its status there.
 * The whole point of the fix is that NEITHER of these decides the SDK's return value, so the tests
 * drive the two independently.
 *
 * The offset is explicit because the two branches submit different structures:
 * FIELD_OFFSET(PACKET_OID_DATA, Length) natively, FIELD_OFFSET(PACKET_OID_DATA_WOW64, Length)
 * under WOW64.
 */
extern BOOL  g_ShimWriteBackLength;
extern ULONG g_ShimWriteBackOffset;
extern ULONG g_ShimWriteBackValue;

/* observation */
extern LONG   g_ShimIoctlCalls;
extern DWORD  g_ShimLastIoctlCode;
extern DWORD  g_ShimLastInSize;
extern DWORD  g_ShimLastOutSize;
extern LONG   g_ShimGetOverlappedCalls;
extern LONG   g_ShimWaitedForCompletion;   /* GetOverlappedResult called with bWait = TRUE */
extern LONG   g_ShimEventSignalled;

void ShimReset(void);

HANDLE WINAPI ShimCreateFile(LPCTSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                             DWORD disp, DWORD flags, HANDLE tmpl);
BOOL WINAPI ShimDeviceIoControl(HANDLE h, DWORD code, LPVOID in, DWORD inLen, LPVOID out,
                                DWORD outLen, LPDWORD ret, LPOVERLAPPED ov);
BOOL WINAPI ShimGetOverlappedResult(HANDLE h, LPOVERLAPPED ov, LPDWORD bytes, BOOL wait);

#ifdef __cplusplus
}
#endif

#ifndef OIDSHIM_IMPL
#undef  CreateFile
#define CreateFile          ShimCreateFile
#define DeviceIoControl     ShimDeviceIoControl
#define GetOverlappedResult ShimGetOverlappedResult
#endif /* OIDSHIM_IMPL */

#endif /* NDISAPI_TEST_OIDSHIM_H */
