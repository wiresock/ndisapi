/*************************************************************************/
/*                                                                       */
/* Module Name:  oidshim.c                                               */
/*                                                                       */
/* Description: the programmable device behind oidshim.h                  */
/*                                                                       */
/* Environment:                                                          */
/*   User mode test                                                       */
/*                                                                       */
/*************************************************************************/

#define OIDSHIM_IMPL   /* this file calls the REAL Win32 functions */
#include "oidshim.h"

SHIM_IOCTL_MODE g_ShimIoMode = ShimIoImmediateSuccess;
DWORD g_ShimIoImmediateError = ERROR_INVALID_FUNCTION;

BOOL  g_ShimTerminalSuccess = TRUE;
DWORD g_ShimTerminalError = ERROR_GEN_FAILURE;
DWORD g_ShimTerminalBytes = 0;

BOOL  g_ShimWriteBackLength = FALSE;
ULONG g_ShimWriteBackOffset = 0;
ULONG g_ShimWriteBackValue = 0;

LONG  g_ShimIoctlCalls = 0;
DWORD g_ShimLastIoctlCode = 0;
DWORD g_ShimLastInSize = 0;
DWORD g_ShimLastOutSize = 0;
LONG  g_ShimGetOverlappedCalls = 0;
LONG  g_ShimWaitedForCompletion = 0;
LONG  g_ShimEventSignalled = 0;

void ShimReset(void)
{
    g_ShimIoMode = ShimIoImmediateSuccess;
    g_ShimIoImmediateError = ERROR_INVALID_FUNCTION;
    g_ShimTerminalSuccess = TRUE;
    g_ShimTerminalError = ERROR_GEN_FAILURE;
    g_ShimTerminalBytes = 0;
    g_ShimWriteBackLength = FALSE;
    g_ShimWriteBackOffset = 0;
    g_ShimWriteBackValue = 0;
    g_ShimIoctlCalls = 0;
    g_ShimLastIoctlCode = 0;
    g_ShimLastInSize = 0;
    g_ShimLastOutSize = 0;
    g_ShimGetOverlappedCalls = 0;
    g_ShimWaitedForCompletion = 0;
    g_ShimEventSignalled = 0;
}

/*
 * A real, overlapped-capable handle, so that the object believes the device opened and
 * m_hFileHandle != INVALID_HANDLE_VALUE. Nothing is ever read from it or written to it: every
 * operation the SDK performs on the handle is redirected here. It deletes itself on close, which
 * the SDK's destructor performs.
 */
HANDLE WINAPI ShimCreateFile(LPCTSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                             DWORD disp, DWORD flags, HANDLE tmpl)
{
    WCHAR dir[MAX_PATH], path[MAX_PATH];

    UNREFERENCED_PARAMETER(name);
    UNREFERENCED_PARAMETER(access);
    UNREFERENCED_PARAMETER(share);
    UNREFERENCED_PARAMETER(sa);
    UNREFERENCED_PARAMETER(disp);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(tmpl);

    if (!GetTempPathW(MAX_PATH, dir))
        return INVALID_HANDLE_VALUE;
    if (!GetTempFileNameW(dir, L"nds", 0, path))
        return INVALID_HANDLE_VALUE;

    return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                       FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                       NULL);
}

/*
 * The programmable device.
 *
 * In the pending mode it SIGNALS THE EVENT and then returns ERROR_IO_PENDING, which is what a
 * driver that completes quickly really does - and is precisely the case the old SDK mistook for
 * success: it waited on the event, saw it signalled, and asked no further.
 */
BOOL WINAPI ShimDeviceIoControl(HANDLE h, DWORD code, LPVOID in, DWORD inLen, LPVOID out,
                                DWORD outLen, LPDWORD ret, LPOVERLAPPED ov)
{
    UNREFERENCED_PARAMETER(h);
    UNREFERENCED_PARAMETER(in);

    InterlockedIncrement(&g_ShimIoctlCalls);
    g_ShimLastIoctlCode = code;
    g_ShimLastInSize = inLen;
    g_ShimLastOutSize = outLen;

    if (g_ShimWriteBackLength && out != NULL &&
        outLen >= g_ShimWriteBackOffset + sizeof(ULONG))
    {
        *(ULONG*)((char*)out + g_ShimWriteBackOffset) = g_ShimWriteBackValue;
    }

    if (ret)
        *ret = 0;

    switch (g_ShimIoMode)
    {
    case ShimIoImmediateSuccess:
        if (ov && ov->hEvent)
        {
            SetEvent(ov->hEvent);
            InterlockedIncrement(&g_ShimEventSignalled);
        }
        return TRUE;

    case ShimIoImmediateFailure:
        SetLastError(g_ShimIoImmediateError);
        return FALSE;

    case ShimIoPending:
    default:
        if (ov && ov->hEvent)
        {
            SetEvent(ov->hEvent);
            InterlockedIncrement(&g_ShimEventSignalled);
        }
        SetLastError(ERROR_IO_PENDING);
        return FALSE;
    }
}

BOOL WINAPI ShimGetOverlappedResult(HANDLE h, LPOVERLAPPED ov, LPDWORD bytes, BOOL wait)
{
    UNREFERENCED_PARAMETER(h);
    UNREFERENCED_PARAMETER(ov);

    InterlockedIncrement(&g_ShimGetOverlappedCalls);
    if (wait)
        InterlockedIncrement(&g_ShimWaitedForCompletion);

    if (!g_ShimTerminalSuccess)
    {
        SetLastError(g_ShimTerminalError);
        return FALSE;
    }

    if (bytes)
        *bytes = g_ShimTerminalBytes;

    return TRUE;
}
