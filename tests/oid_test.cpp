/*
 * oid_test.cpp - the terminal-status contract of CNdisApi::NdisrdRequest, against the REAL
 * ndisapi/ndisapi.cpp.
 *
 * NdisrdRequest issues its IOCTL overlapped. The old code waited on the OVERLAPPED event and then
 * decided the outcome by comparing PACKET_OID_DATA::Length against the length it had submitted.
 * Both halves of that are wrong:
 *
 *   - A signalled event means the request COMPLETED, not that it SUCCEEDED. The terminal status was
 *     never fetched, so a request that completed with a failure was reported as success.
 *   - Length is result accounting, not a status. On success the driver sets it to the bytes it
 *     actually transferred, so a SUCCESSFUL query that returned fewer bytes than the caller offered
 *     was reported as a failure.
 *
 *   REAL (ndisapi/ndisapi.cpp compiled as itself):
 *     CNdisApi::NdisrdRequest, CNdisApi::CompleteOverlappedRequest, CNdisApi::DeviceIoControl, the
 *     constructor, the WOW64 conversion branch and its handle mapping.
 *   SUBSTITUTED, and never claimed otherwise (tests/oidshim.*):
 *     CreateFile, DeviceIoControl and GetOverlappedResult. A real driver, real NDIS and real
 *     asynchrony are not modelled; what is modelled is the three answers the I/O manager can give.
 *
 * THE ORACLE: the value NdisrdRequest returns must equal the terminal status of the request, and
 * nothing else - not whether the event was signalled, and not what Length holds afterwards.
 *
 * The WOW64 branch is not simulated. m_bIsWow64Process is left genuine, so the 32-bit build of this
 * test on 64-bit Windows really takes it; the test asserts which branch ran, from the size of the
 * structure the shim was handed, rather than assuming.
 *
 * Build (x64 and x86 Native Tools), from this directory:
 *     cl /nologo /W4 /EHsc /std:c++17 /D_LIB /DUNICODE /D_UNICODE /I. /I..\include
 *        /FIoidshim.h oid_test.cpp oidshim.c ..\ndisapi\ndisapi.cpp
 *        /link ws2_32.lib iphlpapi.lib advapi32.lib
 */
#include "precomp.h"

#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool ok, const std::string& what, const std::string& detail = "")
{
    ++g_checks;
    printf("  [%s] %s%s\n", ok ? "ok" : "FAIL", what.c_str(),
           detail.empty() ? "" : (" - " + detail).c_str());
    if (!ok) ++g_failures;
}

std::string f(const char* fmt, ...)
{
    char b[512];
    va_list a;
    va_start(a, fmt);
    vsnprintf(b, sizeof(b), fmt, a);
    va_end(a);
    return b;
}

// ---------------------------------------------------------------- which branch this build takes

bool WowBranch()
{
#ifdef _WIN64
    return false;
#else
    BOOL wow = FALSE;
    ::IsWow64Process(::GetCurrentProcess(), &wow);
    return wow != FALSE;
#endif
}

ULONG LengthOffset()
{
    return WowBranch() ? (ULONG)FIELD_OFFSET(PACKET_OID_DATA_WOW64, Length)
                       : (ULONG)FIELD_OFFSET(PACKET_OID_DATA, Length);
}

DWORD ExpectedInSize(DWORD capacity)
{
    return WowBranch() ? (DWORD)(sizeof(PACKET_OID_DATA_WOW64) - 1 + capacity)
                       : (DWORD)(sizeof(PACKET_OID_DATA) - 1 + capacity);
}

// ---------------------------------------------------------------- the fixture

struct Request
{
    std::vector<unsigned char> buffer;

    explicit Request(DWORD capacity)
    {
        buffer.assign(sizeof(PACKET_OID_DATA) + capacity, 0);
        oid()->hAdapterHandle = (HANDLE)(ULONG_PTR)1;
        oid()->Oid = 0x0001010E;  // OID_GEN_CURRENT_PACKET_FILTER
        oid()->Length = capacity;
    }

    PPACKET_OID_DATA oid() { return reinterpret_cast<PPACKET_OID_DATA>(buffer.data()); }
};

// One case. The shim is reset, programmed, and the SHIPPING method is called.
struct Case
{
    SHIM_IOCTL_MODE mode = ShimIoImmediateSuccess;
    DWORD immediateError = ERROR_INVALID_FUNCTION;
    BOOL  terminalSuccess = TRUE;
    DWORD terminalError = ERROR_GEN_FAILURE;
    bool  writeBack = false;       // the driver writes a Length into the buffer before completing
    ULONG writeBackValue = 0;
};

BOOL Run(const CNdisApi& api, Request& req, BOOL set, const Case& c)
{
    ShimReset();
    g_ShimIoMode = c.mode;
    g_ShimIoImmediateError = c.immediateError;
    g_ShimTerminalSuccess = c.terminalSuccess;
    g_ShimTerminalError = c.terminalError;
    g_ShimWriteBackLength = c.writeBack ? TRUE : FALSE;
    g_ShimWriteBackOffset = LengthOffset();
    g_ShimWriteBackValue = c.writeBackValue;
    ::SetLastError(ERROR_SUCCESS);
    return api.NdisrdRequest(req.oid(), set);
}

// ---------------------------------------------------------------- the cases

void SynchronousAnswers(const CNdisApi& api)
{
    printf("synchronous answers\n");

    {
        Request r(8);
        Case c; c.mode = ShimIoImmediateSuccess;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == TRUE, "immediate success: GET returns TRUE", f("got %d", got));
        check(g_ShimIoctlCalls == 1, "immediate success: one IOCTL", f("%ld", g_ShimIoctlCalls));
        check(g_ShimGetOverlappedCalls == 0,
              "immediate success: the terminal status is already known, so it is not fetched again",
              f("%ld calls", g_ShimGetOverlappedCalls));
        check(g_ShimLastIoctlCode == IOCTL_NDISRD_NDIS_GET_REQUEST,
              "immediate success: the GET control code was used");
    }

    {
        Request r(8);
        Case c; c.mode = ShimIoImmediateSuccess;
        const BOOL got = Run(api, r, TRUE, c);
        check(got == TRUE, "immediate success: SET returns TRUE", f("got %d", got));
        check(g_ShimLastIoctlCode == IOCTL_NDISRD_NDIS_SET_REQUEST,
              "immediate success: the SET control code was used");
    }

    {
        Request r(8);
        Case c; c.mode = ShimIoImmediateFailure; c.immediateError = ERROR_NOT_SUPPORTED;
        const BOOL got = Run(api, r, FALSE, c);
        const DWORD err = ::GetLastError();
        check(got == FALSE, "immediate failure: returns FALSE", f("got %d", got));
        check(err == ERROR_NOT_SUPPORTED,
              "immediate failure: the last error still describes the failure", f("0x%lX", err));
        check(g_ShimGetOverlappedCalls == 0,
              "immediate failure: nothing pended, so no completion is awaited");
    }

    {
        Request r(8);
        Case c; c.mode = ShimIoImmediateFailure; c.immediateError = ERROR_NOT_SUPPORTED;
        const BOOL got = Run(api, r, TRUE, c);
        check(got == FALSE, "immediate failure: SET returns FALSE", f("got %d", got));
    }
}

void PendingAnswers(const CNdisApi& api)
{
    printf("pending answers - the terminal status decides\n");

    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = TRUE;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == TRUE, "pending success: GET returns TRUE", f("got %d", got));
        check(g_ShimGetOverlappedCalls == 1,
              "pending success: the terminal status is fetched exactly once",
              f("%ld calls", g_ShimGetOverlappedCalls));
        check(g_ShimWaitedForCompletion == 1,
              "pending success: the completion is waited for exactly once, inside "
              "GetOverlappedResult", f("%ld waits", g_ShimWaitedForCompletion));
    }

    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = TRUE;
        const BOOL got = Run(api, r, TRUE, c);
        check(got == TRUE, "pending success: SET returns TRUE", f("got %d", got));
    }

    // The core regression. The event is signalled - the request COMPLETED - but it completed with
    // a failure. The old code saw only the signal.
    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = FALSE;
        c.terminalError = ERROR_NOT_SUPPORTED;
        const BOOL got = Run(api, r, FALSE, c);
        const DWORD err = ::GetLastError();
        check(g_ShimEventSignalled == 1,
              "pending failure: the event WAS signalled, so the old wait would have been satisfied");
        check(got == FALSE, "pending failure: GET returns FALSE", f("got %d", got));
        check(err == ERROR_NOT_SUPPORTED,
              "pending failure: the last error describes the completed request", f("0x%lX", err));
    }

    // Same, with the driver having written a Length back that equals what was submitted - which is
    // what the old comparison read as success.
    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = FALSE;
        c.terminalError = ERROR_NOT_SUPPORTED;
        c.writeBack = true; c.writeBackValue = 8;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == FALSE,
              "pending failure: GET returns FALSE even though Length still equals the submitted "
              "length", f("got %d, Length %lu", got, r.oid()->Length));
    }

    // The SET case. A SET never copies anything back, so under WOW64 the caller's Length CANNOT
    // change - the old code's comparison was guaranteed to report success there.
    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = FALSE;
        c.terminalError = ERROR_INVALID_PARAMETER;
        const BOOL got = Run(api, r, TRUE, c);
        const DWORD err = ::GetLastError();
        check(got == FALSE,
              WowBranch() ? "pending failure: WOW64 SET returns FALSE"
                          : "pending failure: SET returns FALSE",
              f("got %d, Length %lu", got, r.oid()->Length));
        check(err == ERROR_INVALID_PARAMETER,
              "pending failure: SET reports the completed request's error", f("0x%lX", err));
        check(r.oid()->Length == 8,
              "pending failure: a SET does not disturb the caller's Length",
              f("%lu", r.oid()->Length));
    }
}

void ShortTransfers(const CNdisApi& api)
{
    printf("a successful request that transferred fewer bytes than were offered\n");

    // Section 9: capacity 8, the driver succeeds having written 4.
    {
        Request r(8);
        Case c; c.mode = ShimIoImmediateSuccess;
        c.writeBack = true; c.writeBackValue = 4;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == TRUE, "short GET success: returns TRUE", f("got %d", got));
        check(r.oid()->Length == 4, "short GET success: the caller receives Length = 4",
              f("%lu", r.oid()->Length));
    }

    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = TRUE;
        c.writeBack = true; c.writeBackValue = 4;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == TRUE, "short GET success over a pending completion: returns TRUE",
              f("got %d", got));
        check(r.oid()->Length == 4,
              "short GET success over a pending completion: the caller receives Length = 4",
              f("%lu", r.oid()->Length));
    }

    // A full-length success must still be TRUE: the fix must not invert the old test.
    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = TRUE;
        c.writeBack = true; c.writeBackValue = 8;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == TRUE, "full-length GET success: returns TRUE", f("got %d", got));
        check(r.oid()->Length == 8, "full-length GET success: Length is unchanged",
              f("%lu", r.oid()->Length));
    }

    // A short SET. Section 8 asks for the native and WOW64 output behaviour to be audited
    // SEPARATELY, and this is where they legitimately differ: natively the driver writes into
    // the caller's own buffer, so a short SET success is visible as Length = BytesRead; under
    // WOW64 a SET copies nothing back at all, so the caller's Length cannot change. Both are
    // successes, and the fix is that the RETURN VALUE no longer depends on which happened.
    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = TRUE;
        c.writeBack = true; c.writeBackValue = 4;
        const BOOL got = Run(api, r, TRUE, c);
        check(got == TRUE, "short SET success: returns TRUE", f("got %d", got));
        if (WowBranch())
            check(r.oid()->Length == 8,
                  "short SET success: under WOW64 nothing is copied back, so Length is untouched",
                  f("%lu", r.oid()->Length));
        else
            check(r.oid()->Length == 4,
                  "short SET success: natively the caller receives Length = 4 bytes read",
                  f("%lu", r.oid()->Length));
    }

    // A driver that reports ZERO bytes but succeeded is still a success.
    {
        Request r(8);
        Case c; c.mode = ShimIoPending; c.terminalSuccess = TRUE;
        c.writeBack = true; c.writeBackValue = 0;
        const BOOL got = Run(api, r, FALSE, c);
        check(got == TRUE, "zero-length GET success: returns TRUE", f("got %d", got));
    }
}

void BranchIdentity(const CNdisApi& api)
{
    printf("which branch this build actually took\n");

    Request r(8);
    Case c;
    Run(api, r, FALSE, c);

    const DWORD expected = ExpectedInSize(8);
    check(g_ShimLastInSize == expected,
          WowBranch() ? "the WOW64 conversion branch ran (PACKET_OID_DATA_WOW64 was submitted)"
                      : "the native branch ran (PACKET_OID_DATA was submitted)",
          f("submitted %lu bytes, expected %lu", g_ShimLastInSize, expected));
    check(g_ShimLastOutSize == expected, "the output length matches the input length",
          f("%lu", g_ShimLastOutSize));

#ifdef _WIN64
    printf("  (64-bit build: the WOW64 branch does not exist here; the 32-bit build covers it)\n");
#else
    if (!WowBranch())
        printf("  (32-bit build on 32-bit Windows: the WOW64 branch is unreachable here)\n");
#endif
}

} // namespace

int main()
{
    printf("CNdisApi::NdisrdRequest - terminal status contract\n");
    printf("build: %d-bit, WOW64 branch %s\n\n",
           (int)(sizeof(void*) * 8), WowBranch() ? "TAKEN" : "not taken");

    // The constructor opens the "device" through the shim and, under WOW64, primes its handle map.
    CNdisApi api;
    if (!api.IsDriverLoaded())
    {
        printf("FATAL: the shimmed device did not open; nothing below would be meaningful\n");
        return 2;
    }

    BranchIdentity(api);
    SynchronousAnswers(api);
    PendingAnswers(api);
    ShortTransfers(api);

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    printf("RESULT=%d\n", g_failures == 0 ? 0 : 1);
    return g_failures == 0 ? 0 : 1;
}
