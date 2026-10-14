# FastIO lifecycle integration regression

This optional Windows/MSVC suite compiles the supplied SDK's real `ndisapi.cpp`, `fastio_packet_filter.h`, and network/event helpers together with the supplied driver's actual `LWF/fastio.c` and `LWF/lifecycle.c`. It is separate from the SDK aggregate because it requires a matching driver checkout and Microsoft GSL headers.

```powershell
.\tests\fastio_lifecycle\Run-Lifecycle.ps1 -Arch x64 `
  -SdkRoot D:\projects\ndisapi-release `
  -DriverRoot D:\projects\winpkfilter-pool\kernel `
  -GslIncludeRoot D:\vcpkg\installed\x64-windows\include
```

Repeat with `-Arch x86`. The script finds MSVC through vswhere (or honors `VCVARSALL`). `-OutputDirectory` is optional; the default is a unique directory under `tests/bin/fastio_lifecycle`. An existing output directory is rejected. SDK and driver Common.h must match. The driver checkout must include its adjacent `../ndisapi/include/Common.h` and maintained `tests/shim_lwf` services.

Each run records copied inputs, SHA256 values before and after execution, executable hash and PE architecture, separate build/child native exits, stdout/stderr, and `result.json`. Builds compile the supplied source paths, never the copied evidence. Child timeout is 60 seconds; faults, setup errors, incomplete/duplicate footers, stderr, source changes and assertion-count disagreements invalidate evidence. With valid_test_evidence=true, child native 0 means all assertions passed and child native 1 is a completed assertion failure. Explicit invalid-test/build paths exit 2. Preflight errors throw before a valid result exists and may make powershell -File exit 1; an outer exit alone is never test evidence.

The 15 cases cover start/stop/restart, destruction, stop before the worker is scheduled, failures at each of four registrations, event attachment, adapter mode, thread construction, private handle open/event initialization, and each of three aligned allocations after packet-buffer allocation. Assertions check dedicated/shared registration ownership, preservation of the inherited base handle, rollback of acquired events, release of partial buffers, retryability, state publication, and owner closure before storage release. Early open/allocation failures must issue no adapter mode, packet-event or flush requests. The mode hook checks request success/failure and handle selection; successful mode reset is additionally established by the real network_adapter::release source, not a simulated driver adapter implementation.

Only OS/NDIS mapping, handle/IOCTL dispatch and scheduling boundaries are substituted. CreateFile/CloseHandle bridge real SDK calls to actual LC_OnCreate/LC_OnClose and FIO owner logic. Windows events and underlying threads are real. The scheduler gate makes delayed execution deterministic. Aligned deletes that would free live registered memory record named failures and quarantine allocations until owner cleanup, avoiding crash-only evidence. Recovery actions occur only after the violated invariant is recorded.

The fixture forces IsWow64Process=false to exercise native 32-bit structures on a 64-bit test host. It does not claim WOW64 FastIO support or kernel/IRQL/real-MDL validation. Adapter mode/event IOCTLs are tracked service mocks, while registration and close algorithms are actual driver source. Start/stop calls follow the sequential public lifecycle; concurrent start and stop are not covered or promised.

Successful runs currently emit 15 cases and 156 checks. A failed restart adds the explicit stopped-state failure check (157 checks in the captured baseline). The runner verifies the complete named assertion stream against the terminal footer and native verdict. The existing fastio_reader suite separately validates packet consumption/routing in standard and jumbo x86/x64 layouts.
