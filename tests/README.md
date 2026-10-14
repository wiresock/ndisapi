# Offline regressions for the SDK

No driver, no adapter, no administrator rights. `run_all.cmd` builds and runs everything.

```
run_all.cmd            build + run for x64 and x86
run_all.cmd ablation   also run exact checksum/FastIO ablations and the historical OID regression ablation
```

`OVERALL RESULT=0` is the only passing outcome.

## `oid_test.cpp` - `CNdisApi::NdisrdRequest`, terminal status

`NdisrdRequest` issues its IOCTL overlapped. The pre-fix code waited on the `OVERLAPPED` event and
then decided the outcome by comparing `PACKET_OID_DATA::Length` against the length it had
submitted. Both halves are wrong:

* A signalled event means the request **completed**, not that it **succeeded**. The terminal status
  was never fetched, so a request that completed with a failure was reported as success. Under
  WOW64 a failed **set** could not be detected at all: the only write-back is guarded by `!Set`, so
  `Length` was necessarily unchanged and the comparison necessarily said "success".
* `Length` is result accounting, not a status. On success the driver sets it to the bytes actually
  transferred, so a **successful** query that returned fewer bytes than the caller offered was
  reported as a failure.

`CompleteOverlappedRequest` now asks the operating system - `GetOverlappedResult`, which performs
the wait itself, so the completion is waited for exactly once - and its answer is what the caller
is told.

**Real:** `ndisapi/ndisapi.cpp` compiled as itself - `NdisrdRequest`, `CompleteOverlappedRequest`,
`CNdisApi::DeviceIoControl`, the constructor, and the WOW64 conversion branch with its handle
mapping.
**Substituted** (`oidshim.h` / `oidshim.c`), and never claimed otherwise: `CreateFile`,
`DeviceIoControl` and `GetOverlappedResult`. A real driver, real NDIS and real asynchrony are not
modelled; what is modelled is the three answers the I/O manager can give - immediate success,
immediate failure, and `ERROR_IO_PENDING` followed by a terminal status.

Adapter enumeration supplies a genuine full 64-bit identity and the test consumes the SDK's
returned public handle. OID immediate and terminal byte counts have independent controls; the
historical status assertions remain unchanged.

The shim is force-included (`/FIoidshim.h`) **after** `<windows.h>` has declared the real
functions, so the platform declarations are untouched and only the SDK's own calls are diverted.

### The WOW64 branch is not simulated

`m_bIsWow64Process` is left genuine. The 32-bit build running on 64-bit Windows really is a WOW64
process and really takes the conversion branch; the test asserts which branch ran, from the size of
the structure the shim was handed, instead of assuming. Both architectures are therefore required -
neither substitutes for the other.

### The oracle

The value `NdisrdRequest` returns must equal the terminal status of the request, and nothing else:
not whether the event was signalled, and not what `Length` holds afterwards. 32 checks per
architecture.

### Ablation

`run_all.cmd ablation` compiles the same tests against `ndisapi/ndisapi.cpp` and `include/ndisapi.h`
as they were at **20aa90f**, the last commit with the defect, and requires the run to fail. It does: 11
failures on x64 and 10 on x86 - the extra one is the short SET, whose old WOW64
behaviour happened to be right for the wrong reason. The first is

```
[FAIL] pending success: the terminal status is fetched exactly once - 0 calls
```

and the substantive ones are `pending failure: GET returns FALSE - got 1` (the completed failure
reported as success, with `GetLastError()` still `0x3E5` `ERROR_IO_PENDING`) and
`short GET success: returns TRUE - got 0` (the successful short transfer reported as a failure).

Pass a different revision as the second argument to ablate against something else.

## OID request byte extents

The maintained [OID bounds fixture](oid_bounds/README.md) runs on native x64 and
genuine WOW64 from `run_all.cmd`. It requires malformed or unrepresentable request
sizes to be rejected before staging or IOCTL submission, using bounded allocator
and copy controls. Valid generic GET/SET, short results and terminal completion
semantics remain covered. No live driver or large allocation is used.

## Handle and static table regressions

The maintained [handles fixture](handles/README.md) is also run on x64 and genuine WOW64.
It covers checked mapping at all callers, stable enumeration identities, immutable input staging,
transactional table outputs, terminal completion storage lifetime, byte extents and overflow.
Its pre-implementation oracle was frozen before the Task12a change; the three C++ fixture files
are preserved byte-for-byte. The historical 20aa90f ablation above is specific to the OID suite.

## Packet result and staging regressions

The maintained [packets fixture](packets/README.md) also runs on x64 and genuine WOW64.
It exercises all nine single, sorted and unsorted convenience APIs, pending ownership, validated
metadata/counts, independent staging arithmetic, and transactional WOW64 frame copy-back.

## FastIO example reader

`fastio_reader/Run-Reader.ps1` compiles the actual example class/header for x86/x64 and standard/jumbo layouts, including its worker and private section-drain helper. All four configurations run from `run_all.cmd`; `ablation` also requires exact pre-fix worker and targeted remaining-capacity failure contracts. See `fastio_reader/README.md` for schedules, substituted boundaries, counts, and runtime/evidence safeguards. No driver is used.

## Checksum fixed-array ceilings

The [checksum fixture](checksum/README.md) compiles the complete actual SDK and
exercises all four methods and their C exports on x64 and genuine WOW64, with
standard/jumbo frames and both checksum compatibility branches. All eight runs
require guarded oversized rejection and unchanged valid golden checksums. The
optional ablation uses the exact accepted pre-ceiling SDK and requires its named
66 failures; crashes or unrelated failures cannot satisfy it.

## Maintained safe negative gates

Run `run_all.cmd safe-gates [fresh-output-directory]` for current-source handle/packet negative gates and positive handles, packets and event controls on x64 and WOW64 x86. This selection exits before historical OID and ablation suites. Outputs use a unique directory by default and an existing explicit directory is rejected. The handle mutation applies only to WOW64 conversion (x64 gets a positive control); packet published-count mutations run on both ABIs. All guards and copying loops remain intact. Gates require ordinary exit 1, complete valid receipt/footer, zero guarded faults and a relevant identity/count assertion. No historical source is executed.
