# SDK backport from 3.8.2 to the v3.6.2 line

This branch carries the user-mode SDK bug fixes, performance work, safety hardening and
offline regression tests from `release/v3.8.2` onto `v3.6.2` (`f08d851`). The v3.6.2
driver is unchanged: no kernel source, driver binary, driver version, IOCTL code or
driver-facing structure was modified.

## Driver compatibility

* `include/Common.h` changes are comments plus one SDK-side macro
  (`STATIC_FILTER_ADAPTER_UNMAPPED`). A generated dump of `sizeof` for all 42
  driver-facing structures, all 37 IOCTL codes, `sizeof(CNdisApi)` and
  `NDISRD_VERSION` (`0x06023000`) is byte-identical to v3.6.2 on x64 and x86.
  `STATIC_FILTER` keeps its v3.6.2 size (184 bytes; 3.7.1+ is 232).
* `include/ndisapi.h` adds one non-virtual public member,
  `CNdisApi::CompleteOverlappedRequest`. No data member, export (`.def`) or C API
  signature changed.
* Every new reply check in the SDK was checked against the v3.6.2 driver source
  (`kernel` repository, `origin/v3.6.2`; `common/ioctl.c`, `LWF/device.c`,
  `LWF/send.c`, `IM/`, `SYS/`). The driver sets `IoStatus.Information` to exactly
  what the SDK now requires for READ_PACKET(S), the unsorted IOCTLs,
  GET_PACKET_FILTERS(_RESET_STATS) and GET_TCPIP_INTERFACES. OID reply lengths are
  never larger than the submitted length. Only the OID IOCTLs can pend, and the SDK
  handles that through `CompleteOverlappedRequest`.
* The Fast I/O example reader (`read_fast_io_section`) was checked against the
  v3.6.2 LWF writer protocol (`LWF/ndisrd.c`). It uses the same flags and
  compare-and-swap order, and the 3.8.2 reader is correct against it.

## Backported commits

| 3.8.2 | Backport | Change |
|---|---|---|
| 20aa90f | f731624 | TCP/UDP checksum underflow / out-of-bounds read fix |
| 8ef57c1 | c0de45a | OID requests report the terminal status of a pending request |
| 04164f8 | 0d278bd | Ablation classification (tests) |
| 65593c0 | 7d0af62 | Wide RFC 1071 checksum (`ndisapi/inet_checksum.h`), ICMP length guard, no pad-byte write |
| 71d94f6 | 24967e5 | WOW64 adapter-handle validation; static filter tables staged (caller's filter is no longer modified) |
| 0b0f21f | b056d5f | Packet request/result validation; pending request storage retained |
| 3281bcf | d5ffa79 | Fast I/O example: bounded reader storage, atomic snapshot consumption |
| 5f4390e | f4b4e65 | Reject `m_Length > sizeof(m_IBuffer)` in checksum helpers |
| 505287c | 2f606a2 | OID request extents validated before staging |
| d3f01c8 | 6db08a4 | Fast I/O example: close the registration owner before freeing buffers |
| 5685e3a | 8274fda | OID reply lengths bounded before WOW64 publication |
| 73adae8 | e36015e | WOW64 adapter map refreshed once before publishing filter tables |
| 3abab10 | 754913b | Bounded, reusable event leases for synchronous SDK calls |
| d1c64a2 | e7462d0 | Safe negative gates; **docs rewritten** for the v3.6.2 PASS_RDR/DROP_RDR behavior |
| 4272941 | 11393d1 | Unsorted send tally docs, **extended** with v3.6.2 failure behavior |
| 3a701c5 | 7deb48f | `ERROR_INVALID_HANDLE` when the driver handle is invalid |
| 3a142e3 | 80aee6c | Unmapped WOW64 filter rows stay readable; delete-by-ID references removed |
| 166f3b1 | c64f89a | Fast I/O lifetime docs kept; **event docs rewritten** for v3.6.2 (SYNCHRONIZE access, previous event released on failure) |
| 0b3bf26 | 0ecf4eb | **Replaced** with v3.6.2 driver and SDK error-status docs |
| 5914400 | 3c14b46 | Runner line-ending policy (`.gitattributes`) |
| 5411fd5 | 3b4b7f0 | Tests honor explicit supported toolchains |
| — | 9819e83 | Ablation baselines repointed to the backport commits, with v3.6.2 blob hashes |

## Excluded from 3.8.2

| 3.8.2 | Reason |
|---|---|
| 3c3c86e (v3.7.1 filter extensions) | Grows `STATIC_FILTER` by 48 bytes (`m_ulProcessId`, `m_ulUniqueFilterId`, `m_ulReserved[4]`), bumps `NDISRD_VERSION` and adds `IOCTL_NDISRD_DELETE_FILTER_BY_ID` / `DeleteStaticFilterById`. The v3.6.2 driver has none of these and fails the IOCTL with error 87. The harmless rename of `RemoveStaticFilter`'s parameter (`dwFilterId` to `dwIndex`) is left out with it. |
| 682bf1b | Exports `DeleteStaticFilterById` from the legacy DLL `.def` files; depends on 3c3c86e. |
| ecdc39f, d38a761 | SDK/driver version bumps to 3.8.1 / 3.8.2. |
| Text of d1c64a2, 166f3b1, 0b3bf26, 4272941 that describes the 3.8.2 driver | It is wrong for v3.6.2 (see the README sections marked "v3.6.2 driver"). The code and tests from those commits are included. |

## Behavior changes for SDK callers

All of these come from the 3.8.2 SDK and apply unchanged here:

* A successful OID query that returns fewer bytes than offered (including zero) now
  returns `TRUE`. A completed OID failure now returns `FALSE`; the old SDK could
  report `TRUE` with unwritten data, or `FALSE` with `ERROR_IO_PENDING`.
* `Send*`/`ReadPackets` with zero packets and `NdisrdRequest` with `Length == 0`
  fail with `ERROR_INVALID_PARAMETER` before any IOCTL. A zero-packet sorted send
  used to succeed as a no-op.
* `ReadPackets` resets `dwPacketsSuccess` to 0 on failure.
* Unsorted packet APIs fail with `ERROR_NOT_SUPPORTED` in a WOW64 process. The old
  SDK passed 32-bit pointer arrays to the 64-bit driver.
* WOW64: unknown adapter handles fail with `ERROR_INVALID_HANDLE` before any IOCTL.
  Static-filter calls no longer overwrite the caller's `m_Adapter` with a 64-bit
  driver handle.
* `SetPacketFilterTable` with an empty table fails client-side. The v3.6.2 driver
  already rejected it.
* `STATIC_FILTER_ADAPTER_UNMAPPED` (`0xFFFFFFFF`) is output-only and rejected by
  SET/ADD/INSERT.

## Validation

* **Builds (VS2022 v143):** `ndisapi.lib`, `ndisapi.dll` and `ndisapi.net`, Debug
  and Release, for Win32, x64 and ARM64. All 18 configurations build with no
  compiler warnings. The Fast I/O examples `capture`, `ipv6_parser` and
  `sni_inspector` build for Release x64 and Win32.
* **Builds (legacy):** `ndisapi.vs2012` (v110_xp, VS 11.0 `CL.exe`,
  `_USING_V110_SDK71_`) builds in all four configurations with no warnings.
  `ndisapi.cpp` also compiles with VS2012 under `/Zc:forScope-` (x86 and x64).
  VC6 is not installed, so the VC6 project was not built. The checksum suite
  exercises the VC6 code path of `inet_checksum.h`
  (`INET_CHECKSUM_FORCE_LEGACY_COMPAT`).
* **Offline regression suite:** `tests\run_all.cmd ablation` passes
  (`OVERALL RESULT=0`). This covers the OID, OID bounds, handles, packets, events,
  Fast I/O reader and checksum suites on x64 and genuine WOW64 x86. All 14
  ablations reproduce their exact expected failures against the backport
  baselines. `tests\run_all.cmd safe-gates <short-dir>` passes 7 of 7.
  Use a short output directory: very deep paths make the linker fail with
  `LNK1104 'GUID TEMPFILE'`.
* **Live, unchanged driver** (ndisrd 3.6.2.1 LWF; `GetVersion` = `0x06023000`):
  a read-only probe ran on x64 and WOW64 x86 against both the old v3.6.2 SDK and
  this branch, covering 12 adapters. The calls were adapter enumeration,
  GetAdapterMode, queue size, hardware filter, OID queries, empty
  ReadPacket/ReadPackets, filter table size and reads, pool size, unsorted read and
  a bogus handle. All results match except the intended fixes:
  * Zero-length OID successes now return `TRUE` (old: `FALSE`, `ERROR_IO_PENDING`).
  * Failed `GetHwPacketFilter` requests now return `FALSE` (old: `TRUE` with
    uninitialized data).
  * A stale `dwPacketsSuccess` is cleared.
  * The WOW64 bogus handle reports `ERROR_INVALID_HANDLE`.
  * WOW64 unsorted read reports `ERROR_NOT_SUPPORTED`.

  The probe makes no calls that change state (adapter modes, filter tables, event
  registration, packet sends, Fast I/O), so those paths are covered by the offline
  suites and the source review only.

## Known limitations and follow-ups

* The ablation baselines name commits on this branch. They stay valid only when the
  branch is integrated by fast-forward, without rebasing.
* As in 3.8.2, `GetHwPacketFilter` copies 4 bytes even when a successful reply is
  shorter; `NdisrdRequest` correctly treats a short reply as success. This is
  unchanged from 3.8.2 and can be fixed in both lines.
* Driver-side v3.6.2 issues that 3.8.2 fixed remain in the v3.6.2 driver, because
  driver changes are out of scope here:
  * the LWF OID path marks the request pending and then returns synchronously;
  * the 32-bit size calculation for SET_PACKET_FILTERS can wrap;
  * Fast I/O: the packet count is 16-bit and can wrap, a `data_size` below the
    header size underflows, a kernel pointer is copied into the user-visible
    `INTERMEDIATE_BUFFER`, and pages are probed with `KernelMode`.
