# Packet result, staging, and convenience-event regressions

`Run-Packets.ps1 -Arch x64` and `-Arch x86` compile the entire shipping SDK translation unit and run the packet and event suites in separate bounded processes. `-Suite Packets` or `-Suite Events` selects one suite. The x86 executable uses genuine WOW64 detection. No driver is required.

The original packet assertions in `packets_test.cpp` are preserved. They cover all nine single/sorted/unsorted convenience APIs, the independently frozen staging-array arithmetic case, immediate/pending terminal outcomes, request lifetime, cleanup error preservation, counts, metadata extents, over-capacity results, allocation failures, and all-frame validation before WOW64 output publication. Exact-ceiling copies and every copied payload are verified. The public async wrapper has a separate compatibility control. Constructor open-failure injection also tests the real invalid-handle wrapper and every supported packet convenience path, plus a static-filter convenience call, after a genuine successful pending request leaves ERROR_IO_PENDING stale. Those calls must return FALSE with ERROR_INVALID_HANDLE, perform no new submission/completion/wait, and preserve zero failure counts and balanced staging allocations. No invalid OS OVERLAPPED completion is executed; completion remains the bounded I/O mock. Metadata byte counts do not need to contain indirect packet payloads. Native payload writes cannot be rolled back after failure.

The packet shim replaces device I/O, completion, SDK allocation/free, and cleanup. Guarded SDK allocations end at an inaccessible page. Its SDK-only memmove hook records and refuses requests above the frame ceiling; ordinary/exact-ceiling copies use the real CRT. Guarded indexing faults are failed assertions, never successful SDK rejection. The packet oracle obtains its adapter handle through real SDK enumeration/mapping.

## Event reuse and lifetime

`packets_events_test.cpp` exercises the actual synchronous SDK helper through `AddStaticFilterFront`, using separate SDK instances for concurrently pending calls. `packets_events_shim.cpp` retains real Win32 event create/reset/close operations, adds bounded failure controls and counters, and substitutes only I/O submission/completion. Its synchronized request tracker holds at most 32 requests and snapshots at most 1024 bytes per request; there is no driver or unbounded allocation.

The event suite verifies:

- 1000 sequential calls reuse one event, with no additional creation/closure and a reset before every reuse.
- Creation/reset errors survive cleanup, no I/O is submitted on these failures, and failed slots can be reused.
- Immediate and pending success/failure retain their result and error semantics.
- Sixteen overlapping pending calls have distinct OVERLAPPED, event, and request identities. Events cannot be reset/closed before terminal completion and request storage stays unchanged.
- Saturation uses fresh events for immediate success/failure and pending failure; failed fallback creation does not disturb existing leases.
- Sixteen retained handles remain bounded across 128 later SDK instances; active overflow may temporarily increase the live count.
- After all calls and instances quiesce, the real module-static destructor closes every retained event. The final checks/RESULT footer is emitted only when the final retained event closes; a leak yields an incomplete verdict and rejected evidence.

The production cache is module-private, lazily populated, and fixed at 16 slots across all CNdisApi instances. A per-call lease remains exclusive through terminal completion. No pool lock is held across I/O or waiting, and no CNdisApi members or public exports are added. Public asynchronous calls retain caller-owned storage/event behavior. Module unload or static teardown requires all SDK callers to have quiesced; unloading while a call is active is unsupported. The tests use separate instances to avoid introducing a claim about unrelated shared-instance mutable result accounting.

The maintained runner owns hidden process handles, captures numeric exits, drains both pipes concurrently, bounds execution/output draining, rejects duplicate/incomplete/inconsistent footers, and hashes every SDK/header/fixture build input before and after each build/run. Exit 0 means all assertions pass; exit 1 means a completed failing test; exit 2 means invalid evidence or build/setup failure. A post-main teardown failure that disagrees with the process exit is rejected as invalid evidence. `tests/run_all.cmd` runs both suites on both architectures. Its historical OID ablation belongs to the separate OID suite and is not required for event-cache validation.

These are standard-layout offline SDK tests, not kernel/NIC/ARM64 runtime or end-to-end latency evidence. Caller storage must remain valid; concurrent caller mutation remains outside the contract. Public ABI and generic OID policy are unchanged.