# Packet result and WOW64 staging regressions

`Run-Packets.ps1 -Arch x64` and `-Arch x86` compile the entire shipping SDK translation unit. The x86 executable uses genuine WOW64 detection and obtains its adapter handle through real SDK enumeration/mapping. No driver is required.

The three C++ fixture files are exact copies of the pre-implementation extended oracle. It retains the original nine-API oracle and adds a separately frozen staging-array arithmetic case: request metadata still fits INT_MAX while the WOW64 packet array exceeds SIZE_MAX. The same assertions run before and after the implementation.

Coverage includes immediate/pending terminal outcomes, private request/event lifetime, cleanup error preservation, zero/failure counts, metadata extents, over-capacity results, zero/one request capacity, independent request/packet-array overflow, allocation failures, and all-frame validation before WOW64 output publication. Exact-ceiling copies and every copied payload are verified. The public async wrapper has a separate compatibility control. Metadata byte counts never need to contain indirect packet payloads. Native payload writes cannot be rolled back after failure.

The shim replaces device I/O, completion, SDK allocation/free and cleanup. Guarded SDK allocations end at an inaccessible page. Its SDK-only memmove hook records and refuses requests above the frame ceiling, so unsafe baseline stack copies cannot corrupt the fixture. These are explicitly modeled unsafe-copy requests; ordinary/exact-ceiling copies use the real CRT. Actual guarded indexing faults are recorded separately as failed no-fault assertions, never as successful SDK rejection. The entire test must finish with a consistent footer.

The maintained runner owns a hidden process handle, captures a numeric exit, drains both pipes concurrently, bounds execution and output draining, rejects duplicate/incomplete/inconsistent footers, and binds the SDK/header/fixture hashes before and after compilation/execution. Exit 0 means all assertions pass; exit 1 means a completed failing test; exit 2 means invalid evidence or build/setup failure. An explicit source root/output directory can run the same fixture against a frozen baseline. Tests/run_all.cmd runs both architectures. Its historical 20aa90f ablation remains specific to the separate OID suite.

These are standard-layout offline tests, not kernel/NIC/ARM64 runtime evidence. Caller storage must remain valid; concurrent caller mutation is outside the API contract. Public ABI and generic OID policy are unchanged.
