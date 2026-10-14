# OID request byte extents

Run `powershell -NoProfile -ExecutionPolicy Bypass -File tests/oid_bounds/Run-Bounds.ps1 -Arch x64` and repeat with `-Arch x86`. Optional `-SourceRoot` selects a checkout and `-OutputDirectory` selects a fresh evidence directory. Default outputs have unique names under `tests/bin/oid_bounds`. Existing evidence directories are refused.

The fixture compiles the complete actual SDK translation unit, constructor, WOW64 handle mapping, request method and C export. It exercises GET and SET through both C and C++ entry points. The 32-bit process must run on 64-bit Windows and report its genuine WOW64 branch; x64 reports native.

Each architecture requires 416 checks: zero lengths and values beyond the signed IOCTL byte extent must return FALSE before creating an event, allocating, copying payload or submitting an IOCTL. Caller bytes and canaries must remain unchanged. The exact INT_MAX serialized extent reaches a controlled allocator or IOCTL refusal without allocating gigabytes or accessing the claimed payload. Valid one-, four- and eight-byte requests retain generic OID behavior, short replies, immediate/pending success and terminal failures.

Win32 device I/O, completion and event/handle recording are substituted. SDK staging allocations are bounded to one MiB and end at a guard page; oversized copies are intercepted before memory access and fail an assertion. Any caught access fault is a failed check. No driver is loaded and no actual large request is sent. These are bounded source-level checks, not NDIS or live kernel validation.

The runner records numeric build/child exits, actual branch, a complete assertion/footer count, unchanged source/fixture hashes and a 30-second execution limit. Compilation errors, timeouts, abnormal exits and inconsistent output never count as a passing test.
