# Checksum fixed-array ceilings

`Run-Checksum.ps1 -Arch x64` compiles the complete real SDK translation unit and
runs the unchanged prepared `checksum_ceiling_test.cpp` oracle. `-Arch x86`
requires a genuine WOW64 process. `-Layout jumbo` selects the 9,014-byte frame;
the default standard frame is 1,514 bytes. `-Codec legacy` compiles the
`INET_CHECKSUM_FORCE_LEGACY_COMPAT` branch; the default is modern. `run_all.cmd`
runs all eight combinations. No driver is opened and no kernel operation occurs.

Each run contains 181 cases and 775 checks. Four static C++ methods and all four
C exports receive `MAX_ETHER_FRAME + 1`, 65,535 and `MAXDWORD`. Metadata before a
PAGE_NOACCESS frame proves the early return occurs before any frame access. A
whole guarded INTERMEDIATE_BUFFER with a recognized protocol and an IP extent
one byte beyond its fixed array proves oversized packets remain byte-identical.
Caught access violations count as failures, never as successful rejection.

The 120 valid whole-packet golden cases cover protocol-header-bearing zero/odd/even
payloads, 20/24/60-byte IP headers, maximum-minus-one and maximum frames. A byte-pair
oracle is pinned by an independent IPv4 vector (0xb861); only intended checksum
bytes may change. Real `inet_checksum::sum16_be` also receives exact guarded spans
of 0/1/2/3/4/15/16/17/31/32/33/MAX-1/MAX bytes. The existing odd-tail algorithm is
unchanged. These tests do not claim a new NULL-pointer contract or comprehensive
validation of malformed short captures or every invalid IPv4 header.

`run_all.cmd ablation` additionally exports all seven SDK source/header Git blobs
from accepted pre-ceiling commit `3281bcfe15080e4e8c927ea98663751a3430a317`, verifies
their pinned SHA-256 hashes and compiles this same oracle. The only accepted RED
result is exactly 181 cases / 775 checks / 66 named failures / 42 caught access
violations with numeric process exit 1. Valid golden and accumulator controls must
still pass. Ordinary GREEN requires zero failures and zero access violations.
The prepared oracle's SHA-256 is
`B3FB8E4DA7A09D3E11A9BD143AAB54FD342BFC3B42EE2C46BF179E2E7C54708E`.

The maintained runner owns the child process handle and drains both pipes
concurrently, imposes a 30-second execution and 5-second drain/termination limit,
requires one terminal adjacent SUMMARY/RESULT pair and exactly 775 assertion rows,
and checks numeric exit, architecture, WOW64 state, frame layout and codec branch.
It hashes the seven real source/header inputs plus fixture/runner/build script
before and after execution. A timeout, crash, missing exit, incomplete footer,
unexpected failure or changed source cannot pass. Per-run `result.json` records
input and executable/log hashes. VS2022 Professional is the default toolchain;
`VCVARSALL` can select another installed compiler and the parent aggregate runner
supplies its discovered toolchain. Build environment details remain in
`environment.log` and `build.log`.
