param([Parameter(Mandatory=$true)][ValidateSet('x64','x86')][string]$Arch,
    [ValidateSet('standard','jumbo')][string]$Layout = 'standard',
    [ValidateSet('all','baseline','capacity')][string]$Kind = 'all',
    [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
function SourceHash([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $sourceRoot "tests\bin\fastio_reader\ablation\$Arch-$Layout" }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$baseline = '0b0f21fddd0032b0b236b01d35ea4145bec4d0e7'
function Export-GitBlob([string]$RelativePath, [string]$Destination) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    $process = New-Object Diagnostics.Process
    $process.StartInfo = New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = 'git'
    $process.StartInfo.Arguments = '-C "' + $sourceRoot + '" show "' + $baseline + ':' + $RelativePath + '"'
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    try {
        if (-not $process.Start()) { throw 'git show did not start.' }
        $errorOutput = $process.StandardError.ReadToEndAsync()
        $stream = [IO.File]::Create($Destination)
        try { $process.StandardOutput.BaseStream.CopyTo($stream) } finally { $stream.Dispose() }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw ('git show failed: ' + $errorOutput.GetAwaiter().GetResult()) }
    } finally { $process.Dispose() }
}
function Check-Red([string]$Name, [string]$Path, [int]$RunnerExit, [string[]]$Expected) {
    $receipt = Get-Content -LiteralPath (Join-Path $Path 'result.json') -Raw | ConvertFrom-Json
    $lines = [IO.File]::ReadAllLines((Join-Path $Path 'run.log'))
    $actual = @($lines | Where-Object { $_.StartsWith('[FAIL] ') })
    if ($RunnerExit -ne 1 -or $receipt.run_exit -ne 1 -or -not $receipt.valid_test_evidence -or
        $actual.Count -ne $Expected.Count -or ($actual -join "`n") -cne ($Expected -join "`n")) {
        throw "$Name did not produce the exact attributed RED failures."
    }
    if ($Name -eq 'baseline') {
        $complete = @($lines | Where-Object { $_.StartsWith('TRACE late-complete ') })
        $pending = @($lines | Where-Object { $_.StartsWith('TRACE late-busy-complete ') })
        if ($complete.Count -ne 1 -or -not $complete[0].EndsWith('writer=1/1/requeued=0') -or
            $pending.Count -ne 1 -or -not $pending[0].EndsWith('writer=1/0/requeued=1')) {
            throw 'Baseline did not preserve completed-loss versus pending-requeue attribution.'
        }
    }
    [pscustomobject]@{ kind=$Name; valid_test_evidence=$true; exact_failures=$actual; run_exit=1; receipt=(Join-Path $Path 'result.json') }
}
$results = @()
if ($Kind -eq 'all' -or $Kind -eq 'baseline') {
    $frozen = Join-Path $OutputDirectory 'baseline-source'
    $expectedHashes = @{
        'include/Common.h'='020DB86AE6433CFF112C93F1DDE3DB2FA526EB5A8CB6EC431EC9FE2A7FCD8BAB'
        'examples/cpp/common/ndisapi/fastio_packet_filter.h'='93EB2AAF046F449526C63A03BE5A3785981B30651F4A77D5D1FD67F15559F7DC'
    }
    foreach ($relative in $expectedHashes.Keys) {
        $destination = Join-Path $frozen $relative
        Export-GitBlob $relative $destination
        if ((SourceHash $destination) -ne $expectedHashes[$relative]) {
            throw "Unexpected frozen baseline blob: $relative"
        }
    }
    $out = Join-Path $OutputDirectory 'baseline'
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Run-Reader.ps1') -Arch $Arch -Layout $Layout -SourceRoot $frozen -OutputDirectory $out -WorkerOnly
    $rc = $LASTEXITCODE
    if (-not ($rc -is [int])) { throw 'Missing baseline runner exit code.' }
    $contract = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'worker-red-contract.json') -Raw | ConvertFrom-Json
    $results += Check-Red 'baseline' $out $rc $contract.$Layout.exact_failures
}
if ($Kind -eq 'all' -or $Kind -eq 'capacity') {
    $mutant = Join-Path $OutputDirectory 'capacity-source'
    $headerRelative = 'examples/cpp/common/ndisapi/fastio_packet_filter.h'
    foreach ($relative in @('include/Common.h', $headerRelative)) {
        $destination = Join-Path $mutant $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
        Copy-Item -LiteralPath (Join-Path $sourceRoot $relative) -Destination $destination -Force
    }
    $header = Join-Path $mutant $headerRelative
    $text = [IO.File]::ReadAllText($header)
    $needle = 'count > capacity'
    if ([regex]::Matches($text, [regex]::Escape($needle)).Count -ne 1) { throw 'Capacity ablation target is ambiguous.' }
    # Remove only the remaining-capacity refusal. Keep the physical bound,
    # copied cursor, reset CAS, reader-claim guard, and every other branch.
    $text = $text.Replace($needle, '(count > capacity && false)')
    [IO.File]::WriteAllText($header, $text, [Text.UTF8Encoding]::new($false))
    $out = Join-Path $OutputDirectory 'capacity'
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Run-Reader.ps1') -Arch $Arch -Layout $Layout -SourceRoot $mutant -OutputDirectory $out
    $rc = $LASTEXITCODE
    if (-not ($rc -is [int])) { throw 'Missing capacity runner exit code.' }
    $expected = @(
        '[FAIL] helper-initial-insufficient: helper returns normally'
        '[FAIL] helper-initial-insufficient: helper rejects before any over-capacity copy attempt'
        '[FAIL] helper-initial-insufficient: no excess-tail copy is attempted after reset contention'
        '[FAIL] helper-late-over-remaining: helper returns normally'
        '[FAIL] helper-late-over-remaining: helper rejects before any over-capacity copy attempt'
        '[FAIL] helper-late-over-remaining: no excess-tail copy is attempted after reset contention'
    )
    $results += Check-Red 'capacity' $out $rc $expected
}
[pscustomobject]@{ architecture=$Arch; layout=$Layout; baseline_commit=$baseline; results=$results; utc=[DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'ablation-result.json') -Encoding UTF8
Write-Output "FastIO reader $Kind ablation PASS ($Arch/$Layout)."
exit 0