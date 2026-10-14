param(
    [Parameter(Mandatory=$true)][ValidateSet('x64','x86')][string]$Arch,
    [ValidateSet('standard','jumbo')][string]$Layout = 'standard',
    [ValidateSet('modern','legacy')][string]$Codec = 'modern',
    [string]$SourceRoot, [string]$OutputDirectory,
    [ValidateSet('green','baseline-red')][string]$ExpectedOutcome = 'green'
)
$ErrorActionPreference = 'Stop'
function SourceHash([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
$testRoot = $PSScriptRoot
if (-not $SourceRoot) { $SourceRoot = [IO.Path]::GetFullPath((Join-Path $testRoot '..\..')) }
$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $SourceRoot "tests\bin\checksum\$Arch-$Layout-$Codec" }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$inputPaths = @(
    'ndisapi\ndisapi.cpp', 'ndisapi\precomp.h', 'ndisapi\inet_checksum.h',
    'ndisapi\iphlp.h', 'ndisapi\resource.h', 'include\Common.h', 'include\ndisapi.h'
) | ForEach-Object { Join-Path $SourceRoot $_ }
$inputPaths += @('checksum_ceiling_test.cpp', 'build_checksum.cmd', 'Run-Checksum.ps1') |
    ForEach-Object { Join-Path $testRoot $_ }
$before = [ordered]@{}
foreach ($path in $inputPaths) { $before[$path] = SourceHash $path }
& (Join-Path $testRoot 'build_checksum.cmd') $Arch $Layout $Codec $SourceRoot $OutputDirectory
$buildExit = $LASTEXITCODE
if (-not ($buildExit -is [int]) -or $buildExit -ne 0) {
    if (Test-Path -LiteralPath (Join-Path $OutputDirectory 'build.log')) {
        Get-Content -LiteralPath (Join-Path $OutputDirectory 'build.log')
    }
    exit 2
}
$startInfo = New-Object Diagnostics.ProcessStartInfo
$startInfo.FileName = Join-Path $OutputDirectory 'checksum_ceiling_test.exe'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.WorkingDirectory = $OutputDirectory
$process = New-Object Diagnostics.Process
$process.StartInfo = $startInfo
$logPath = Join-Path $OutputDirectory 'run.log'
try {
    if (-not $process.Start()) { throw 'Test process did not start.' }
    # Retain the process handle and drain both pipes concurrently. A missing
    # ExitCode, incomplete output, timeout or crash can never be a test verdict.
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit(30000)
    if ($timedOut) {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'Timed-out test did not terminate.' }
    }
    $runExit = $process.ExitCode
    $outputDrained = [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 5000)
    if ($outputDrained) {
        [IO.File]::WriteAllText($logPath, $stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'stderr.log'), $stderr.GetAwaiter().GetResult())
    } else {
        [IO.File]::WriteAllText($logPath, '')
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'stderr.log'), 'Output drain timed out.')
    }
}
finally { $process.Dispose() }
$after = [ordered]@{}
$sourceChanged = $false
foreach ($path in $inputPaths) {
    $after[$path] = SourceHash $path
    if ($before[$path] -ne $after[$path]) { $sourceChanged = $true }
}
$log = [IO.File]::ReadAllText($logPath)
$footer = [regex]::Match($log, '(?m)^SUMMARY cases=(\d+) checks=(\d+) failures=(\d+) access_violations=(\d+)\r?\nRESULT=([01])\r?\n?\z')
$summaryCount = [regex]::Matches($log, '(?m)^SUMMARY ').Count
$verdictCount = [regex]::Matches($log, '(?m)^RESULT=').Count
$actualFailures = @([regex]::Matches($log, '(?m)^\[FAIL\] (.+)\r?$') | ForEach-Object { $_.Groups[1].Value.TrimEnd() })
$assertionLines = [regex]::Matches($log, '(?m)^\[(PASS|FAIL)\] ').Count
$expectedFailures = @()
if ($ExpectedOutcome -eq 'baseline-red') {
    foreach ($api in @('cpp','c')) {
        foreach ($kind in @('ip','icmp','tcp','udp')) {
            foreach ($length in 0..2) {
                $expectedFailures += "ceiling/$api-$kind/length-$length/metadata: oversized length returns before frame access"
                $expectedFailures += "ceiling/$api-$kind/length-$length/full: entire oversized packet is unchanged"
                if ($kind -ne 'ip') {
                    $expectedFailures += "ceiling/$api-$kind/length-$length/full: oversized length never reads beyond fixed array"
                }
            }
        }
    }
}
$exactFailures = $actualFailures.Count -eq $expectedFailures.Count -and
    ((@($actualFailures | Sort-Object) -join "`n") -ceq (@($expectedFailures | Sort-Object) -join "`n"))
$expectedExit = if ($ExpectedOutcome -eq 'baseline-red') { 1 } else { 0 }
$expectedFaults = if ($ExpectedOutcome -eq 'baseline-red') { 42 } else { 0 }
$bits = if ($Arch -eq 'x64') { 64 } else { 32 }
$wow64 = if ($Arch -eq 'x86') { 1 } else { 0 }
$capacity = if ($Layout -eq 'jumbo') { 9014 } else { 1514 }
$legacy = if ($Codec -eq 'legacy') { 1 } else { 0 }
$config = "CONFIG pointer_bits=$bits wow64=$wow64 frame_capacity=$capacity legacy_codec=$legacy"
$configLines = @([IO.File]::ReadAllLines($logPath) | Where-Object { $_.StartsWith('CONFIG ') })
$invalidReason = ''
if ($timedOut) { $invalidReason = 'Timed out.' }
elseif (-not $outputDrained) { $invalidReason = 'Output drain timed out.' }
elseif ($sourceChanged) { $invalidReason = 'SDK or fixture inputs changed during build/run.' }
elseif (-not ($runExit -is [int]) -or $runExit -ne $expectedExit) { $invalidReason = 'Child did not return the required numeric test verdict.' }
elseif (-not $footer.Success -or $summaryCount -ne 1 -or $verdictCount -ne 1) { $invalidReason = 'Missing, duplicate or nonterminal SUMMARY/RESULT footer.' }
elseif ($configLines.Count -ne 1 -or $configLines[0] -cne $config) { $invalidReason = 'Wrong architecture, WOW64, layout or checksum branch.' }
elseif (-not $exactFailures -or $assertionLines -ne 775 -or
    $footer.Groups[1].Value -ne '181' -or $footer.Groups[2].Value -ne '775' -or
    [int]$footer.Groups[3].Value -ne $expectedFailures.Count -or
    [int]$footer.Groups[4].Value -ne $expectedFaults -or
    [int]$footer.Groups[5].Value -ne $runExit) { $invalidReason = 'Footer or assertions differ from the exact regression contract.' }
$artifacts = [ordered]@{}
foreach ($name in @('checksum_ceiling_test.exe','build.log','environment.log','run.log','stderr.log')) {
    $artifacts[$name] = SourceHash (Join-Path $OutputDirectory $name)
}
[pscustomobject]@{
    architecture=$Arch; layout=$Layout; codec=$Codec; source_root=$SourceRoot
    expected_outcome=$ExpectedOutcome; build_exit=$buildExit; run_exit=$runExit
    input_sha256_before=$before; input_sha256_after=$after; artifact_sha256=$artifacts
    valid_test_evidence=($invalidReason -eq ''); invalid_reason=$invalidReason
    complete_footer=$footer.Value.TrimEnd(); exact_failure_set=$exactFailures
    assertion_lines=$assertionLines; failed_assertions=$actualFailures.Count
    timeout_seconds=30; output_drain_seconds=5; utc=[DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
Get-Content -LiteralPath $logPath -Tail 3
if ($invalidReason) { Write-Output "INVALID TEST EVIDENCE: $invalidReason"; exit 2 }
Write-Output "Checksum $ExpectedOutcome contract PASS ($Arch/$Layout/$Codec)."
exit 0
