param([Parameter(Mandatory=$true)][ValidateSet('x64','x86')][string]$Arch,
    [ValidateSet('standard','jumbo')][string]$Layout = 'standard', [string]$SourceRoot,
    [string]$OutputDirectory, [switch]$WorkerOnly)
$ErrorActionPreference = 'Stop'
function SourceHash([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
$testRoot = $PSScriptRoot
if (-not $SourceRoot) { $SourceRoot = [IO.Path]::GetFullPath((Join-Path $testRoot '..\..')) }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $SourceRoot "tests\bin\fastio_reader\$Arch-$Layout" }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$inputPaths = @('include\Common.h', 'examples\cpp\common\ndisapi\fastio_packet_filter.h') |
    ForEach-Object { Join-Path $SourceRoot $_ }
$inputPaths += @('fastio_reader_test.cpp', 'build_reader.cmd', 'Run-Reader.ps1') |
    ForEach-Object { Join-Path $testRoot $_ }
$before = [ordered]@{}
foreach ($path in $inputPaths) { $before[$path] = SourceHash $path }
$mode = if ($WorkerOnly) { 'worker-only' } else { 'all' }
& (Join-Path $testRoot 'build_reader.cmd') $Arch $Layout $SourceRoot $OutputDirectory $mode
$buildExit = $LASTEXITCODE
if (-not ($buildExit -is [int]) -or $buildExit -ne 0) {
    Get-Content -LiteralPath (Join-Path $OutputDirectory 'build.log')
    exit 2
}
$logPath = Join-Path $OutputDirectory 'run.log'
$startInfo = New-Object Diagnostics.ProcessStartInfo
$startInfo.FileName = Join-Path $OutputDirectory 'fastio_reader_test.exe'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.WorkingDirectory = $OutputDirectory
$startInfo.EnvironmentVariables['TEMP'] = Join-Path $OutputDirectory 'temp'
$startInfo.EnvironmentVariables['TMP'] = Join-Path $OutputDirectory 'temp'
$process = New-Object Diagnostics.Process
$process.StartInfo = $startInfo
try {
    if (-not $process.Start()) { throw 'Test process did not start.' }
    # Own the process handle and drain both pipes concurrently. Neither a lost
    # ExitCode nor a pipe deadlock may turn a failed/incomplete test into PASS.
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
$footer = [regex]::Match($log, '(?m)^([0-9]+) checks, ([0-9]+) failures\r?\nRESULT=([01])\r?\n?\z')
$summaryCount = [regex]::Matches($log, '(?m)^[0-9]+ checks, [0-9]+ failures\r?$').Count
$verdictCount = [regex]::Matches($log, '(?m)^RESULT=').Count
$failureLines = [regex]::Matches($log, '(?m)^\[FAIL\] ').Count
$assertionLines = [regex]::Matches($log, '(?m)^\[(PASS|FAIL)\] ').Count
$expectedChecks = if ($WorkerOnly) { 235 } else { 270 }
$invalidReason = ''
if ($timedOut) { $invalidReason = 'Timed out.' }
elseif (-not $outputDrained) { $invalidReason = 'Output drain timed out.' }
elseif ($sourceChanged) { $invalidReason = 'SDK or fixture inputs changed during build/run.' }
elseif ([IO.File]::ReadAllText((Join-Path $OutputDirectory 'stderr.log')).Trim()) { $invalidReason = 'Unexpected stderr output.' }
elseif (-not ($runExit -is [int]) -or ($runExit -ne 0 -and $runExit -ne 1)) { $invalidReason = 'Child did not return a numeric test verdict (crash/setup failure).' }
elseif (-not $footer.Success -or $summaryCount -ne 1 -or $verdictCount -ne 1) { $invalidReason = 'Missing, duplicate, or nonterminal checks/RESULT footer.' }
else {
    $checks = [int64]$footer.Groups[1].Value
    $failures = [int64]$footer.Groups[2].Value
    if ([int]$footer.Groups[3].Value -ne $runExit -or
        ($failures -eq 0) -ne ($runExit -eq 0) -or
        $checks -ne $expectedChecks -or $assertionLines -ne $checks -or
        $failures -gt $checks -or $failureLines -ne $failures) {
        $invalidReason = 'Footer disagrees with numeric child exit or complete assertion counts.'
    }
}
Get-Content -LiteralPath $logPath -Tail 5
[pscustomobject]@{
    architecture=$Arch; layout=$Layout; worker_only=[bool]$WorkerOnly; source_root=$SourceRoot; build_exit=$buildExit; run_exit=$runExit
    input_sha256_before=$before; input_sha256_after=$after
    valid_test_evidence=($invalidReason -eq ''); invalid_reason=$invalidReason
    summary_count=$summaryCount; verdict_count=$verdictCount; failed_assertions=$failureLines; assertion_count=$assertionLines; expected_checks=$expectedChecks
    timeout_seconds=30; output_drain_seconds=5; utc=[DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
if ($invalidReason) { Write-Output "INVALID TEST EVIDENCE: $invalidReason"; exit 2 }
exit $runExit
