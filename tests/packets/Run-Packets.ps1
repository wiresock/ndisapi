param([ValidateSet('x64','x86')][string]$Arch, [string]$SourceRoot, [string]$OutputDirectory, [ValidateSet('All','Packets','Events')][string]$Suite='All')
$ErrorActionPreference = 'Stop'
function SourceHash([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
$testRoot = $PSScriptRoot
if (-not $SourceRoot) { $SourceRoot = [IO.Path]::GetFullPath((Join-Path $testRoot '..\..')) }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $SourceRoot "tests\bin\packets\$Arch" }
if ($Suite -eq 'All') {
    $shell = (Get-Process -Id $PID).Path
    $overall = 0
    foreach ($childSuite in @('Packets','Events')) {
        & $shell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Arch $Arch -SourceRoot $SourceRoot -OutputDirectory (Join-Path $OutputDirectory $childSuite.ToLowerInvariant()) -Suite $childSuite
        $childExit = $LASTEXITCODE
        if (-not ($childExit -is [int]) -or $childExit -notin @(0,1,2)) { $childExit = 2 }
        if ($childExit -gt $overall) { $overall = $childExit }
    }
    exit $overall
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$inputPaths = @(
    'ndisapi\ndisapi.cpp', 'ndisapi\precomp.h', 'ndisapi\inet_checksum.h',
    'ndisapi\iphlp.h', 'ndisapi\resource.h', 'include\Common.h', 'include\ndisapi.h'
) | ForEach-Object { Join-Path $SourceRoot $_ }
$inputPaths += @('packets_test.cpp', 'packets_shim.cpp', 'packets_shim.h', 'packets_events_test.cpp', 'packets_events_shim.cpp', 'packets_events_shim.h', 'build_packets.cmd', 'Run-Packets.ps1') |
    ForEach-Object { Join-Path $testRoot $_ }
$before = [ordered]@{}
foreach ($path in $inputPaths) { $before[$path] = SourceHash $path }
& (Join-Path $testRoot 'build_packets.cmd') $Arch $SourceRoot $OutputDirectory
$buildExit = $LASTEXITCODE
if (-not ($buildExit -is [int]) -or $buildExit -ne 0) {
    Get-Content -LiteralPath (Join-Path $OutputDirectory 'build.log')
    exit 2
}
$logPath = Join-Path $OutputDirectory 'run.log'
$startInfo = New-Object Diagnostics.ProcessStartInfo
$executable = if ($Suite -eq 'Events') { 'packets_events_test.exe' } else { 'packets_test.exe' }
$startInfo.FileName = Join-Path $OutputDirectory $executable
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
$footer = [regex]::Match($log, '(?m)^([0-9]+) checks, ([0-9]+) failures, ([0-9]+) guarded faults, ([0-9]+) scoped checks\r?\nRESULT=([01])\r?\n?\z')
$summaryCount = [regex]::Matches($log, '(?m)^[0-9]+ checks, [0-9]+ failures, [0-9]+ guarded faults, [0-9]+ scoped checks\r?$').Count
$verdictCount = [regex]::Matches($log, '(?m)^RESULT=').Count
$failureLines = [regex]::Matches($log, '(?m)^\[FAIL\] ').Count
$faultLines = [regex]::Matches($log, '(?m)^\[FAULT\] ').Count
$invalidReason = ''
if ($timedOut) { $invalidReason = 'Timed out.' }
elseif (-not $outputDrained) { $invalidReason = 'Output drain timed out.' }
elseif ($sourceChanged) { $invalidReason = 'SDK or fixture inputs changed during build/run.' }
elseif (-not ($runExit -is [int]) -or ($runExit -ne 0 -and $runExit -ne 1)) { $invalidReason = 'Child did not return a numeric test verdict (crash/setup failure).' }
elseif (-not $footer.Success -or $summaryCount -ne 1 -or $verdictCount -ne 1) { $invalidReason = 'Missing, duplicate, or nonterminal checks/RESULT footer.' }
else {
    $checks = [int64]$footer.Groups[1].Value
    $failures = [int64]$footer.Groups[2].Value
    $faults = [int64]$footer.Groups[3].Value
    $scoped = [int64]$footer.Groups[4].Value
    if ([int]$footer.Groups[5].Value -ne $runExit -or
        ($failures -eq 0) -ne ($runExit -eq 0) -or
        $checks -le 0 -or $scoped -le 0 -or $scoped -gt $checks -or
        $failures -gt $checks -or $faults -gt $failures -or
        $failureLines -ne $failures -or $faultLines -ne $faults) {
        $invalidReason = 'Footer disagrees with numeric child exit or assertion/fault counts.'
    }
}
Get-Content -LiteralPath $logPath -Tail 5
[pscustomobject]@{
    architecture=$Arch; suite=$Suite; source_root=$SourceRoot; build_exit=$buildExit; run_exit=$runExit
    input_sha256_before=$before; input_sha256_after=$after
    valid_test_evidence=($invalidReason -eq ''); invalid_reason=$invalidReason
    summary_count=$summaryCount; verdict_count=$verdictCount; failed_assertions=$failureLines; guarded_faults=$faultLines
    timeout_seconds=30; output_drain_seconds=5; utc=[DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
if ($invalidReason) { Write-Output "INVALID TEST EVIDENCE: $invalidReason"; exit 2 }
exit $runExit
