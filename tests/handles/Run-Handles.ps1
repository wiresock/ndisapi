param([ValidateSet('x64','x86')][string]$Arch, [string]$SourceRoot, [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
# Hash directly so a Developer Command Prompt's inherited module search path
# cannot select an incompatible PowerShell Utility module.
function SourceHash([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
$testRoot = $PSScriptRoot
if (-not $SourceRoot) { $SourceRoot = [IO.Path]::GetFullPath((Join-Path $testRoot '..\..')) }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $SourceRoot "tests\bin\handles\$Arch" }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$sourcePath = Join-Path $SourceRoot 'ndisapi\ndisapi.cpp'
$sourceBefore = SourceHash $sourcePath
& (Join-Path $testRoot 'build_handles.cmd') $Arch $SourceRoot $OutputDirectory
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0) {
    Get-Content -LiteralPath (Join-Path $OutputDirectory 'build.log')
    exit 2
}
$logPath = Join-Path $OutputDirectory 'run.log'
# Own the process handle directly. Windows PowerShell's Start-Process -PassThru
# can lose ExitCode after a timed WaitForExit; a missing exit must never mean PASS.
$startInfo = New-Object Diagnostics.ProcessStartInfo
$startInfo.FileName = Join-Path $OutputDirectory 'handles_test.exe'
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$process = New-Object Diagnostics.Process
$process.StartInfo = $startInfo
try {
    if (-not $process.Start()) { throw 'Test process did not start.' }
    # Drain both pipes concurrently so a failing oracle cannot fill a pipe.
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit(20000)
    if ($timedOut) { $process.Kill(); $process.WaitForExit() }
    $runExit = $process.ExitCode
    $outputDrained = [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 5000)
    if ($outputDrained) {
        [IO.File]::WriteAllText($logPath, $stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'stderr.log'), $stderr.GetAwaiter().GetResult())
    }
    else {
        [IO.File]::WriteAllText($logPath, '')
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'stderr.log'), 'Output drain timed out.')
    }
}
finally { $process.Dispose() }
$sourceAfter = SourceHash $sourcePath
$log = [IO.File]::ReadAllText($logPath)
$footer = [regex]::Match($log, '(?m)^checks=([0-9]+) failures=([0-9]+) guarded_baseline_faults=([0-9]+)\r?\nRESULT=([01])\r?\n?\z')
$invalidReason = ''
if ($timedOut) { $invalidReason = 'Timed out.' }
elseif (-not $outputDrained) { $invalidReason = 'Output drain timed out.' }
elseif ($sourceBefore -ne $sourceAfter) { $invalidReason = 'SDK source changed during build/run.' }
elseif ($runExit -ne 0 -and $runExit -ne 1) { $invalidReason = 'Child did not return a test verdict (crash/setup failure).' }
elseif (-not $footer.Success) { $invalidReason = 'Missing complete checks/RESULT footer.' }
elseif ([int]$footer.Groups[4].Value -ne $runExit -or
        ([int64]$footer.Groups[2].Value -eq 0) -ne ($runExit -eq 0) -or
        [int64]$footer.Groups[1].Value -eq 0 -or
        ([int64]$footer.Groups[3].Value -ne 0 -and $runExit -eq 0)) {
    $invalidReason = 'Footer disagrees with the child exit or check/fault counts.'
}
Get-Content -LiteralPath $logPath -Tail 5
[pscustomobject]@{
    architecture=$Arch; source_root=$SourceRoot; build_exit=$buildExit; run_exit=$runExit
    source_sha256=$sourceBefore; source_sha256_after=$sourceAfter
    valid_test_evidence=($invalidReason -eq ''); invalid_reason=$invalidReason
    utc=[DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
if ($invalidReason) { Write-Output "INVALID TEST EVIDENCE: $invalidReason"; exit 2 }
exit $runExit
