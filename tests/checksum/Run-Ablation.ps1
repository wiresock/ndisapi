param([Parameter(Mandatory=$true)][ValidateSet('x64','x86')][string]$Arch,
    [ValidateSet('standard','jumbo')][string]$Layout = 'standard',
    [ValidateSet('modern','legacy')][string]$Codec = 'modern', [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $sourceRoot "tests\bin\checksum\ablation\$Arch-$Layout-$Codec" }
$baseline = 'd5ffa791639a7ca3674d5bb4ffd1b2260f90360f'
function SourceHash([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
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
$expectedHashes = @{
        'ndisapi/ndisapi.cpp'='81172DE55D19ECE860D8D0371FE5EF44ECBC3A93C573AD6D6D7DBC68334B0C1A'
        'ndisapi/precomp.h'='F35E0858303B86602E8417C8AF9F6021EBA5452D6BF762FFE2F352B9A893BCFE'
        'ndisapi/iphlp.h'='878AB7871CF4D1679ED74513BF9FDD334EEC5079FF13CD77904EA16F5522C6C7'
        'ndisapi/resource.h'='01604134C55938C4DE1CDDBF1198C96E7BF6C1C3DE2921F654E9C7038F0291E4'
        'ndisapi/inet_checksum.h'='8A3D6BC7F2E59E9586BD399EDC7B302CFF4C8F1BAD55AF58D04D89B5CC707310'
        'include/Common.h'='9FA76D0C32774C387DDC4ADC368DFB565BF6472A592B282E79DD4C1BE013892E'
        'include/ndisapi.h'='F0BE9279706767F5370CDD3C35AF397C2CF468F7D94A7DAD70A2CF11ED994886'
}
$frozen = Join-Path $OutputDirectory 'baseline-source'
foreach ($relative in $expectedHashes.Keys) {
    $destination = Join-Path $frozen $relative
    Export-GitBlob $relative $destination
    if ((SourceHash $destination) -ne $expectedHashes[$relative]) {
        throw "Unexpected frozen baseline blob: $relative"
    }
}
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Run-Checksum.ps1') -Arch $Arch -Layout $Layout -Codec $Codec -SourceRoot $frozen -OutputDirectory $OutputDirectory -ExpectedOutcome baseline-red
$runnerExit = $LASTEXITCODE
if (-not ($runnerExit -is [int]) -or $runnerExit -ne 0) { throw 'Checksum baseline did not reproduce its exact RED contract.' }
$receipt = Get-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Raw | ConvertFrom-Json
if (-not $receipt.valid_test_evidence -or $receipt.run_exit -ne 1 -or -not $receipt.exact_failure_set) { throw 'Invalid baseline receipt.' }
[pscustomobject]@{ architecture=$Arch; layout=$Layout; codec=$Codec; baseline_commit=$baseline
    git_blob_sha256=$expectedHashes; runner_exit=$runnerExit; result_sha256=(SourceHash (Join-Path $OutputDirectory 'result.json'))
    utc=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $OutputDirectory 'ablation-result.json') -Encoding UTF8
Write-Output "Checksum ablation PASS ($Arch/$Layout/$Codec)."
exit 0
