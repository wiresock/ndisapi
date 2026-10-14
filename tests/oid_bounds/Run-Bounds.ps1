param([ValidateSet('x64','x86')][string]$Arch,[string]$SourceRoot=(Join-Path $PSScriptRoot '..\..'),[string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(-not $OutputDirectory) { $OutputDirectory=Join-Path $PSScriptRoot ("..\bin\oid_bounds\$Arch-"+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)) }
$SourceRoot=[IO.Path]::GetFullPath($SourceRoot)
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists; choose a fresh evidence directory' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
function Hash([string]$Path) {
    $alg=[Security.Cryptography.SHA256]::Create();$stream=[IO.File]::OpenRead($Path)
    try {[BitConverter]::ToString($alg.ComputeHash($stream)).Replace('-','')}
    finally {$stream.Dispose();$alg.Dispose()}
}
$inputs=@('ndisapi\ndisapi.cpp','include\ndisapi.h','include\Common.h','ndisapi\precomp.h','ndisapi\iphlp.h','ndisapi\inet_checksum.h') | ForEach-Object {Join-Path $SourceRoot $_}
$inputs+=@('bounds_shim.h','bounds_shim.cpp','bounds_test.cpp','build_bounds.cmd','Run-Bounds.ps1') | ForEach-Object {Join-Path $PSScriptRoot $_}
$before=[ordered]@{};foreach($path in $inputs) {$before[$path]=Hash $path}
& (Join-Path $PSScriptRoot 'build_bounds.cmd') $Arch $SourceRoot $OutputDirectory
$buildExit=$LASTEXITCODE
if(-not ($buildExit -is [int]) -or $buildExit -ne 0) {
    Get-Content -LiteralPath (Join-Path $OutputDirectory 'build.log') -Tail 30
    exit 2
}
$si=New-Object Diagnostics.ProcessStartInfo
$si.FileName=Join-Path $OutputDirectory 'bounds_test.exe'
$si.WorkingDirectory=$OutputDirectory
$si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
$process=New-Object Diagnostics.Process;$process.StartInfo=$si
try {
    if(-not $process.Start()) {throw 'Could not start offline fixture'}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $timeout=-not $process.WaitForExit(30000)
    if($timeout) {$process.Kill();$process.WaitForExit()}
    $runExit=$process.ExitCode
    if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)) {throw 'Output drain timed out'}
    $log=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'run.log'),$log)
    [IO.File]::WriteAllText((Join-Path $OutputDirectory 'stderr.log'),$err)
} finally {$process.Dispose()}
$after=[ordered]@{};$drift=$false
foreach($path in $inputs) {$after[$path]=Hash $path;if($after[$path] -ne $before[$path]) {$drift=$true}}
$footer=[regex]::Match($log,'(?m)^([0-9]+) checks, ([0-9]+) failures\r?\nRESULT=([01])\r?\n?\z')
$assertions=[regex]::Matches($log,'(?m)^\[(PASS|FAIL)\] ').Count
$failed=[regex]::Matches($log,'(?m)^\[FAIL\] ').Count
$invalid=''
if($timeout) {$invalid='Runtime timeout'}
elseif($drift) {$invalid='Input changed'}
elseif($err.Trim()) {$invalid='Unexpected stderr'}
elseif(-not ($runExit -is [int]) -or $runExit -notin @(0,1)) {$invalid='Abnormal child exit'}
elseif(-not $footer.Success -or [regex]::Matches($log,'(?m)^RESULT=').Count -ne 1) {$invalid='Invalid footer'}
elseif([int]$footer.Groups[1].Value -ne 416 -or $assertions -ne 416 -or [int]$footer.Groups[2].Value -ne $failed -or [int]$footer.Groups[3].Value -ne $runExit -or (($failed -eq 0) -ne ($runExit -eq 0))) {$invalid='Incomplete or inconsistent verdict'}
elseif($Arch -eq 'x86' -and $log -notmatch '(?m)^branch=WOW64 ') {$invalid='x86 did not execute genuine WOW64'}
elseif($Arch -eq 'x64' -and $log -notmatch '(?m)^branch=native ') {$invalid='x64 did not execute native branch'}
$controlFailures=[regex]::Matches($log,'(?m)^\[FAIL\].*(valid=|pending failure|exact INT_MAX envelope)').Count
[pscustomobject]@{architecture=$Arch;build_exit=$buildExit;run_exit=$runExit;checks=$assertions;failures=$failed;control_failures=$controlFailures;valid_evidence=($invalid -eq '');invalid_reason=$invalid;before=$before;after=$after;utc=[DateTime]::UtcNow.ToString('o')} |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
$log.Split([char]10) | Select-Object -First 1
$log.Split([char]10) | Select-Object -Last 4
Write-Output "control_failures=$controlFailures valid_evidence=$($invalid -eq '')"
if($invalid) {Write-Output $invalid;exit 2}
exit $runExit
