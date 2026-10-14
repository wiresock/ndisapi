param(
 [Parameter(Mandatory=$true)][ValidateSet('x86','x64')][string]$Arch,
 [Parameter(Mandatory=$true)][string]$SdkRoot,
 [Parameter(Mandatory=$true)][string]$DriverRoot,
 [Parameter(Mandatory=$true)][string]$GslIncludeRoot,
 [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$SdkRoot = (Resolve-Path -LiteralPath $SdkRoot).Path
$DriverRoot = (Resolve-Path -LiteralPath $DriverRoot).Path
$GslIncludeRoot = (Resolve-Path -LiteralPath $GslIncludeRoot).Path
if (-not $OutputDirectory) {
 $OutputDirectory = Join-Path $SdkRoot ('tests\bin\fastio_lifecycle\' + $Arch + '-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory must be new; previous evidence must be preserved.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'temp') | Out-Null
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
$inputs = @()
foreach ($dir in @('include','ndisapi','examples\cpp\common')) {
 $inputs += Get-ChildItem -LiteralPath (Join-Path $SdkRoot $dir) -File -Recurse | Where-Object { $_.Extension -in '.h','.cpp' } | ForEach-Object { [pscustomobject]@{path=$_.FullName; snapshot='sdk\' + $_.FullName.Substring($SdkRoot.Length+1)} }
}
foreach ($rel in @('LWF\precomp.h','LWF\fastio.c','LWF\fastio.h','LWF\lifecycle.c','LWF\lifecycle.h','LWF\wanclass.h','LWF\w45diag.h','common\iphlp.h','tests\shim_lwf\precomp.h','tests\shim_lwf\shim_lwf.c')) {
 $inputs += [pscustomobject]@{path=(Join-Path $DriverRoot $rel); snapshot='driver\' + $rel}
}
$driverCommon = [IO.Path]::GetFullPath((Join-Path $DriverRoot '..\ndisapi\include\Common.h'))
if ((Hash $driverCommon) -ne (Hash (Join-Path $SdkRoot 'include\Common.h'))) { throw 'SDK and driver Common.h differ; this integration requires matching ABI definitions.' }
$inputs += [pscustomobject]@{path=$driverCommon; snapshot='driver-sdk\include\Common.h'}
$inputs += Get-ChildItem -LiteralPath (Join-Path $GslIncludeRoot 'gsl') -File -Recurse | ForEach-Object { [pscustomobject]@{path=$_.FullName; snapshot='gsl\'+$_.FullName.Substring($GslIncludeRoot.Length+1)} }
$inputs += Get-ChildItem -LiteralPath $PSScriptRoot -File | ForEach-Object { [pscustomobject]@{path=$_.FullName; snapshot='fixture\'+$_.Name} }
$before = [ordered]@{}
foreach ($input in $inputs) {
 $before[$input.path] = Hash $input.path
 $dest = Join-Path $OutputDirectory ('inputs\'+$input.snapshot)
 New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($dest)) | Out-Null
 Copy-Item -LiteralPath $input.path -Destination $dest
 if ((Hash $dest) -ne $before[$input.path]) { throw 'Snapshot hash mismatch.' }
}
$inputs | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'inputs.json') -Encoding UTF8
& (Join-Path $PSScriptRoot 'build_r5.cmd') $Arch $SdkRoot $DriverRoot $OutputDirectory $GslIncludeRoot
$buildExit = $LASTEXITCODE
Set-Content -LiteralPath (Join-Path $OutputDirectory 'build.native-exit.txt') -Value $buildExit
if (-not ($buildExit -is [int]) -or $buildExit -ne 0) { Get-Content -LiteralPath (Join-Path $OutputDirectory 'build.log'); exit 2 }
$exe = Join-Path $OutputDirectory 'r5_lifecycle_test.exe'
$bytes = [IO.File]::ReadAllBytes($exe)
$pe = [BitConverter]::ToInt32($bytes,0x3c)
$machine = [BitConverter]::ToUInt16($bytes,$pe+4)
$expectedMachine = if ($Arch -eq 'x86') { 0x14c } else { 0x8664 }
if ($machine -ne $expectedMachine) { throw 'Unexpected executable machine architecture.' }
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName=$exe; $info.WorkingDirectory=$OutputDirectory; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
$info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
$info.EnvironmentVariables['TEMP']=Join-Path $OutputDirectory 'temp'; $info.EnvironmentVariables['TMP']=Join-Path $OutputDirectory 'temp'
$process=New-Object Diagnostics.Process; $process.StartInfo=$info
try {
 if (-not $process.Start()) { throw 'Child did not start.' }
 $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
 $timedOut=-not $process.WaitForExit(60000)
 if ($timedOut) { $process.Kill(); if (-not $process.WaitForExit(5000)) { throw 'Child kill failed.' } }
 $runExit=$process.ExitCode
 $drained=[Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout,$stderr),5000)
 $out=if($drained){$stdout.GetAwaiter().GetResult()}else{''}
 $err=if($drained){$stderr.GetAwaiter().GetResult()}else{'Pipe drain timed out.'}
 [IO.File]::WriteAllText((Join-Path $OutputDirectory 'run.log'),$out)
 [IO.File]::WriteAllText((Join-Path $OutputDirectory 'stderr.log'),$err)
 Set-Content -LiteralPath (Join-Path $OutputDirectory 'child.native-exit.txt') -Value $runExit
} finally { $process.Dispose() }
$after=[ordered]@{}; $changed=$false
foreach($input in $inputs){$after[$input.path]=Hash $input.path;if($after[$input.path] -ne $before[$input.path]){$changed=$true}}
$footer=[regex]::Match($out,'(?m)^RESULT arch=(32|64) cases=([0-9]+) checks=([0-9]+) failures=([0-9]+)\r?\n?\z')
$verdicts=[regex]::Matches($out,'(?m)^RESULT ').Count
$assertions=[regex]::Matches($out,'(?m)^(PASS|FAIL) ').Count
$fails=[regex]::Matches($out,'(?m)^FAIL ').Count
$invalid=''
if($timedOut){$invalid='Child timeout.'}
elseif(-not $drained){$invalid='Output drain timeout.'}
elseif($changed){$invalid='Inputs changed during build/run.'}
elseif($err.Trim()){$invalid='Unexpected stderr.'}
elseif($out -match 'HARNESS-ERROR'){$invalid='Harness error.'}
elseif(-not ($runExit -is [int]) -or $runExit -notin 0,1){$invalid='Crash/setup exit is not a controlled test verdict.'}
elseif(-not $footer.Success -or $verdicts -ne 1){$invalid='Missing, duplicate or nonterminal footer.'}
else {
 $expectedBits=if($Arch -eq 'x86'){32}else{64}
 if([int]$footer.Groups[1].Value -ne $expectedBits -or [int]$footer.Groups[2].Value -ne 15 -or [int]$footer.Groups[3].Value -ne $assertions -or [int]$footer.Groups[4].Value -ne $fails -or (($fails -eq 0) -ne ($runExit -eq 0))){$invalid='Footer disagrees with architecture, cases, complete assertions or native exit.'}
}
[pscustomobject]@{
 architecture=$Arch; sdk_root=$SdkRoot; driver_root=$DriverRoot; gsl_include_root=$GslIncludeRoot
 build_exit=$buildExit; run_exit=$runExit; valid_test_evidence=($invalid -eq ''); invalid_reason=$invalid
 cases=15; assertion_count=$assertions; failed_assertions=$fails; timeout_seconds=60; pe_machine=$machine
 executable_sha256=(Hash $exe); input_sha256_before=$before; input_sha256_after=$after; utc=[DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
Write-Output $footer.Value
if($invalid){Write-Output "INVALID TEST EVIDENCE: $invalid"; exit 2}
exit $runExit
