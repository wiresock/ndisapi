param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root ('tests\bin\safe-gates\' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '-' + [Guid]::NewGuid().ToString('N')) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists; preserving prior evidence.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$shell = (Get-Process -Id $PID).Path
function HashFile([string]$p) {
    $a=[Security.Cryptography.SHA256]::Create(); $f=[IO.File]::OpenRead($p)
    try { [BitConverter]::ToString($a.ComputeHash($f)).Replace('-','') } finally { $f.Dispose(); $a.Dispose() }
}
$results = New-Object Collections.Generic.List[object]
$overall=0
foreach ($arch in @('x64','x86')) {
    foreach ($kind in @('handles','packets')) {
        $runner = if ($kind -eq 'handles') { Join-Path $PSScriptRoot 'Run-Handles.ps1' } else { Join-Path $root 'tests\packets\Run-Packets.ps1' }
        $positive = Join-Path $OutputDirectory ("positive-$kind-$arch")
        & $shell -NoProfile -ExecutionPolicy Bypass -File $runner -Arch $arch -SourceRoot $root -OutputDirectory $positive
        $rc=$LASTEXITCODE
        $results.Add([pscustomobject]@{kind=$kind; architecture=$arch; control='positive'; runner_exit=$rc; directory=$positive})
        if ($rc -ne 0) { $overall=1 }
        if ($kind -eq 'handles' -and $arch -eq 'x64') { continue } # Conversion is WOW64-only.
        $negative=Join-Path $OutputDirectory ("negative-$kind-$arch")
        $frozen=Join-Path $negative 'source'
        New-Item -ItemType Directory -Path $frozen | Out-Null
        foreach ($dir in @('include','ndisapi')) {
            New-Item -ItemType Directory -Path (Join-Path $frozen $dir) | Out-Null
            Get-ChildItem -LiteralPath (Join-Path $root $dir) -File | Copy-Item -Destination (Join-Path $frozen $dir)
        }
        $hashes=[ordered]@{}
        Get-ChildItem -LiteralPath $frozen -Recurse -File | ForEach-Object { $hashes[$_.FullName.Substring($frozen.Length+1)]=HashFile $_.FullName }
        $path=Join-Path $frozen 'ndisapi\ndisapi.cpp'
        $source=[IO.File]::ReadAllText($path)
        $mutations=@()
        if ($kind -eq 'handles') {
            # Locate within the exact bounded conversion method rather than other returns.
            $start=$source.IndexOf('    BOOL From32to64Handle(')
            $end=$source.IndexOf('    BOOL From64to32Handle(', $start)
            if ($start -lt 0 -or $end -lt 0) { throw 'Missing bounded conversion method.' }
            $method=$source.Substring($start,$end-$start)
            $anchor="        return TRUE;`r`n    }"
            if ([regex]::Matches($method,[regex]::Escape($anchor)).Count -ne 1) { throw 'Ambiguous handle mutation.' }
            $changed=$method.Replace($anchor,"        result = 0; // Safe gate: lose validated logical identity only.`r`n"+$anchor)
            $source=$source.Substring(0,$start)+$changed+$source.Substring($end)
            $mutations+=@{old=$anchor;new=("        result = 0; // Safe gate: lose validated logical identity only.`r`n"+$anchor);occurrences=1}
            $signature='initial valid mapping/.*: expected full adapter identity submitted once'
        } else {
            $a='    caller->dwPacketsSuccess = count;'
            if ([regex]::Matches($source,[regex]::Escape($a)).Count -ne 1) { throw 'Ambiguous WOW64 publication.' }
            $source=$source.Replace($a,'    caller->dwPacketsSuccess = 0; // Safe gate: validated publication only.')
            $start=$source.IndexOf('BOOL CNdisApi::ReadPackets(')
            $end=$source.IndexOf('/**',$start)
            if ($start -lt 0 -or $end -lt 0) { throw 'Missing native ReadPackets.' }
            $method=$source.Substring($start,$end-$start)
            $a="    return TRUE;`r`n}"
            if ([regex]::Matches($method,[regex]::Escape($a)).Count -ne 1) { throw 'Ambiguous native publication.' }
            $source=$source.Substring(0,$start)+$method.Replace($a,"    pPackets->dwPacketsSuccess = 0; // Safe gate: validated publication only.`r`n"+$a)+$source.Substring($end)
            $mutations+=@{old='    caller->dwPacketsSuccess = count;';new='    caller->dwPacketsSuccess = 0; // Safe gate: validated publication only.';occurrences=1}
            $mutations+=@{old=$a;new=("    pPackets->dwPacketsSuccess = 0; // Safe gate: validated publication only.`r`n"+$a);occurrences=1}
            $signature='READ_MANY/.*(count published only on valid success|exact bounded count|one packet count)'
        }
        [IO.File]::WriteAllText($path,$source,(New-Object Text.UTF8Encoding($false)))
        $candidate=HashFile $path
        [pscustomobject]@{original_hashes=$hashes; candidate_sdk_sha256=$candidate; mutations=$mutations} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $negative 'mutation.json') -Encoding UTF8
        $run=Join-Path $negative 'run'
        $args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$runner,'-Arch',$arch,'-SourceRoot',$frozen,'-OutputDirectory',$run)
        if ($kind -eq 'packets') { $args+=@('-Suite','Packets') }
        & $shell @args
        $rc=$LASTEXITCODE
        $receipt=Join-Path $run 'result.json'
        $valid=$false; $reason='Missing receipt.'
        if (Test-Path $receipt) {
            $r=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
            $log=[IO.File]::ReadAllText((Join-Path $run 'run.log'))
            $faults=if ($kind -eq 'handles') { [regex]::Match($log,'guarded_baseline_faults=([0-9]+)').Groups[1].Value } else { [regex]::Match($log,'([0-9]+) guarded faults').Groups[1].Value }
            $named=[regex]::IsMatch($log,'(?m)^\[FAIL\] .*'+$signature)
            $valid=($rc -eq 1 -and $r.build_exit -eq 0 -and $r.run_exit -eq 1 -and $r.valid_test_evidence -eq $true -and $faults -eq '0' -and $named -and (HashFile $path) -eq $candidate)
            $reason=if ($valid) { '' } else { 'Negative must have exit1, valid receipt, zero faults, relevant assertion and frozen source.' }
        }
        $results.Add([pscustomobject]@{kind=$kind;architecture=$arch;control='negative';runner_exit=$rc;valid_gate=$valid;reason=$reason;directory=$negative})
        if (-not $valid) { $overall=1 }
    }
}
[pscustomobject]@{result=$overall; runs=$results; historical_oid_executed=$false} | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputDirectory 'safe-gates-result.json') -Encoding UTF8
Write-Output "SAFE GATES RESULT=$overall output=$OutputDirectory"
exit $overall
