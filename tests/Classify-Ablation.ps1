<#
.SYNOPSIS
  Decide what an ablation run actually proved.

.DESCRIPTION
  An ablation is the claim "the old code fails these tests". That is evidence only when the old
  code BUILT, RAN TO A VERDICT, terminated NORMALLY, exited with the assertion-failure code, and
  failed for the REQUIRED reason. Every other outcome looks similar from the outside and proves
  nothing - which is the point: a runner that reads any nonzero exit as success is satisfied by a
  compile error, by a crash, and by a test that failed for an unrelated reason.

  The classifications:

    COMPILE_FAILED              the pre-change sources did not build
    SETUP_FAILED                they could not be produced at all
    TEST_CRASHED                the child terminated abnormally, or produced no verdict
    UNEXPECTED_PASS             it ran and passed - the tests do not test the change
    EXPECTED_ASSERTION_FAILURE  the only accepted outcome
    INVALID_EVIDENCE            it ran to a verdict, but not the one required: the wrong exit
                                code, no failing verdict, or the required signature absent

  INVALID_EVIDENCE is a sixth name deliberately: the specification names that case ("exit 1 +
  missing signature => invalid negative evidence") without assigning it one of the five, and
  calling it TEST_CRASHED would say something untrue about a process that did not crash.

  Abnormal termination is detected from the exit code: an unhandled exception surfaces as its
  exception code (0xC0000005 and friends), which is outside the range a test ever returns
  deliberately. A crash AFTER the footer is printed is therefore still a crash.

.OUTPUTS
  The classification on stdout. Exit code 0 only for EXPECTED_ASSERTION_FAILURE.
#>
[CmdletBinding()]
param(
    # OK when the build and the staging both succeeded
    [ValidateSet('OK', 'COMPILE_FAILED', 'SETUP_FAILED')][string]$BuildOutcome = 'OK',
    # the child's exit code. Omit it to say "no exit code was captured", which is not success.
    [string]$ExitCode = '',
    [string]$LogPath = '',
    [string]$LogText = '',
    [int]$ExpectedExitCode = 1,
    # proof the run reached its end at all
    [string]$VerdictPattern = '(?m)^(PASS|FAIL)\b',
    # the FAILING verdict specifically
    [string]$FailFooterPattern = '(?m)^FAIL\b',
    # the old behaviour the ablation is supposed to demonstrate
    [Parameter(Mandatory)][string]$SignaturePattern,
    [string]$Label = 'ablation'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

function Get-AblationClassification {
    param(
        [string]$BuildOutcome, [string]$ExitCode, [string]$Log,
        [int]$ExpectedExitCode, [string]$VerdictPattern, [string]$FailFooterPattern,
        [string]$SignaturePattern
    )

    if ($BuildOutcome -eq 'SETUP_FAILED') {
        return [pscustomobject]@{ classification = 'SETUP_FAILED'; accepted = $false
                                  reason = 'the pre-change sources could not be produced' }
    }
    if ($BuildOutcome -eq 'COMPILE_FAILED') {
        return [pscustomobject]@{ classification = 'COMPILE_FAILED'; accepted = $false
                                  reason = 'the pre-change sources did not build, which proves nothing' }
    }

    # An absent exit code is "not established", never success.
    if ([string]::IsNullOrWhiteSpace($ExitCode)) {
        return [pscustomobject]@{ classification = 'TEST_CRASHED'; accepted = $false
                                  reason = 'no exit code was captured, so the run cannot be attributed' }
    }
    $code = 0
    if (-not [int]::TryParse($ExitCode.Trim(), [ref]$code)) {
        return [pscustomobject]@{ classification = 'TEST_CRASHED'; accepted = $false
                                  reason = "the exit code '$ExitCode' is not a number" }
    }

    # Abnormal termination. An unhandled exception surfaces as its exception code, which is
    # outside the range a test returns on purpose - so this catches a crash that happened AFTER
    # the footer was printed, which otherwise looks exactly like a successful ablation.
    if ($code -lt 0 -or $code -gt 255) {
        return [pscustomobject]@{ classification = 'TEST_CRASHED'; accepted = $false
                                  reason = ("the child terminated abnormally: exit 0x{0:X8} ({1})" -f $code, $code) }
    }

    $reachedEnd = $Log -match $VerdictPattern
    if (-not $reachedEnd) {
        return [pscustomobject]@{ classification = 'TEST_CRASHED'; accepted = $false
                                  reason = "the run produced no verdict (exit $code)" }
    }

    if ($code -eq 0) {
        $note = if ($Log -match $FailFooterPattern) {
            ' - and it printed a failing verdict while exiting 0, which is inconsistent in itself'
        } else { '' }
        return [pscustomobject]@{ classification = 'UNEXPECTED_PASS'; accepted = $false
                                  reason = "the pre-change code PASSED, so the tests do not test the change$note" }
    }

    if ($code -ne $ExpectedExitCode) {
        return [pscustomobject]@{ classification = 'INVALID_EVIDENCE'; accepted = $false
                                  reason = "it ran to a verdict but exited $code, not the expected $ExpectedExitCode" }
    }

    if ($Log -notmatch $FailFooterPattern) {
        return [pscustomobject]@{ classification = 'INVALID_EVIDENCE'; accepted = $false
                                  reason = "it exited $code but printed no failing verdict" }
    }

    if ($Log -notmatch $SignaturePattern) {
        return [pscustomobject]@{ classification = 'INVALID_EVIDENCE'; accepted = $false
                                  reason = 'it failed, but NOT on the assertion the change is about' }
    }

    return [pscustomobject]@{ classification = 'EXPECTED_ASSERTION_FAILURE'; accepted = $true
                              reason = "exit $code, a failing verdict, and the required signature" }
}

# Dot-sourced by the fixtures; run directly by the ablation runners.
if ($MyInvocation.InvocationName -ne '.') {
    $log = $LogText
    if (-not $log -and $LogPath -and (Test-Path $LogPath)) {
        $log = (Get-Content -LiteralPath $LogPath -Raw -ErrorAction SilentlyContinue)
    }
    if ($null -eq $log) { $log = '' }

    $r = Get-AblationClassification -BuildOutcome $BuildOutcome -ExitCode $ExitCode -Log $log `
            -ExpectedExitCode $ExpectedExitCode -VerdictPattern $VerdictPattern `
            -FailFooterPattern $FailFooterPattern -SignaturePattern $SignaturePattern

    Write-Host ("ABLATION RESULT [{0}]: {1} - {2}" -f $Label, $r.classification, $r.reason)
    if ($r.accepted) {
        $m = [regex]::Match($log, $SignaturePattern)
        if ($m.Success) { Write-Host ("  signature: " + $m.Value.Trim()) }
    }
    exit $(if ($r.accepted) { 0 } else { 1 })
}
