<#
.SYNOPSIS
    Contains a risky user: revoke sessions, optionally confirm compromised, optionally block sign-in.

.DESCRIPTION
    Order matters. Revoking refresh tokens first cuts off existing sessions. Confirming
    compromised raises the user to High risk so user-risk Conditional Access forces a
    secure password change on next sign-in. Disabling the account is opt-in and meant for
    confirmed account takeover where the user cannot be contacted out-of-band.

    Every action is written to a JSON evidence file for the incident ticket.

.EXAMPLE
    ./Invoke-RiskyUserContainment.ps1 -UserPrincipalName jdoe@contoso.com -ConfirmCompromised -WhatIf
.EXAMPLE
    ./Invoke-RiskyUserContainment.ps1 -UserPrincipalName jdoe@contoso.com -ConfirmCompromised -DisableAccount
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $UserPrincipalName,
    [switch] $ConfirmCompromised,
    [switch] $DisableAccount,
    [string] $EvidenceDir = '.\evidence'
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'User.RevokeSessions.All','IdentityRiskyUser.ReadWrite.All','User.ReadWrite.All' -NoWelcome

$user = Get-MgUser -UserId $UserPrincipalName -Property Id,UserPrincipalName,AccountEnabled,DisplayName
$log  = [ordered]@{ user = $user.UserPrincipalName; id = $user.Id; started = (Get-Date).ToUniversalTime().ToString('o'); actions = @() }

if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, 'Revoke all sign-in sessions')) {
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    $log.actions += 'revokeSignInSessions'
    Write-Host "Sessions revoked for $($user.UserPrincipalName)" -ForegroundColor Yellow
}

if ($ConfirmCompromised -and $PSCmdlet.ShouldProcess($user.UserPrincipalName, 'Confirm user compromised')) {
    Confirm-MgRiskyUserCompromised -UserIds @($user.Id)
    $log.actions += 'confirmCompromised'
    Write-Host 'Marked confirmed compromised (risk raised to High)' -ForegroundColor Yellow
}

if ($DisableAccount -and $PSCmdlet.ShouldProcess($user.UserPrincipalName, 'Disable account')) {
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    $log.actions += 'disableAccount'
    Write-Host 'Account disabled' -ForegroundColor Red
}

New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$file = Join-Path $EvidenceDir ("containment-{0}-{1}.json" -f ($user.UserPrincipalName -replace '[^\w\.-]','_'), (Get-Date -Format yyyyMMdd-HHmmss))
$log.completed = (Get-Date).ToUniversalTime().ToString('o')
$log | ConvertTo-Json -Depth 4 | Set-Content $file
Write-Host "Evidence: $file" -ForegroundColor Cyan
