<#
.SYNOPSIS
    Deploys the three risk-based Conditional Access policies from /policies in report-only mode.

.DESCRIPTION
    Resolves the break-glass group placeholder, refuses to deploy if the group is missing,
    and creates each policy as enabledForReportingButNotEnforced. Promote to enabled only
    after reviewing report-only impact in Sign-in logs for at least 7 days.

    Requires Entra ID P2 (Identity Protection risk conditions).

.PARAMETER BreakGlassGroupName
    Display name of the security group that holds emergency access accounts.

.EXAMPLE
    ./New-RiskBasedConditionalAccess.ps1 -BreakGlassGroupName "SG-BreakGlass-Exclusions"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $BreakGlassGroupName,
    [string] $PolicyPath = (Join-Path $PSScriptRoot '..\policies')
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess','Policy.Read.All','Group.Read.All' -NoWelcome

$group = Get-MgGroup -Filter "displayName eq '$BreakGlassGroupName'"
if (-not $group -or @($group).Count -ne 1) {
    throw "Break-glass group '$BreakGlassGroupName' must resolve to exactly one group. Aborting."
}
Write-Host "Break-glass group: $($group.DisplayName) ($($group.Id))" -ForegroundColor Cyan

$existing = Get-MgIdentityConditionalAccessPolicy -All

foreach ($file in Get-ChildItem -Path $PolicyPath -Filter 'ca-*.json') {
    $raw  = (Get-Content $file.FullName -Raw).Replace('<BREAK_GLASS_GROUP_OBJECT_ID>', $group.Id)
    $body = $raw | ConvertFrom-Json -AsHashtable

    if ($body.state -ne 'enabledForReportingButNotEnforced') {
        throw "$($file.Name) is not report-only. Refusing to deploy straight to enforcement."
    }

    $match = $existing | Where-Object DisplayName -eq $body.displayName
    if ($match) {
        if ($PSCmdlet.ShouldProcess($body.displayName, 'Update existing policy')) {
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $match.Id -BodyParameter $body
            Write-Host "Updated:  $($body.displayName)" -ForegroundColor Yellow
        }
    }
    elseif ($PSCmdlet.ShouldProcess($body.displayName, 'Create policy')) {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $body | Out-Null
        Write-Host "Created:  $($body.displayName)" -ForegroundColor Green
    }
}
