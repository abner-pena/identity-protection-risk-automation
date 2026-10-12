<#
.SYNOPSIS
    Grants a Logic App managed identity the least-privilege Graph application permissions
    needed by logic-app/risky-user-response.json.

.DESCRIPTION
    Managed identities cannot be granted Graph permissions in the portal, so this assigns the
    app roles directly on the Microsoft Graph service principal.

    IdentityRiskyUser.ReadWrite.All : read risky users, confirm compromised, dismiss
    User.RevokeSessions.All         : revoke refresh tokens
    (Deliberately NOT granted: User.ReadWrite.All, Directory.ReadWrite.All)

.EXAMPLE
    ./Set-RiskAutomationPermissions.ps1 -ManagedIdentityObjectId 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $ManagedIdentityObjectId)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'AppRoleAssignment.ReadWrite.All','Application.Read.All' -NoWelcome

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$wanted  = 'IdentityRiskyUser.ReadWrite.All','User.RevokeSessions.All'

foreach ($name in $wanted) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
    $already = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId |
        Where-Object { $_.AppRoleId -eq $role.Id }
    if ($already) { Write-Host "Already granted: $name"; continue }

    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -BodyParameter @{
        principalId = $ManagedIdentityObjectId
        resourceId  = $graphSp.Id
        appRoleId   = $role.Id
    } | Out-Null
    Write-Host "Granted: $name" -ForegroundColor Green
}
