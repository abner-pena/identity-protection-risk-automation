<#
.SYNOPSIS
    Reports on users currently flagged by Entra ID Protection, with their recent risk detections.

.DESCRIPTION
    Pulls riskyUsers (atRisk or confirmedCompromised by default), joins each to the last 7 days
    of riskDetections, and exports a CSV for triage or weekly review.

.EXAMPLE
    ./Get-RiskyUserReport.ps1 -OutFile .\risky-users.csv
#>
[CmdletBinding()]
param(
    [string] $OutFile = ".\risky-users-$(Get-Date -Format yyyyMMdd).csv",
    [ValidateSet('low','medium','high')] [string] $MinimumRisk = 'medium'
)

$ErrorActionPreference = 'Stop'
Connect-MgGraph -Scopes 'IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All' -NoWelcome

$rank   = @{ none = 0; low = 1; medium = 2; high = 3 }
$since  = (Get-Date).AddDays(-7).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$riskyUsers = Get-MgRiskyUser -All -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" |
    Where-Object { $rank[$_.RiskLevel.ToString().ToLower()] -ge $rank[$MinimumRisk] }

$detections = Get-MgRiskDetection -All -Filter "activityDateTime ge $since"

$report = foreach ($u in $riskyUsers) {
    $d = $detections | Where-Object UserId -eq $u.Id | Sort-Object ActivityDateTime -Descending
    [pscustomobject]@{
        UserPrincipalName = $u.UserPrincipalName
        RiskLevel         = $u.RiskLevel
        RiskState         = $u.RiskState
        RiskLastUpdated   = $u.RiskLastUpdatedDateTime
        DetectionCount7d  = @($d).Count
        DetectionTypes    = (($d.RiskEventType | Select-Object -Unique) -join '; ')
        LastIp            = ($d | Select-Object -First 1).IPAddress
        LastCountry       = ($d | Select-Object -First 1).Location.CountryOrRegion
    }
}

$report | Sort-Object @{e={$rank[$_.RiskLevel.ToString().ToLower()]};Descending=$true}, RiskLastUpdated |
    Export-Csv -Path $OutFile -NoTypeInformation

Write-Host "$(@($report).Count) risky users written to $OutFile" -ForegroundColor Green
$report | Group-Object RiskLevel | Select-Object Name, Count | Format-Table -AutoSize
