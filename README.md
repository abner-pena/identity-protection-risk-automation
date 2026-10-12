# Identity Protection Risk Automation

Risk-based access control and automated response in Microsoft Entra ID: Conditional Access policies that react to user risk and sign-in risk, a Logic App that revokes sessions for high-risk users within 15 minutes, PowerShell for containment and reporting, and KQL that proves the controls work and catches attempts to weaken them.

**Author:** Abner Peña, IAM & Cloud Security Engineer
**Stack:** Entra ID Protection, Conditional Access, Microsoft Graph, Azure Logic Apps, Managed Identities, Graph PowerShell, KQL

---

## Overview

Static policy ("MFA for everyone") does not distinguish a login from the user's laptop from a login from a Tor exit node. Identity Protection scores both the **sign-in** (is this authentication attempt suspicious?) and the **user** (is this account likely compromised?). The gap most tenants leave open is what happens after the score is raised: nobody is watching the Risky users blade at 2 a.m., so a High risk account keeps working.

This lab closes that gap in three layers:

| Layer | Control | Outcome |
|---|---|---|
| Prevent | CA-RISK-002: medium/high sign-in risk requires MFA | Stolen password alone is not enough |
| Prevent | CA-RISK-003: any sign-in risk on privileged roles is blocked | Admins never step up through risk, they stop |
| Self-heal | CA-RISK-001: high user risk requires MFA plus secure password change | Compromised account forces its own credential reset |
| Respond | Logic App polls high-risk users every 15 min, revokes sessions, alerts SecOps | Stolen tokens die without waiting for a human |
| Verify | KQL for gaps, spray, tampering, and automation audit | Evidence the controls fire, and alarms when someone weakens them |

## Architecture

```
 Sign-in ──> Identity Protection ──> signInRisk / userRisk
                    │                          │
                    │                  Conditional Access
                    │              (MFA / password change / block)
                    ▼
            riskyUsers (High, atRisk)
                    │  polled every 15 min
                    ▼
        Logic App (managed identity)
        ├─ POST /users/{id}/revokeSignInSessions
        └─ Teams alert ──> runbooks/risky-user-triage.md
                    │
 Log Analytics <────┘  SigninLogs, AuditLogs, AADUserRiskEvents ──> kql/*.kql
```

## Repository layout

| Path | Purpose |
|---|---|
| `policies/` | Three Conditional Access policies as JSON, report-only by default |
| `scripts/New-RiskBasedConditionalAccess.ps1` | Deploys policies, resolves break-glass group, refuses enforced state |
| `scripts/Set-RiskAutomationPermissions.ps1` | Grants the Logic App identity two Graph app roles, nothing more |
| `scripts/Invoke-RiskyUserContainment.ps1` | Revoke sessions, confirm compromised, optional disable, JSON evidence |
| `scripts/Get-RiskyUserReport.ps1` | CSV of risky users joined to 7-day detections |
| `logic-app/risky-user-response.json` | ARM template for the automation |
| `kql/` | Five detections and audits |
| `runbooks/risky-user-triage.md` | Analyst decision table and containment steps |
| `SETUP.md` | Licensing, prerequisites, safe ways to generate test risk |

## Walkthrough

### 1. Deploy the policies in report-only
```powershell
Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess'
./scripts/New-RiskBasedConditionalAccess.ps1 -BreakGlassGroupName "SG-BreakGlass-Exclusions"
```
All three policies land as `enabledForReportingButNotEnforced`. The script throws if a JSON file is edited to an enforced state, so nothing reaches users without a deliberate promotion. Let them run 7 days and review impact under Sign-in logs > Conditional Access > Report-only.

Design notes:
- **User-risk policy pairs `mfa` with `passwordChange` (AND).** Password change alone can be completed by an attacker holding the password. Requiring MFA first proves the real user is present.
- **`signInFrequency: everyTime`** is required alongside the user-risk control so an existing session cannot skip the remediation.
- **Admins get a block, not a prompt.** Prompting a Global Admin on a risky sign-in just gives an attacker with a phished MFA token a second chance.

### 2. Deploy the automation
```bash
az deployment group create -g rg-iam-automation \
  --template-file logic-app/risky-user-response.json \
  --parameters teamsWebhookUrl="<webhook>"
```
Take the `managedIdentityPrincipalId` output, then grant least privilege:
```powershell
./scripts/Set-RiskAutomationPermissions.ps1 -ManagedIdentityObjectId <principalId>
```
Only `IdentityRiskyUser.ReadWrite.All` and `User.RevokeSessions.All` are granted. The identity cannot read mail, edit users, or change policies, so a compromised Logic App cannot become a privilege escalation path.

### 3. Generate a detection and watch the loop
Follow `SETUP.md` to raise a test user to High risk. Expected sequence:
1. Test user shows `High / atRisk` under Risky users.
2. Within 15 minutes the Logic App run shows `Revoke_sessions` succeeded and Teams receives the alert.
3. Next sign-in by the test user is forced through MFA and a password change.
4. User risk moves to `remediated` after the change.

### 4. Triage and contain manually
```powershell
./scripts/Get-RiskyUserReport.ps1 -MinimumRisk medium
./scripts/Invoke-RiskyUserContainment.ps1 -UserPrincipalName risk.test1@contoso.com -ConfirmCompromised -WhatIf
```
Use `-WhatIf` first. Real runs write `evidence/containment-*.json` for the ticket.

### 5. Monitor
| Query | Question it answers |
|---|---|
| `risky-signins-passing-ca.kql` | Did a risky sign-in succeed without MFA? (policy gap) |
| `password-spray-leading-to-risk.kql` | Is one IP hitting many accounts, and did any succeed? |
| `risk-detection-trends.kql` | Which detection types dominate, and is volume shifting? |
| `risk-remediation-tamper.kql` | Who dismissed risk or edited risk-based CA policies? |
| `automation-actions-audit.kql` | Did the Logic App only do what it was granted to do? |

## Key takeaways
- Risk scoring is only half a control. Automated response is what turns a score into a closed door.
- Block, do not prompt, for privileged roles on any risk level.
- Automation identities should hold two permissions, not twenty. Managed identity means no secret to leak.
- Dismissing risk is a privileged act and should be audited like policy edits.
- Ship report-only first, with break-glass exclusion enforced by the deploy script, not by memory.

## Limitations
Polling (15 min) is not real time. For faster response, stream `AADRiskyUsers` into Sentinel and trigger a playbook from an analytic rule. Risk detections also vary in latency: some are real-time, others offline and can lag hours.

## Technologies
Microsoft Entra ID Protection, Conditional Access, Microsoft Graph API, Azure Logic Apps, Managed Identities, Log Analytics, Graph PowerShell SDK, KQL.
