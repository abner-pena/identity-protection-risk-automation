# Setup

## Licensing
- **Microsoft Entra ID P2** (or Microsoft 365 E5): required for risk-based Conditional Access and the risky users APIs.
- Azure subscription for the Logic App (consumption tier, pennies per month) and a Log Analytics workspace.

## Tenant prerequisites
1. Two break-glass accounts in a security group (for example `SG-BreakGlass-Exclusions`), excluded from every policy here.
2. Users registered for MFA. Sign-in risk policies that demand MFA from unregistered users create lockouts.
3. Entra ID diagnostic settings exporting `SigninLogs`, `AuditLogs`, `AADUserRiskEvents`, `AADRiskyUsers` to Log Analytics.
4. A Teams channel with an incoming webhook for SecOps alerts.

## Tooling
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
# Roles for the deploying admin: Conditional Access Administrator, Privileged Role Administrator (for app role grants)
```

## Test accounts
Create `risk.test1@<tenant>` and `risk.test2@<tenant>` with MFA registered. Never use real users to generate risk.

## Safe ways to generate detections
- **Anonymous IP:** sign in to a test account through Tor Browser. Detection appears in minutes to a few hours.
- **Sign-in risk simulation:** Identity Protection > Risky sign-ins also lets admins mark a sign-in as compromised, which raises user risk.
- **Manual user risk:** Risky users > select test user > Confirm user compromised.
Do not test against production users.
