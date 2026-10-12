# Runbook: Risky User Triage

**Owner:** IAM / SecOps  **Trigger:** Teams alert from `la-risky-user-response`, or weekly `Get-RiskyUserReport.ps1` review
**Goal:** Decide compromised or benign within 60 minutes of a High risk alert.

## 1. Gather (5 min)
1. Open the user in Entra admin center > Protection > Risky users > Risk detections.
2. Note detection types and `DetectionTimingType` (realtime vs offline).
3. Run `kql/risky-signins-passing-ca.kql` filtered to the user. Did any risky sign-in succeed without MFA?
4. Check the user's registered auth methods and recent changes (new MFA method added in the same window is a strong takeover signal).

## 2. Classify

| Evidence | Verdict | Action |
|---|---|---|
| Impossible travel, user confirms VPN or travel | Benign | Confirm safe sign-in, dismiss user risk |
| Anonymous IP (Tor) sign-in, user denies | Compromised | Step 3 |
| Leaked credentials detection | Compromised until password changed | Step 3, no need to wait for contact |
| Password spray hit, successful sign-in from spray IP | Compromised | Step 3 plus check mailbox rules and OAuth consents |
| New MFA method registered from risky IP | Compromised | Step 3, remove the new method |
| Unfamiliar sign-in properties, user on new laptop | Likely benign | Contact user, dismiss after confirmation |

## 3. Contain
```powershell
./scripts/Invoke-RiskyUserContainment.ps1 -UserPrincipalName user@contoso.com -ConfirmCompromised
```
Add `-DisableAccount` only if the user cannot be reached and activity is ongoing. Contact the user out-of-band (phone, manager), never by replying to the compromised mailbox.

## 4. Eradicate
- Remove attacker-registered MFA methods and review inbox rules, forwarding, and OAuth grants.
- User completes secure password change with MFA (forced by CA-RISK-001).
- Re-enable account if disabled; confirm risk state returns to `remediated`.

## 5. Close
Attach the `evidence/containment-*.json` file to the ticket, record root cause (phish, reuse, spray), and note any CA gap found via `risky-signins-passing-ca.kql`.

## Escalate to full incident response when
Privileged role holder, multiple users sharing an attacker IP, or evidence of mailbox or data access.
