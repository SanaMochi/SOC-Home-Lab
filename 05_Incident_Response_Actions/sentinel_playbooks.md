# Incident Response — Microsoft Sentinel Playbook Automation

## Overview

This document covers the design, configuration, and execution of an automated response
playbook built in Microsoft Sentinel using Azure Logic Apps. The playbook demonstrates
end-to-end SOAR (Security Orchestration, Automation, and Response) capability: a
Sentinel analytics rule detects a specific event, automatically triggers an automation
rule, which runs a Logic App playbook that sends an email notification.

This closes the loop between detection and response — the analyst receives an alert
without needing to manually monitor the Sentinel portal, and the response action is
logged and auditable.


## Architecture

```
Windows Security Log (DC01)
        ↓
Sentinel Analytics Rule: "AD Account Disabled"
        ↓  (alert created)
Automation Rule: "Notify on Account Disable"
        ↓  (runs playbook)
Logic App: sentinel-alert-notifier
        ↓  (sends email)
Analyst Inbox
```

## Component 1 — Analytics Rule: AD Account Disabled

The analytics rule is the detection layer — it queries the SecurityEvent table for
Event ID 4725 (user account disabled) and fires an alert when a match is found.

![Sentinel Analytics home showing AD Account Disabled rule — Medium severity, Enabled, MITRE T1531](screenshots/analytics_home.png)

### Rule Configuration

![Analytics rule detail showing KQL query, 5-minute frequency, and MITRE T1531 mapping](screenshots/analytics_rule.png)

| Field | Value |
|-------|-------|
| Rule Name | AD Account Disabled |
| Severity | Medium |
| Status | Enabled |
| MITRE Tactic | Impact |
| MITRE Technique | T1531 — Account Access Removal |
| Rule Type | Scheduled |
| Query Frequency | Every 5 minutes |
| Query Period | Last 5 minutes |
| Alert Threshold | More than 0 results |
| Incident Creation | Enabled |
| Alert Grouping | Disabled |

### KQL Query

```kql
SecurityEvent
| where EventID == 4725
| where TargetUserName == "jdoe"
```

Event ID 4725 is generated on the domain controller whenever a user account is disabled.
The query is scoped to jdoe for this simulation. In a production rule, the
`TargetUserName` filter would be removed to monitor all account disables, with
allowlisting for expected automated service account management.

**MITRE T1531 — Account Access Removal** covers attacker-initiated account disabling
used to lock out legitimate users during an attack. This rule detects the same event
type from a defensive IR perspective — an analyst disabling a compromised account.

## Component 2 — Permissions Configuration

Before a playbook can be run by Sentinel, the SOC-Lab resource group must be granted
permissions for Sentinel to invoke Logic Apps within it.

![Sentinel Manage Permissions page showing SOC-Lab_RG granted permission](screenshots/permissions.png)

SOC-Lab_RG is listed under Current Permissions — Sentinel has been authorised to run
playbooks contained in this resource group. Without this configuration, the automation
rule would fail silently when attempting to trigger the playbook.

## Component 3 — Automation Rule: Notify on Account Disable

The automation rule is the bridge between the analytics rule and the playbook. It listens
for alerts created by a specific analytics rule and defines what action to take.

![Sentinel Automation home showing 1 automation rule, 1 enabled rule, 1 enabled playbook](screenshots/automation_home.png)

### Automation Rule Configuration

![Automation rule edit screen showing trigger, condition scoped to AD Account Disabled, and Run playbook action](screenshots/playbook_in_rule.png)

| Field | Value |
|-------|-------|
| Rule Name | Notify on Account Disable |
| Trigger | When alert is created |
| Condition | Analytic rule name contains "AD Account Disabled" |
| Action | Run playbook: sentinel-alert-notifier |
| Scope | Azure subscription 1 / SOC-Lab_RG |
| Expiration | Indefinite |
| Order | 1 |
| Status | Enabled |

The condition scopes the automation rule to fire only when the specific AD Account
Disabled analytics rule generates an alert — preventing the playbook from running on
every alert in the workspace. In a production environment, multiple automation rules
can be chained with different conditions and actions, building a full automated triage
and response workflow.

### Playbook Attached to Analytics Rule

The playbook is also visible directly in the analytics rule's Automated response tab,
confirming the connection from both directions:

![Analytics rule wizard Automated response tab showing Notify on Account Disable rule attached](screenshots/rule_wizard.png)


## Component 4 — Logic App Playbook: sentinel-alert-notifier

The playbook is a Stateful Azure Logic App with one trigger and one action.

### Playbook Overview

![Logic App overview showing sentinel-alert-notifier — Enabled, 1 trigger, 1 action, West US](screenshots/playbook_overview.png)

| Field | Value |
|-------|-------|
| Logic App Name | sentinel-alert-notifier |
| Resource Group | soc-lab_rg |
| Location | West US |
| Subscription | Azure subscription 1 |
| Definition | 1 trigger, 1 action |
| Status | Enabled |
| Workflow Type | Stateful |

### Playbook Flow (Designer View)

![Logic App designer showing Microsoft Sentinel alert trigger connected to Send email (V2) action](screenshots/playbook_flow.png)

The playbook consists of two steps:

**Step 1 — Trigger: Microsoft Sentinel Alert**
Fires when Sentinel invokes the playbook via the automation rule. Receives the full
alert context from Sentinel including alert name, severity, entities, and incident details.

**Step 2 — Action: Send email (V2)**
Sends an email notification via Gmail to the analyst inbox. In a production environment
this would use an SMTP connector, Office 365, or a ticketing system integration (e.g.
ServiceNow, PagerDuty). The email subject and body use dynamic fields from the Sentinel
alert context to populate alert-specific information.


## Playbook Execution

### Manual Trigger

The playbook was triggered manually from the Logic App overview page to validate the
end-to-end flow. In production, this trigger fires automatically whenever the automation
rule conditions are met.

![Toast notification confirming successful manual trigger of sentinel-alert-notifier](screenshots/manual_trigger.png)

### Execution Result

![Logic App run view showing Step 1 (Sentinel alert, 0s) and Step 2 (Send email, 0.4s) both Succeeded](screenshots/flow_success.png)

| Step | Action | Duration | Status |
|------|--------|----------|--------|
| 1 | Microsoft Sentinel alert trigger | 0s | Succeeded |
| 2 | Send email (V2) | 0.4s | Succeeded |

Total execution time: 1.43 seconds from trigger to email delivery.

### Run History

![Logic App Run History showing one completed run — Succeeded, 1.43 seconds, March 15 2:28 AM](screenshots/runs_history.png)

| Field | Value |
|-------|-------|
| Status | Succeeded |
| Start Time | 3/15/2026 2:28:26 AM |
| Duration | 1.43 seconds |

### Email Received

![Gmail showing received Sentinel alert email with blank subject dynamic fields](screenshots/email.png)

The email arrived at 2:28 AM, matching the Logic App run timestamp exactly. The Subject
line shows "Sentinel Alert:" with blank dynamic fields for alert name, severity, and
entity — this is expected behaviour when the playbook is triggered manually without a
live Sentinel alert context. The dynamic fields (`AlertDisplayName`, `Severity`,
`Entities`) are populated by Sentinel when the playbook is invoked automatically by
a real alert. A manual trigger from the Logic App designer fires the trigger step
without injecting alert context, so the fields resolve as empty.

In a live incident trigger, the email would read:

```
Subject: Sentinel Alert: AD Account Disabled
Body:    Severity: Medium | Entity: jdoe
```


## End-to-End Flow Validation

| Component | Configuration | Execution |
|-----------|--------------|-----------|
| Analytics rule (AD Account Disabled) | Enabled, KQL confirmed, 5-min frequency | Scoped to EID 4725 |
| Automation rule (Notify on Account Disable) | Enabled, condition scoped, playbook attached | Configured correctly |
| Permissions (SOC-Lab_RG) | Sentinel authorised to run playbooks | No permission errors |
| Logic App (sentinel-alert-notifier) | Enabled, 1 trigger + 1 action | Ran in 1.43 seconds |
| Email delivery | Gmail connector authenticated | Received at 2:28 AM |


## Production Enhancements

This playbook demonstrates the baseline automation capability. In a production SOC,
the same pattern would be extended with additional actions:

| Enhancement | How to Implement | Value |
|-------------|-----------------|-------|
| Add incident comment | Sentinel → Add comment to incident action | Creates audit trail in the incident timeline |
| Create ServiceNow ticket | ServiceNow connector → Create record | Auto-generates incident ticket with alert details |
| Disable account automatically | Active Directory connector → Disable account | Removes need for manual analyst action |
| Post to Teams channel | Teams connector → Post message | Real-time SOC team notification |
| Enrich with threat intel | VirusTotal or MDTI connector | Auto-populates IOC reputation data |
| Assign incident to analyst | Sentinel → Assign incident action | Routes alert to on-call analyst automatically |

The progression from this lab playbook to a production playbook is additive — each
action block is added to the same Logic App designer canvas without rebuilding the
trigger or permissions configuration.


## MITRE ATT&CK Context

| Detection Target | Technique | ID | Playbook Response |
|-----------------|-----------|-----|-------------------|
| Account disabled (IR action) | Account Access Removal | T1531 | Email notification to analyst |
| Attacker-initiated account lockout | Account Access Removal | T1531 | Same rule would fire if attacker disabled accounts |
