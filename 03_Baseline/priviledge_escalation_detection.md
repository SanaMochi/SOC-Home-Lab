# Privilege Escalation Detection – Group Membership Changes

## Objective

Detect privilege escalation through unauthorized modification of Active Directory privileged group membership.

Attackers frequently escalate privileges by:
- Adding compromised accounts to privileged groups
- Modifying administrative roles for persistence
- Temporarily elevating access during lateral movement

Because these actions directly impact domain-wide control, they represent high-risk identity events.

## Data Source

Windows Security Log (Domain Controller).

Relevant Event IDs:

- 4728 – Member added to security-enabled global group
- 4729 – Member removed from security-enabled global group

These events are generated only on Domain Controllers because group membership changes are processed by Active Directory.

## Detection Logic

### Splunk Query Used

```SPL
index=wineventlog (EventCode=4728 OR EventCode=4729)
| search Group_Name="*Admin*"
| table _time host SubjectUserName Group_Name Member_Name
| sort -_time
```
This query prioritizes high-value administrative groups.

## Key Investigation Fields

| Field | Purpose |
|------|---------|
| SubjectUserName | Who performed the change |
| TargetUserName / Member_Name | Which account was modified |
| Group_Name | Which group was modified |
| _time | Timeline correlation |

These fields allow analysts to quickly determine whether the change was authorized.

## Analytical Observations

### Privileged Groups Represent High-Risk Changes

Privileged Group Changes Are High-Signal Events

Groups such as:

- Domain Admins
- Enterprise Admins
- Administrators

grant broad control across the environment.

Unexpected membership changes strongly indicate:
- Privilege escalation
- Persistence
- Domain compromise

Because attackers often add accounts temporarily, even short-lived changes are important.

### Administrative Context Must Be Validated

Event 4728 only shows that a change occurred—not whether it was legitimate.

During investigations analysts must verify:

- Change request alignment
- Administrative account ownership
- Time-of-day anomalies

Unauthorized administrative context significantly increases risk.

### Group Changes Are Common in Real Attacks

This technique appears frequently in:

- Post-exploitation phases
- Lateral movement chains
- Domain takeover scenarios

Attack tools and frameworks often automate group modifications after credential compromise.

## False Positive Considerations

Legitimate causes include:
- Planned administrative changes
- Account provisioning workflows
- Automated identity management tools

Because of this, privileged group changes should be correlated with:
- Change management records
- Known administrative hosts

## Detection Tuning Opportunities

Detection quality improves by:
- Monitoring only privileged groups
- Excluding known administrative service accounts
- Correlating with logon source systems (Event 4624

## MITRE ATT&CK Mapping

Technique:

T1098 – Account Manipulation

This technique involves modifying account permissions to maintain access.

## Artifacts Collected

Screenshots demonstrate:
- Event 4728 & 4729 detection results
- Expanded event fields used during investigation

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Baseline/Screenshots/add_to_group.png" width=90% />
</p>

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/03_Baseline/Screenshots/leave_group.png" width=90% />
</p>
