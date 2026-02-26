# Active Directory Deployment
A Windows Server 2022 virtual machine was configured as the domain controller for the lab environment.
Configuration included:
* Installed Active Directory Domain Services
* Promoted server to Domain Controller
* Created domain: corp.local

The domain controller also provides:
* DNS services for internal name resolution
* Authentication services for domain users and computers

# Organizational Structure
The following objects were created to simulate a small enterprise environment:
Organizational Units:

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/ou_structure.png" width=50% />
</p>

## Users:
* Administrative account: Administrator
* Standard user accounts: John Doe, Alice Smith
* Service account: svc_backup

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/ad_users.png" width=50% />
</p>

## Groups:
IT Support security group
* Domain Admins (default)

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/ad_groups.png" width=50% />
</p>

* Workstations:
CLIENT01

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/ad_computers.png" width=50% />
</p>

This structure enables realistic authentication and privilege escalation scenarios.

# Domain Join Validation
A Windows client machine was joined to the domain to generate:
* Authentication logs
* Group membership changes
* Privilege escalation events

Successful domain join was verified through:
* Domain login testing

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/jdoe_login_client01.png" width=50% />
</p>

* DNS resolution validation

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/dns_validation.png" width=30% />
</p>

* Group Policy application

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/domain_build/group_policy_cllient01.png" width=50% />
</p>

# Troubleshooting
## Issue 1 — Domain Join Failure Due to Unsupported OS Edition
### Problem
The client machine could not join the domain.

### Root Cause
The system was installed using Windows 10 Home, which does not support domain join functionality.

Domain join requires:
* Pro
* Education
* Enterprise

### Resolution
Reinstalled the client VM using Windows 11 Enterprise.

Domain join completed successfully after installation.

### Validation
* Domain login successful
* whoami returned domain context
 
## Issue 2 — GPO Showing “N/A” in Applied Group Policy
### Problem
After creating and linking a Group Policy Object (GPO), the policy did not appear in the applied results on the client system.

Running: \
```gpresult /r ```

Showed: \
```Applied Group Policy Objects: N/A```

### Root Cause
The GPO contained no configured settings. \
Windows does not process or apply a GPO unless at least one policy setting is explicitly configured (Enabled or Disabled). \
An empty GPO will still be linked but will not appear in applied policy results.

### Resolution
Edited the GPO and configured at least one test policy setting:

Example path: \
```Group Policy Management → Domain → Edit selected policy → Policies```

Enable or disable at least one rule.

Then forced policy update:\
```gpupdate /force```
After policy refresh, the GPO appeared correctly in:\
```gpresult /r```

### Validation
GPO now listed under Applied Group Policy Objects.

Client successfully receiving domain policy updates.


# Lessons Learned
* Windows edition selection directly impacts domain functionality.
* Empty GPOs are not processed by clients and will not appear in gpresult output.
* Always configure at least one setting when testing GPO deployment.
* Validate SYSVOL access when troubleshooting GPO application.
