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

![ous](Screenshots/domain_build/ou_structure.png)

## Users:
* Administrative account: Administrator
* Standard user accounts: John Doe, Alice Smith
* Service account: svc_backup

![users](Screentshots/domain_build/ad_users.png)

## Groups:
IT Support security group
* Domain Admins (default)

![groups](Screentshots/domain_build/ad_groups.png)

* Workstations:
CLIENT01

![computers](Screentshots/domain_build/ad_computers.png)

This structure enables realistic authentication and privilege escalation scenarios.

# Domain Join Validation
A Windows client machine was joined to the domain to generate:
* Authentication logs
* Group membership changes
* Privilege escalation events

Successful domain join was verified through:
* Domain login testing

![jdoe on client01](Screentshots/domain_build/jdoe_login_client01)

* DNS resolution validation

![nslookup](Screentshots/domain_build/dns_validation.png)

* Group Policy application

![gp_jdoe](Screentshots/domain_build/group_policy_client01.png)
