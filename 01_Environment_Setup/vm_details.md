# Virtual Machine Specifications
Two primary virtual machines were deployed.

## Domain Controller (DC01)
* OS: Windows Server 2022
* RAM: 4 GB
* CPU: 2 cores
* Roles: \
&nbsp;&nbsp;&nbsp;&nbsp;- Active Directory Domain Services \
&nbsp;&nbsp;&nbsp;&nbsp;- DNS Server

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/vm_details/dc01_hw.png" width=30% />
</p>

## Client Endpoint (CLIENT01)
* OS: Windows 11 Enterprise
* RAM: 4 GB
* CPU: 2 cores
* Joined to: corp.local

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/vm_details/client01_hw.png" width=30% />
</p>

## Purpose of Each System
### DC01
* Identity management
* Authentication logging
* Privilege escalation simulation

### CLIENT01
* Endpoint telemetry generation
* Attack simulation host
* EDR visibility testing


