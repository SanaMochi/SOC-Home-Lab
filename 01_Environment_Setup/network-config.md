# Virtual Network Design

The lab environment uses VMware NAT networking to simulate an internal enterprise network while maintaining internet access for tool installation and cloud integration.

Network components:

- Internal virtual subnet
- NAT gateway for outbound traffic
- Static IP assignment for the domain controller

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/vmware_subnet_ip_and_gateway.png" width=50%/>
</p>

# IP Configuration
The domain controller was assigned a static IP to ensure consistent DNS resolution.

| | IP |
|------|----------|
|DC01 | 192.168.113.10 |
|CLIENT01 | 192.168.113.20 |
|Gateway | 192.168.113.2 |


<p align="center">
  <img src= "https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/ipconfig_dc01.png" width=70% />
  <img src= "https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/ipconfig_client01.png" width=50% />
</p>

The client machine uses the domain controller as its primary DNS server.

This ensures proper:

- Domain authentication
- Group Policy retrieval
- Host resolution

# Connectivity Validation

The following tests were performed:

* Ping between client and domain controller
<p align="center">
    <img src= "https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/ping_dc01.png" width=50% />
    <img src= "https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/ping_client01.png" width=50% /> 
</p>

* DNS resolution of domain resources
<p align="center">
    <img src= "https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/dns_validation.png" width=30% />
</p>

* Access to SYSVOL and NETLOGON shares
<p align="center">
    <img src= "https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/sysvol_netlogon.png" width=50% />
</p>

These checks ensure stable domain communication.


