# Virtual Network Design

The lab environment uses VMware NAT networking to simulate an internal enterprise network while maintaining internet access for tool installation and cloud integration.

Network components:

- Internal virtual subnet
- NAT gateway for outbound traffic
- Static IP assignment for the domain controller

<p align="center">
  <img src="https://github.com/SanaMochi/SOC-Home-Lab/blob/main/01_Environment_Setup/Screenshots/network_config/vmware_subnet_ip_and_gateway.png" width=30%/>
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

# Troubleshooting
## Issue — Network Connectivity Failure Due to Stale Virtual Adapter Bindings
### Problem
Network connectivity intermittently failed after modifying virtual network adapters.

Symptoms included:
* Inconsistent connectivity between domain systems
* IP configuration appearing correct but communication failing

### Root Cause
After removing and re-adding the NAT adapter in the hypervisor, Windows created new adapter instances while retaining previous IP bindings associated with hidden adapters.

This resulted in an IP address assigned to a non-active adapter instance \
This behavior is common in virtualized environments.

### Resolution
Removed stale adapter bindings and reassigned the static IP to the active adapter.


### Validation
* Stable communication between DC01 and CLIENT01
* Successful DNS resolution
* Domain authentication functioning normally


# Lessons Learned
* Virtual network adapter changes can leave stale bindings that break connectivity.
* Always validate networking before proceeding to telemetry configuration.
* Domain infrastructure issues propagate into SIEM and detection layers if not resolved early.

