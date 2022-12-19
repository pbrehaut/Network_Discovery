# Network Discovery

Install

pip install pyats[full]

pip install rest.connector


This script uses pyATS to get the ARP Caches from Layer 3 Network Gateway devices to discover what servers are active on the network.

The IPs owned by the network devices are discovered automatically where possible and excluded from the report that is generated since only unknown IPs are of interest.

The steps are as follows:

The IPs on every device in the testbed YAML file are discovered: Nexus, ASA (L3 Interfaces and HSRP), F5 (Self IPs, VIPs, SNATs). These IPs are excluded.

Each L3 Device, usually Routers/Switches and Firewalls have their local networks discovered and each IP in the range pinged to attempt to get an ARP entry.

The ARPs are retrieved from all L3 Gateway devices and the MAC addresses from all L2 devices (Nexus and IOS Switches).

A report of all the ARPs and MAC table entries is generated excluding the Network Device owned IPs, a list of excluded IPs (text file) and MACs to be excluded (list in the script).

A separate comments file is loaded in to allow comments made about IPs to be saved an then re-inputted to the report each time the script is run to maintain manual discovery work that has been done for previous iterations of the report.


Comments file (put the IP Address and any comments after)
e.g.


10.0.0.1 Customer A Server 1

10.0.0.5 Customer A Server 2
