This DHCP server for ESP32/Arduino is not to be trusted! It has been substantially vibe coded.

1. DHCPDISCOVER — client → broadcast
Client asks for an IP
Sent to 255.255.255.255, from source IP 0.0.0.0

2. DHCPOFFER — server → broadcast (or unicast)
Server offers an IP (yiaddr)
Includes lease time, subnet mask, gateway, etc.

3. DHCPREQUEST — client → broadcast
Client accepts the offered IP
Repeats the xid and specifies server ID (Option 54)
lDHCPACK — server → client
Confirms the assignment
Client can now use the IP