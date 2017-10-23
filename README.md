# uvxbridge
user level vxlan bridge and firewall

uvxbridge -i \<ingress\> -e \<egress\> -c \<config\> -m \<config mac address\> -p \<provisioning agent mac address\> [-d]

v0.1:
2017.10.13 - Friday --- DONE
- v4 only
- VLAN support incomplete
- regular MTU only
- only a single interface address and default route is accepted
- 2 copies on both ingress and egress
- VALE permits broadcast
- ptnetmap integrated

v0.2:
2017.10.20 - Friday
v0.1 +
 - optimized datapath to avoid lookups
 - firewall support with per VM interface state table

v0.3
2017.10.27 - Friday
v0.2 +
 - smart VALE (enforces subnet IDs) works

v0.4
2017.11.03 - Friday
v0.3 +
 - ptnetmap integration upstreamable

v0.5
2017.11.10 - Friday
v0.4 +
 - Jumbo frames
 - additional routes / interface addresses
 - VLAN support enabled 

Unscheduled:
- adding support for JITted BPF filters in uvxbridge and VALE
- encrypted tunnels
- rate limiting in VALE and uvxbridge
