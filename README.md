# uvxbridge
user level vxlan bridge

uvxbridge -i \<ingress\> -e \<egress\> -c \<config\> -m \<config mac address\> -p \<provisioning agent mac address\> [-d]

v0.1:
2017.10.13 - Friday
- v4 only
- VLAN support incomplete
- regular MTU only
- only a single interface address and default route is accepted
- 2 copies on both ingress and egress
- VALE permits broadcast

v0.2:
2017.10.20 - Friday
v0.1 +
 - minimal firewall support (configuration done w/ UDP + ioctl structs)
 - 1 copy on ingress / egress

v0.3
2017.10.27 - Friday
v0.2 +
 - ptnetmap integration 1st draft
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

