# multipath-tcp-tools

## A collection tools for analysis and configuration of Multipath Transmission Control Protocol (MPTCP)

### network-traffic-analysis-tools
---
The network-traffic-analysis-tools directory contains a collection of applications written in C to help both *analyze* and *visualize* MPTCP packet traces.

### mptcp-over-ppp-links
---
The mptcp-over-ppp-links directory contains the scripts and files needed to support the type of MPTCP over PPP tests used in this experiment.

This resulting system leverages MPTCP to provide long-lived, responsive TCP connections that would have previously stalled or timed out using MLPPP.  The system as a whole provides better fairness, stability, and responsiveness, allowing multiple data flows to share the available resources equally and automatically.  It provides a more efficient and reliable communication channel.  This can be done without impacting the scientific payloads directly, changing only the ground station and aircraft gateway.

Packages of these files are available in the downloads/releases section.  However, if you need the source or are curious as to which files are modified, this is the place to look.

### multipath-udp-proxy
--- 
The multipath-udp-proxy directory contains a python script used to proxy a tun interface to the available PPP links, effectively creating a "Multipath-UDP" that adapts to link outages.

### mptcp-kernel-patches
---
The mptcp-kernel-patches directory contains the patches made to the 3.18 and 4.4 MPTCP kernels used in these builds.
