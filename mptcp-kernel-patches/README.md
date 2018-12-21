## A collection of kernel patches for Multipath Transmission Control Protocol (MPTCP)
---

### MPTCP Kernels
---
MPTCP development tree can be found here:

https://github.com/multipath-tcp/mptcp

### Patch Naming Structure
---
```
MPTCP_<MPTCP_Version>_<Kernel_Version>_<MPTCP_Commit_Hash>.<Patch_Name>.diff
```

### Patch Details
--- 
Patches are broken down into three major changes.  One of the changes, the Ignore Interface Patch, is not applicable to the older MPTCP version.

#### RTO Patch
The round trip time of our system typically exceeds the default RTO, resulting in a guaranteed retransmission of the first SYN packet.  This patch modifies the Initial RTO to 5 seconds (and the corresponding fallback value). RFC 6298 suggestions do not apply to these satellite links. In the future this may be better as a sysctl.

#### Remove Address
This patch adds a "dont_remove" module option to the fullmesh path manager.  When set, *never* issue REMOVE_ADDR messages.  This is useful when all interfaces share a common IP address but the host is not running in a passive state.  Without this option, if a single link went down, all links would be removed - as they shared a common address.

#### Ignore Interfaces
This patch adds a "ignore_iface" module option to the fullmesh path manager.  When set, only unique IP addresses will create additional subflows.  Functionality was added to the fullmesh path manager to use both address and interface ID to determine if a new subflow was to be created.  In our setup, this caused the undesired behavior of additional flows being created when all the interfaces shared a single IP address.  This option attempts to revert this addition to the older behavior.

#### All Patches
As the name implies, this is a collection of all applicable patches for a given revision level.
