#!/bin/bash

tar --transform "s|^|mptcp_gs_install/|" --exclude "snapshot.sh" --owner 0 --group 0 -czvhf ~/mptcp_gs_install.$(date -u '+%FT%H-%M-%SZ').tgz *
