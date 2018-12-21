#!/bin/bash

tar --transform "s|^|mptcp_ac_install/|" --exclude "snapshot.sh" --owner 0 --group 0 -czvhf ~/mptcp_ac_install.$(date -u '+%FT%H-%M-%SZ').tgz *
