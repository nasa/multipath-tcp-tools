#!/bin/bash

## USAGE - Prompted or configuration file options

# The version of this script
VERSION=3

die() { printf "STOP: %s" "${@+$@$'\n'}" 1>&2; exit 1; }

# Date and time script was run
DATE=$(date '+%F_%H-%M-%S')
# The directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# The temp directory used, within $DIR
TMP_DIR=$(mktemp -d -p "$DIR")

# Quick sanity check, this script is intended to be run from the same location
if [ "${DIR}" != "/home/nasa/baseline" ]; then
  die "Please run this script from /home/nasa/baseline"
fi

# Source the config file if it is available
if [ -f ${DIR}/mptcp.host.config ]; then
  . ${DIR}/mptcp.host.config
fi

# If the SSL configuration has changed a recompile will be needed
IRC_SSL=$(md5sum ${DIR}/host_configs/unrealircd.ssl.cnf|cut -d' ' -f1)

# USER_WAIT if 0 we will wait forever for confirmation, otherwise sleep
# this amount and continue automatically
USER_WAIT=${USER_WAIT:-0}

# PRIOR is set if this is not the first time this script has been run
# as evidenced by the install.log file.  If there is a version change
# between installs of this script, halt as manual cleanup is required.
PRIOR=''
if [ -e ${DIR}/install.log ]
then
  PRIOR=$(grep "Version:" ${DIR}/install.log | cut -d: -f2)
  if [ "${PRIOR}" != "${VERSION}" ]
  then
    die "Install completed with a different version of the script.  Cleanup manually first."
  fi
  PRIOR_IPADDRESS=$(grep "IPAddress:" ${DIR}/install.log | cut -d: -f2)
  PRIOR_DEVICES=$(grep "Devices:" ${DIR}/install.log | cut -d: -f2)
  PRIOR_AIRCRAFT_NET=$(grep "Aircraft:" ${DIR}/install.log | cut -d: -f2)
  PRIOR_IRC_ID=$(grep "IRC_ID:" ${DIR}/install.log | cut -d: -f2)
  PRIOR_IRC_SSL=$(grep "IRC_SSL:" ${DIR}/install.log | cut -d: -f2)
  # Use some of the prior values only if the user has not set them
  # (the one that may have been randomly generated)
  IRC_ID=${IRC_ID:-$PRIOR_IRC_ID}
  # Force a RECOMPILE if the SSL config has changed
  if [ "${IRC_SSL}" != "${PRIOR_IRC_SSL}" ]; then SSL_RECOMPILE="1"; fi
  #DEVICE_LIST=${DEVICE_LIST:-"$PRIOR_DEVICES"}
fi

function cleanup {
  # Delete temp directory
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# This script was build for Ubuntu... try and find the version
UVER=$(grep VERSION_ID /etc/os-release | grep -o [0-9.]*)
# ... Tested on 14.04 and 16.04
[[ ("$UVER" == "16.04" ) || ( "$UVER" == "14.04") ]] || die "Unsupported Ubuntu Version: ${UVER}"

# IRC ID is not prompted... but you can define it as IRC_ID before execution
# It should be a two digit value between 00 and 99.  We generate one randomly.
# ie: > export IRC_ID="02"
IRC_ID=${IRC_ID:-$(printf "%02d" $((( $RANDOM % 100 ))))}

# IRC DOMAIN is not prompted... but you can define it as IRC_DOMAIN before execution.
# It should be the remainder of the IRC FQDN (because UnrealIRCd demands as such :-/)
# It defaults to an empty string "" which would give the automatically generated hostname of:
# mptcp-gs-2{IRC_ID}.{IRC_DOMAIN}
# Thus with an IRC ID of "00" and an IRC_DOMAIN of "example.org" the server name becomes:
# mptcp-gs-200.example.org
IRC_DOMAIN=${IRC_DOMAIN:-""}

# "RECOMPILE" Option
# By setting the environment variable RECOMPILE to anything other than
# an empty string you can force UnrealIRCd to be recompiled.  Note
# that you will get a new SSL cert and IRC_ID (unless you specify it
# manually) if you choose to recompile.

# "AIRCRAFT_NETWORK"
# Variable to identify the aircraft network in CIDR notation
AIRCRAFT_NETWORK=${AIRCRAFT_NETWORK:-"10.1.1.0/24"}
if [ "${AIRCRAFT_NETWORK}" == "" ]; then
  AIRCRAFT_NETWORK="10.1.1.0/24"
fi

# "EXTERNAL_IP_ADDRESS"
# Variable to identify the "External" IP address of the ground station.
# This may be a private address if the ground station is virtualized.
# If commands line options are used this is the first positional argument.
EXTERNAL_IP_ADDRESS=${EXTERNAL_IP_ADDRESS:-""}

# "DEVICE_LIST"
# Variable which is a string list of devices to use as modems.  It can be used
# in place of the command line positional arguments.  Use spaces " " as the delimiter.
DEVICE_LIST=${DEVICE_LIST:-""}

# Extract or Prompt for IP address (we take a stab at the most likely default)
IPADDR=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' |grep -v '10.*'| grep -v '192.168.*' | head -n 1)
if [ -n "${PRIOR}" ] && [ -z "${IPADDR}" ] && [ -z "${EXTERNAL_IP_ADDRESS}" ]; then 
  EXTERNAL_IP_ADDRESS=${PRIOR_IPADDRESS}
elif [ -z "${IPADDR}" ]; then
  # Lift the restriction on private addresses and try again
  IPADDR=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
fi
if [ "${EXTERNAL_IP_ADDRESS}" == "AUTO" ]; then EXTERNAL_IP_ADDRESS=${IPADDR}; fi
INPUT=${EXTERNAL_IP_ADDRESS:-""}
if ! [ "${INPUT}" ]
then
  echo -n "External IP Address? [Default: ${IPADDR}]? "
  if (( $(echo "${USER_WAIT} <= 0" | bc -l) )); then read INPUT; else INPUT=""; fi
  if [ "${INPUT}" == "" ]
  then
    INPUT=${IPADDR}
  fi
fi
if [[ ${INPUT} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
then
  IPADDR=${INPUT}
else
  die "Invalid IPv4 address"
fi
IFACE=$(ip -4 route show |grep "src ${IPADDR}"|grep -Eo "dev ([^ ]*)"|cut -d' ' -f2)
if [ "$IFACE" == "" ]; then
  # Perhaps we are NAT'ed and this was the gateway address?  Not what we asked for, but it would get us the right interface
  IFACE=$(ip -4 route show |grep "${IPADDR}"|grep -Eo "dev ([^ ]*)"|cut -d' ' -f2)
fi
if [ "$IFACE" == "" ]; then
  # We still don't have the interface, give up!
  die "Unable to determine the proper external network interface!  Check your IP address!"
fi

# Extract or Prompt for Serial Devices
declare -a SDEVS
if [ "${DEVICE_LIST}" ]; then
  SDEVS=(${DEVICE_LIST})
  NMODEMS=${#SDEVS[@]}
else
  # Prompt for the devices with best guess defaults
  echo -n "Number of Modems [Default: 4]? "
  NMODEMS=4
  if (( $(echo "${USER_WAIT} <= 0" | bc -l) )); then read INPUT; else INPUT=""; fi
  if [ "${INPUT}" != "" ]
  then
    NMODEMS=${INPUT}
  fi
  if (( NMODEMS > 0 ))
  then
    for ((i=0;i<$NMODEMS;i++))
    do
      echo -n "Enter Device #${i} Name [Default: ttyS${i}]: "
      if (( $(echo "${USER_WAIT} <= 0" | bc -l) )); then read INPUT; else INPUT=""; fi
      if [ "${INPUT}" == "" ]
      then
        SDEVS+=("ttyS${i}")
      else
        SDEVS+=("${INPUT}")
      fi
    done
  else
    die "Enter a numerical value greater than 0"
  fi
fi
for i in ${SDEVS[@]}
do
  if [ ! -e "/dev/$i" ]
  then
    die "Cannot find /dev/$i"
  fi
done

# Let the user know what we are doing
echo ""
echo "########## Reconfiguration Starting!! ##########"
echo "Using the following IP address: $IPADDR on interface $IFACE"
echo "Using the following ${NMODEMS} devices: ${SDEVS[@]}"
echo "Using the following aircraft network: ${AIRCRAFT_NETWORK}"
echo ""
echo "If the above looks wrong hit Control-C now!"
if (( $(echo "${USER_WAIT} > 0" | bc -l) ))
then
  echo "Continuing in ${USER_WAIT} seconds..."
  sleep ${USER_WAIT}
else
  echo "Otherwise hit Enter to continue..."
  read INPUT
fi

SUDO=''
if (( $EUID != 0 ))
then
  echo ""
  echo "NOTE!!!!! This script requires elevated privileges."
  echo "Please enter your user (${USER}) password when prompted."
  SUDO='sudo'
  $SUDO echo ""
  if (( $? != 0 ))
  then
    die "Unable to continue without elevated privileges."
  fi
fi

# Make note of this install
echo "Version:${VERSION}"   >> ${TMP_DIR}/install.log
echo "IPAddress:${IPADDR}" >> ${TMP_DIR}/install.log
echo "Devices:${SDEVS[@]}"  >> ${TMP_DIR}/install.log
echo "Aircraft:${AIRCRAFT_NETWORK}" >> ${TMP_DIR}/install.log
echo "IRC_ID:${IRC_ID}" >> ${TMP_DIR}/install.log
echo "IRC_SSL:${IRC_SSL}" >> ${TMP_DIR}/install.log

## STEP 1 - Clean up the tty files which may be different from the prior install
if [ -n "${PRIOR}" ]
then
  echo "Prior install detected, attempting to clean up any stray devices."
  # Stop the modems if running - make sure the script we made still exists
  if [ -e ${HOME}/stop_ppp.sh ]
  then
    $SUDO ${HOME}/stop_ppp.sh
  fi
  # Backup and remove old devices files from the last install that won't be used this install
  for i in $(grep "Devices:" ${DIR}/install.log | cut -d: -f2)
  do
    if [[ ! "${SDEVS[@]}" =~ "${i}" ]]
    then
      $SUDO mv -vf /etc/init/${i}.conf /etc/init/${i}.conf.${DATE}.bak     2>/dev/null
      $SUDO mv -vf /lib/systemd/system/${i}.service /lib/systemd/system/${i}.service.${DATE}.bak     2>/dev/null
      $SUDO mv -vf /etc/ppp/options.${i} /etc/ppp/options.${i}.${DATE}.bak 2>/dev/null
    fi
  done
fi

## STEP 2 - Copy Baseline Configurations

# https://wiki.ubuntu.com/SystemdForUpstartUsers
# Create the 'per device' files and other tty files
echo -e '#!/bin/bash\nSUDO='';if (( $EUID != 0 )); then SUDO='sudo'; fi\n' > ${TMP_DIR}/start_ppp.sh
echo -e '#!/bin/bash\nSUDO='';if (( $EUID != 0 )); then SUDO='sudo'; fi\n' > ${TMP_DIR}/stop_ppp.sh
cat ${DIR}/etc/mgetty/mgetty.config.baseline > ${TMP_DIR}/mgetty.config
cat ${DIR}/etc/mgetty/login.config > ${TMP_DIR}/login.config
echo -e "AIRCRAFT_NETWORK='${AIRCRAFT_NETWORK}'" >> ${TMP_DIR}/network.config
for ((i=0;i<${#SDEVS[@]};i++))
do
  DEV="${SDEVS[$i]}"
  # /etc/init (UPSTART)
  sed "s/ttySX/${DEV}/g" ${DIR}/etc/init/ttySX.conf.baseline > ${TMP_DIR}/${DEV}.conf
  $SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/init ${TMP_DIR}/${DEV}.conf
  if [ "$UVER" == "16.04" ] && [ -d /lib/systemd/system ]
  then
    # /lib/systemd/system (SYSTEMD)
    sed "s/ttySX/${DEV}/g" ${DIR}/lib/systemd/system/ttySX.service.baseline > ${TMP_DIR}/${DEV}.service
    $SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /lib/systemd/system ${TMP_DIR}/${DEV}.service
    # Start/Stop Scripts (SYSTEMD)
    echo "\$SUDO systemctl restart ${DEV} 2>/dev/null || \$SUDO systemctl start ${DEV}" >> ${TMP_DIR}/start_ppp.sh
    echo "\$SUDO systemctl stop ${DEV} 2>/dev/null"  >> ${TMP_DIR}/stop_ppp.sh
  else
    # Start/Stop Scripts (UPSTART)
    echo "\$SUDO restart ${DEV} 2>/dev/null || \$SUDO start ${DEV}" >> ${TMP_DIR}/start_ppp.sh
    echo "\$SUDO stop ${DEV} 2>/dev/null"  >> ${TMP_DIR}/stop_ppp.sh
  fi
  # /etc/ppp
  sed "s/ttySX/${DEV}/g;s/.X./.${i}./" ${DIR}/etc/ppp/options.ttySX.baseline > ${TMP_DIR}/options.${DEV}
  $SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/ppp ${TMP_DIR}/options.${DEV}
  # /etc/mgetty
  sed "s/ttySX/${DEV}/g" ${DIR}/etc/mgetty/mgetty.config.add >> ${TMP_DIR}/mgetty.config

done
$SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/mgetty ${TMP_DIR}/mgetty.config
$SUDO install -b -S ".${DATE}.bak" -m 600 -o root -g root -t /etc/mgetty ${TMP_DIR}/login.config
$SUDO install -b -S ".${DATE}.bak" -m 755 -o root -g root -t /etc/ppp/ip-up.d/ ${DIR}/etc/ppp/ip-up.d/iptables-up
$SUDO install -b -S ".${DATE}.bak" -m 755 -o root -g root -t /etc/ppp/ip-down.d/ ${DIR}/etc/ppp/ip-down.d/iptables-down
$SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/ppp/ ${TMP_DIR}/network.config
$SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/ppp/ ${DIR}/etc/ppp/options
$SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/ppp/ ${DIR}/etc/ppp/logrotate.conf
# Make sure Reverse Path Filtering is OFF!
$SUDO bash -c 'grep -rl "^[^#].*rp_filter=1" /etc/ | xargs sed -i".${DATE}.bak" "s/rp_filter=1/rp_filter=0/g"'


## STEP 3 - Install rc.local
sed "s/{IFACE}/${IFACE}/g;s/{IPADDR}/${IPADDR}/g;s/{NUM}/${NMODEMS}/g" ${DIR}/etc/rc.local.baseline > ${TMP_DIR}/rc.local
if [ -n "${AUTO_START}" ]; then sed -i 's|#/home/nasa/start_ppp.sh|/home/nasa/start_ppp.sh|g' ${TMP_DIR}/rc.local; fi
$SUDO install -b -S ".${DATE}.bak" -m 755 -o root -g root -t /etc ${TMP_DIR}/rc.local
# Setup port forwarding rules
echo -e "#!/bin/sh\n\n# This following line should not be needed on Virtual Machines" > ${TMP_DIR}/port_forwarding.sh
if [ -n "${VIRTUAL_HOST}" ]; then echo -n '#' >> ${TMP_DIR}/port_forwarding.sh; fi
echo "iptables -t nat -I POSTROUTING 1 -o ${IFACE} -p udp -j SNAT --to-source ${IPADDR}" >> ${TMP_DIR}/port_forwarding.sh
echo -e "\n# Specify any port forwards\n# Example:" >> ${TMP_DIR}/port_forwarding.sh
echo "# iptables -t nat -A PREROUTING -p udp --dport 2022 -i ${IFACE} -j DNAT --to-destination 10.1.1.18:22" >> ${TMP_DIR}/port_forwarding.sh
if [ -n "${PORT_FORWARD}" ]; then
  for RULE in ${PORT_FORWARD}; do
    IFS="," read DPORT DST <<< "${RULE}"
    echo "iptables -t nat -A PREROUTING -p udp --dport ${DPORT} -i ${IFACE} -j DNAT --to-destination ${DST}" >> ${TMP_DIR}/port_forwarding.sh
  done
fi
$SUDO install -b -S ".${DATE}.bak" -m 755 -o root -g root -t /etc ${TMP_DIR}/port_forwarding.sh


## STEP 4 - Reconfigure IRC (UnrealIRCd) if needed
UNREAL_VER="4.0.18"
if [ -z "${PRIOR}" ] || [ ! -z "${RECOMPILE}" ]
then
  $SUDO su - ircd -c "rm -rf /home/ircd/unrealircd-${UNREAL_VER}/ 2>/dev/null"
  $SUDO su - ircd -c "tar -zxvf ${DIR}/packages/unrealircd-${UNREAL_VER}.tar.gz"
  $SUDO su - ircd -c "patch -d unrealircd-${UNREAL_VER}/ -p1 < ${DIR}/packages/unrealircd.grc.servername.patch"
  $SUDO install -m 664 -o ircd -g ircd ${DIR}/packages/unrealircd.config.settings /home/ircd/unrealircd-${UNREAL_VER}/config.settings
  $SUDO su - ircd -c "cd unrealircd-${UNREAL_VER}; ./Config -clean -nointro -quick"
fi
if [ -z "${PRIOR}" ] || [ ! -z "${RECOMPILE}" ] || [ -n "${SSL_RECOMPILE}" ]
then
  $SUDO install -m 600 -o ircd -g ircd ${DIR}/host_configs/unrealircd.ssl.cnf /home/ircd/unrealircd-${UNREAL_VER}/src/ssl.cnf
  $SUDO su - ircd -c "make -C unrealircd-${UNREAL_VER} pem"
  $SUDO su - ircd -c "make -C unrealircd-${UNREAL_VER} install"
  sed "s/{IRC_ID}/${IRC_ID}/g;s/{IPADDR}/${IPADDR}/g" ${DIR}/home/ircd/unrealircd/conf/unrealircd.conf.baseline > ${TMP_DIR}/unrealircd.conf
  $SUDO install -b -S ".${DATE}.bak" -m 600 -o ircd -g ircd -t /home/ircd/unrealircd/conf ${TMP_DIR}/unrealircd.conf
fi
# Always copy in the user irc configs
sed "s/{IRC_ID}/${IRC_ID}/g;s/{IRC_DOMAIN}/${IRC_DOMAIN}/g;s/{IPADDR}/${IPADDR}/g" ${DIR}/host_configs/irc-server.conf > ${TMP_DIR}/irc-server.conf
sed "s/{IRC_ID}/${IRC_ID}/g;s/{IRC_DOMAIN}/${IRC_DOMAIN}/g;s/{IPADDR}/${IPADDR}/g" ${DIR}/host_configs/irc-network.conf > ${TMP_DIR}/irc-network.conf
$SUDO install -b -S ".${DATE}.bak" -m 600 -o ircd -g ircd -t /home/ircd/unrealircd/conf ${TMP_DIR}/irc-server.conf
$SUDO install -b -S ".${DATE}.bak" -m 600 -o ircd -g ircd -t /home/ircd/unrealircd/conf ${TMP_DIR}/irc-network.conf


## FINISHED
install -b -S ".${DATE}.bak" -m 775 -t ${HOME} ${TMP_DIR}/start_ppp.sh ${TMP_DIR}/stop_ppp.sh
install -b -S ".${DATE}.bak" -m 644 ${TMP_DIR}/install.log ${DIR}/install.log
echo ""
echo "########## Reconfiguration Complete!! ##########"
echo "##########    Reboot Recommended!!    ##########"
echo ""
