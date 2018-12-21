#!/bin/bash

## USAGE - Prep System for Configuration
## No options

# The version of this script
VERSION=3

die() { printf "STOP: %s" "${@+$@$'\n'}" 1>&2; exit 1; }

# Date and time script was run
DATE=$(date '+%F_%H-%M-%S')
# The directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function cleanup {
  :; # Nothing to clean up
}
trap cleanup EXIT

# This script was build for Ubuntu... try and find the version
UVER=$(grep VERSION_ID /etc/os-release | grep -o [0-9.]*)
# ... Tested on 14.04 and 16.04
[[ ("$UVER" == "16.04" ) || ( "$UVER" == "14.04") ]] || die "Unsupported Ubuntu Version: ${UVER}"

# Let the user know what we are doing
echo ""
echo "########## Installation Starting!! ##########"
echo ""
echo "If you do not want to alter your kernel or host hit Control-C now!"
echo "Otherwise hit Enter to continue..."
read INPUT

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

## STEP 1 - Install Software Packages
PACKAGES='''
bc
iptables
iproute2
net-tools
tcpdump
openssh-client
openssh-server
python
mgetty
make
git
bison
flex
libdb-dev
libssl-dev
squid3
ppp
ntpdate
'''
$SUDO apt-get -y install ${PACKAGES}
if (( $? != 0 ))
then
  die "Unable to install packages... please check your network connection."
fi

## STEP 2 - Create the Users
for i in nasa ircd
do
  id -u $i > /dev/null 2>&1
  if (( $? != 0 ))
  then
    echo "Creating $i user..."
    $SUDO adduser --quiet --disabled-password --gecos "" $i || die "Unable to create the $i user"
  fi
done

## STEP 3 - Install MPTCP Kernel and make it Default
# DPKG gets mad if the kernel is already installed, check for it
KERNEL_OK=$(ls -1 ${DIR}/packages/ | grep -Eo 'linux-[^+]*\+' | xargs dpkg-query -l 2>/dev/null | grep -c 'ii')
if (( KERNEL_OK < 2 ))
then
  # Kernel not present, need to install
  if [ "$(getconf LONG_BIT)" == "64" ]
  then
    echo "Installing 64-bit MPTCP Kernel"
    $SUDO dpkg -i ${DIR}/packages/linux*mptcp*_amd64.deb
  else
    echo "Installing 32-bit MPTCP Kernel"
    $SUDO dpkg -i ${DIR}/packages/linux*mptcp*_i386.deb
  fi
  KERNEL_REV=$(uname -r | cut -d. -f1-2)
  if [ "${KERNEL_REV}" == 4.4 ]
  then
    GRUB='Advanced options for Ubuntu>Ubuntu, with Linux 4.4.88+'
  else
    GRUB='Advanced options for Ubuntu>Ubuntu, with Linux 3.18.43+'
  fi
  $SUDO sed -i".${DATE}.bak" "s/^GRUB_DEFAULT=.*/GRUB_DEFAULT='${GRUB}'/" /etc/default/grub || $SUDO echo "GRUB_DEFAULT='${GRUB}'" >> /etc/default/grub
  $SUDO update-grub
fi

## STEP 4 - Install MPTCP tools into the NASA home directory
$SUDO su - nasa -c "rm -Rf ~/iproute-mptcp-0.92 2>/dev/null"
$SUDO su - nasa -c "tar -C ~ -zxvf ${DIR}/packages/iproute-mptcp-0.92.tar.gz"
$SUDO su - nasa -c "make -C iproute-mptcp-0.92"
$SUDO make -C ~nasa/iproute-mptcp-0.92 install
$SUDO su - nasa -c "rm -Rf ~/net-tools-0.92_debian 2>/dev/null"
$SUDO su - nasa -c "tar -C ~ -zxvf ${DIR}/packages/net-tools-0.92_debian.tar.gz"
$SUDO su - nasa -c "yes '' | make -C ~/net-tools-0.92_debian config"
$SUDO su - nasa -c "make -C ~/net-tools-0.92_debian"
$SUDO make -C ~nasa/net-tools-0.92_debian install

## STEP 5 - Configure Directories

declare -a dirs=(
  '("/etc/init" "755" "root" "root")'
  '("/etc/mgetty" "755" "root" "root")'
  '("/etc/ppp/ip-down.d" "755" "root" "root")'
  '("/etc/ppp/ip-up.d" "755" "root" "root")'
  '("/home/nasa/baseline/" "775" "nasa" "nasa")'
  '("/var/log/ppp" "755" "root" "root")'
  '("/home/ircd/unrealircd" "775" "ircd" "ircd")'
)

for i in "${dirs[@]}"
do
  eval j=$i
  if [ -d "${j[0]}" ]
  then
    echo "${j[0]} exists"
  else
    echo "${j[0]} does not exist... creating"
    $SUDO install -d -m ${j[1]} -o ${j[2]} -g ${j[3]} ${j[0]}
  fi
done

## STEP 6 - Install UDP Proxy program
$SUDO install -b -S ".${DATE}.bak" -m 664 -o nasa -g nasa -t /home/nasa ${DIR}/home/nasa/udp_proxy.py

## STEP 7 - Install rc.local
$SUDO install -b -S ".${DATE}.bak" -m 755 -o root -g root -t /etc ${DIR}/etc/rc.local

## STEP 8 - Configure HTTP proxy (SQUID)
if [ -d /etc/squid3 ]
then
  $SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/squid3 ${DIR}/etc/squid3/squid.conf
elif [ -d /etc/squid ]
then
  # Location of squid3 configs changed in 16.04 from /etc/squid3 to /etc/squid
  $SUDO install -b -S ".${DATE}.bak" -m 644 -o root -g root -t /etc/squid ${DIR}/etc/squid3/squid.conf
fi
# Add proxy elements to /etc/environment
$SUDO sed -n -i -e '/^http_proxy=/!p' -e '$ahttp_proxy="http://localhost:3128"' /etc/environment
$SUDO sed -n -i -e '/^https_proxy=/!p' -e '$ahttps_proxy="http://localhost:3128"' /etc/environment

## STEP 9 - Copy baseline configs to the nasa user so that we have a set location for reconfigurations
if [ "${DIR}" != "/home/nasa/baseline" ]
then
  $SUDO cp -av ${DIR}/* /home/nasa/baseline/
  $SUDO chown -R nasa:nasa /home/nasa/baseline/
  cd ${DIR}; cd ../
  rm -Rf ${DIR} 2>/dev/null
fi

## FINISHED
echo ""
echo "########## Installation Complete!! ##########"
if (( $(uname -r | grep -c normadd) == 0 ))
then
  echo "##########    REBOOT REQUIRED!!    ##########"
  echo "---> PLEASE REBOOT TO ENTER THE MPTCP BUILD"
fi
echo ""
