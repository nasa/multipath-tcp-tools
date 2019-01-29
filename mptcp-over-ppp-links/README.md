LICENSE
-------
NASA OPEN SOURCE AGREEMENT VERSION 1.3

Government Agency: NASA Glenn Research Center
Government Agency Original Software Designation: LEW-19620-1
Government Agency Original Software Title: Multipath TCP (MPTCP) Tools, Analysis, and Configurations
User Registration Requested. Please Visit https://github.com/nasa/multipath-tcp-tools
Government Agency Point of Contact for Original Software: Joseph Ishac <jishac@nasa.gov>

Please see LICENSE file for full text.

DESCRIPTION
-----------

A collection of scripts to automate the install and configuration of a MPTCP host.  There are a set of scripts for a "ground station" install and an "aircraft" install.  The aircraft is intended to dial into a respective ground station over multiple satellite modems.

These scripts are intended to provide a "turn-key" solution for MPTCP and UDP.  See RELEASES for pre-built packages.

OVERVIEW
--------

This software suit was utilized in the studies documented under the paper titled "Improving Scientific Payload Communication Over Multiple, Low-Capacity Links" and found online at:

https://ntrs.nasa.gov/search.jsp?R=20180004402

This source tree contains several directories:

*aircraft* contains the files needed to configure a host to act as an aircraft and thus, dial out to a supporting ground station.

*ground* contains the files needed to configure a host (or virtual host) to act as a ground station and thus, receive calls.  

*packages* contains compressed archives of software common to both builds along with pre-compiled MPTCP kernels that contain custom patches.

RELEASES
--------
Pre-built tarballs, virtual machines, or other packages can be found at https://github.com/nasa/multipath-tcp-tools/releases

INSTALLATION
------------

**NOTE WELL**: Please see the section on KNOWN ISSUES AND LIMITATIONS for important build limitations

### WARNING!!!!!!!

These scripts modify system files and utilizes experimental code. It is not capable of backing out all changes an can leave your system in a state which requires manual cleanup.  A reasonable effort is made to backup files, but please be cautious.  This script also installs a new kernel and modifies the boot loader.

Installation tarballs can be made using make in the root directory (or can be downloaded directly from the git releases).

Copy the installation tarball to a fresh host and unpack.

In the newly created directory there will be a script, `system_prep.sh`, which is used to prep the system, installing the needed kernels and packages.

After the script completes, the system can be configured using:
```
sudo /home/nasa/baseline/reconfigure.sh
```
Please see the README file included in the installation tarball for specifics on configuration.


KNOWN ISSUES AND LIMITATIONS
----------------------------
1. Not all combinations thoroughly tested.

  Currently this setup has only been extensively tested with an Ubuntu 14.04 ground station running the 3.18 kernel and an aircraft running Ubuntu 16.04 with the 4.4 kernel.  Other combinations have not been thoroughly tested.

2. Tested under Ubuntu 14 and 16

The scripts expect and were tested using an Ubuntu system, but may be compatible with other similar operating systems.

