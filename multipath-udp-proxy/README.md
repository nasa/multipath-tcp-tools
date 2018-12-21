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

This program attempts to forward tunneled traffic and send it over multiple
interfaces that can reach the same destination.  One use case is when sending
data through multiple PPP links.  The performance of this solution will be
better than multi-link PPP (ML-PPP) for links that are lossy or unreliable.

The name udp_proxy comes from original intent of this program to supplement
Multipath TCP (MPTCP).  UDP traffic would be forwarded to the tun interface,
and this proxy would service any packets placing them on the PPP interfaces.

Currently transmission of a packet is tried N number of times, where N is the
number of expected interfaces.  Future versions of this code may attempt to
leverage traffic priority classes or other more advanced features.

USAGE
-----
```
usage: udp_proxy.py [-h] [-V] [-D] [-v] [-q] [-f] [-b] [-d] [-P FILE]
                    [-p PREFIX] [-n NUM] [-i [INDEX [INDEX ...]]] [-s SIZE]
                    [-r RATE] [-T TUN] [-t FILE] [-w SEC]

This program will forward UDP traffic to a set of interfaces. It uses raw
sockets and thus requires elevated (root) permissions.

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -D, --debug           Extra debugging information
  -v, --verbose         Increase verboseness of messages
  -q, --quiet           Disable any extra dialog
  -f, --force           Ignore sanity checks
  -b, --blocking        Enable blocking. Block input until SDU bytes are
                        received
  -d, --discard         If an interface is down, discard the data instead of
                        retrying on another interface.
  -P FILE, --pcap FILE  Read input from the specified pcap file instead of
                        standard in. (NOT YET SUPPORTED)
  -p PREFIX, --prefix PREFIX
                        Interface PREFIX to search for outbound traffic.
                        (Default: ppp)
  -n NUM, --number-of-interfaces NUM
                        Number of interfaces to try and use. (Default: 4)
  -i [INDEX [INDEX ...]], --index [INDEX [INDEX ...]]
                        Specific INDEX(es) to use for the interface. NOTE:
                        Order is maintained. (Default is to use [0, 1, 2, 3])
  -s SIZE, --size SIZE  Max packet SIZE in bytes (SDU) (Default 1500)
  -r RATE, --rate RATE  Limit data to RATE bits/second (Default Unlimited)
  -T TUN, --tunnel TUN  Attach to and Send/Receive to TUN device.
  -t FILE, --timestamp FILE
                        Record a timestamped log of outbound and inbound data
                        packets in FILE.
  -w SEC, --wait SEC    Connections which are idle after timeout SEC are
                        terminated. Useful for piping from files.
```

EXAMPLES
--------

```
sudo python udp_proxy.py -T tun0
```

Will attempt to forward packets from tun0 to 4 PPP devices: ppp0, ppp1, ppp2, ppp3

```
sudo python udp_proxy.py -D -vv -T tun0 >> /var/log/udp_proxy.log 2>&1
```

Same as the first example, but also log activity to a log file.

```
sudo python udp_proxy.py -T tun0 -n 8
```

Will produce an error, not enough interfaces specified.  To remedy either specify:

```
sudo python udp_proxy.py -T tun0 -n 8 -i 0 1 2 3 4 5 6 7
```

or use the force option:

```
sudo python udp_proxy.py -T tun0 -n 8 -f; # Extrapolates the initial [0,1,2,3] to [0,1,2,3,4,5,6,7]
```

The force option can also be used to quickly re-index the device list from 0

```
sudo python udp_proxy.py -T tun0 -n 4 -i 4 -f; # Uses ppp4, ppp5, ppp6, ppp7
```

The -f option is also required if the initial index is not fully used (truncation).

```
sudo python udp_proxy.py -T tun0 -n 2
```

Will also produce an error.  Thus, if you intend to modify the number of interfaces, either use the -f option or specify the indexes using -i
