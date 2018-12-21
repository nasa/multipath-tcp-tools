#!/usr/bin/python

# Copyright (c) 2018
# United States Government as represented by Joseph Ishac <jishac@nasa.gov>
# No copyright is claimed in the United States under Title 17, U.S.Code. All Other Rights Reserved.

# This program attempts to forward tunneled traffic and send it over multiple
# interfaces that can reach the same destination.  One use case is when sending
# data through multiple PPP links.  The performance of this solution will be
# better than multi-link PPP (ML-PPP) for links that are lossy or unreliable.

# The name udp_proxy comes from original intent of this program to supplement
# Multipath TCP (MPTCP).  UDP traffic would be forwarded to the tun interface,
# and this proxy would service any packets placing them on the PPP interfaces.

# Currently transmission of a packet is tried N number of times, where N is the
# number of expected interfaces.  Future versions of this code may attempt to
# leverage traffic priority classes or other more advanced features.

import os, sys, socket, time, signal
import struct, logging, math
from argparse import ArgumentParser, ArgumentTypeError, SUPPRESS
import fcntl
import select

def sigint_handler(signal, stackframe):
  # Handler for Ctrl-C (SIGINT)
  print ""
  logging.debug('Caught Interrupt, Exiting!')
  cleanup()
  sys.exit(2)

def main_exit(msg="",val=1):
  if (val == 0):
    logging.warn(msg)
  else:
    logging.critical(msg)
  cleanup()
  sys.exit(val)

def cleanup():
  global sock
  global fd_stream
  global fd_trace
  if sock is not None:
    sock.close()
  if fd_stream is not None:
    fd_stream.close()
  if fd_trace is not None:
    fd_trace.close()

class tunnel():
  tun = None
  def __init__ (self, name, mode='r+b'):
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    self.tun = open('/dev/net/tun', mode)
    ifr = struct.pack('16sH', str(name), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(self.tun, TUNSETIFF, ifr)
    #fcntl.ioctl(self.tun, TUNSETOWNER, 1000)
    fcntl.fcntl(self.tun, fcntl.F_SETFL, os.O_NONBLOCK)
    self.fileno = self.tun.fileno()
  def read(self, size):
    return os.read(self.fileno, size)
  def write(self, buff):
    return os.write(self.fileno, buff)
  def close(self):
    return True

if __name__ == '__main__':
  # Administrative Stuff
  signal.signal(signal.SIGINT, sigint_handler)
  # Globals that will require "cleanup"
  sock = None
  sock_list = []
  fd_stream = None
  fd_trace = None
  # Parse Arguments
  parser = ArgumentParser(description="This program will forward UDP traffic to a set of interfaces.  It uses raw sockets and thus requires elevated (root) permissions.")
  parser.add_argument("-V", "--version", action="version", version='%(prog)s version 1.00, Joseph Ishac (jishac@nasa.gov)')
  parser.add_argument("-D", "--debug", action="store_true", dest="debug", default=False, help="Extra debugging information")
  parser.add_argument("-v", "--verbose", action="count", dest="verbose", help="Increase verboseness of messages")
  parser.add_argument("-q", "--quiet", action="store_const", dest="verbose", const=0, help="Disable any extra dialog")
  parser.add_argument("-f", "--force", action="store_true", dest="force", default=False, help="Ignore sanity checks")
  parser.add_argument("-b", "--blocking", action="store_true", dest="blocking", default=False, help="Enable blocking. Block input until SDU bytes are received")
  parser.add_argument("-d", "--discard", action="store_true", dest="discard", default=False, help="If an interface is down, discard the data instead of retrying on another interface.")
  parser.add_argument("-P", "--pcap",
                      action="store", type=str, dest="pcap", default=None,
                      help="Read input from the specified pcap file instead of standard in.", metavar="FILE")
  parser.add_argument("-p", "--prefix",
                      action="store", type=str, dest="prefix", default="ppp",
                      help="Interface PREFIX to search for outbound traffic. (Default: %(default)s)", metavar="PREFIX")
  parser.add_argument("-n", "--number-of-interfaces",
                      action="store", type=int, dest="niface", default=4,
                      help="Number of interfaces to try and use. (Default: %(default)s)", metavar="NUM")
  parser.add_argument("-i", "--index",
                      action="store", type=int, dest="index", default=range(4), nargs="*",
                      help="Specific INDEX(es) to use for the interface. NOTE: Order is maintained. (Default is to use %(default)s)", metavar="INDEX")
  parser.add_argument("-s", "--size",
                      action="store", type=int, dest="sdu", default=1500,
                      help="Max packet SIZE in bytes (SDU) (Default %(default)s)", metavar="SIZE")
  parser.add_argument("-r", "--rate",
                      action="store", type=int, dest="rate", default=0,
                      help="Limit data to RATE bits/second (Default Unlimited)", metavar="RATE")
  parser.add_argument("-T", "--tunnel",
                      action="store", type=str, dest="tunnel_dev", default=None,
                      help="Attach to and Send/Receive to TUN device.", metavar="TUN")
  parser.add_argument("-t", "--timestamp",
                      action="store", type=str, dest="trace",
                      help="Record a timestamped log of outbound and inbound data packets in FILE.", metavar="FILE")
  parser.add_argument("-w", "--wait",
                      action="store", type=int, dest="wait", default=0,
                      help="Connections which are idle after timeout SEC are terminated. Useful for piping from files.", metavar="SEC")
  options = parser.parse_args()

  # Option Checking
  if (options.sdu <= 0):
    parser.error("Packet size too small!")
  if (options.pcap is not None):
    # TODO - pcap support?
    parser.error("Sorry this feature is not implemented yet.")

  if (options.rate > 0):
    delay = (8.0*float(options.sdu))/float(options.rate)
  else:
    delay = 0

  # Establish logging
  # Set log level here in "basicConfig", levels are NOTSET, DEBUG, INFO, WARNING, ERROR and CRITICAL
  logging_format = "%(asctime)s; %(levelname)s; %(funcName)s; %(lineno)d; %(message)s"
  if options.debug:
    logging.basicConfig(level=logging.DEBUG, format=logging_format)
  elif (options.verbose >= 2):
    logging.basicConfig(level=logging.INFO, format=logging_format)
  elif (options.verbose == 1):
    logging.basicConfig(level=logging.ERROR, format=logging_format)
  else:
    logging.basicConfig(level=logging.CRITICAL, format=logging_format)
  
  # Check index values
  if (len(options.index) < options.niface):
    if (options.force):
      while (len(options.index) < options.niface):
        options.index.append(options.index[-1]+1)
      logging.warn("Not enough indexes given, extrapolating to: {}".format(options.index[:options.niface]))
    else:
      parser.error("Not enough interfaces identified!")
  elif (len(options.index) > options.niface):
    if (options.force):
      options.index = options.index[:options.niface]
      logging.warn("Full index will not be used! Only using: {}".format(options.index[:options.niface]))
    else:
      parser.error("Too many interfaces identified!")
  for i in options.index:
    if (i<0):
      parser.error("An index cannot be negative!")

  # Establish Input Timeout Timer if needed
  if (options.wait > 0):
    input_to = 0
    fd_in_empty = False

  # If we are tracing the data, check that we have write access.
  if (options.trace is not None):
    try: fd_trace = open(options.trace, 'wb')
    except IOError, e:
      main_exit('Cannot write to %s: %s'%(options.trace,e),1)

  # Show all set options for Debugging output
  if (options.debug):
    print "Set Options:", options

  # Check for root
  if os.geteuid() != 0:
    if (options.force):
      logging.warning("You need to have root privileges to run this script.")
    else:
      main_exit("You need to have root privileges to run this script.")

  # Establish a RAW socket - Requires ROOT PRIVILEGES
  try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
  except socket.error, err:
    main_exit("Unable to create a socket!: {}".format(err))

  if (options.tunnel_dev is not None):
    # Tunnel Support
    try:
      fd_stream = tunnel(options.tunnel_dev)
      fd_in = fd_stream
      fd_out = fd_stream
      fd_in_ready = fd_stream.tun
    except IOError, e:
      main_exit('Error accessing tunnel: %s'%(e),1)
  else:
    # Normal Input/Output
    # This is Handy for just typing in input and sending it, but that's not terribly useful
    # TODO - Make this dump into a packet?  Will the raw bits to the ppp interface work?  (ie show up on the other side?)
    try:
      fd_in = os.fdopen(sys.stdin.fileno(),'rb',0)
      fd_out = os.fdopen(sys.stdout.fileno(),'wb', 0)
      fd_stream = fd_out
      fd_in_ready = fd_in
      if (options.blocking is False):
        fcntl.fcntl(fd_in, fcntl.F_SETFL, os.O_NONBLOCK)
    except IOError,e:
      main_exit('Broken Pipe',1)
  sock_list.append(fd_in_ready)
  
  # Don't block on the network interface, but instead raise errors
  sock.setblocking(0)

  # Message Handling
  last_tx = 0
  msg = None
  msg_part = None
  cur_iface = 0

  # Error Handling
  tx_fail={}
  tx_fail_reasons = [None, 19, 100]

  # Main Service Loop
  while 1:
    recv_r, send_r, error_r = select.select(sock_list, [], [sock], 0.2)
    
    # Sending Data

    if (fd_in_ready in recv_r):
      # Postpone our read if we are rate limiting
      if ( (delay == 0) or ((time.time() - last_tx) > delay) ):
        # If tracing, store the time before any other processing.
        if (fd_trace is not None):
          start_tx = time.time()
        # Test to see if raw socket is ready for data
        _,send_r,_ = select.select([], [sock], [], 0)
        if (sock in send_r):
          tx_data = ''
          try: tx_data = fd_in.read(options.sdu)
          except EOFError, e: pass
          except IOError, e: pass
          except OSError, e: pass
          data_len = len(tx_data)
          if (options.wait > 0):
            if (data_len > 0):
              fd_in_empty = False
            else:
              fd_in_empty = True

          if (data_len > 0):
            # Setup a loop here that will retry each interface
            # Leveraging: Socket Error: [Errno 19] No such device
            # Also Errno 100 when the interface exists but it not established yet
            tx_success=False
            tx_fail['cnt'] = 0
            tx_fail['reason'] = None
            while ((not tx_success) and (tx_fail['reason'] in tx_fail_reasons) and (tx_fail['cnt'] < options.niface)):
              iface = options.prefix+str(options.index[cur_iface])
              cur_iface = (cur_iface + 1)%options.niface
              try:
                sock.sendto(tx_data, (iface, 0x0800))
                logging.info("Data SENT on {}".format(iface))
                tx_success=True
              except socket.error, err:
                tx_fail['cnt'] += 1
                tx_fail['reason'] = err.errno
                logging.debug("Socket Error: {}".format(err))
                if (options.discard or (tx_fail['reason'] not in tx_fail_reasons) or (tx_fail['cnt'] == options.niface)):
                  logging.info("Data DROP on {}".format(iface))
                else:
                  logging.info("Data SKIP on {}".format(iface))
                tx_success=False
              if ((options.trace) or (delay > 0)):
                last_tx = time.time()
                if (fd_trace is not None):
                  fd_trace.write("Tx, {:f}, {:f}, {}, {}, {}, {}, {}\n".format(last_tx,start_tx,data_len,iface,tx_success,tx_fail['reason'],str(tx_data).encode('hex')))
                  fd_trace.flush()
              if (options.discard):
                # Don't ever retry if discard is set
                break
          else:
            logging.debug("Failed to write to interface: Nothing to Send")
        else:
          logging.debug("Interface blocked write!")

    # Receive Data

    if (sock in recv_r):
      # For this code, we are not expecting to receive anything on this socket... warn if it happens
      logging.warn("Raw socket has data pending??")
    
    # Erred Socks

    if (sock in error_r):
      # Not expecting this either...
      main_exit("Got note that raw sock is broken... fix!")

    # Input Timeout Checking

    if (options.wait > 0):
      if ((fd_in_ready not in recv_r) or (fd_in_empty)):
        if (input_to == 0):
          input_to = time.time()
        else:
          if (time.time() > (input_to + options.wait)):
            main_exit("Input Timeout",0)
      else:
        input_to = 0

  fd_stream.close()
  sock.close()


