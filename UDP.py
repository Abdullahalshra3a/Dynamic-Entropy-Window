
#!/usr/bin/python   
#A script to generate packets to destination 10.0.0.9, using the source ip of the sending node using UDP
#you can run this script from any node you want'''
from random import randint
import sys, os
from scapy.all import *


def generatePackets():
      if len(sys.argv) != 3:
        print "Usage: arping2tex <net>\n eg: arping2text 192.168.1.0/24"
        sys.exit(1)
      src= sys.argv[1]
      dst= sys.argv[2]
      #print src, dst       
      data = "Abdullah Soliman Alshraa"
      ip=IP(src= src, dst= dst)
      udp=UDP(sport= 2235, dport=5546)#, 
      pkt = (ip/udp/data)
      x = random.randint(1,10)
      send(pkt, count = x, inter=1./x)   
    
if __name__ == '__main__':
    generatePackets()

