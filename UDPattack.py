
#!/usr/bin/python   
#A script to generate packets to destination 10.0.0.9, using the source ip of the sending node using UDP
#you can run this script from any node you want'''

import sys, os
from scapy.all import *
from random import randint

def generatePackets():
      if len(sys.argv) != 3:
        print "Usage: arping2tex <net>\n eg: arping2text 192.168.1.0/24"
        sys.exit(1)
      src= sys.argv[1]
      dst= sys.argv[2]
      #print src, dst      
      data = "Abdullah Soliman Alshraa"
      ip=IP(src= src, dst= dst)
      udp=UDP(sport= 2235, dport=5546)# inter=1./20 means 20 pkt in secondes      
      if src == "10.0.0.4" or src == "10.0.0.7" :
         pkt = (ip/udp/Raw(RandString(size=472)))
         send(pkt, count = 500, inter=1./1000)
         print "Hello"   
      else:
         x = random.randint(1,10)
         pkt = (ip/udp/data)
         send(pkt, count = x)   
    
if __name__ == '__main__':
    generatePackets()
