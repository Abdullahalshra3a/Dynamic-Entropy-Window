#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from random import randint
import time
import os, psutil
import threading
from mininet.topo import Topo

Pkt_number = 0
def emptyNet():
   os.system('sudo mn -c')
   os.system('pkill -KILL iperf')
   net = Mininet(controller=RemoteController,  switch=OVSKernelSwitch)
   c1 = net.addController('c1', controller=RemoteController, ip="127.0.0.1")
   host= [0]*15 
   for i in range(1,16):
      if i < 10 :
           mac = '00:00:00:00:00:0%s'%str(i)
           ip = '10.0.0.%s'%str(i)
           host[i-1]= net.addHost('h%s'%str(i),  ip=ip, mac=mac)
      else:      
           mac = '00:00:00:00:00:%s'%str(i)
           ip = '10.0.0.%s'%str(i)
           host[i-1]= net.addHost('h%s'%str(i),  ip=ip, mac=mac)
     

   switch = [0]*20 
   for i in range(1,21):
      # x = i + 1
      if i < 10 :
          dpid='000000000000010%s'%str(i)
      else:      
          dpid='00000000000001%s'%str(i)     
      switch[i-1]= net.addSwitch('s%s'%str(i), dpid= dpid)
      

   linkopts = dict(cls=TCLink, bw=100, delay='5ms')#800Mb = 100MByte
   print 'bulding links for Core switches from S1 to S4.'
   net.addLink(switch[0], switch[4], **linkopts)
   net.addLink(switch[0], switch[6], **linkopts)
   net.addLink(switch[0], switch[8], **linkopts)
   net.addLink(switch[0], switch[10], **linkopts)
   net.addLink(switch[1], switch[4], **linkopts)
   net.addLink(switch[1], switch[6], **linkopts)
   net.addLink(switch[1], switch[8], **linkopts)
   net.addLink(switch[1], switch[10], **linkopts)

   net.addLink(switch[2], switch[5], **linkopts)
   net.addLink(switch[2], switch[7], **linkopts)
   net.addLink(switch[2], switch[9], **linkopts)
   net.addLink(switch[2], switch[11], **linkopts)
   net.addLink(switch[3], switch[5], **linkopts)
   net.addLink(switch[3], switch[7], **linkopts)
   net.addLink(switch[3], switch[9], **linkopts)
   net.addLink(switch[3], switch[11], **linkopts)
   print 'bulding links for aggregation switches from S5 to S12.'
   net.addLink(switch[4], switch[12], **linkopts)
   net.addLink(switch[4], switch[13], **linkopts)
   net.addLink(switch[5], switch[12], **linkopts)
   net.addLink(switch[5], switch[13], **linkopts)
   net.addLink(switch[6], switch[14], **linkopts)
   net.addLink(switch[6], switch[15], **linkopts)
   net.addLink(switch[7], switch[14], **linkopts)
   net.addLink(switch[7], switch[15], **linkopts)

   net.addLink(switch[8], switch[16], **linkopts)
   net.addLink(switch[8], switch[17], **linkopts)
   net.addLink(switch[9], switch[16], **linkopts)
   net.addLink(switch[9], switch[17], **linkopts)
   net.addLink(switch[10], switch[18], **linkopts)
   net.addLink(switch[10], switch[19], **linkopts)
   net.addLink(switch[11], switch[18], **linkopts)
   net.addLink(switch[11], switch[19], **linkopts)
   #switch[19].linkTo(switch[20])


   print 'bulding links between hosts and edge switches.'
   for i in range(12,20):
      if i == 12:
         for x in range(0,2):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 13:
         for x in range(2,4):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 14:
         for x in range(4,6):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 15:
         for x in range(6,8):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 16:
          for x in range(8,10):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 17:
          for x in range(10,12):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 18:
          for x in range(12,14):
               net.addLink(switch[i], host[x], **linkopts)
      elif i == 19:
          for x in range(14,15):
               net.addLink(switch[i], host[x], **linkopts)
      else:
          pass     
                         

   
   net.build()
   c1.start()
   
   
   for i in range(0,20):
     switch[i].start([c1])
   net.start()
   enableSTP()
   net.staticArp()
   os.system('sudo tcpdump -i lo -w ryu-local.cap &')
   server=net.get('h%s'%str(15))
   server.cmdPrint('sudo hping3 -c 1 -i  --verbose  -p 5546 10.0.0.15 &')

   server.cmd('sudo tcpdump -i server-eth0 port 5546 -w server.pcap &')
   info( '*** Starting the simulation in 30 Seconds ***\n')
   time.sleep(30)
   #global Pkt_number

   for i in range(1,15):
     client=net.get('h%s'%str(i))
     client.cmdPrint('sudo hping3 -c 1 -i  --verbose  -p 5546 10.0.0.15 &')


   finish_time = 0
   i = 0 
   start_time = time.time()     
   while finish_time <60:# Training time to gather the information
         i = i + 1
         t = threading.Thread(target= Training, args=(net,i,))
         t.setDaemon(True)
         t.start()
         if i == 14:
            time.sleep(1)
            i = 0
         finish_time = time.time() - start_time
   time.sleep(1)

   while finish_time < 240:
         i = i + 1
         x = threading.Thread(target= Attack, args=(net,i))
         x.setDaemon(True)
         x.start()
         if i == 14:
            time.sleep(1)
            i = 0
         finish_time = time.time() - start_time 
   print 'finish_time = ', finish_time 
   
   CLI( net )
   net.stop()
       
   
def Training(net,i):
        client=net.get('h%s'%str(i))
        client.cmdPrint('sudo python UDP.py 10.0.0.%s 10.0.0.15 &'%(str(i)))


def Attack(net,i):
        client = net.get('h%s'%str(i)) 
        if i == 4:
            value = randint(1, 10)
            client.cmdPrint('sudo hping3 -d 472 -c %d --udp -i u100 --verbose  -s 2235 -p 5546 10.0.0.15 -S'%(value))        
        else:
            client=net.get('h%s'%str(i))
            client.cmdPrint('sudo python UDP.py 10.0.0.%s 10.0.0.15 &'%str(i))

def enableSTP():
    """
    //HATE: Dirty Code
    """
    for x in range(1,21):
        cmd = "ovs-vsctl set Bridge s%s stp_enable=true" %x
        os.system(cmd)
        print cmd    

if __name__ == '__main__':

    setLogLevel( 'info' )
    emptyNet()
