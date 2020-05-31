#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import CPULimitedHost
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
   net = Mininet(controller=RemoteController,host=CPULimitedHost, link=TCLink )
   c1 = net.addController('c1', controller=RemoteController, ip="127.0.0.1")
   host= [0]*15 
   for i in range(1,16):
      if i < 10 :
           mac = '00:00:00:00:00:0%s'%str(i)
           ip = '10.0.0.%s'%str(i)
           host[i-1]= net.addHost('h%s'%str(i),  ip=ip, mac=mac, cpu = 0.04)
      else:      
           mac = '00:00:00:00:00:%s'%str(i)
           ip = '10.0.0.%s'%str(i)
           host[i-1]= net.addHost('h%s'%str(i),  ip=ip, mac=mac, cpu = 0.04)
     

   switch = [0]*20 
   for i in range(1,21):
      # x = i + 1
      if i < 10 :
          dpid='000000000000010%s'%str(i)
      else:      
          dpid='00000000000001%s'%str(i)     
      switch[i-1]= net.addSwitch('s%s'%str(i), dpid= dpid)
      

   linkopts = dict(cls=TCLink, bw=100, delay='5ms', max_queue_size=100, use_htb=True)#800Mb = 100MByte
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
   #c1.cmd("tcpdump -i any -nn port 6633 -U -w mylog &")
   
   for i in range(0,20):
     switch[i].start([c1])
   net.start()
   enableSTP()
   net.staticArp()
   
   info( '\n*** Starting web server ***\n')
   h15 = net.get('h15')
   os.system('sudo tcpdump -i lo -w ryu-local.cap &')
   h15.cmdPrint('iperf -s -u -p 5546 -i 245 > Server.log &')
   #h15.cmdPrint('sudo ./D-ITG-2.8.1-r1023/bin/ITGRecv &')
   h15.cmd('sudo tcpdump -i h15-eth0 port 5546 -w server.pcap &')
   #h15.cmdPrint('sudo tcpdump -i h15-eth0 udp -c 1000 src 10.0.0.7 -w Delay.pcap &')
   info( '*** Starting the simulation in 30 Seconds ***\n')
   info( '*** Run the ryu Controller now ***\n')
   time.sleep(30)

   for i in range(1,15):
     client=net.get('h%s'%str(i))
     client.cmdPrint('sudo hping3 -c 1 -i --udp --verbose  -p 5546 10.0.0.15 &')

   time.sleep(2)
   finish_time = 0
   i = 0 
   start_time = time.time()
   for i in range(1,15):
       t = threading.Thread(target= Training, args=(net,i,))
       t.setDaemon(True)
       t.start()     
   while finish_time <61:# Training time to gather the information       
         finish_time = time.time() - start_time

   time.sleep(1)
   global Pkt_number
   """
   #x = threading.Thread(target= Attacker, args=(net,1))
   #x.setDaemon(True)
   #x.start()
   for i in range(1,15):
         x = threading.Thread(target= Attack, args=(net,i))
         x.setDaemon(True)
         x.start()
   """
   Attack(net)
   while finish_time < 240:
         finish_time = time.time() - start_time 

   print 'finish_time = ', finish_time 
   print Pkt_number 
   CLI( net )
   net.stop()
       
   
def Training(net,i):
      start_time = time.time()
      finish_time = 0
      while finish_time < 60: 
        x = randint(1,10)
        #client.cmdPrint('hping3 10.0.0.15  -c %s -s 2235 -p 5546 --data 500 &'%str(value))
        client=net.get('h%s'%str(i))         
        client.cmdPrint('sudo python UDP.py 10.0.0.%s 10.0.0.15 %s &'%(i,x))
        time.sleep(1)
        finish_time = time.time() - start_time 
def Attacker(net,i):
         start_time = time.time()
         finish_time = 0
         while finish_time < 180:
           client=net.get('h%s'%str(i))
           #client.cmdPrint('sudo python UDPattack.py 10.0.0.%s 10.0.0.15 &'%str(i))
           client.cmd('hping3 10.0.0.15  -c %s --udp --flood  --verbose -s 2235 -p 5546 --data 500 &'%x)        
           time.sleep(1)
           finish_time = time.time() - start_time 

def Attack(net):
        global Pkt_number
        K = [1,3,5]
           #if i == 7:
           #client=net.get('h%s'%str(i))
           #client.cmdPrint('sudo python UDPNormal.py 10.0.0.%s 10.0.0.15 &'%str(i))
           #Pkt_number = Pkt_number + 100
           #value = 10000 #randint(1, 10) P
           #client.cmdPrint('iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP &')        
           #client.cmdPrint('hping3 10.0.0.15  -c 1000 --udp --verbose -s 2235 -p 5546 --data 500 &')
        start_time = time.time()
        finish_time = 0
        N = 0
        attackers = [1,2,3]
        attackers.append(K[N])
        Period = 10        
        while finish_time < 180:
          for i in range(1,15):
             if i in attackers:
               x = 10000 #randint(1000,1500)
               client=net.get('h%s'%str(i))
               #client.cmdPrint('sudo python UDP.py 10.0.0.%s 10.0.0.15 &'%str(i))
               client.cmdPrint('hping3 10.0.0.15 -c %s --udp -i u10 --verbose -s 2235 -p 5546  &' %x)#--data 500        
               finish_time = time.time() - start_time          
             else:
                x = randint(300,400)
                client=net.get('h%s'%str(i))
                client.cmdPrint('sudo python UDP.py 10.0.0.%s 10.0.0.15 %s &'%(i,x))
                #client.cmdPrint('sudo ./D-ITG-2.8.1-r1023/bin/ITGSend -T UDP -a 127.0.0.1 -c 100 -C %s \-l sender.log -x receiver.log &'%x)
                Pkt_number = Pkt_number + x
                finish_time = time.time() - start_time
                if finish_time > Period:
                   Period = Period + 20
                   N = N + 1     
                   #attackers = K[N-1:N+1]
                   #attacker = k[:N]
          t_end = time.time() + 1 
          while time.time() < t_end:
            pass

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
