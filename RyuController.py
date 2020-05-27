# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import division
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, ipv6 , arp, icmp
from ryu.lib.packet import ether_types
import math
import threading 
import psutil, os, sys 
import time
from scipy.stats import pearsonr
#import numpy as np
#import matplotlib.pyplot as plt
 
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    Data_Path = {}
    Flowcounter = {}
    blockPkt =[]
    blockByte=[]
    CPU = {}
    Memory = {}
    prevaluePkt={}
    prevalueByte={}
    ingressPkt={}
    ingressByte={}# Number of pkts for each ingress port in last round
    AvaPkt=[]# initial window
    AvaByte=[]
    Counter = 0
    Hostnumber = 14 # according to the Topology we have 14 user and one server
    WindowSizePkt = 8 # initail windows size
    WindowSizeByte = 8
    blockedlist = {}# the dpid and port which connected to the blocked user
    host = {}# includes the IP adrress with the mac addres for each host
    Edgeswitch = [275,276,277,278,279,280,281,288]
    ResultPkt = []
    ResultByte = []
    ServerPkt = []
    ServerByte = []
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.Hostport()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.Data_Path[datapath.id]= datapath
        self.Flowcounter.setdefault(dpid, 1)
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        #initial point to calculate CPU & Mem usage 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        

    def add_flow(self, datapath, priority, match, actions,in_port=None, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)
           

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increasesetd
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg 
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocol(ipv4.ipv4)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        if ip:# ckeck the adresses 
           if len(self.host) > self.Hostnumber:#we have 14 hosts and one server
              if ip.src in self.host.keys():
                   pass
              else:
                 print "BLOCK"
                 actions = []
                 match = parser.OFPMatch(in_port=in_port)
                 self.add_flow(datapath, 100, match, in_port , actions)
                 return
           else:
             print "new item"
             self.host.setdefault(ip.src, src)
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        #install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if ip:
               ipv = ip.src #getting the source ip address
               match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=0x800, ipv4_src= ipv )
            else:
               match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.Flowcounter[dpid] = self.Flowcounter[dpid] + 1 #countor for the number of entries according to dpid 

    def send_port_stats_request(self):
          for dpid in self.Edgeswitch:
               datapath = self.Data_Path[dpid]
               #Currently not waiting for switch to respond to previous request
               ofp = datapath.ofproto
               ofp_parser = datapath.ofproto_parser

            # ofp.OFPP_ANY sends request for all ports
               req = ofp_parser.OFPPortStatsRequest(datapath , 0, ofp.OFPP_ANY)
               datapath.send_msg(req)
               #print "states request of switch %d sent", dpid

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
           datapath = ev.msg.datapath
           dpid = datapath.id
           for stat in ev.msg.body:
            if stat.port_no in range(3,5):
              self.prevaluePkt.setdefault((dpid,stat.port_no), 0)
              self.prevalueByte.setdefault((dpid,stat.port_no), 0)
              if (dpid,stat.port_no) in self.blockedlist.keys():
                       pass
              elif dpid == 288:#server info
                DiffPkt = stat.tx_packets - self.prevaluePkt[dpid,stat.port_no]
                DiffByte = stat.tx_bytes - self.prevalueByte[dpid,stat.port_no]
                self.prevaluePkt[dpid,stat.port_no] = stat.tx_packets
                self.prevalueByte[dpid,stat.port_no]= stat.tx_bytes
                self.ServerPkt.append(DiffPkt)
                self.ServerByte.append(DiffByte)
              else:               
                DiffPkt = stat.rx_packets - self.prevaluePkt[dpid,stat.port_no]
                DiffByte = stat.rx_bytes - self.prevalueByte[dpid,stat.port_no]
                self.prevaluePkt[dpid,stat.port_no] = stat.rx_packets
                self.prevalueByte[dpid,stat.port_no]= stat.rx_bytes
                self.ingressPkt[dpid,stat.port_no] = DiffPkt #number of pkts during the last round for a cartain host
                self.ingressByte[dpid,stat.port_no] = DiffByte #number of Bytes during the last round for a cartain host #number of Bytes during the last round for a cartain host
                self.Counter = self.Counter + 1 #counter for connected hosts which calculated into the summation result

              if self.Counter >= self.Hostnumber:
                self.Counter = 0
                probabilityPkt = []
                probabilityByte = []
                for dpid in self.Edgeswitch[:-1]:# -1 becuease the last switch has the server
                  for inport in range(3,5):
                    if (dpid,inport) in self.blockedlist.keys():
                       pass
                    else:
                     self.ingressPkt.setdefault((dpid,inport),0)
                     self.ingressByte.setdefault((dpid,inport),0)
                     if sum(self.ingressPkt.values())<= 0 or sum(self.ingressByte.values()) <= 0:
                        return 
                     z = self.ingressPkt[dpid,inport] / sum(self.ingressPkt.values()) 
                     y = self.ingressByte[dpid,inport] / sum(self.ingressByte.values()) 
                     if z <= 0 or y <= 0:
                        return 
                     probabilityPkt.append(z * math.log(z, 2))
                     probabilityByte.append(y * math.log(y, 2))
                EntropyPkt = - int((sum(probabilityPkt) / math.log(len(probabilityPkt), 2)) * 1000)
                EntropyByte = - int((sum(probabilityByte)/math.log(len(probabilityByte), 2)) * 1000)
                self.initial_WindowPkt(EntropyPkt)
                self.initial_WindowByte(EntropyByte)

    def GainPkt(self, EntropyPkt, Threshold):
           while EntropyPkt < Threshold :
              keys = max(self.ingressPkt, key = lambda k: self.ingressPkt[k])
              n = keys
              dpid = n[0]
              port = n[1]
              datapath = self.Data_Path[dpid]
              parser = datapath.ofproto_parser
              match = parser.OFPMatch(in_port = port)
              actions= []
              in_port = port
              self.add_flow(datapath, 100, match , actions, in_port, buffer_id=None)
              self.blockedlist.setdefault((datapath.id,in_port), 0)
              self.blockedlist[datapath.id,in_port ] = self.blockedlist[datapath.id,in_port] + 1
              if keys in self.ingressPkt:
                 del self.ingressPkt[keys]
              if keys in self.ingressByte:
                 del self.ingressByte[keys]
              self.Hostnumber = self.Hostnumber - 1 
              probabilityPkt = []
              a = 0
              for k, values in self.ingressPkt.items():
                   z = values/ sum(self.ingressPkt.values())
                   probabilityPkt.append( z * math.log(z, 2))
                   a = a + 1
              EntropyPkt = - int((sum(probabilityPkt) / math.log(a, 2)) * 1000)
              print EntropyPkt , Threshold 
    def GainByte(self, EntropyByte, Threshold):

           while EntropyByte < Threshold :
              keys = max(self.ingressByte, key = lambda k: self.ingressByte[k])
              print keys
              n =  keys
              dpid = n[0]
              port = n[1]
              datapath = self.Data_Path[dpid]
              parser = datapath.ofproto_parser
              match = parser.OFPMatch(in_port = port)
              actions = []
              in_port = port
              self.add_flow(datapath, 100, match , actions, in_port, buffer_id=None)
              self.blockedlist.setdefault((datapath.id,in_port), 0)
              self.blockedlist[datapath.id,in_port ] = self.blockedlist[datapath.id,in_port] + 1
              if keys in self.ingressPkt:
                 del self.ingressPkt[keys]
              if keys in self.ingressByte:
                 del self.ingressByte[keys]
              self.Hostnumber = self.Hostnumber - 1 
              probabilityByte = []
              a = 0
              for k, values in self.ingressByte.items():
                   z = values/ sum(self.ingressByte.values())
                   probabilityByte.append( z * math.log(z, 2))
                   a = a + 1
              EntropyByte = - int((sum(probabilityByte) / math.log(a, 2)) * 1000)   
              print EntropyByte , Threshold 
    def initial_WindowPkt(self,EntropyPkt):

         if len(self.AvaPkt) >= self.WindowSizePkt:
             self.PktEntropycalculation(EntropyPkt)
             return
         if len(self.ServerPkt) > 10:
           self.ServerPkt = self.ServerPkt[-10:]

         if EntropyPkt > 600:#adjust the iniital window with the reasonable values 
             self.addtoWindowPkt(EntropyPkt)   

    def addtoWindowPkt(self, EntropyPkt): 
         for i in range(0,len(self.AvaPkt)):
             if self.AvaPkt[i][0] == EntropyPkt:
                self.AvaPkt[i][1] = self.AvaPkt[i][1] + 1
                self.Check_Pktwindow(i)
                return
         self.AvaPkt.append([EntropyPkt, 1])
         print "the Pkt length = ", len(self.AvaPkt)

    def initial_WindowByte(self, EntropyByte):
         if len(self.AvaByte) >= self.WindowSizeByte:
             self.ByteEntropycalculation(EntropyByte)
             return
         if len(self.ServerByte) > 10:
             self.ServerPkt = self.ServerPkt[-10:]

         if EntropyByte > 600:
             self.addtoWindowByte(EntropyByte)
             
         
    def addtoWindowByte(self, EntropyByte): 
         for i in range(0,len(self.AvaByte)):
             if self.AvaByte[i][0] == EntropyByte:
                self.AvaByte[i][1] = self.AvaByte[i][1] + 1
                self.Check_Bytewindow(i)
                return
         self.AvaByte.append([EntropyByte, 1])

    def PktEntropycalculation(self, Entropy):
          S = 0
          for i in range(0,self.WindowSizePkt):
             S = S + self.AvaPkt[i][0]
          
          Mean = S / self.WindowSizePkt
          A = 0
          for i in range(0, self.WindowSizePkt):
             A = A + math.pow((self.AvaPkt[i][0] - Mean), 2)
          Mean = int(Mean)
          Deviation = int(math.sqrt(A/(self.WindowSizePkt - 1 ))) #sample standerd deviation
          Threshold = Mean - (Deviation * 3)
          print "MeanPkt,Threshold,Entropy "
          print Mean,Threshold,Entropy 
          self.ResultPkt.append([Mean,Threshold,Entropy])
          self.Pkt_ThresholdVerification( Threshold, Entropy)

          ResultPktfile = open ('ResultPkt.txt', 'w')
          ResultPktfile.write(str(self.ResultPkt))
          ResultPktfile.close
          blockfile = open ('blockPkt.txt', 'w')
          blockfile.write(str(self.blockPkt))
          blockfile.close
          b = open ('AvaPkt.txt', 'w')
          b.write(str(self.AvaPkt))
          b.close
          
          

    def ByteEntropycalculation(self, Entropy):
          S = 0
          for i in range(0,self.WindowSizeByte):
             S = S + self.AvaByte[i][0]
          Mean = S / self.WindowSizeByte
          A = 0
          for i in range(0, self.WindowSizeByte):
             A = A + math.pow((self.AvaByte[i][0] - Mean), 2)
          Mean = int(Mean)
          Deviation = int(math.sqrt(A/(self.WindowSizeByte - 1)))
          Threshold = Mean - (Deviation * 3)
          print "MeanByte,Threshold,Entropy "
          print Mean,Threshold,Entropy 
          self.ResultByte.append([Mean,Threshold,Entropy])
          self.Byte_ThresholdVerification(Threshold, Entropy)

          ResultBytefile = open ('ResultByte.txt', 'w')
          ResultBytefile.write(str(self.ResultByte))
          ResultBytefile.close
          blockfile = open ('blockByte.txt', 'w')
          blockfile.write(str(self.blockByte))
          blockfile.close
          bl = open ('AvaByte.txt', 'w')
          bl.write(str(self.AvaByte))
          bl.close

    def Check_Pktwindow(self, x):# to increase or decrease the pkt window size
          if len(self.AvaPkt) < self.WindowSizePkt:
             return
          Frequency = self.AvaPkt[x][1]
          for i in range(0,self.WindowSizePkt):
             if self.AvaPkt[i][1] < Frequency:
                oldQ, n = self.VariancePkt()#we don't need n
                Temp0 = self.AvaPkt[x][0]
                Temp1 = self.AvaPkt[x][1]
                self.AvaPkt[x][0] = self.AvaPkt[i][0]
                self.AvaPkt[x][1] = self.AvaPkt[i][1]
                self.AvaPkt[i][0] = Temp0
                self.AvaPkt[i][1] = Temp1
                newQ, Quantity = self.VariancePkt()
                print Quantity
                direct = newQ /oldQ
                inverse = oldQ / newQ
                ratio = math.sqrt(pow(direct - inverse, 2))
                if ratio > (1 + 0.05 ):
                   if oldQ > newQ:
                      self.WindowSizePkt = int(self.WindowSizePkt + Quantity)
                   else:
                      self.WindowSizePkt = int(self.WindowSizePkt - Quantity)
                print " self.WindowSizePkt =", self.WindowSizePkt 
                return

    def VariancePkt(self):
         S = 0
         Q = 0
         for i in range(0,self.WindowSizePkt):
             S = S + self.AvaPkt[i][0]
         Mean = S / self.WindowSizePkt
         Smallest = self.AvaPkt[0][0]
         Greatest = self.AvaPkt[0][0]
         for i in range(1, self.WindowSizePkt):
             Q = Q + pow(self.AvaPkt[i][0] - Mean, 2)
             if self.AvaPkt[i][0] > Greatest:
                Greatest = self.AvaPkt[i][0]
             if self.AvaPkt[i][0] < Smallest:
                Smallest = self.AvaPkt[i][0]

         Q = Q/self.WindowSizePkt
         Qmax = (Mean - Smallest) * (Greatest - Mean)
         Quantity = Qmax/Q
         return Q , round(Quantity)

    def VarianceByte(self):
         S = 0
         Q = 0
         for i in range(0,self.WindowSizeByte):
             S = S + self.AvaByte[i][0]
         Mean = S / self.WindowSizeByte
         Smallest = self.AvaByte[0][0]
         Greatest = self.AvaByte[0][0]
         for i in range(0, self.WindowSizeByte):
             Q = Q + pow(self.AvaByte[i][0] - Mean, 2)
             if self.AvaByte[i][0] > Greatest:
                Greatest = self.AvaByte[i][0]
             if self.AvaByte[i][0] < Smallest:
                Smallest = self.AvaByte[i][0]

         Q = Q/self.WindowSizeByte
         Qmax = (Mean - Smallest) * (Greatest - Mean)
         Quantity = Qmax/Q
         return Q , round(Quantity)

    def Check_Bytewindow(self, x):
        if len(self.AvaByte) < self.WindowSizeByte:
             return
        Frequency = self.AvaByte[x][1]
        for i in range(0,self.WindowSizeByte):
          if self.AvaByte[i][1] < Frequency:
             oldQ, n = self.VarianceByte()#we don't need n
             Temp0 = self.AvaByte[x][0]
             Temp1 = self.AvaByte[x][1]
             self.AvaByte[x][0] = self.AvaByte[i][0]
             self.AvaByte[x][1] = self.AvaByte[i][1]
             self.AvaByte[i][0] = Temp0
             self.AvaByte[i][1] = Temp1
             newQ, Quantity = self.VarianceByte()
             print Quantity 
             direct = newQ /oldQ
             inverse = oldQ / newQ
             ratio = math.sqrt(pow(direct - inverse, 2))
             if ratio > (1 + 0.05 ):
                if oldQ > newQ:
                   self.WindowSizeByte = int(self.WindowSizeByte + Quantity)
                else:
                   self.WindowSizeByte = int(self.WindowSizeByte - Quantity)
             print "self.WindowSizeByte", self.WindowSizeByte
             return

    def Hostport(self):
        for i in self.Edgeswitch:
           for x in range(3,5):
              self.prevaluePkt[i, x]= 0
              self.prevalueByte[i, x]= 0
         
    def Pkt_ThresholdVerification(self, Threshold, Entropy):
        data1 = [1,2,3,4,5,6,7,8,9,10]
        data2 = [1,2,3,4,5,6,7,8,9,10,11]
        l = 0
        # calculate Pearson's correlation

        if len(self.ServerPkt) > 10 :
           self.ServerPkt = self.ServerPkt[-11:]
           #print " len(self.ServerPkt) ", len(self.ServerPkt)
           Oldcorr, _ = pearsonr(data1, self.ServerPkt[:-1])
           Newcorr, _ = pearsonr(data2, self.ServerPkt)
           l = Newcorr - Oldcorr
           print " l = ", l 
           if Entropy < Threshold:
                 if l > 0.15: 
                       self.ServerPkt.pop(-1)# The controller would not consider the result out of the normal behaviour
                       self.blockPkt.append(3)
                       self.GainPkt(Entropy, Threshold)# In order to block the attackers
           else: 
             self.ServerPkt.pop(0)
             self.blockPkt.append(0)
             self.addtoWindowPkt(Entropy)


    def Byte_ThresholdVerification(self, Threshold, Entropy):
        data1 = [1,2,3,4,5,6,7,8,9,10]
        data2 = [1,2,3,4,5,6,7,8,9,10,11]
        l = 0
        # calculate Pearson's correlation
        if len(self.ServerByte) > 10:
           Oldcorr, _ = pearsonr(data1, self.ServerByte[-10:])
           Newcorr, _ = pearsonr(data2, self.ServerByte[-11:])
           l = Newcorr - Oldcorr
           print " l = ", l 
           if Entropy < Threshold:
                 if l > 0.15:
                       self.ServerByte.pop(-1)
                       self.blockByte.append(3)
                       self.GainByte(Entropy, Threshold)
           else: 
             self.ServerByte.pop(0)
             self.blockByte.append(0)
             self.addtoWindowByte(Entropy)

class ThreadingExample(SimpleSwitch13):
    """ Threading example class
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self):
        """ Constructor
        """
        thread = threading.Thread(target=self.get_CpuMemory_usage, args=())
        thread.daemon = True                            # Daemonize thread
        thread.start()

        thread1 = threading.Thread(target=self.monitor_port, args=())
        thread1.daemon = True                            # Daemonize thread
        thread1.start()                                  # Start the execution

    def get_CpuMemory_usage(self):
        point = 0
        while True:
          pid = os.getpid()
          #print(pid)
          ps = psutil.Process(pid)
          cpuUse = ps.cpu_percent(interval=1)
          memoryUse = ps.memory_percent()
          point = point + 1
          self.CPU[point]= cpuUse
          self.Memory[point]= memoryUse
          Cpufile = open ('CpuUsage.txt', 'w')
          Cpufile.write(str(self.CPU))
          Cpufile.close
          Memoryfile = open ('memoryUsage.txt', 'w')
          Memoryfile.write(str(self.Memory))
          Memoryfile.close
          Entryfile = open ('Flowcounter.txt', 'w')
          Entryfile.write(str(self.Flowcounter))
          Entryfile.close
          blockedfile= open ('blockedlist.txt', 'w')
          blockedfile.write(str(self.blockedlist))
          blockedfile.close
          time.sleep(3)

    def monitor_port(self):
          time.sleep(20)
          while True:
               self.send_port_stats_request()
               time.sleep(5)
               
example = ThreadingExample()
