# Copyright 2020 Lin Wang

# This code is part of the Advanced Computer Networks (2020) course at Vrije 
# Universiteit Amsterdam.

# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.lib.packet import ether_types
class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Initialize mac address table
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Get datapath ID to identify the switch
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # TODO: learning switch implementation
        #analyze the received packet
        pkt = packet.Packet(msg.data) #data
        #eth_pkt = pkt.get_protocol(ethernet.ethernet) #ethernet
        #dst = eth_pkt.dst #destination
        #src = eth_pkt.src #source
        #get the port from packet_in
        in_port = msg.match['in_port']
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        #if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
            #ignore all packets ARP
        #    return

        

        #know mac addrs to avoid flood
        #pkt_ARP = packet.Packet(msg.data)
        #arp_pkt = pkt_ARP.get_protocol(arp.arp)
        #dst_arp = arp_pkt.dst_arp
        #src_arp = arp_pkt.src_arp

        

        #self.logger.info("packet in [dpid: %s], [src: %s], [dst: %s], [in_port: %s]", dpid, src, dst, in_port)
        
        #check if it is an arp packet or not, if it is not save the port inside the table
        if arp_pkt:
            #self.logger.info("Switch %s Discard ip %s",dpid, arp_pkt.dst_ip)
            if(arp_pkt.opcode==arp.ARP_REQUEST):
                self.logger.info("SWITCH %s, ARP REQUEST",dpid)
            else:
                self.logger.info("SWITCH %s, ARP REPLY",dpid)

            arp_dst=arp_pkt.dst_mac
            arp_src=arp_pkt.src_mac

            self.logger.info("DST: %s SRC: %s", arp_dst, arp_src)
            self.logger.info("========================================")

            self.mac_to_port[dpid][arp_src] = in_port   

            if arp_dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][arp_dst]
            else:
                out_port = ofproto.OFPP_FLOOD
    
            actions = [parser.OFPActionOutput(out_port)]

        elif ip_pkt:
            eth_pkt = pkt.get_protocol(ethernet.ethernet) #ethernet
            if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            dst = eth_pkt.dst #destination
            src = eth_pkt.src #source

            self.logger.info("IP ON SWITCH %s",dpid)

            self.mac_to_port[dpid][src] = in_port
            #self.logger.info("Switch %s Learning source %s port %s",dpid, src, in_port)

            #if mac addrs is known decide which port to send the packet
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            #action list
            actions = [parser.OFPActionOutput(out_port)]

            self.logger.info("DST %s SRC %s DSTIP %s SRCIP %s",dst,src, ip_pkt.dst, ip_pkt.src)
            self.logger.info("========================================")
            #install a flow to avoid future packet in
            if out_port != ofproto.OFPP_FLOOD:
                #match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                #self.add_flow(datapath, 1, match, actions)
                # check IP Protocol and create a match for IP
                #if eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
                #ip = pkt.get_protocol(ipv4.ipv4)
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
                #match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    #    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #    return
                    #else:
                self.add_flow(datapath, 1, match, actions)
                self.logger.info("ADDED FLOW")
        else:
            return

        # Construct packet_out message and send it
        out = parser.OFPPacketOut(datapath=datapath,
                                  in_port=in_port, 
                                  actions=actions, 
                                  buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                  data=msg.data)
        datapath.send_msg(out)
