#!/usr/bin/python
#from /https://gist.github.com/zarzen/1de31629d5167ab197ca393b983ac277

from scapy.all import *
import argparse

def packet_with_seq_n(iface, src_ip, src_port, dst_ip, dst_port, seq_num):
#    packet = IP(dst="192.168.100.123", src="192.168.100.144")/TCP(sport=333, dport=222, seq=112344)/"Sequence number 112344"
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst=dst_ip, src=src_ip)/TCP(sport=src_port, dport=dst_port, seq=seq_num)/"PAYLOAD HERE"
    sendp(packet, iface=iface)
    # lsc() can see functions descriptions.

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('iface'    , help='interface name')
    parser.add_argument('src_ip'   , help='source IP')
    parser.add_argument('src_port' , help='source port', type=int)
    parser.add_argument('dst_ip'   , help='destination IP')
    parser.add_argument('dst_port' , help='destination port', type=int)
    parser.add_argument('seq_num'  , help='TCP sequence number', type=int)
    args = parser.parse_args()
    packet_with_seq_n(args.iface, args.src_ip, args.src_port, args.dst_ip, args.dst_port, args.seq_num)
