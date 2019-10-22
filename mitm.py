from scapy.all import *
from threading import Thread, Event
from time import sleep
import utils
from sortedcontainers import SortedList, SortedDict
from pprint import pprint

import sys
from decimal import Decimal


class PacketSniffer(threading.Thread):
    """
    Packet Sniffer Object using Scapy
    """

    def __init__(self, ifname, callback_object, app_protocol="tcp"):
        super(PacketSniffer, self).__init__()

        self.daemon = True

        self.socket = None
        self.stop_sniffer = Event()
        self.packet_filter_string = app_protocol
        self.ifname = config.get("network", "ifname")
        self.callback_object = callback_object

    def is_not_outgoing(self, pkt):
        """
        Filter for ingoing packets
        :param pkt: Scapy packet object instance
        :return: False if it is an outgoing packet, True otherwise
        """
        try:
            return pkt[Ether].src.lower() != get_if_hwaddr(conf.iface).lower()
        except IndexError:
            return False

    def is_outgoing(self, pkt):
        """
        Filter for outgoing packets
        :param pkt: Scapy packet object instance
        :return: True if it is an outgoing packet, False otherwise
        """
        try:
            return pkt[Ether].src.lower() == get_if_hwaddr(conf.iface).lower()
        except IndexError:
            return False

    def sniffer_callback(self, pkt):
        """
        Callback passed to Scapy sniff function
        :param pkt: Scapy packet object instance
        """
        #if "Ether" in pkt and "IP" in pkt and "TCP" in pkt:
        if "TCP" in pkt:

            # Debug check for packet details
            print(pkt.summary())
            
            # TODO: forward to exit (virtual) interface


    def print_packet(self, pkt):
        """
        Prints out packet src and dst IP
        :param pkt: Scapy packet object instance
        """
        ip_layer = pkt.getlayer(IP)
        print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

    # New threaded functions

    def run(self):
        """
        Starts the socket and Scapy sniffer
        """
        print "Starting Packet Sniffer on [ %s ]:[ %s ]..." % (self.ifname, self.packet_filter_string)
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.ifname,
            filter=self.packet_filter_string
        )

        sniff(
            opened_socket=self.socket,
            #filter=self.packet_filter_string,
            lfilter=self.is_not_outgoing,
            # prn=self.print_packet,
            prn=self.sniffer_callback,
            stop_filter=self.should_stop_sniffer
        )

    def join(self, timeout=None):
        """
        Join method for multithreading.
        :param timeout:
        """
        self.stop_sniffer.set()
        super(PacketSniffer, self).join(timeout)

    def should_stop_sniffer(self):
        """
        Stops the sniffer when the internal variable is set
        :return: True if stop_sniffer is set, False otherwise
        """
        return self.stop_sniffer.isSet()
        
if __name__ == '__main__':
    config = ConfigParser.ConfigParser()
    config.read('config.ini')
    sniffer = sniffer.PacketSniffer(config, self, app_protocol="tcp")
    self.sniffer.start()
	print ("Sniffer started")
	try:
		while True:
			time.sleep(500)
	except KeyboardInterrupt:
		print("[*] Stop sniffing")

		self.sniffer.join(timeout=2.0)

		if self.sniffer.isAlive():
			self.sniffer.socket.close()