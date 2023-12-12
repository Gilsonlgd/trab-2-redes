from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from scapy.all import *
from scapy.all import sniff

def callbackFunction(packet):
    try:
        print(packet.summary())
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    setLogLevel( 'info' )
    sniff(prn=callbackFunction)