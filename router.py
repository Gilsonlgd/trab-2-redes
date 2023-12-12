from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from scapy.all import *
from scapy.all import sniff
import threading

nat_table = {}
count1 = 0
count2 = 0
def nat(packet):
	global nat_table
	global count1
	global count2
	try:
		# IP e TCP são do scapy
		# Extrai o endereço IP de origem do pacote e o armazena na variável ip_src.
		ip_src = packet[IP].src
		# Extrai o endereço IP de destino do pacote e o armazena na variável ip_dst.
		ip_dst = packet[IP].dst
		# chave com a 5 tuple que identifica única e exclusivamente uma conexão de rede.
		key = (ip_src, packet.sport, ip_dst, packet.dport, packet.proto)
		# verifica se a chave ja esta na tabela NAT
		if packet.sniffed_on == 'r-eth0':
			if key not in nat_table:
				nat_table[key] = {
						'src_ip': ip_src,  # IP de origem original
						'dst_ip': ip_dst,  # IP de destino 
						'src_port': packet.sport,  # Porta de origem original
						'dst_port': packet.dport  # Porta de destino original
				}
			packet[IP].src = '8.8.254.254'	
			sendp(packet, iface='r-eth1')
			if count1 < 5:
				print('pacote indo', packet.show())
				count1 += 1
		elif packet.sniffed_on == 'r-eth1':
			if count2 < 5:
				print('pacote voltando', packet.show())
				count2 += 1
			for key, value in nat_table.items():
				if (ip_src == value['dst_ip'] and packet.sport == value['dst_port'] and packet.dport == value['src_port']):
					packet[IP].dst = value['src_ip']
					'''if TCP in packet:
						packet[TCP].dport = value['src_port']
					elif UDP in packet:
						packet[UDP].dport = value['src_port']'''
					sendp(packet, iface='r-eth0')
					print('enviou de volta')
					break
	except KeyboardInterrupt:
		pass

def nat_callback(packet):
    try:
        print("Packet captured: ", packet.summary())
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    setLogLevel( 'info' )
    sniff(iface=["r-eth0","r-eth1"], filter='ip',  prn=nat)
