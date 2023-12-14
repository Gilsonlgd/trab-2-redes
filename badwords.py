from scapy.all import *
from scapy.all import Raw

import requests

# Define the words to be replaced
blocked_words = ["word1", "word2", "word3", "xereca", "pinto", "rola"]
replacement_char = "ranieri"
server_url = "http://8.8.8.8"

def supports_packet(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)

def is_sent_packet(packet):
    return packet[Ether].src == get_if_hwaddr(packet.sniffed_on)

def recalc_check_sum(pkt: Packet):
    del pkt[IP].chksum
    del pkt[IP].payload.chksum
    return pkt.__class__(bytes(pkt))

def substitute_badwords(payload: str):
    for word in blocked_words:
        replacement = replacement_char * len(word)
        payload = payload.replace(word, replacement)
    return payload

def replace_badwords(packet):
    if TCP in packet and packet[TCP].payload:
        payload = packet[TCP].payload.load.decode('utf-8')
        result = bytes(substitute_badwords(payload), 'utf-8')
        
        packet_cpy = packet.copy()
        packet_cpy[TCP].payload = Raw(result)
        return recalc_check_sum(packet_cpy)
    return packet

def process_http(packet):
    try:
        if not packet:
            return

        if not supports_packet(packet):
            return
        
        if is_sent_packet(packet):
            return
        
        result_packet = replace_badwords(packet)
        if result_packet:
            
            # Send the modified packet directly to the server
            requests.post(server_url, data={'message': repr(result_packet)})
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sniff(iface=["r-eth0"], prn=process_http)
