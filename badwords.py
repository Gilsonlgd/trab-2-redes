from scapy.all import *
from scapy.layers.inet import IP, TCP

# Define the words to be replaced
blocked_words = ["word1", "word2", "word3"]
replacement_word = "REPLACEMENT"

def supports_packet(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw) or not packet.sniffed_on == 'r-eth1'

def is_sent_packet(packet):
    return packet[Ether].src == get_if_hwaddr(packet.sniffed_on)

def recalc_check_sum(pkt: Packet):
    del pkt[IP].chksum
    del pkt[IP].payload.chksum
    return pkt.__class__(bytes(pkt))

def substitute_badwords(payload: str):
    payload_cpy = payload
    for word in blocked_words:
        payload_cpy = payload_cpy.replace(word, replacement_word)
    return payload_cpy

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
        print("Original Packet: ", packet.show())
        print("Modified Packet:", result_packet.show())
        
        sendp(result_packet, iface="r-eth1", verbose=False)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sniff(iface=["r-eth0"], prn=process_http)
