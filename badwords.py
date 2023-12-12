from scapy.all import *
from scapy.layers.inet import IP, TCP

# Define the words to be replaced
blocked_words = ["word1", "word2", "word3"]
replacement_word = "REPLACEMENT"

def supports_packet(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)

def is_sent_packet(packet):
    return packet[Ether].src == get_if_hwaddr(packet.sniffed_on)

def substitute_badwords(payload: str):
    payload_cp = payload
    for word in blocked_words:
        payload_cp = payload_cp.replace(word, replacement_word)
    return payload_cp

def recalc_check_sum(pkt: Packet):
    del pkt[IP].chksum
    del pkt[IP].payload.chksum
    return pkt.__class__(bytes(pkt))

def replace_badwords(packet):
    if TCP in packet and Raw in packet:
        payload = packet[TCP].payload.load.decode('utf-8')
        result = bytes(substitute_badwords(payload), 'utf-8')
        
        packet_cp = packet.copy()
        packet_cp[TCP].payload = Raw(result)
        return recalc_check_sum(packet_cp)
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
        
        sendp(result_packet, iface=packet.sniffed_on, verbose=False)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sniff(iface=["r-eth0", "r-eth1"], prn=process_http)
