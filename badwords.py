from scapy.all import *

# Define the words to be replaced
blocked_words = ["word1", "word2", "word3"]
replacement_word = "REPLACEMENT"

def supports_packet(packet):
    return packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)

def is_sent_packet(packet):
    return packet[Ether].src == get_if_hwaddr(packet.sniffed_on)

def substitute_badwords(payload: bytes):
    payload_cp = payload.decode('utf-8')
    for word in blocked_words:
        payload_cp = payload_cp.replace(word, replacement_word)
    return bytes(payload_cp, 'utf-8')

def recalc_check_sum(pkt: Packet):
    del pkt[IP].chksum
    del pkt[IP].payload.chksum
    return pkt.__class__(bytes(pkt))

def replace_badwords(packet):
    if TCP in packet and Raw in packet:
        tcp_options = packet[TCP].options

        # Check if the modification option is already present
        if not any(opt[0] == 99 for opt in tcp_options):
            payload = bytes(packet[TCP].payload.load)
            result = substitute_badwords(payload)

            packet_cp = packet.copy()
            packet_cp[TCP].payload = Raw(result)
            packet_cp[IP].id += 1  # Increment the IP ID to avoid checksum problems
            # Add a custom TCP option to indicate modification
            packet_cp[TCP].options = [(99, b'modified')]
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
        if (result_packet):
            print("Original Packet: ", packet.show())
            print("Modified Packet:", result_packet.show())
            sendp(result_packet, iface="r-eth1", verbose=False)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sniff(iface=["r-eth0", "r-eth1"], prn=process_http)
