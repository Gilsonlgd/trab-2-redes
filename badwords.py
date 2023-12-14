from scapy.all import *
from scapy.all import Raw
from threading import Thread
import time

import requests

# Define the words to be replaced
blocked_words = []
replacement_char = "*"
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
        
        start_time = time.time()
        result_packet = replace_badwords(packet)
        end_time = time.time()
        if result_packet:
            # Send the modified packet directly to the server
            requests.post(server_url, data={'message': repr(result_packet)})
        elapsed_time = end_time - start_time
        print(f"Tempo de execução: {elapsed_time} segundos")
        with open('exec_time.txt', 'a') as file:
            file.write(elapsed_time + '\n')
    except KeyboardInterrupt:
        pass

def scapy_sniffer():
    sniff(iface=["r-eth0"], prn=process_http)

def user_input_thread():
    global blocked_words
    while True:
        user_input = input("Digite uma palavra para bloquear (ou 'exit' para sair): ")
        if user_input.lower() == 'exit':
            break

        if user_input not in blocked_words:
            blocked_words.append(user_input)
            print(f'A palavra "{user_input}" foi adicionada à lista de badwords.')
            with open('blocked_words.txt', 'a') as file:
                file.write(user_input + '\n')
        else:
            print(f'A palavra "{user_input}" já está na lista de badwords.')
            
def read_blocked_words_from_file():
    try:
        with open('blocked_words.txt', 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        return []

if __name__ == '__main__':
    scapy_thread = Thread(target=scapy_sniffer)
    scapy_thread.start()

    blocked_words = read_blocked_words_from_file()
    user_input_thread = Thread(target=user_input_thread)
    user_input_thread.start()

    scapy_thread.join()
    user_input_thread.join()
