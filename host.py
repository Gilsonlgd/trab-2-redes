from mininet.topo import Topo
from mininet.net import Mininet
from scapy.all import *
import threading
import requests  # Importe a biblioteca requests
from mininet.cli import CLI

def send_http_request(server_ip, message):
    url = f'http://{server_ip}'
    data = {'message': message}
    response = requests.post(url, data=data)
    print(f'Resposta do servidor: {response.text}')

if __name__ == '__main__':
    # Endereço IP do servidor
    server_ip = '8.8.8.8'
    
    while True:
        user_input = input("Digite a mensagem a ser enviada para o servidor (ou 'exit' para sair): ")
        print(user_input)

        # Verifique se o usuário deseja sair
        if user_input.lower() == 'exit':
            break

        # Envie a mensagem para o servidor como uma requisição HTTP POST
        send_http_request(server_ip, user_input)
    exit(0)

    # Pare a thread de captura quando o usuário sair
    capture_thread.join()

