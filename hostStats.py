from threading import Thread
import time
import requests

message64Bytes = "Maria dirigia seu carro ao som animado de Anitta e Pabblo Vittar"
message1500Bytes = message64Bytes * 23 + "Maria dirigia seu carro ao som"
messageLen = 64


def send_http_request(server_ip, message, resultados):
    url = f'http://{server_ip}'
    data = {'message': message}
    try:
        start_time = time.time()
        response = requests.post(url, data=data)
        end_time = time.time()

        tempo_resposta = end_time - start_time
        resultados.append(tempo_resposta)

    except requests.exceptions.RequestException as e:
        print(f'Erro ao enviar a mensagem para o servidor: {e}')

def main():
    # Endereço IP do servidor
    server_ip = '8.8.8.8'

    # Número total de solicitações a serem feitas
    num_solicitacoes = 100

    # Lista para armazenar os tempos de resposta
    tempos_resposta = []

    # Cria threads para realizar as solicitações simultaneamente
    threads = []
    for _ in range(num_solicitacoes):
        thread = Thread(target=send_http_request, args=(server_ip, message64Bytes, tempos_resposta))
        threads.append(thread)
        thread.start()

    # Aguarda todas as threads terminarem
    for thread in threads:
        thread.join()

    # Calcula estatísticas
    tempo_total = sum(tempos_resposta)
    tempo_medio = tempo_total / num_solicitacoes
    tempo_minimo = min(tempos_resposta)
    tempo_maximo = max(tempos_resposta)
    
    total_pacotes_transmitidos = len(tempos_resposta) * 2
    taxa_pacotes_por_segundo = total_pacotes_transmitidos / tempo_total if tempo_total > 0 else 0
    
    total_bytes_transmitidos = total_pacotes_transmitidos * messageLen
    taxa_transferencia = total_bytes_transmitidos / tempo_total if tempo_total > 0 else 0
    
    # Escreve estatísticas em um arquivo
    with open('estatisticas.txt', 'a') as arquivo:
        arquivo.write(f"Total de solicitações: {num_solicitacoes}\n")
        arquivo.write(f"Tempo total: {tempo_total:.2f} segundos\n")
        arquivo.write(f"Tempo médio por solicitação: {tempo_medio:.4f} segundos\n")
        arquivo.write(f"Tempo mínimo de resposta: {tempo_minimo:.4f} segundos\n")
        arquivo.write(f"Tempo máximo de resposta: {tempo_maximo:.4f} segundos\n")
        arquivo.write(f"Taxa de Pacotes por Segundo: {taxa_pacotes_por_segundo:.2f} pacotes por segundo\n")
        arquivo.write(f"Taxa de Transferência: {taxa_transferencia:.2f} bytes por segundo\n")

if __name__ == '__main__':
    main()
