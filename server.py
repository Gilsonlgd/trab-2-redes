from flask import Flask, request

app = Flask(__name__)

accumulated_packets = []
count = 0

@app.route('/', methods=['POST'])
def receive_message():
    global count
    try:
        # Access the 'message' parameter from the POST request
        modified_packet = request.form['message']
        
        # Find the index of 'message=' in the modified packet
        message_index = modified_packet.find('message=')

        if message_index != -1:
            # Extract the content after 'message='
            message_content = modified_packet[message_index + len('message='):].strip()
            print(f'Message Content: {message_content}')
            count = count + 1

            return 'Mensagem recebida com sucesso!'
        else:
            accumulated_packets.append(modified_packet)
            if accumulated_packets:                
                accumulated_packets.clear()
                return 'Mensagem recebida com sucesso!'
            
            return 'Aguardando mais pacotes...'
    except Exception as e:
        print(f'Erro ao processar a mensagem: {e}')
        return 'Erro ao processar a mensagem'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
    print("Numero de requisições recebidas: " + str(count))
