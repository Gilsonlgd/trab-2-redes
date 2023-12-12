from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['POST'])
def receive_message():
    try:
        message = request.form['message']
        # Aqui você pode processar a mensagem recebida da maneira desejada
        # (por exemplo, salvar em um arquivo, exibir no console, etc.)
        print(f'Mensagem recebida: {message}')

        # Responda com uma mensagem de confirmação
        return 'Mensagem recebida com sucesso!'
    except Exception as e:
        print(f'Erro ao processar a mensagem: {e}')
        return 'Erro ao processar a mensagem'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
