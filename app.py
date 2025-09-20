from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from threading import Timer
import sqlite3
import mini_pgp  # Importa o seu script
import os
import webbrowser

app = Flask(__name__)
CORS(app)  # Permite que a página web acesse a API

# Inicializar banco de dados
DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({"success": True, "name": user[0], "email": email})
        else:
            return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Rota para servir o arquivo index.html
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    name = data.get('name')
    email = data.get('email')

    try:
        # Adicionar ao banco de dados
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
        conn.commit()
        conn.close()

        # Gerar identidade do usuário
        mini_pgp.generate_identity(name, email, name.lower())
        return jsonify({"success": True, "message": f"Usuário {name} adicionado com sucesso!"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "Erro: Email já cadastrado."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/list_users', methods=['GET'])
def list_users():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM users")
        users = [row[0] for row in cursor.fetchall()]
        conn.close()
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/receive', methods=['POST'])
def receive_message():
    data = request.json
    recipient = data.get('recipient')

    try:
        success, plaintext, meta = mini_pgp.recv_encrypted(recipient.lower(), 'encrypted_message.pkg.json')
        if success:
            return jsonify({
                "success": True,
                "plaintext": plaintext.decode('utf-8'),
                "sender_identity": meta["sender_identity"],
                "sender_fingerprint": meta["sender_fingerprint"]
            })
        else:
            return jsonify({"success": False, "error": meta.get("error", "Erro desconhecido")}), 400
    except FileNotFoundError:
        return jsonify({"success": False, "error": "Erro: Arquivo de chave do destinatário não encontrado."}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/messages/sent/<email>', methods=['GET'])
def get_sent_messages(email):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT recipient, message, timestamp
            FROM messages
            WHERE sender = ?
            ORDER BY timestamp DESC
        """, (email,))
        messages = [
            {"recipient": row[0], "message": row[1], "timestamp": row[2]}
            for row in cursor.fetchall()
        ]
        conn.close()
        return jsonify({"success": True, "messages": messages})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/messages/received/<email>', methods=['GET'])
def get_received_messages(email):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender, message, timestamp
            FROM messages
            WHERE recipient = ?
            ORDER BY timestamp DESC
        """, (email,))
        messages = [
            {"sender": row[0], "message": row[1], "timestamp": row[2]}
            for row in cursor.fetchall()
        ]
        conn.close()
        return jsonify({"success": True, "messages": messages})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')

    try:
        # Salvar mensagem no banco de dados
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)",
                       (sender, recipient, message))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Mensagem enviada com sucesso!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/messages/<user>', methods=['GET'])
def get_messages(user):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender, recipient, message, timestamp
            FROM messages
            WHERE recipient = ? OR sender = ?
            ORDER BY timestamp DESC
        """, (user, user))
        messages = [
            {"sender": row[0], "recipient": row[1], "message": row[2], "timestamp": row[3]}
            for row in cursor.fetchall()
        ]
        conn.close()
        return jsonify({"success": True, "messages": messages})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    init_db()  # Inicializa o banco de dados

    # Função para abrir o navegador
    def open_browser():
        webbrowser.open_new("http://127.0.0.1:5000")

    # Usar um Timer para abrir o navegador após 1 segundo
    Timer(1, open_browser).start()

    app.run(debug=True)