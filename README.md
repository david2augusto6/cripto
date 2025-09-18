# cripto

"""
Aplicação simples para envio de mensagens com assinatura digital (do remetente)
Gera certificados ad-hoc (self-signed) para remetente e receptor e oferece funções
para assinar, verificar, cifrar (opcional) e decifrar (opcional).


Requisitos:
pip install cryptography


Uso (exemplos):
python app_mensagem_assinada.py gen --name sender
python app_mensagem_assinada.py gen --name receiver
python app_mensagem_assinada.py sign --key keys/sender_key.pem --msg "Olá mundo"
python app_mensagem_assinada.py verify --cert keys/sender_cert.pem --msg "Olá mundo" --sig <signature-base64>
python app_mensagem_assinada.py demo


Arquivos gerados (por padrão em ./keys):
<name>_key.pem -> chave privada PEM (RSA)
<name>_cert.pem -> certificado X.509 self-signed PEM


Descrição das operações:
- gen: gera par de chaves e certificado self-signed
- sign: assina uma mensagem com a chave privada (PSS + SHA256)
- verify: verifica assinatura com o certificado (público)
- encrypt/decrypt (opcionais): cifram mensagens para o receptor com RSA-OAEP


"""