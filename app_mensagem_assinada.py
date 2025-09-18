#!/usr/bin/env python3
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
  <name>_key.pem    -> chave privada PEM (RSA)
  <name>_cert.pem   -> certificado X.509 self-signed PEM

Descrição das operações:
  - gen: gera par de chaves e certificado self-signed
  - sign: assina uma mensagem com a chave privada (PSS + SHA256)
  - verify: verifica assinatura com o certificado (público)
  - encrypt/decrypt (opcionais): cifram mensagens para o receptor com RSA-OAEP

"""

import argparse
import base64
import os
import sys
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

KEYS_DIR = "keys"


def ensure_keys_dir():
    os.makedirs(KEYS_DIR, exist_ok=True)


def generate_key_and_cert(name: str, bits: int = 2048, validity_days: int = 365):
    """Gera chave RSA privada e certificado X.509 self-signed para 'name'."""
    ensure_keys_dir()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AdHoc Messaging"),
    ])

    now = datetime.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    key_path = os.path.join(KEYS_DIR, f"{name}_key.pem")
    cert_path = os.path.join(KEYS_DIR, f"{name}_cert.pem")

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def sign_message(private_key, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def encrypt_for_recipient(public_key, message: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return ciphertext


def decrypt_with_private(private_key, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return plaintext


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")


def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def cmd_gen(args):
    key_path, cert_path = generate_key_and_cert(args.name)
    print(f"Gerado: {key_path}\nGerado: {cert_path}")


def cmd_sign(args):
    priv = load_private_key(args.key)
    msg = args.msg.encode("utf-8")
    sig = sign_message(priv, msg)
    print(b64(sig))


def cmd_verify(args):
    cert = load_cert(args.cert)
    pub = cert.public_key()
    msg = args.msg.encode("utf-8")
    sig = ub64(args.sig)
    ok = verify_signature(pub, msg, sig)
    print("OK" if ok else "FAIL")


def cmd_encrypt(args):
    cert = load_cert(args.cert)
    pub = cert.public_key()
    ciphertext = encrypt_for_recipient(pub, args.msg.encode("utf-8"))
    print(b64(ciphertext))


def cmd_decrypt(args):
    priv = load_private_key(args.key)
    plaintext = decrypt_with_private(priv, ub64(args.ct))
    print(plaintext.decode("utf-8"))


def cmd_demo(args):
    # Demo completo: gera certs, assina, verifica, cifra e decifra
    s_key, s_cert = generate_key_and_cert("sender")
    r_key, r_cert = generate_key_and_cert("receiver")

    sender_priv = load_private_key(s_key)
    sender_cert = load_cert(s_cert)
    receiver_priv = load_private_key(r_key)
    receiver_cert = load_cert(r_cert)

    message = b"Mensagem secreta importante"

    sig = sign_message(sender_priv, message)
    print("Mensagem: ", message.decode())
    print("Assinatura (base64):", b64(sig))

    ok = verify_signature(sender_cert.public_key(), message, sig)
    print("Verificação da assinatura:", "OK" if ok else "FAIL")

    # Opcional: cifrar para receptor
    ct = encrypt_for_recipient(receiver_cert.public_key(), message)
    print("Cifrado (base64):", b64(ct))

    pt = decrypt_with_private(receiver_priv, ct)
    print("Decifrado:", pt.decode())


def build_parser():
    p = argparse.ArgumentParser(description="App de mensagens assinadas (ad-hoc certs)")
    sub = p.add_subparsers(dest="cmd")

    g = sub.add_parser("gen", help="Gera chave e certificado self-signed")
    g.add_argument("--name", required=True, help="Nome para o certificado (p.ex. sender)")
    g.set_defaults(func=cmd_gen)

    s = sub.add_parser("sign", help="Assina uma mensagem com chave privada PEM")
    s.add_argument("--key", required=True, help="Caminho para chave privada PEM")
    s.add_argument("--msg", required=True, help="Mensagem a assinar")
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="Verifica assinatura com certificado PEM")
    v.add_argument("--cert", required=True, help="Caminho para certificado PEM")
    v.add_argument("--msg", required=True, help="Mensagem original")
    v.add_argument("--sig", required=True, help="Assinatura em base64")
    v.set_defaults(func=cmd_verify)

    e = sub.add_parser("encrypt", help="Cifra mensagem com certificado do receptor")
    e.add_argument("--cert", required=True, help="Certificado PEM do receptor")
    e.add_argument("--msg", required=True, help="Mensagem a cifrar")
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser("decrypt", help="Decifra com chave privada PEM")
    d.add_argument("--key", required=True, help="Chave privada PEM do receptor")
    d.add_argument("--ct", required=True, help="Ciphertext em base64")
    d.set_defaults(func=cmd_decrypt)

    dm = sub.add_parser("demo", help="Executa demo: gera certs, assina, verifica, cifra, decifra")
    dm.set_defaults(func=cmd_demo)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
