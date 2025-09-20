#!/usr/bin/env python3
"""
mini_pgp.py — Mensageria assinada e opcionalmente criptografada, estilo PGP (não compatível com OpenPGP).

Recursos:
- Gera "certificados" ad-hoc (autoassinados) contendo chaves públicas de assinatura (Ed25519) e troca (X25519).
- Assina mensagens (pacote .spkg JSON) e verifica.
- Envia mensagens assinadas e criptografadas para um destinatário (pacote .pkg JSON) e recebe (verifica + decifra).

⚠️ Avisos de segurança
- Este código é educacional e não substitui padrões auditados (OpenPGP, age, Minisign, etc.).
- Proteja suas chaves privadas; use disco criptografado. Não compartilhe *.key.
- Não implementa revogação, expiração, web-of-trust, múltiplos destinatários, nem carimbo do tempo confiável.

Dependências: cryptography (pip install cryptography)
Python >= 3.9

Uso rápido:
  # 1) Gerar identidade do remetente
  python mini_pgp.py gen-id --name "Alice" --email alice@example.com --out alice
  
  # 2) Gerar identidade do destinatário
  python mini_pgp.py gen-id --name "Bob" --email bob@example.com --out bob
  
  # 3) Assinar um texto (sem criptografia)
  echo "olá, mundo" > msg.txt
  python mini_pgp.py sign --sender alice --in msg.txt --out msg.spkg.json
  
  # 4) Verificar assinatura
  python mini_pgp.py verify --in msg.spkg.json
  
  # 5) Enviar (assinar + criptografar para Bob)
  python mini_pgp.py send --sender alice --to bob.cert.json --in msg.txt --out msg.pkg.json
  
  # 6) Receber (verificar + decifrar)
  python mini_pgp.py recv --recipient bob --in msg.pkg.json --out plaintext.txt

Estrutura de arquivos criada por --out <prefixo>:
  <prefixo>.cert.json       (certificado público self-signed)
  <prefixo>.sig.key         (chave privada Ed25519 — SIGILO)
  <prefixo>.kex.key         (chave privada X25519 — SIGILO)
"""

from __future__ import annotations
import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Utilidades ---------------------------------------------------------------

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _canon(obj) -> bytes:
    """JSON canônico (ordenado, compacto) em bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# Certificado ad-hoc ------------------------------------------------------

def generate_identity(name: str, email: str, out_prefix: str) -> None:
    """Gera par de chaves Ed25519 (assinatura) e X25519 (troca), e certificado autoassinado."""
    # Chaves privadas
    sig_sk = Ed25519PrivateKey.generate()
    kex_sk = X25519PrivateKey.generate()

    sig_pk = sig_sk.public_key()
    kex_pk = kex_sk.public_key()

    cert = {
        "version": 1,
        "identity": {"name": name, "email": email},
        "alg": {"sig": "ed25519", "kex": "x25519", "cipher": "chacha20poly1305"},
        "pubkeys": {
            "sig": _b64e(sig_pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )),
            "kex": _b64e(kex_pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )),
        },
        "created": int(time.time()),
    }
    fp = _sha256(_canon({"pubkeys": cert["pubkeys"], "identity": cert["identity"]}))
    cert["fingerprint"] = fp.hex()

    # Autoassinatura do certificado
    to_sign = _canon({k: cert[k] for k in ["version", "identity", "alg", "pubkeys", "created", "fingerprint"]})
    selfsig = sig_sk.sign(to_sign)
    cert["selfsig"] = _b64e(selfsig)

    # Persistir
    with open(f"{out_prefix}.cert.json", "w", encoding="utf-8") as f:
        json.dump(cert, f, ensure_ascii=False, indent=2)

    with open(f"{out_prefix}.sig.key", "wb") as f:
        f.write(sig_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(f"{out_prefix}.kex.key", "wb") as f:
        f.write(kex_sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(f"Criado: {out_prefix}.cert.json, {out_prefix}.sig.key, {out_prefix}.kex.key")

# Carregamento de chaves/cert --------------------------------------------

def load_sig_sk(path: str) -> Ed25519PrivateKey:
    data = open(path, "rb").read()
    if len(data) != 32:
        sys.exit("Chave de assinatura inválida (esperado 32 bytes raw)")
    return Ed25519PrivateKey.from_private_bytes(data)


def load_kex_sk(path: str) -> X25519PrivateKey:
    data = open(path, "rb").read()
    if len(data) != 32:
        sys.exit("Chave de troca inválida (esperado 32 bytes raw)")
    return X25519PrivateKey.from_private_bytes(data)


def load_cert(path: str) -> dict:
    cert = json.load(open(path, "r", encoding="utf-8"))
    # Verificar autoassinatura
    to_sign = _canon({k: cert[k] for k in ["version", "identity", "alg", "pubkeys", "created", "fingerprint"]})
    sig = _b64d(cert["selfsig"])
    sig_pk = Ed25519PublicKey.from_public_bytes(_b64d(cert["pubkeys"]["sig"]))
    try:
        sig_pk.verify(sig, to_sign)
    except Exception:
        sys.exit("Certificado inválido: autoassinatura falhou")
    # Checar fingerprint
    fp = _sha256(_canon({"pubkeys": cert["pubkeys"], "identity": cert["identity"]})).hex()
    if fp != cert.get("fingerprint"):
        sys.exit("Certificado inválido: fingerprint divergente")
    return cert

# Assinatura e verificação -----------------------------------------------

def sign_message(sender_prefix: str, message_bytes: bytes, out_path: str) -> None:
    sig_sk = load_sig_sk(f"{sender_prefix}.sig.key")
    sender_cert = load_cert(f"{sender_prefix}.cert.json")

    payload = {
        "type": "SIGNED",
        "created": int(time.time()),
        "sender": {"cert": sender_cert},
        "message": _b64e(message_bytes),
    }
    to_sign = _canon({k: payload[k] for k in ["type", "created", "sender", "message"]})
    sig = sig_sk.sign(to_sign)
    payload["signature"] = _b64e(sig)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"Pacote assinado salvo em {out_path}")


def verify_signed(path: str) -> Tuple[bool, bytes]:
    pkg = json.load(open(path, "r", encoding="utf-8"))
    if pkg.get("type") != "SIGNED":
        sys.exit("Pacote não é do tipo SIGNED")
    sender_cert = pkg["sender"]["cert"]
    # Já valida autoassinatura/fingerprint
    _ = load_cert_tmp(sender_cert)

    to_verify = _canon({k: pkg[k] for k in ["type", "created", "sender", "message"]})
    sig = _b64d(pkg["signature"])
    sig_pk = Ed25519PublicKey.from_public_bytes(_b64d(sender_cert["pubkeys"]["sig"]))

    try:
        sig_pk.verify(sig, to_verify)
        ok = True
    except Exception:
        ok = False
    msg = _b64d(pkg["message"]) if ok else b""
    return ok, msg

# Criptografia (ECIES X25519 + HKDF + ChaCha20-Poly1305) -----------------

def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"mini_pgp v1")
    return hkdf.derive(shared_secret)


def send_encrypted(sender_prefix: str, recipient_cert_path: str, message_bytes: bytes, out_path: str) -> None:
    sig_sk = load_sig_sk(f"{sender_prefix}.sig.key")
    sender_cert = load_cert(f"{sender_prefix}.cert.json")
    rcpt_cert = load_cert(recipient_cert_path)

    # Ephemeral X25519 para PFS
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()

    rcpt_kex_pk = X25519PublicKey.from_public_bytes(_b64d(rcpt_cert["pubkeys"]["kex"]))
    shared = eph_sk.exchange(rcpt_kex_pk)

    salt = os.urandom(16)
    key = _derive_key(shared, salt)
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)

    header = {
        "type": "ENCRYPTED",
        "created": int(time.time()),
        "alg": {"kdf": "HKDF-SHA256", "cipher": "chacha20poly1305", "kex": "x25519"},
        "sender": {"cert": sender_cert, "eph_pub": _b64e(eph_pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ))},
        "recipient": {"fingerprint": rcpt_cert["fingerprint"]},
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
    }

    ciphertext = aead.encrypt(nonce, message_bytes, _canon(header))

    pkg = {**header, "ciphertext": _b64e(ciphertext)}

    # Assinar o pacote cifrado para autenticidade explícita do remetente
    to_sign = _canon({k: pkg[k] for k in [
        "type", "created", "alg", "sender", "recipient", "salt", "nonce", "ciphertext"
    ]})
    pkg["signature"] = _b64e(sig_sk.sign(to_sign))

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(pkg, f, ensure_ascii=False, indent=2)
    print(f"Pacote ENCRYPTED salvo em {out_path}")


def recv_encrypted(recipient_prefix: str, in_path: str) -> Tuple[bool, bytes, dict]:
    pkg = json.load(open(in_path, "r", encoding="utf-8"))
    if pkg.get("type") != "ENCRYPTED":
        sys.exit("Pacote não é do tipo ENCRYPTED")

    sender_cert = pkg["sender"]["cert"]
    _ = load_cert_tmp(sender_cert)  # valida cert do remetente

    # Verificar assinatura do pacote
    to_verify = _canon({k: pkg[k] for k in [
        "type", "created", "alg", "sender", "recipient", "salt", "nonce", "ciphertext"
    ]})
    sig = _b64d(pkg["signature"])
    sig_pk = Ed25519PublicKey.from_public_bytes(_b64d(sender_cert["pubkeys"]["sig"]))
    try:
        sig_pk.verify(sig, to_verify)
    except Exception:
        return False, b"", {"error": "Assinatura do pacote inválida"}

    # Decifrar
    rcpt_kex_sk = load_kex_sk(f"{recipient_prefix}.kex.key")
    eph_pub = X25519PublicKey.from_public_bytes(_b64d(pkg["sender"]["eph_pub"]))
    shared = rcpt_kex_sk.exchange(eph_pub)

    salt = _b64d(pkg["salt"])
    nonce = _b64d(pkg["nonce"])
    key = _derive_key(shared, salt)
    aead = ChaCha20Poly1305(key)

    try:
        plaintext = aead.decrypt(nonce, _b64d(pkg["ciphertext"]), _canon({k: pkg[k] for k in [
            "type", "created", "alg", "sender", "recipient", "salt", "nonce"
        ]}))
    except Exception:
        return False, b"", {"error": "Falha ao decifrar (nonce/salt/chave incorretos ou pacote corrompido)"}

    return True, plaintext, {"sender_fingerprint": sender_cert["fingerprint"], "sender_identity": sender_cert["identity"]}

# Helpers para validar cert embutido (sem ler arquivo) --------------------

def load_cert_tmp(cert: dict) -> dict:
    to_sign = _canon({k: cert[k] for k in ["version", "identity", "alg", "pubkeys", "created", "fingerprint"]})
    sig = _b64d(cert["selfsig"])
    sig_pk = Ed25519PublicKey.from_public_bytes(_b64d(cert["pubkeys"]["sig"]))
    sig_pk.verify(sig, to_sign)  # lança se inválido
    fp = _sha256(_canon({"pubkeys": cert["pubkeys"], "identity": cert["identity"]})).hex()
    if fp != cert.get("fingerprint"):
        raise ValueError("fingerprint divergente")
    return cert

# CLI ---------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="mini_pgp — assinaturas e mensagens criptografadas")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-id", help="Gerar identidade (cert + chaves privadas)")
    g.add_argument("--name", required=True)
    g.add_argument("--email", required=True)
    g.add_argument("--out", required=True, help="prefixo de saída (ex.: alice)")

    s = sub.add_parser("sign", help="Assinar mensagem (sem criptografia)")
    s.add_argument("--sender", required=True, help="prefixo da identidade (ex.: alice)")
    s.add_argument("--in", dest="inp", required=True, help="arquivo de entrada")
    s.add_argument("--out", required=True, help="arquivo .spkg.json")

    v = sub.add_parser("verify", help="Verificar pacote assinado .spkg.json")
    v.add_argument("--in", dest="inp", required=True)

    e = sub.add_parser("send", help="Assinar e criptografar para destinatário")
    e.add_argument("--sender", required=True)
    e.add_argument("--to", required=True, help="caminho para certificado do destinatário (.cert.json)")
    e.add_argument("--in", dest="inp", required=True)
    e.add_argument("--out", required=True, help="arquivo .pkg.json")

    r = sub.add_parser("recv", help="Verificar + decifrar pacote .pkg.json")
    r.add_argument("--recipient", required=True, help="prefixo da identidade local (ex.: bob)")
    r.add_argument("--in", dest="inp", required=True)
    r.add_argument("--out", required=False, help="arquivo para salvar o plaintext")

    args = p.parse_args()

    if args.cmd == "gen-id":
        generate_identity(args.name, args.email, args.out)

    elif args.cmd == "sign":
        message_bytes = open(args.inp, "rb").read()
        sign_message(args.sender, message_bytes, args.out)

    elif args.cmd == "verify":
        ok, msg = verify_signed(args.inp)
        print("Assinatura:", "OK" if ok else "INVÁLIDA")
        if ok:
            try:
                text = msg.decode("utf-8")
                print("Mensagem (UTF-8):\n" + text)
            except UnicodeDecodeError:
                print(f"Mensagem binária ({len(msg)} bytes)")

    elif args.cmd == "send":
        message_bytes = open(args.inp, "rb").read()
        send_encrypted(args.sender, args.to, message_bytes, args.out)

    elif args.cmd == "recv":
        ok, pt, meta = recv_encrypted(args.recipient, args.inp)
        print("Pacote válido:", ok)
        if ok:
            print("Remetente:", meta["sender_identity"], "fingerprint:", meta["sender_fingerprint"])
            if args.out:
                with open(args.out, "wb") as f:
                    f.write(pt)
                print("Plaintext salvo em", args.out)
            else:
                try:
                    print("Mensagem (UTF-8):\n" + pt.decode("utf-8"))
                except UnicodeDecodeError:
                    print(f"Mensagem binária ({len(pt)} bytes); use --out para salvar.")

if __name__ == "__main__":
    main()
