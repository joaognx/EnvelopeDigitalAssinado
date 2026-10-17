"""
Gera pares de chaves RSA em PEM para testes (equivalente ao OpenSSL):
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out remetente_priv.pem
  openssl pkey -in remetente_priv.pem -pubout -out remetente_pub.pem

Uso: python gerar_chaves.py [pasta] [bits]
Gera remetente_priv.pem, remetente_pub.pem, destinatario_priv.pem, destinatario_pub.pem
"""

import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def gerar_par(prefixo, pasta=".", bits=2048):
    privada = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem_priv = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,          # BEGIN PRIVATE KEY
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  # BEGIN PUBLIC KEY
    )
    caminho_priv = os.path.join(pasta, f"{prefixo}_priv.pem")
    caminho_pub = os.path.join(pasta, f"{prefixo}_pub.pem")
    with open(caminho_priv, "wb") as f:
        f.write(pem_priv)
    with open(caminho_pub, "wb") as f:
        f.write(pem_pub)
    return caminho_priv, caminho_pub


if __name__ == "__main__":
    pasta = sys.argv[1] if len(sys.argv) > 1 else "chaves"
    try:
        bits = int(sys.argv[2]) if len(sys.argv) > 2 else 2048
        if bits < 2048:
            print("Aviso: use pelo menos 2048 bits (OAEP com SHA-512 exige isso).")
        os.makedirs(pasta, exist_ok=True)
        for nome in ("remetente", "destinatario"):
            priv, pub = gerar_par(nome, pasta, bits)
            print(f"Gerado: {priv} e {pub}")
    except ValueError:
        print("Erro: o número de bits deve ser um inteiro (ex.: 2048).")
    except OSError as e:
        print(f"Erro ao gravar as chaves: {e}")