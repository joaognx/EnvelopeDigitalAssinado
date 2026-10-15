"""
Testa o módulo rsa_assinatura com as chaves da pasta chaves/.
Rode de dentro da pasta envelope:  python teste_minhas_chaves.py
"""

import os

from rsa_assinatura import (
    ErroCripto, assinar, carregar_chave_privada, carregar_chave_publica,
    cifrar_chave_sessao, codificar, decifrar_chave_sessao, verificar_assinatura,
)

try:
    dst_pub = carregar_chave_publica("chaves/dest_pub.pem")
    dst_priv = carregar_chave_privada("chaves/dest_priv.pem")
    rem_pub = carregar_chave_publica("chaves/rem_pub.pem")
    rem_priv = carregar_chave_privada("chaves/rem_priv.pem")
    print(f"Chave do destinatário: {dst_pub.key_size} bits")
    print(f"Chave do remetente:    {rem_pub.key_size} bits")

    # Simula a Pessoa 1 (chave AES e ciphertext aleatórios)
    chave_cod = codificar(os.urandom(32), "Base64")
    ct_cod = codificar(os.urandom(48), "Base64")

    cifrada = cifrar_chave_sessao(chave_cod, dst_pub, "SHA-256", "Base64")
    assinatura = assinar(ct_cod, rem_priv, "SHA-256", "Base64")
    print("chave_sessao:", cifrada[:40], "...")
    print("assinatura:  ", assinatura[:40], "...")

    print("Assinatura válida?", verificar_assinatura(
        ct_cod, assinatura, rem_pub, "SHA-256", "Base64"))
    print("Chave recuperada igual?", decifrar_chave_sessao(
        cifrada, dst_priv, "SHA-256", "Base64") == chave_cod)
except ErroCripto as e:
    print("Erro:", e)