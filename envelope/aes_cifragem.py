

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from rsa_assinatura import ErroCripto, codificar, decodificar

TAM_CHAVE = 32   # AES-256
TAM_IV = 16      # tamanho do bloco do AES
TAM_BLOCO_BITS = 128


def cifrar_mensagem(texto, codificacao):
    if not isinstance(texto, str):
        raise ErroCripto("A mensagem deve ser um texto.")

    # 1. segredos aleatórios (bytes)
    chave_bytes = os.urandom(TAM_CHAVE)
    iv_bytes = os.urandom(TAM_IV)

    # 2. a mensagem é o próprio dado -> encode
    dados = texto.encode("utf-8")

    # 3. padding PKCS#7 (completa o último bloco de 16 bytes)
    padder = padding.PKCS7(TAM_BLOCO_BITS).padder()
    dados_com_padding = padder.update(dados) + padder.finalize()

    # 4. AES-256-CBC
    cifra = Cipher(algorithms.AES(chave_bytes), modes.CBC(iv_bytes))
    encryptor = cifra.encryptor()
    criptograma = encryptor.update(dados_com_padding) + encryptor.finalize()

    # 5. bytes binários -> texto, só na saída
    return (codificar(chave_bytes, codificacao),
            codificar(iv_bytes, codificacao),
            codificar(criptograma, codificacao))


def decifrar_mensagem(chave, iv, criptograma, codificacao):
    
    # 1. os três são disfarces de bytes binários -> decodificar
    chave_bytes = decodificar(chave, codificacao)
    iv_bytes = decodificar(iv, codificacao)
    criptograma_bytes = decodificar(criptograma, codificacao)

    # conferências de tamanho, com mensagens claras
    if len(chave_bytes) != TAM_CHAVE:
        raise ErroCripto(
            f"A chave de sessão deve ter 32 bytes (AES-256), mas tem {len(chave_bytes)}."
        )
    if len(iv_bytes) != TAM_IV:
        raise ErroCripto(f"O IV deve ter 16 bytes, mas tem {len(iv_bytes)}.")
    if len(criptograma_bytes) == 0 or len(criptograma_bytes) % 16 != 0:
        raise ErroCripto(
            "O criptograma está corrompido: seu tamanho deveria ser múltiplo de 16 bytes."
        )

    # 2. AES-256-CBC
    cifra = Cipher(algorithms.AES(chave_bytes), modes.CBC(iv_bytes))
    decryptor = cifra.decryptor()
    dados_com_padding = decryptor.update(criptograma_bytes) + decryptor.finalize()

    # 3. remover o padding: se a chave ou o IV estiverem errados, o padding
    #    sai inválido e a biblioteca lança ValueError
    try:
        unpadder = padding.PKCS7(TAM_BLOCO_BITS).unpadder()
        dados = unpadder.update(dados_com_padding) + unpadder.finalize()
    except ValueError:
        raise ErroCripto(
            "Falha ao decifrar a mensagem (padding inválido). Verifique a chave "
            "de sessão e o IV, ou se o criptograma foi corrompido."
        ) from None

    # 4. os bytes são as letras da mensagem -> decode
    try:
        return dados.decode("utf-8")
    except UnicodeDecodeError:
        raise ErroCripto(
            "A mensagem decifrada não é texto UTF-8 válido. A chave ou o IV "
            "provavelmente estão errados."
        ) from None


if __name__ == "__main__":
    for cod in ("Base64", "Hex"):
        for msg in ["ola", "exatamente16byte", "Segurança em Sistemas: ação, coração e pão!"]:
            chave, iv, ct = cifrar_mensagem(msg, cod)
            tamanho = len(decodificar(ct, cod))
            resultado = decifrar_mensagem(chave, iv, ct, cod)
            status = "OK  " if resultado == msg else "ERRO"
            print(f"{status} {cod:6} | {len(msg.encode('utf-8')):3} bytes -> {tamanho:3} cifrados | {resultado!r}")