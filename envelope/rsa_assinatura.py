import base64
import os
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class ErroCripto(Exception):
    pass

def codificar(dados, codificacao):
    try:
        if codificacao == "Base64":
            return base64.b64encode(dados).decode("ascii")
        elif codificacao == "Hex":
            return dados.hex()
        else:
            raise ErroCripto(f"Codificação '{codificacao}' não suportada. Use 'Base64' ou 'Hex'.")
    except(binascii.Error, ValueError):
        raise ErroCripto(f"Caracteres inválidos.")

def decodificar(texto, codificacao):
    if codificacao not in ("Base64", "Hex"):
        raise ErroCripto(f"Codificação '{codificacao}' não suportada. Use 'Base64' ou 'Hex'.")

    try:
        if codificacao == "Base64":
            return base64.b64decode(texto, validate=True)
        else:
            return bytes.fromhex(texto)
    except (binascii.Error, ValueError):
        raise ErroCripto(
            f"O valor não é {codificacao} válido. Verifique se a codificação "
            f"informada no JSON corresponde aos dados."
        )

def checar(nome, obtido, esperado):
    if obtido == esperado:
        print("OK   ", nome)
    else:
        print("ERRO ", nome, "| esperado:", repr(esperado), "| obtido:", repr(obtido))

def carregar_chave_publica(caminho):
    try:
        with open(caminho, "rb") as f:
            dados = f.read()
    except FileNotFoundError:
        raise ErroCripto(f"Caminho {caminho} não encontrado")
    try:
        return serialization.load_pem_public_key(dados)
    except ValueError:
        raise ErroCripto(f"'{caminho}' não é uma chave pública PEM válida. "
                         f"Verifique se não passou a chave privada no lugar.")

def carregar_chave_privada(caminho):
    with open(caminho, "rb") as f:
        dados = f.read()
    try:
        return serialization.load_pem_private_key(dados, password=None)
    except ValueError:
        raise ErroCripto(f"'{caminho}' não é uma chave privada PEM válida. "
                         f"Verifique se não passou a chave pública no lugar.")

def obter_hash(nome_hash):
    if nome_hash == "SHA-256":
        return hashes.SHA256()
    elif nome_hash == "SHA-512":
        return hashes.SHA512()
    else:
        raise ErroCripto(f"Hash '{nome_hash}' não suportado. Use 'SHA-256' ou 'SHA-512'.")
    
def cifrar_chave_sessao(chave_codificada, chave_publica, nome_hash, codificacao):
    if len(decodificar(chave_codificada, codificacao)) != 32:
        raise ErroCripto("A chave de sessão deve ter 256 bits (32 bytes).")
    mensagem = chave_codificada.encode("utf-8")

    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=obter_hash(nome_hash)),
        algorithm=obter_hash(nome_hash),
        label=None,
    )

    try:
        cifrado = chave_publica.encrypt(mensagem, pad)
    except ValueError:
        raise ErroCripto("Não foi possível cifrar a chave de sessão. A chave RSA "
                         "pode ser pequena demais para o hash escolhido; use 2048 bits ou mais.")
    return codificar(cifrado, codificacao)

def decifrar_chave_sessao(chave_cifrada, chave_privada, nome_hash, codificacao):
    cifrado = decodificar(chave_cifrada, codificacao)

    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=obter_hash(nome_hash)),
        algorithm=obter_hash(nome_hash),
        label=None,
    )

    try:
        mensagem = chave_privada.decrypt(cifrado, pad)
    except ValueError:
        raise ErroCripto(
            "Não foi possível decifrar a chave de sessão. Verifique se está usando "
            "a chave privada do destinatário correta e o mesmo hash OAEP da cifragem."
        )

    return mensagem.decode("utf-8")

def assinar(ct_codificado, chave_privada, nome_hash, codificacao):
    dados = ct_codificado.encode("utf-8")

    assinatura = chave_privada.sign(dados, padding.PKCS1v15(), obter_hash(nome_hash))

    return codificar(assinatura, codificacao)

def verificar_assinatura(ct_codificado, assinatura_codificada, chave_publica, nome_hash, codificacao):
    dados = ct_codificado.encode("utf-8")

    assinatura = decodificar(assinatura_codificada, codificacao)

    try:
        chave_publica.verify(assinatura, dados, padding.PKCS1v15(), obter_hash(nome_hash))
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    # codificar
    checar("codificar Base64", codificar(b"ola", "Base64"), "b2xh")
    checar("codificar Hex", codificar(b"ola", "Hex"), "6f6c61")

    # decodificar
    checar("decodificar Base64", decodificar("b2xh", "Base64"), b"ola")
    checar("decodificar Hex", decodificar("6f6c61", "Hex"), b"ola")

    # ida e volta com 32 bytes aleatórios (do tamanho de uma chave AES)
    chave = os.urandom(32)
    checar("ida e volta Base64", decodificar(codificar(chave, "Base64"), "Base64"), chave)
    checar("ida e volta Hex", decodificar(codificar(chave, "Hex"), "Hex"), chave)

    pub = carregar_chave_publica("chaves/dest_pub.pem")
    priv = carregar_chave_privada("chaves/dest_priv.pem")
    print("Pública:", pub.key_size, "bits")
    print("Privada:", priv.key_size, "bits")

    for nome_hash in ("SHA-256", "SHA-512"):
        chave_aes = codificar(os.urandom(32), "Base64")
        cifrada = cifrar_chave_sessao(chave_aes, pub, nome_hash, "Base64")
        recuperada = decifrar_chave_sessao(cifrada, priv, nome_hash, "Base64")
        checar("OAEP " + nome_hash, recuperada, chave_aes)

    rem_pub = carregar_chave_publica("chaves/rem_pub.pem")
    rem_priv = carregar_chave_privada("chaves/rem_priv.pem")

    ct = codificar(os.urandom(48), "Base64")      # simula o criptograma da Pessoa 1
    ass = assinar(ct, rem_priv, "SHA-256", "Base64")

    checar("assinatura válida", verificar_assinatura(ct, ass, rem_pub, "SHA-256", "Base64"), True)

    adulterado = "X" + ct[1:]                      # troca o primeiro caractere
    checar("criptograma adulterado", verificar_assinatura(adulterado, ass, rem_pub, "SHA-256", "Base64"), False)

    checar("chave errada", verificar_assinatura(ct, ass, pub, "SHA-256", "Base64"), False)

    def deve_dar_erro(nome, funcao):
        try:
            funcao()
            print("ERRO ", nome, "| não lançou ErroCripto")
        except ErroCripto as e:
            print("OK   ", nome, "|", e)


    deve_dar_erro("Base64 corrompido", lambda: decodificar("@@@isso não é base64@@@", "Base64"))
    deve_dar_erro("chave privada no lugar da pública", lambda: carregar_chave_publica("chaves/dest_priv.pem"))
    deve_dar_erro("decifrar com a chave errada", lambda: decifrar_chave_sessao(
        cifrar_chave_sessao(codificar(os.urandom(32), "Base64"), pub, "SHA-256", "Base64"),
        rem_priv, "SHA-256", "Base64"))
    deve_dar_erro("hash inválido", lambda: obter_hash("MD5"))
    deve_dar_erro("codificação inválida", lambda: codificar(b"ola", "Base32"))
    deve_dar_erro("arquivo inexistente", lambda: carregar_chave_publica("chaves/nao_existe.pem"))