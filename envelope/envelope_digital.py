import json
import os
import tempfile
from cryptography.hazmat.primitives.asymmetric import rsa

from aes_cifragem import cifrar_mensagem, decifrar_mensagem
from rsa_assinatura import (
    ErroCripto, checar, assinar, carregar_chave_privada, carregar_chave_publica,
    cifrar_chave_sessao, decifrar_chave_sessao, verificar_assinatura,
)

class AssinaturaInvalida(ErroCripto):
    pass

def ler_texto(caminho):
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise ErroCripto(f"Arquivo {caminho} não encontrado")
    except UnicodeDecodeError:
        raise ErroCripto(f"'{caminho}' não está em UTF-8. Salve o arquivo com a codificação UTF-8.")
    except OSError as e:
        raise ErroCripto(f"Não foi possível ler '{caminho}': {e.strerror}")

def gravar_arquivo(caminho, conteudo):
    try:
        with open(caminho, "w", encoding="utf-8", newline="") as f:
            f.write(conteudo)
    except OSError as e:
        raise ErroCripto(f"Não foi possível gravar '{caminho}': {e.strerror}")

def carregar_chave(caminho, privada):
    try:
        if privada:
            chave = carregar_chave_privada(caminho)
        else:
            chave = carregar_chave_publica(caminho)
    except FileNotFoundError:
        raise ErroCripto(f"Caminho {caminho} não encontrado")
    except TypeError:
        raise ErroCripto(f"'{caminho}' está protegida por senha. Use uma chave privada sem senha.")
    except OSError as e:
        raise ErroCripto(f"Não foi possível ler '{caminho}': {e.strerror}")

    if privada and not isinstance(chave, rsa.RSAPrivateKey):
        raise ErroCripto(f"'{caminho}' não é uma chave privada RSA.")
    if not privada and not isinstance(chave, rsa.RSAPublicKey):
        raise ErroCripto(f"'{caminho}' não é uma chave pública RSA.")
    return chave

def validar_hash(nome_hash, campo):
    if nome_hash not in ("SHA-256", "SHA-512"):
        raise ErroCripto(f"Hash {nome_hash!r} não suportado em '{campo}'. Use 'SHA-256' ou 'SHA-512'.")

def validar_codificacao(codificacao):
    if codificacao not in ("Base64", "Hex"):
        raise ErroCripto(f"Codificação {codificacao!r} não suportada. Use 'Base64' ou 'Hex'.")

def montar_json(hash_oaep, hash_assinatura, codificacao, iv, chave_sessao, mensagem_cifrada, assinatura):
    return {
        "parametros": {
            "algoritmo_simetrico": "AES-256-CBC",
            "padding_simetrico": "PKCS7",
            "algoritmo_chave": "RSA-OAEP",
            "hash_oaep": hash_oaep,
            "algoritmo_assinatura": "RSA",
            "hash_assinatura": hash_assinatura,
            "codificacao": codificacao,
        },
        "envelope": {
            "iv": iv,
            "chave_sessao": chave_sessao,
            "mensagem_cifrada": mensagem_cifrada,
            "assinatura": assinatura,
        },
    }

def ler_envelope(caminho):
    try:
        with open(caminho, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ErroCripto(f"Envelope {caminho} não encontrado")
    except json.JSONDecodeError as e:
        raise ErroCripto(f"'{caminho}' não é um JSON válido (linha {e.lineno}, coluna {e.colno}).")
    except UnicodeDecodeError:
        raise ErroCripto(f"'{caminho}' não está em UTF-8.")
    except OSError as e:
        raise ErroCripto(f"Não foi possível ler '{caminho}': {e.strerror}")

def validar_envelope(dados):
    if not isinstance(dados, dict):
        raise ErroCripto("O JSON deve ser um objeto com os blocos 'parametros' e 'envelope'.")
    for bloco in ("parametros", "envelope"):
        if not isinstance(dados.get(bloco), dict):
            raise ErroCripto(f"Bloco '{bloco}' ausente ou inválido no JSON.")

    parametros = dados["parametros"]
    envelope = dados["envelope"]

    fixos = {
        "algoritmo_simetrico": "AES-256-CBC",
        "padding_simetrico": "PKCS7",
        "algoritmo_chave": "RSA-OAEP",
        "algoritmo_assinatura": "RSA",
    }
    for campo, esperado in fixos.items():
        if campo not in parametros:
            raise ErroCripto(f"Parâmetro '{campo}' ausente no JSON.")
        if parametros[campo] != esperado:
            raise ErroCripto(f"Parâmetro '{campo}' com valor {parametros[campo]!r}. "
                             f"O protocolo exige {esperado!r}.")

    for campo in ("hash_oaep", "hash_assinatura", "codificacao"):
        if campo not in parametros:
            raise ErroCripto(f"Parâmetro '{campo}' ausente no JSON.")
    validar_hash(parametros["hash_oaep"], "hash_oaep")
    validar_hash(parametros["hash_assinatura"], "hash_assinatura")
    validar_codificacao(parametros["codificacao"])

    for campo in ("iv", "chave_sessao", "mensagem_cifrada", "assinatura"):
        if campo not in envelope:
            raise ErroCripto(f"Campo '{campo}' ausente no envelope.")
        if not isinstance(envelope[campo], str) or envelope[campo] == "":
            raise ErroCripto(f"O campo '{campo}' do envelope deve ser um texto não vazio.")

    return parametros, envelope

def criar_envelope(caminho_texto, caminho_pub_dest, caminho_priv_rem, caminho_saida,
                   hash_oaep="SHA-256", hash_assinatura="SHA-256", codificacao="Base64"):
    validar_hash(hash_oaep, "hash_oaep")
    validar_hash(hash_assinatura, "hash_assinatura")
    validar_codificacao(codificacao)

    texto = ler_texto(caminho_texto)
    pub_dest = carregar_chave(caminho_pub_dest, False)
    priv_rem = carregar_chave(caminho_priv_rem, True)

    chave, iv, ct = cifrar_mensagem(texto, codificacao)
    chave_sessao = cifrar_chave_sessao(chave, pub_dest, hash_oaep, codificacao)
    assinatura = assinar(ct, priv_rem, hash_assinatura, codificacao)

    dados = montar_json(hash_oaep, hash_assinatura, codificacao, iv, chave_sessao, ct, assinatura)
    gravar_arquivo(caminho_saida, json.dumps(dados, indent=2, ensure_ascii=False) + "\n")
    return dados

def abrir_envelope(caminho_envelope, caminho_priv_dest, caminho_pub_rem, caminho_saida):
    parametros, envelope = validar_envelope(ler_envelope(caminho_envelope))
    codificacao = parametros["codificacao"]

    priv_dest = carregar_chave(caminho_priv_dest, True)
    pub_rem = carregar_chave(caminho_pub_rem, False)

    valida = verificar_assinatura(envelope["mensagem_cifrada"], envelope["assinatura"], pub_rem,
                                  parametros["hash_assinatura"], codificacao)
    if not valida:
        raise AssinaturaInvalida(
            "INTEGRIDADE VIOLADA: a assinatura do criptograma é inválida. Verifique se o envelope "
            "foi alterado, se a chave pública do remetente está correta e se o hash da assinatura confere."
        )

    try:
        chave = decifrar_chave_sessao(envelope["chave_sessao"], priv_dest, parametros["hash_oaep"], codificacao)
    except UnicodeDecodeError:
        raise ErroCripto("A chave de sessão decifrada não é texto Base64/Hex. "
                         "O remetente pode ter cifrado a chave sem codificar.")

    texto = decifrar_mensagem(chave, envelope["iv"], envelope["mensagem_cifrada"], codificacao)

    gravar_arquivo(caminho_saida, texto)
    return texto


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    pasta = tempfile.mkdtemp()
    texto = os.path.join(pasta, "mensagem.txt")
    env = os.path.join(pasta, "envelope.json")
    saida = os.path.join(pasta, "saida.txt")
    gravar_arquivo(texto, "Segurança em Sistemas: ação, coração e pão!")

    for cod in ("Base64", "Hex"):
        for nome_hash in ("SHA-256", "SHA-512"):
            criar_envelope(texto, "chaves/dest_pub.pem", "chaves/rem_priv.pem", env, nome_hash, nome_hash, cod)
            resultado = abrir_envelope(env, "chaves/dest_priv.pem", "chaves/rem_pub.pem", saida)
            checar(f"envelope {cod} {nome_hash}", resultado, ler_texto(texto))

    dados = criar_envelope(texto, "chaves/dest_pub.pem", "chaves/rem_priv.pem", env)
    dados["envelope"]["mensagem_cifrada"] = "X" + dados["envelope"]["mensagem_cifrada"][1:]
    gravar_arquivo(env, json.dumps(dados))

    def deve_dar_erro(nome, funcao, tipo=ErroCripto):
        try:
            funcao()
            print("ERRO ", nome, "| não lançou", tipo.__name__)
        except tipo as e:
            print("OK   ", nome, "|", e)

    deve_dar_erro("criptograma adulterado",
                  lambda: abrir_envelope(env, "chaves/dest_priv.pem", "chaves/rem_pub.pem", saida),
                  AssinaturaInvalida)
    deve_dar_erro("envelope inexistente",
                  lambda: abrir_envelope("nao_existe.json", "chaves/dest_priv.pem", "chaves/rem_pub.pem", saida))
    deve_dar_erro("JSON sem bloco envelope", lambda: validar_envelope({"parametros": {}}))
    deve_dar_erro("chave privada inexistente", lambda: carregar_chave("chaves/nao_existe.pem", True))
    deve_dar_erro("pública no lugar da privada", lambda: carregar_chave("chaves/dest_pub.pem", True))
    deve_dar_erro("hash inválido", lambda: validar_hash("MD5", "hash_oaep"))
