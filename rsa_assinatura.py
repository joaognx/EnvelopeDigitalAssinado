

import base64
import binascii

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HASHES_SUPORTADOS = {
    "SHA-256": hashes.SHA256,
    "SHA-512": hashes.SHA512,
}
CODIFICACOES_SUPORTADAS = ("Base64", "Hex")


class ErroCripto(Exception):
    """Erro tratado do módulo (mensagem pronta para mostrar ao usuário)."""


# ---------------------------------------------------------------------------
# Utilitários: hash e codificação
# ---------------------------------------------------------------------------
def obter_hash(nome_hash):
    """Converte "SHA-256"/"SHA-512" em objeto de hash da biblioteca."""
    nome = str(nome_hash).strip().upper().replace("_", "-")
    if nome in ("SHA256",):
        nome = "SHA-256"
    if nome in ("SHA512",):
        nome = "SHA-512"
    if nome not in HASHES_SUPORTADOS:
        raise ErroCripto(
            f"Hash '{nome_hash}' não suportado. Use 'SHA-256' ou 'SHA-512'."
        )
    return HASHES_SUPORTADOS[nome]()


def _normalizar_codificacao(codificacao):
    cod = str(codificacao).strip().lower()
    if cod == "base64":
        return "Base64"
    if cod == "hex":
        return "Hex"
    raise ErroCripto(
        f"Codificação '{codificacao}' inválida. Use 'Base64' ou 'Hex'."
    )


def codificar(dados: bytes, codificacao: str) -> str:
    """bytes -> texto Base64 (padrão, com '=') ou Hex (minúsculo)."""
    cod = _normalizar_codificacao(codificacao)
    if cod == "Base64":
        return base64.b64encode(dados).decode("ascii")
    return dados.hex()


def decodificar(texto: str, codificacao: str) -> bytes:
    """Texto Base64/Hex -> bytes, com validação estrita."""
    cod = _normalizar_codificacao(codificacao)
    if not isinstance(texto, str) or not texto.strip():
        raise ErroCripto("Campo vazio ou inválido: esperado texto codificado.")
    limpo = "".join(texto.split())  # tolera quebras de linha/espaços
    try:
        if cod == "Base64":
            return base64.b64decode(limpo, validate=True)
        return bytes.fromhex(limpo)
    except (binascii.Error, ValueError):
        raise ErroCripto(
            f"O valor não é {cod} válido. Confira se a codificação informada "
            f"no JSON corresponde aos dados."
        ) from None


# ---------------------------------------------------------------------------
# Carregamento de chaves PEM
# ---------------------------------------------------------------------------
def _ler_arquivo(caminho):
    try:
        with open(caminho, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise ErroCripto(f"Arquivo de chave não encontrado: '{caminho}'.") from None
    except PermissionError:
        raise ErroCripto(f"Sem permissão para ler o arquivo: '{caminho}'.") from None
    except OSError as e:
        raise ErroCripto(f"Erro ao ler '{caminho}': {e}") from None


def carregar_chave_publica(caminho):
    """Carrega chave pública RSA em PEM (aceita 'BEGIN PUBLIC KEY' e
    'BEGIN RSA PUBLIC KEY'). Também aceita um certificado X.509 PEM."""
    dados = _ler_arquivo(caminho)
    if b"PRIVATE KEY" in dados:
        raise ErroCripto(
            f"'{caminho}' contém uma chave PRIVADA, mas era esperada a PÚBLICA."
        )
    try:
        if b"BEGIN CERTIFICATE" in dados:
            from cryptography import x509
            chave = x509.load_pem_x509_certificate(dados).public_key()
        else:
            chave = serialization.load_pem_public_key(dados)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ErroCripto(
            f"'{caminho}' não é uma chave pública PEM válida."
        ) from None
    if not isinstance(chave, rsa.RSAPublicKey):
        raise ErroCripto(f"A chave em '{caminho}' não é RSA.")
    return chave


def carregar_chave_privada(caminho, senha=None):
    """Carrega chave privada RSA em PEM ('BEGIN PRIVATE KEY' ou
    'BEGIN RSA PRIVATE KEY'). 'senha' só é necessária se a chave for cifrada."""
    dados = _ler_arquivo(caminho)
    if b"PRIVATE KEY" not in dados and b"PUBLIC KEY" in dados:
        raise ErroCripto(
            f"'{caminho}' contém uma chave PÚBLICA, mas era esperada a PRIVADA."
        )
    if isinstance(senha, str):
        senha = senha.encode("utf-8") if senha else None
    try:
        chave = serialization.load_pem_private_key(dados, password=senha)
    except TypeError:
        if senha is None:
            raise ErroCripto(
                f"A chave privada '{caminho}' está protegida por senha. Informe a senha."
            ) from None
        raise ErroCripto(
            f"A chave privada '{caminho}' não usa senha; deixe a senha em branco."
        ) from None
    except (ValueError, UnsupportedAlgorithm):
        msg = f"'{caminho}' não é uma chave privada PEM válida"
        if senha is not None:
            msg += " ou a senha está incorreta"
        raise ErroCripto(msg + ".") from None
    if not isinstance(chave, rsa.RSAPrivateKey):
        raise ErroCripto(f"A chave em '{caminho}' não é RSA.")
    return chave


# ---------------------------------------------------------------------------
# RSA-OAEP: proteção da chave de sessão
# ---------------------------------------------------------------------------
def _padding_oaep(nome_hash):
    algoritmo = obter_hash(nome_hash)
    # MGF1 usa o mesmo hash do OAEP (convenção exigida pelo enunciado)
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=algoritmo),
        algorithm=algoritmo,
        label=None,
    )


def cifrar_chave_sessao(chave_sessao_codificada: str, chave_publica_dest,
                        hash_oaep: str, codificacao: str) -> str:
    """
    Cifra a chave de sessão com RSA-OAEP usando a chave pública do destinatário.

    chave_sessao_codificada: a chave AES (32 bytes) JÁ codificada em Base64/Hex
                             (string vinda da Pessoa 1). É exatamente essa
                             string, em UTF-8, que é cifrada.
    Retorna o resultado cifrado codificado (valor do campo "chave_sessao").
    """
    if not isinstance(chave_sessao_codificada, str) or not chave_sessao_codificada:
        raise ErroCripto("Chave de sessão codificada ausente ou inválida.")
    # Confere que a string realmente representa 32 bytes na codificação dada
    if len(decodificar(chave_sessao_codificada, codificacao)) != 32:
        raise ErroCripto("A chave de sessão deve ter 256 bits (32 bytes).")

    mensagem = chave_sessao_codificada.encode("utf-8")
    algoritmo = obter_hash(hash_oaep)
    tam_chave = chave_publica_dest.key_size // 8
    limite = tam_chave - 2 * algoritmo.digest_size - 2
    if len(mensagem) > limite:
        raise ErroCripto(
            f"Chave RSA de {chave_publica_dest.key_size} bits é pequena demais "
            f"para OAEP com {hash_oaep} (cabe no máximo {max(limite, 0)} bytes, "
            f"precisa de {len(mensagem)}). Use uma chave RSA de 2048 bits ou mais."
        )
    try:
        cifrado = chave_publica_dest.encrypt(mensagem, _padding_oaep(hash_oaep))
    except ValueError as e:
        raise ErroCripto(f"Falha ao cifrar a chave de sessão: {e}") from None
    return codificar(cifrado, codificacao)


def decifrar_chave_sessao(chave_sessao_cifrada: str, chave_privada_dest,
                          hash_oaep: str, codificacao: str) -> str:
    """
    Operação inversa (usada pela Pessoa 3): retorna a chave de sessão na
    forma codificada (string Base64/Hex), exatamente como foi cifrada.
    """
    cifrado = decodificar(chave_sessao_cifrada, codificacao)
    if len(cifrado) != chave_privada_dest.key_size // 8:
        raise ErroCripto(
            "Tamanho da chave de sessão cifrada não confere com a chave privada "
            "do destinatário. Verifique se está usando a chave correta."
        )
    try:
        claro = chave_privada_dest.decrypt(cifrado, _padding_oaep(hash_oaep))
    except ValueError:
        raise ErroCripto(
            "Não foi possível decifrar a chave de sessão. Causas prováveis: chave "
            "privada do destinatário errada, hash OAEP diferente do usado na "
            "cifragem, ou dado corrompido."
        ) from None
    try:
        return claro.decode("utf-8")
    except UnicodeDecodeError:
        raise ErroCripto(
            "A chave de sessão decifrada não é texto codificado válido."
        ) from None


# ---------------------------------------------------------------------------
# Assinatura digital: RSASSA-PKCS1-v1_5 sobre o criptograma codificado
# ---------------------------------------------------------------------------
def assinar(mensagem_cifrada_codificada: str, chave_privada_remet,
            hash_assinatura: str, codificacao: str) -> str:
    """
    Assina o valor textual do campo "mensagem_cifrada" (criptograma já
    codificado) com a chave privada do remetente.
    Retorna a assinatura codificada (valor do campo "assinatura").
    """
    if not isinstance(mensagem_cifrada_codificada, str) or not mensagem_cifrada_codificada:
        raise ErroCripto("Criptograma ausente: nada para assinar.")
    try:
        assinatura = chave_privada_remet.sign(
            mensagem_cifrada_codificada.encode("utf-8"),
            padding.PKCS1v15(),
            obter_hash(hash_assinatura),
        )
    except ValueError as e:
        raise ErroCripto(f"Falha ao assinar: {e}") from None
    return codificar(assinatura, codificacao)


def verificar_assinatura(mensagem_cifrada_codificada: str, assinatura_codificada: str,
                         chave_publica_remet, hash_assinatura: str,
                         codificacao: str) -> bool:
    """
    Verifica a assinatura sobre o criptograma codificado.
    Retorna True se válida e False se inválida (integridade violada ou
    remetente errado). Erros de formato levantam ErroCripto.
    """
    if not isinstance(mensagem_cifrada_codificada, str) or not mensagem_cifrada_codificada:
        raise ErroCripto("Criptograma ausente: nada para verificar.")
    assinatura = decodificar(assinatura_codificada, codificacao)
    algoritmo = obter_hash(hash_assinatura)
    try:
        chave_publica_remet.verify(
            assinatura,
            mensagem_cifrada_codificada.encode("utf-8"),
            padding.PKCS1v15(),
            algoritmo,
        )
        return True
    except InvalidSignature:
        return False