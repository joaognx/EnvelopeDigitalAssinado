"""
Testes da parte da Pessoa 2. Como o módulo da Pessoa 1 ainda não existe,
a função simular_pessoa1() gera uma chave AES, um IV e um "ciphertext"
aleatórios, no mesmo formato que a Pessoa 1 vai entregar.

Uso: python teste_pessoa2.py
"""

import os
import tempfile
import unittest

from gerar_chaves import gerar_par
from rsa_assinatura import (
    ErroCripto, assinar, carregar_chave_privada, carregar_chave_publica,
    cifrar_chave_sessao, codificar, decifrar_chave_sessao, verificar_assinatura,
)


def simular_pessoa1(codificacao):
    """Substitui o módulo da Pessoa 1 até ele ficar pronto."""
    chave = os.urandom(32)          # AES-256
    iv = os.urandom(16)
    ciphertext = os.urandom(48)     # 3 blocos AES fictícios
    return (codificar(chave, codificacao), codificar(iv, codificacao),
            codificar(ciphertext, codificacao))


class TestePessoa2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pasta = tempfile.mkdtemp()
        cls.rem_priv_p, cls.rem_pub_p = gerar_par("remetente", cls.pasta)
        cls.dst_priv_p, cls.dst_pub_p = gerar_par("destinatario", cls.pasta)
        cls.rem_priv = carregar_chave_privada(cls.rem_priv_p)
        cls.rem_pub = carregar_chave_publica(cls.rem_pub_p)
        cls.dst_priv = carregar_chave_privada(cls.dst_priv_p)
        cls.dst_pub = carregar_chave_publica(cls.dst_pub_p)

    # ---- casos de sucesso, todas as combinações do protocolo -------------
    def test_ida_e_volta_todas_combinacoes(self):
        for cod in ("Base64", "Hex"):
            for h_oaep in ("SHA-256", "SHA-512"):
                for h_ass in ("SHA-256", "SHA-512"):
                    with self.subTest(cod=cod, oaep=h_oaep, ass=h_ass):
                        chave, _, ct = simular_pessoa1(cod)
                        cifrada = cifrar_chave_sessao(chave, self.dst_pub, h_oaep, cod)
                        ass = assinar(ct, self.rem_priv, h_ass, cod)
                        self.assertTrue(verificar_assinatura(ct, ass, self.rem_pub, h_ass, cod))
                        self.assertEqual(
                            decifrar_chave_sessao(cifrada, self.dst_priv, h_oaep, cod), chave)

    def test_oaep_e_aleatorio(self):
        chave, _, _ = simular_pessoa1("Base64")
        a = cifrar_chave_sessao(chave, self.dst_pub, "SHA-256", "Base64")
        b = cifrar_chave_sessao(chave, self.dst_pub, "SHA-256", "Base64")
        self.assertNotEqual(a, b)  # OAEP é probabilístico

    # ---- assinaturas inválidas ------------------------------------------
    def test_ciphertext_adulterado(self):
        _, _, ct = simular_pessoa1("Base64")
        ass = assinar(ct, self.rem_priv, "SHA-256", "Base64")
        adulterado = ("A" if ct[0] != "A" else "B") + ct[1:]
        self.assertFalse(verificar_assinatura(adulterado, ass, self.rem_pub, "SHA-256", "Base64"))

    def test_assinatura_adulterada(self):
        _, _, ct = simular_pessoa1("Hex")
        ass = assinar(ct, self.rem_priv, "SHA-256", "Hex")
        ass_ruim = ("0" if ass[0] != "0" else "1") + ass[1:]
        self.assertFalse(verificar_assinatura(ct, ass_ruim, self.rem_pub, "SHA-256", "Hex"))

    def test_chave_publica_errada(self):
        _, _, ct = simular_pessoa1("Base64")
        ass = assinar(ct, self.rem_priv, "SHA-256", "Base64")
        self.assertFalse(verificar_assinatura(ct, ass, self.dst_pub, "SHA-256", "Base64"))

    def test_hash_diferente(self):
        _, _, ct = simular_pessoa1("Base64")
        ass = assinar(ct, self.rem_priv, "SHA-256", "Base64")
        self.assertFalse(verificar_assinatura(ct, ass, self.rem_pub, "SHA-512", "Base64"))

    # ---- erros tratados (nada de exceção não tratada) -------------------
    def test_erros_tratados(self):
        chave, _, ct = simular_pessoa1("Base64")
        cifrada = cifrar_chave_sessao(chave, self.dst_pub, "SHA-256", "Base64")
        casos = [
            lambda: carregar_chave_publica(os.path.join(self.pasta, "nao_existe.pem")),
            lambda: carregar_chave_publica(self.rem_priv_p),         # privada no lugar da pública
            lambda: carregar_chave_privada(self.rem_pub_p),          # pública no lugar da privada
            lambda: cifrar_chave_sessao(chave, self.dst_pub, "MD5", "Base64"),
            lambda: cifrar_chave_sessao(chave, self.dst_pub, "SHA-256", "Base32"),
            lambda: cifrar_chave_sessao("abc", self.dst_pub, "SHA-256", "Base64"),
            lambda: decifrar_chave_sessao(cifrada, self.rem_priv, "SHA-256", "Base64"),  # chave errada
            lambda: decifrar_chave_sessao(cifrada, self.dst_priv, "SHA-512", "Base64"),  # hash errado
            lambda: verificar_assinatura(ct, "@@@não é base64@@@", self.rem_pub, "SHA-256", "Base64"),
        ]
        for i, caso in enumerate(casos):
            with self.subTest(caso=i):
                with self.assertRaises(ErroCripto):
                    caso()

    def test_chave_rsa_pequena_com_sha512(self):
        _, pub_p = gerar_par("pequena", self.pasta, bits=1024)
        pub = carregar_chave_publica(pub_p)
        chave, _, _ = simular_pessoa1("Hex")  # 64 caracteres
        with self.assertRaises(ErroCripto):
            cifrar_chave_sessao(chave, pub, "SHA-512", "Hex")


if __name__ == "__main__":
    unittest.main(verbosity=2)