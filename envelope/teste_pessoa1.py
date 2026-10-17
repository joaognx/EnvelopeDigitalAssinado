"""
Testes da parte da Pessoa 1 (AES-256-CBC).
Uso (de dentro da pasta envelope):  python teste_pessoa1.py
"""

import unittest

from aes_cifragem import cifrar_mensagem, decifrar_mensagem
from rsa_assinatura import ErroCripto, codificar, decodificar

MENSAGENS = [
    "a",
    "ola",
    "exatamente16byte",                       # 16 bytes: ganha um bloco inteiro de padding
    "Segurança em Sistemas: ação, coração e pão!",
    "linha 1\nlinha 2\n\ttabulada",
    "x" * 1000,
]


class TestePessoa1(unittest.TestCase):
    def test_ida_e_volta(self):
        for cod in ("Base64", "Hex"):
            for msg in MENSAGENS:
                with self.subTest(cod=cod, msg=msg[:20]):
                    chave, iv, ct = cifrar_mensagem(msg, cod)
                    self.assertEqual(decifrar_mensagem(chave, iv, ct, cod), msg)

    def test_tamanhos(self):
        chave, iv, ct = cifrar_mensagem("ola", "Base64")
        self.assertEqual(len(decodificar(chave, "Base64")), 32)
        self.assertEqual(len(decodificar(iv, "Base64")), 16)
        self.assertEqual(len(decodificar(ct, "Base64")), 16)
        _, _, ct16 = cifrar_mensagem("exatamente16byte", "Base64")
        self.assertEqual(len(decodificar(ct16, "Base64")), 32)  # bloco extra de padding

    def test_aleatoriedade(self):
        a = cifrar_mensagem("mesma mensagem", "Base64")
        b = cifrar_mensagem("mesma mensagem", "Base64")
        self.assertNotEqual(a[0], b[0])  # chaves diferentes
        self.assertNotEqual(a[1], b[1])  # IVs diferentes
        self.assertNotEqual(a[2], b[2])  # criptogramas diferentes

    def test_mensagem_vazia(self):
        chave, iv, ct = cifrar_mensagem("", "Hex")
        self.assertEqual(len(decodificar(ct, "Hex")), 16)  # só o bloco de padding
        self.assertEqual(decifrar_mensagem(chave, iv, ct, "Hex"), "")

    def test_erros_tratados(self):
        chave, iv, ct = cifrar_mensagem("mensagem de teste", "Base64")
        outra_chave, outro_iv, _ = cifrar_mensagem("outra", "Base64")
        casos = {
            "texto não é str": lambda: cifrar_mensagem(b"bytes", "Base64"),
            "codificação inválida": lambda: cifrar_mensagem("ola", "Base32"),
            "chave errada": lambda: decifrar_mensagem(outra_chave, iv, ct, "Base64"),
            "chave curta": lambda: decifrar_mensagem(codificar(b"x" * 16, "Base64"), iv, ct, "Base64"),
            "IV com tamanho errado": lambda: decifrar_mensagem(chave, codificar(b"x" * 8, "Base64"), ct, "Base64"),
            "criptograma truncado": lambda: decifrar_mensagem(chave, iv, codificar(decodificar(ct, "Base64")[:-1], "Base64"), "Base64"),
            "criptograma não é Base64": lambda: decifrar_mensagem(chave, iv, "@@@", "Base64"),
            "codificação trocada": lambda: decifrar_mensagem(chave, iv, ct, "Hex"),
        }
        for nome, caso in casos.items():
            with self.subTest(caso=nome):
                with self.assertRaises(ErroCripto):
                    caso()

    def test_iv_errado_nao_quebra(self):
        # Com IV errado, o CBC só estraga o primeiro bloco; ou dá ErroCripto,
        # ou devolve texto diferente — nunca uma exceção não tratada.
        chave, iv, ct = cifrar_mensagem("mensagem com mais de um bloco de texto", "Base64")
        _, outro_iv, _ = cifrar_mensagem("x", "Base64")
        try:
            resultado = decifrar_mensagem(chave, outro_iv, ct, "Base64")
            self.assertNotEqual(resultado, "mensagem com mais de um bloco de texto")
        except ErroCripto:
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)