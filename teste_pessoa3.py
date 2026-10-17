import json
import os
import tempfile
import unittest

from envelope_digital import AssinaturaInvalida, abrir_envelope, criar_envelope
from gerar_chaves import gerar_par
from rsa_assinatura import ErroCripto

MENSAGEM = "Olá, envelope digital! Acentuação: ção, ü, € e emoji 🔐\nSegunda linha."


class TestePessoa3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pasta = tempfile.mkdtemp()
        cls.rem_priv, cls.rem_pub = gerar_par("rem", cls.pasta)
        cls.dst_priv, cls.dst_pub = gerar_par("dest", cls.pasta)
        cls.texto = os.path.join(cls.pasta, "mensagem.txt")
        with open(cls.texto, "w", encoding="utf-8") as f:
            f.write(MENSAGEM)

    def caminho(self, nome):
        return os.path.join(self.pasta, nome)

    def criar(self, nome="envelope.json", **kwargs):
        env = self.caminho(nome)
        criar_envelope(self.texto, self.dst_pub, self.rem_priv, env, **kwargs)
        return env

    def abrir(self, env, priv=None, pub=None):
        return abrir_envelope(env, priv or self.dst_priv, pub or self.rem_pub, self.caminho("saida.txt"))

    def alterar(self, env, bloco, campo, valor):
        with open(env, encoding="utf-8") as f:
            dados = json.load(f)
        if valor is None:
            del dados[bloco][campo]
        else:
            dados[bloco][campo] = valor
        with open(env, "w", encoding="utf-8") as f:
            json.dump(dados, f)

    def test_ida_e_volta_todas_combinacoes(self):
        for cod in ("Base64", "Hex"):
            for h_oaep in ("SHA-256", "SHA-512"):
                for h_ass in ("SHA-256", "SHA-512"):
                    with self.subTest(cod=cod, oaep=h_oaep, ass=h_ass):
                        env = self.criar(hash_oaep=h_oaep, hash_assinatura=h_ass, codificacao=cod)
                        self.assertEqual(self.abrir(env), MENSAGEM)
                        with open(self.caminho("saida.txt"), encoding="utf-8") as f:
                            self.assertEqual(f.read(), MENSAGEM)

    def test_formato_json(self):
        with open(self.criar(), encoding="utf-8") as f:
            dados = json.load(f)
        self.assertEqual(set(dados), {"parametros", "envelope"})
        self.assertEqual(set(dados["parametros"]), {
            "algoritmo_simetrico", "padding_simetrico", "algoritmo_chave", "hash_oaep",
            "algoritmo_assinatura", "hash_assinatura", "codificacao"})
        self.assertEqual(set(dados["envelope"]), {"iv", "chave_sessao", "mensagem_cifrada", "assinatura"})

    def test_criptograma_adulterado(self):
        env = self.criar()
        with open(env, encoding="utf-8") as f:
            ct = json.load(f)["envelope"]["mensagem_cifrada"]
        self.alterar(env, "envelope", "mensagem_cifrada", ("A" if ct[0] != "A" else "B") + ct[1:])
        with self.assertRaises(AssinaturaInvalida):
            self.abrir(env)

    def test_chave_publica_remetente_errada(self):
        with self.assertRaises(AssinaturaInvalida):
            self.abrir(self.criar(), pub=self.dst_pub)

    def test_hash_assinatura_trocado(self):
        env = self.criar(hash_assinatura="SHA-256")
        self.alterar(env, "parametros", "hash_assinatura", "SHA-512")
        with self.assertRaises(AssinaturaInvalida):
            self.abrir(env)

    def test_erros_tratados(self):
        def json_quebrado():
            env = self.caminho("quebrado.json")
            with open(env, "w", encoding="utf-8") as f:
                f.write("{ isso não é json")
            self.abrir(env)

        def campo_ausente():
            env = self.criar("ausente.json")
            self.alterar(env, "envelope", "iv", None)
            self.abrir(env)

        def algoritmo_invalido():
            env = self.criar("alg.json")
            self.alterar(env, "parametros", "algoritmo_simetrico", "DES")
            self.abrir(env)

        def codificacao_minuscula():
            env = self.criar("cod.json")
            self.alterar(env, "parametros", "codificacao", "base64")
            self.abrir(env)

        def iv_errado():
            env = self.criar("iv.json")
            self.alterar(env, "envelope", "iv", "AAAA")
            self.abrir(env)

        def chave_privada_errada():
            self.abrir(self.criar("priv.json"), priv=self.rem_priv)

        casos = {
            "envelope inexistente": lambda: self.abrir(self.caminho("nao_existe.json")),
            "JSON quebrado": json_quebrado,
            "campo ausente": campo_ausente,
            "algoritmo inválido": algoritmo_invalido,
            "codificação fora do padrão": codificacao_minuscula,
            "IV de tamanho errado": iv_errado,
            "chave privada do destinatário errada": chave_privada_errada,
            "chave privada inexistente": lambda: self.abrir(self.criar("x.json"), priv=self.caminho("nada.pem")),
            "pública no lugar da privada": lambda: self.abrir(self.criar("y.json"), priv=self.dst_pub),
            "texto inexistente": lambda: criar_envelope(self.caminho("nada.txt"), self.dst_pub,
                                                        self.rem_priv, self.caminho("z.json")),
            "codificação inválida": lambda: self.criar(codificacao="Base32"),
        }
        for nome, caso in casos.items():
            with self.subTest(caso=nome):
                with self.assertRaises(ErroCripto):
                    caso()


if __name__ == "__main__":
    unittest.main(verbosity=2)
