import os

from envelope_digital import AssinaturaInvalida, abrir_envelope, criar_envelope
from gerar_chaves import gerar_par
from rsa_assinatura import ErroCripto

def ler(mensagem):
    return input(mensagem).replace("﻿", "").strip()

def perguntar(mensagem, padrao=None):
    if padrao:
        mensagem = f"{mensagem} [{padrao}]"
    while True:
        resposta = ler(mensagem + ": ").strip('"')
        if resposta:
            return resposta
        if padrao:
            return padrao
        print("  Informe um valor.")

def escolher(mensagem, opcoes, padrao):
    while True:
        resposta = perguntar(f"{mensagem} ({'/'.join(opcoes)})", padrao)
        for opcao in opcoes:
            if resposta.lower() == opcao.lower():
                return opcao
        print(f"  Opção inválida. Escolha entre: {', '.join(opcoes)}.")

def opcao_criar():
    print("\n--- Criar envelope ---")
    texto = perguntar("Arquivo de texto em claro", "mensagem.txt")
    pub_dest = perguntar("Chave PÚBLICA do destinatário", os.path.join("chaves", "dest_pub.pem"))
    priv_rem = perguntar("Chave PRIVADA do remetente", os.path.join("chaves", "rem_priv.pem"))
    saida = perguntar("Arquivo de saída do envelope", "envelope.json")
    hash_oaep = escolher("Hash do RSA-OAEP", ["SHA-256", "SHA-512"], "SHA-256")
    hash_assinatura = escolher("Hash da assinatura", ["SHA-256", "SHA-512"], "SHA-256")
    codificacao = escolher("Codificação", ["Base64", "Hex"], "Base64")

    criar_envelope(texto, pub_dest, priv_rem, saida, hash_oaep, hash_assinatura, codificacao)
    print(f"\nEnvelope criado com sucesso em '{saida}'.")

def opcao_abrir():
    print("\n--- Abrir envelope ---")
    env = perguntar("Arquivo do envelope", "envelope.json")
    priv_dest = perguntar("Chave PRIVADA do destinatário", os.path.join("chaves", "dest_priv.pem"))
    pub_rem = perguntar("Chave PÚBLICA do remetente", os.path.join("chaves", "rem_pub.pem"))
    saida = perguntar("Arquivo de saída do texto decifrado", "mensagem_decifrada.txt")

    texto = abrir_envelope(env, priv_dest, pub_rem, saida)
    print("\nAssinatura válida. Mensagem decifrada com sucesso.")
    print(f"Texto gravado em '{saida}'.")
    if len(texto) > 300:
        texto = texto[:300] + "..."
    print("-" * 40)
    print(texto)
    print("-" * 40)

def opcao_gerar_chaves():
    print("\n--- Gerar pares de chaves RSA ---")
    pasta = perguntar("Pasta de destino", "chaves")
    while True:
        try:
            bits = int(perguntar("Tamanho da chave em bits", "2048"))
        except ValueError:
            print("  Digite um número inteiro.")
            continue
        if bits >= 2048:
            break
        print("  Use pelo menos 2048 bits (OAEP com SHA-512 exige isso).")

    try:
        os.makedirs(pasta, exist_ok=True)
        for nome in ("rem", "dest"):
            priv, pub = gerar_par(nome, pasta, bits)
            print(f"Gerado: {priv} e {pub}")
    except OSError as e:
        raise ErroCripto(f"Não foi possível gravar as chaves em '{pasta}': {e.strerror}")

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("=== Envelope Digital Assinado (AES-256-CBC + RSA-OAEP + RSA-PKCS1v15) ===")
    print(f"Pasta de trabalho: {os.getcwd()}")
    while True:
        print()
        print("  1) Criar envelope (cifrar e assinar)")
        print("  2) Abrir envelope (verificar e decifrar)")
        print("  3) Gerar pares de chaves RSA")
        print("  0) Sair")

        try:
            opcao = ler("Opção: ")
            if opcao == "1":
                opcao_criar()
            elif opcao == "2":
                opcao_abrir()
            elif opcao == "3":
                opcao_gerar_chaves()
            elif opcao == "0":
                print("Até mais!")
                return
            else:
                print("Opção inválida.")
        except AssinaturaInvalida as e:
            print("\n" + "!" * 60)
            print(f"  {e}")
            print("  Nenhum dado foi decifrado.")
            print("!" * 60)
        except ErroCripto as e:
            print(f"\nErro: {e}")
        except (KeyboardInterrupt, EOFError):
            print("\nOperação cancelada.")
            return
        except Exception as e:
            print(f"\nErro inesperado ({type(e).__name__}): {e}")


if __name__ == "__main__":
    main()
