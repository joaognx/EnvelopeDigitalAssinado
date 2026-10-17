# Envelope Digital Assinado

Trabalho 01 de Segurança em Sistemas Computacionais (UFPI / DC), Prof. Carlos André Batista de Carvalho.

O programa cria e abre **envelopes digitais assinados** com a abordagem **Encrypt-then-Sign**: primeiro cifra a mensagem, depois assina o criptograma.

| Etapa | Algoritmo | Chave usada |
|---|---|---|
| Cifrar a mensagem | AES-256-CBC + PKCS7, com chave de sessão e IV aleatórios | chave de sessão |
| Proteger a chave de sessão | RSA-OAEP (SHA-256 ou SHA-512, MGF1 com o mesmo hash) | pública do **destinatário** |
| Assinar o criptograma | RSASSA-PKCS1-v1_5 (SHA-256 ou SHA-512) | privada do **remetente** |

Tudo é gravado num único arquivo JSON, com codificação **Base64** ou **Hex**. O formato é compatível com o [CyberChef](https://gchq.github.io/CyberChef/) e com os programas dos outros grupos.

---

## Sumário

1. [Instalação e execução](#1-instalação-e-execução)
2. [Estrutura dos arquivos](#2-estrutura-dos-arquivos)
3. [Quem usa qual chave](#3-quem-usa-qual-chave)
4. [A interface](#4-a-interface)
5. [O arquivo envelope.json](#5-o-arquivo-envelopejson)
6. [Usando o CyberChef com o programa](#6-usando-o-cyberchef-com-o-programa)
7. [Testes automáticos](#7-testes-automáticos)
8. [Trocando envelopes com outros grupos](#8-trocando-envelopes-com-outros-grupos)

---

## 1. Instalação e execução

**Requisitos:** Python 3.9 ou superior e a biblioteca `cryptography`.

```bash
pip install cryptography
```

**Executar:**

```bash
cd envelope
python main.py
```

O `main.py` também pode ser aberto de outra pasta ou pelo botão ▶ do VS Code. Ele sempre trabalha a partir da pasta `envelope`, e é lá que procura os arquivos que você digitar.

---

## 2. Estrutura dos arquivos

```
EnvelopeDigitalAssinado/
├── README.md
└── envelope/
    ├── main.py                 interface (menu)                              Pessoa 3
    ├── envelope_digital.py     JSON, validação, abertura e integração        Pessoa 3
    ├── aes_cifragem.py         AES-256-CBC + PKCS7                           Pessoa 1
    ├── rsa_assinatura.py       chaves PEM, RSA-OAEP, assinatura, Base64/Hex  Pessoa 2
    ├── gerar_chaves.py         geração de pares de chaves RSA                Pessoa 2
    ├── mensagem.txt            texto de exemplo para cifrar
    ├── chaves/                 chaves de teste (2048 bits, sem senha)
    │   ├── rem_priv.pem        privada do remetente
    │   ├── rem_pub.pem         pública do remetente
    │   ├── dest_priv.pem       privada do destinatário
    │   └── dest_pub.pem        pública do destinatário
    ├── teste_pessoa1.py        testes do AES
    ├── teste_pessoa2.py        testes do RSA e da assinatura
    ├── teste_minhas_chaves.py  teste rápido com as chaves de chaves/
    └── teste_pessoa3.py        testes do envelope completo
```

As chaves em `chaves/` existem **apenas para teste**. Não use essas chaves para proteger dados reais.

---

## 3. Quem usa qual chave

Existem duas pessoas, cada uma com um par de chaves RSA:

| Operação | Chave do **destinatário** | Chave do **remetente** |
|---|---|---|
| **Criar** o envelope | pública `dest_pub.pem`, para cifrar a chave de sessão | privada `rem_priv.pem`, para assinar |
| **Abrir** o envelope | privada `dest_priv.pem`, para decifrar a chave de sessão | pública `rem_pub.pem`, para verificar a assinatura |

A chave **privada** nunca é compartilhada. Para trocar envelopes com outra pessoa, envie só a sua chave **pública**.

---

## 4. A interface

### 4.1 Tela inicial

```
=== Envelope Digital Assinado (AES-256-CBC + RSA-OAEP + RSA-PKCS1v15) ===
Pasta de trabalho: C:\...\EnvelopeDigitalAssinado\envelope

  1) Criar envelope (cifrar e assinar)
  2) Abrir envelope (verificar e decifrar)
  3) Gerar pares de chaves RSA
  0) Sair
Opção:
```

A **pasta de trabalho** é onde os nomes de arquivo digitados são procurados e onde os arquivos de saída são gravados. Depois de cada operação, o menu volta a aparecer.

### 4.2 Como responder às perguntas

- Cada pergunta mostra um **valor padrão entre colchetes**, por exemplo `[envelope.json]`. Aperte **Enter** para aceitar ou digite outro valor.
- As perguntas pedem **nomes de arquivo**, e não o conteúdo. Para cifrar um texto, salve-o num arquivo `.txt` e informe o nome, **com a extensão**: `vasco.txt`, e não `vasco`.
- Podem ser usados caminhos relativos à pasta de trabalho (`chaves\dest_pub.pem`) ou caminhos completos (`C:\Users\...\arquivo.txt`).
- Caminhos colados **entre aspas**, como o Explorer do Windows copia com "Copiar como caminho", são aceitos: as aspas são removidas.
- Nas perguntas de escolha (hash e codificação), maiúsculas e minúsculas não importam: `hex` vale como `Hex`. Se a resposta não for uma opção válida, a pergunta se repete.

### 4.3 Opção 1: Criar envelope

```
--- Criar envelope ---
Arquivo de texto em claro [mensagem.txt]:
Chave PÚBLICA do destinatário [chaves\dest_pub.pem]:
Chave PRIVADA do remetente [chaves\rem_priv.pem]:
Arquivo de saída do envelope [envelope.json]:
Hash do RSA-OAEP (SHA-256/SHA-512) [SHA-256]:
Hash da assinatura (SHA-256/SHA-512) [SHA-256]:
Codificação (Base64/Hex) [Base64]:

Envelope criado com sucesso em 'envelope.json'.
```

| Pergunta | O que informar |
|---|---|
| Arquivo de texto em claro | arquivo com a mensagem, salvo em **UTF-8** |
| Chave PÚBLICA do destinatário | o `.pem` público de quem vai **receber** |
| Chave PRIVADA do remetente | o **seu** `.pem` privado, de quem está **enviando** |
| Arquivo de saída do envelope | nome do JSON a ser gerado. Se já existir, é **sobrescrito** |
| Hash do RSA-OAEP | hash usado para cifrar a chave de sessão (`SHA-256` ou `SHA-512`) |
| Hash da assinatura | hash usado na assinatura (`SHA-256` ou `SHA-512`) |
| Codificação | como os dados binários aparecem no JSON: `Base64` (mais curto) ou `Hex` |

Cada envelope usa uma chave de sessão e um IV novos. Por isso, cifrar a mesma mensagem duas vezes gera envelopes diferentes.

### 4.4 Opção 2: Abrir envelope

```
--- Abrir envelope ---
Arquivo do envelope [envelope.json]:
Chave PRIVADA do destinatário [chaves\dest_priv.pem]:
Chave PÚBLICA do remetente [chaves\rem_pub.pem]:
Arquivo de saída do texto decifrado [mensagem_decifrada.txt]:

Assinatura válida. Mensagem decifrada com sucesso.
Texto gravado em 'mensagem_decifrada.txt'.
----------------------------------------
vasco
----------------------------------------
```

Os hashes e a codificação **não são perguntados**: o programa lê essas informações do próprio JSON. A tela mostra até 300 caracteres do texto decifrado, e o texto completo fica no arquivo de saída.

**Ordem da abertura:**
1. Lê e valida o JSON.
2. **Verifica a assinatura.**
3. Decifra a chave de sessão com RSA-OAEP.
4. Decifra a mensagem com AES.

Se a assinatura for inválida, o programa para no passo 2 e **nada é decifrado**:

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  INTEGRIDADE VIOLADA: a assinatura do criptograma é inválida. Verifique se o envelope foi alterado, se a chave pública do remetente está correta e se o hash da assinatura confere.
  Nenhum dado foi decifrado.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

Para ver isso acontecer, troque uma letra do campo `mensagem_cifrada` no `envelope.json` e abra de novo.

### 4.5 Opção 3: Gerar pares de chaves RSA

```
--- Gerar pares de chaves RSA ---
Pasta de destino [chaves]:
Tamanho da chave em bits [2048]:
Gerado: chaves\rem_priv.pem e chaves\rem_pub.pem
Gerado: chaves\dest_priv.pem e chaves\dest_pub.pem
```

- O tamanho mínimo aceito é **2048 bits**, porque o RSA-OAEP com SHA-512 não funciona com chaves menores.
- **Atenção:** as chaves existentes na pasta são **sobrescritas**, e envelopes criados com as chaves antigas não poderão mais ser abertos. Para manter as atuais, informe outra pasta, por exemplo `chaves_novas`.

Também é possível gerar as chaves com o OpenSSL, sem senha:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out chaves/rem_priv.pem
openssl pkey -in chaves/rem_priv.pem -pubout -out chaves/rem_pub.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out chaves/dest_priv.pem
openssl pkey -in chaves/dest_priv.pem -pubout -out chaves/dest_pub.pem
```

### 4.6 Opção 0: Sair

Encerra o programa. **Ctrl+C** também encerra, mostrando `Operação cancelada.`

### 4.7 Mensagens de erro

O programa **nunca fecha por causa de um erro**: ele mostra `Erro: <motivo>` e volta ao menu.

| Mensagem (resumo) | Causa provável | Como resolver |
|---|---|---|
| `INTEGRIDADE VIOLADA` | envelope alterado, chave pública do remetente errada ou hash da assinatura divergente | use a `rem_pub.pem` de quem enviou e confira se o arquivo não foi editado |
| `Arquivo ... não encontrado` / `Caminho ... não encontrado` | nome digitado errado ou sem extensão | confira o nome, por exemplo `vasco.txt`, e se o arquivo está na pasta de trabalho |
| `não é uma chave privada PEM válida` | chave pública informada onde se pede a privada | use o arquivo `_priv.pem` |
| `não é uma chave pública PEM válida` | chave privada informada onde se pede a pública | use o arquivo `_pub.pem` |
| `está protegida por senha` | chave privada gerada com senha | gere a chave sem senha |
| `não é uma chave ... RSA` | o `.pem` contém outro tipo de chave | use uma chave RSA |
| `Não foi possível decifrar a chave de sessão` | chave privada de outra pessoa ou hash OAEP divergente | use a `dest_priv.pem` do destinatário correto |
| `não é um JSON válido (linha X, coluna Y)` | JSON corrompido ou editado errado | corrija o ponto indicado ou gere o envelope de novo |
| `ausente no JSON` / `ausente no envelope` | falta um campo | compare com o formato da seção 5 |
| `O protocolo exige ...` / `não suportado` | valor de parâmetro diferente do enunciado | use exatamente os valores da seção 5 |
| `O valor não é Base64/Hex válido` | dado corrompido ou `codificacao` errada | confira se a codificação declarada bate com os dados |
| `não está em UTF-8` | arquivo de texto salvo em outra codificação | salve o arquivo como UTF-8 |
| `A mensagem decifrada não é texto UTF-8 válido` | quem criou o envelope cifrou o texto sem UTF-8 (ex.: CyberChef com acentos) | veja o cuidado com acentos na seção 6.4 |

---

## 5. O arquivo envelope.json

```json
{
  "parametros": {
    "algoritmo_simetrico": "AES-256-CBC",
    "padding_simetrico": "PKCS7",
    "algoritmo_chave": "RSA-OAEP",
    "hash_oaep": "SHA-256",
    "algoritmo_assinatura": "RSA",
    "hash_assinatura": "SHA-256",
    "codificacao": "Base64"
  },
  "envelope": {
    "iv": "...",
    "chave_sessao": "...",
    "mensagem_cifrada": "...",
    "assinatura": "..."
  }
}
```

| Campo | Conteúdo |
|---|---|
| `algoritmo_simetrico`, `padding_simetrico`, `algoritmo_chave`, `algoritmo_assinatura` | valores fixos do protocolo |
| `hash_oaep` | `"SHA-256"` ou `"SHA-512"`, usado no RSA-OAEP e na MGF1 |
| `hash_assinatura` | `"SHA-256"` ou `"SHA-512"`, usado na assinatura |
| `codificacao` | `"Base64"` ou `"Hex"`, aplicada a todos os campos de `envelope` |
| `iv` | vetor de inicialização do AES (16 bytes) |
| `chave_sessao` | a chave AES (32 bytes) **já codificada em Base64/Hex**, cifrada com RSA-OAEP e codificada de novo |
| `mensagem_cifrada` | o criptograma AES |
| `assinatura` | a assinatura do **texto** do campo `mensagem_cifrada`, exatamente como aparece no JSON |

Os valores dos parâmetros precisam ser **exatamente** iguais aos da tabela, inclusive maiúsculas e minúsculas. Por exemplo, `"base64"` é rejeitado.

---

## 6. Usando o CyberChef com o programa

### 6.1 O que é o CyberChef e por que usá-lo

O [CyberChef](https://gchq.github.io/CyberChef/) é uma ferramenta gratuita que roda no navegador. Ele faz centenas de operações com dados: Base64, Hex, AES, RSA, hashes, assinaturas e outras.

O enunciado exige que o programa seja **compatível com ele**. Isso significa duas coisas:
- um envelope criado pelo programa tem que poder ser aberto, passo a passo, no CyberChef;
- um envelope montado no CyberChef tem que poder ser aberto pelo programa.

Isso comprova que o programa segue os padrões de verdade, e por isso os outros grupos conseguem abrir os nossos envelopes.

Os passos abaixo foram **testados nas duas direções**, com Base64 e Hex e com SHA-256 e SHA-512.

### 6.2 Como o CyberChef funciona

| Área da tela | Papel |
|---|---|
| **Operations** (esquerda) | lista de operações. Use a caixa **Search...** para achar uma pelo nome |
| **Recipe** (meio) | a "receita": operações em sequência. **Arraste** as operações para cá, na ordem indicada |
| **Input** (direita, em cima) | onde se cola o dado de entrada |
| **Output** (direita, embaixo) | o resultado, depois de passar por toda a receita |

- A saída de cada operação é a entrada da próxima.
- O resultado é recalculado automaticamente. Para recomeçar, clique na **lixeira** no topo da Recipe.
- Nas chaves, cole **o conteúdo inteiro** do arquivo `.pem`, incluindo as linhas `-----BEGIN ...-----` e `-----END ...-----`.
- Ao copiar valores do JSON, copie **só o que está entre as aspas**.
- Onde aparece **"From Hex / From Base64"**, use a operação que corresponde ao campo `codificacao` do envelope.

### 6.3 Direção 1: abrir no CyberChef um envelope criado pelo programa

**Preparação:**
1. Crie um envelope pelo menu (opção 1). Para o primeiro teste, escolha a codificação `Hex`.
2. Abra o `envelope.json`, a `chaves/rem_pub.pem` e a `chaves/dest_priv.pem` num editor de texto.
3. Abra o CyberChef.

#### Passo A: verificar a assinatura

| | Valor |
|---|---|
| **Input** | o campo `assinatura` |
| **Receita** | 1. **From Hex** / **From Base64**<br>2. **RSA Verify** |
| RSA Public Key (PEM) | conteúdo de `rem_pub.pem` |
| Message | o campo `mensagem_cifrada` |
| Message format | **Raw** |
| Message Digest Algorithm | o valor de `hash_assinatura` |

Resultado esperado: **`Verified OK`**. Se você trocar uma letra da *Message*, o resultado vira `Verification Failure`, que é o mesmo que o programa acusa como *INTEGRIDADE VIOLADA*.

#### Passo B: decifrar a chave de sessão

| | Valor |
|---|---|
| **Input** | o campo `chave_sessao` |
| **Receita** | 1. **From Hex** / **From Base64**<br>2. **RSA Decrypt** |
| RSA Private Key (PEM) | conteúdo de `dest_priv.pem` |
| Key Password | vazio |
| Encryption Scheme | **RSA-OAEP** |
| Message Digest Algorithm | o valor de `hash_oaep` |

Resultado esperado: a chave de sessão **em texto**, com 64 caracteres em Hex ou 44 em Base64. **Copie esse resultado** para o passo C.

#### Passo C: decifrar a mensagem

| | Envelope em **Hex** | Envelope em **Base64** |
|---|---|---|
| **Input** | o campo `mensagem_cifrada` | o campo `mensagem_cifrada` |
| **Receita** | **AES Decrypt** | 1. **From Base64**<br>2. **AES Decrypt** |
| Key | resultado do passo B, seletor **HEX** | resultado do passo B, seletor **BASE64** |
| IV | o campo `iv`, seletor **HEX** | o campo `iv`, seletor **BASE64** |
| Mode | **CBC** | **CBC** |
| Input | **Hex** | **Raw** |
| Output | **Raw** | **Raw** |

Resultado esperado: o texto original, com os acentos corretos. **Não** acrescente *Decode text* depois do AES Decrypt, porque isso estraga os acentos.

### 6.4 Direção 2: montar um envelope no CyberChef e abrir no programa

O exemplo usa **Hex** com **SHA-256**. As mudanças para Base64 e SHA-512 estão ao final.

#### Passo 1: gerar a chave e o IV

- Operação **Pseudo-Random Number Generator**, com *Number of bytes* = **32** e *Output as* = **Hex**. O resultado é a chave AES, com 64 caracteres. Guarde-a.
- Repita com *Number of bytes* = **16** para gerar o IV, com 32 caracteres. Guarde-o.

#### Passo 2: cifrar a mensagem → `mensagem_cifrada`

| | Valor |
|---|---|
| **Input** | o texto da mensagem |
| **Receita** | 1. **Encode text** (Encoding: **UTF-8 (65001)**)<br>2. **To Hex** (Delimiter: **None**)<br>3. **AES Encrypt** |
| Key | a chave do passo 1, seletor **HEX** |
| IV | o IV do passo 1, seletor **HEX** |
| Mode | **CBC** |
| Input | **Hex** |
| Output | **Hex** |

> **Cuidado com acentos.** Por padrão, o CyberChef lê o texto digitado como *Raw Bytes*, ou seja, 1 byte por caractere, e não como UTF-8. Sem as operações *Encode text (UTF-8)* e *To Hex*, letras como `ç`, `ã` e `é` são cifradas fora do UTF-8, e o programa recusa a mensagem com o erro *"A mensagem decifrada não é texto UTF-8 válido"*.
>
> Usar só o *Encode text* e deixar *Input* = Raw **também não funciona**. Para textos sem acento, qualquer caminho funciona.

#### Passo 3: cifrar a chave de sessão → `chave_sessao`

| | Valor |
|---|---|
| **Input** | a chave do passo 1 **como texto**, ou seja, os 64 caracteres hex |
| **Receita** | 1. **RSA Encrypt**<br>2. **To Hex** (Delimiter: **None**) |
| RSA Public Key (PEM) | conteúdo de `dest_pub.pem` |
| Encryption Scheme | **RSA-OAEP** |
| Message Digest Algorithm | **SHA-256** |

O protocolo cifra a chave **já codificada** (o texto), e não os 32 bytes brutos. Por isso a chave entra direto no Input, sem *From Hex*.

#### Passo 4: assinar o criptograma → `assinatura`

| | Valor |
|---|---|
| **Input** | o resultado do passo 2, ou seja, o texto da `mensagem_cifrada` |
| **Receita** | 1. **RSA Sign**<br>2. **To Hex** (Delimiter: **None**) |
| RSA Private Key (PEM) | conteúdo de `rem_priv.pem` |
| Key Password | vazio |
| Message Digest Algorithm | **SHA-256** |

#### Passo 5: montar o JSON e abrir no programa

Crie o arquivo `envelope_cyberchef.json` na pasta `envelope`:

```json
{
  "parametros": {
    "algoritmo_simetrico": "AES-256-CBC",
    "padding_simetrico": "PKCS7",
    "algoritmo_chave": "RSA-OAEP",
    "hash_oaep": "SHA-256",
    "algoritmo_assinatura": "RSA",
    "hash_assinatura": "SHA-256",
    "codificacao": "Hex"
  },
  "envelope": {
    "iv": "<IV do passo 1>",
    "chave_sessao": "<resultado do passo 3>",
    "mensagem_cifrada": "<resultado do passo 2>",
    "assinatura": "<resultado do passo 4>"
  }
}
```

Depois execute `python main.py`, escolha a opção **2** e informe `envelope_cyberchef.json` como arquivo do envelope. Resultado esperado: *"Assinatura válida. Mensagem decifrada com sucesso."* e o texto original.

#### Para montar em Base64 e/ou SHA-512

- **Passo 1:** converta a chave e o IV para Base64 com **From Hex** → **To Base64**.
- **Passo 2:** acrescente **From Hex** e **To Base64** depois do AES Encrypt.
- **Passo 3:** o *Input* passa a ser a **chave em Base64**, e o `To Hex` final vira **To Base64**.
- **Passo 4:** o `To Hex` final vira **To Base64**.
- **JSON:** `"codificacao": "Base64"`, com o `iv` em Base64.
- **SHA-512:** escolha-o no RSA Encrypt e/ou no RSA Sign, e ajuste `hash_oaep` e `hash_assinatura` no JSON de acordo.

### 6.5 Problemas comuns no CyberChef

| Sintoma | Causa provável |
|---|---|
| Erro ao ler a chave | faltou copiar as linhas `-----BEGIN ...-----` / `-----END ...-----` |
| `Verification Failure` sem ter alterado nada | hash diferente de `hash_assinatura`, chave pública errada, ou espaço ou aspas a mais na *Message* |
| Erro no RSA Decrypt | chave privada errada (tem que ser a `dest_priv`), esquema diferente de RSA-OAEP ou hash diferente de `hash_oaep` |
| Texto embaralhado no AES Decrypt | seletor da Key ou do IV no tipo errado (HEX/BASE64), ou chave copiada incompleta |
| Programa recusa um envelope do CyberChef por UTF-8 | faltou *Encode text (UTF-8)* + *To Hex* no passo 2 (seção 6.4) |
| Programa acusa assinatura inválida num envelope do CyberChef | o passo 4 assinou um texto diferente do que foi para o campo `mensagem_cifrada` |

---

## 7. Testes automáticos

Execute de dentro da pasta `envelope`. Todos devem terminar com `OK`:

```bash
python teste_pessoa1.py
```

```bash
python teste_pessoa2.py
```

```bash
python teste_pessoa3.py
```

| Arquivo | O que testa |
|---|---|
| `teste_pessoa1.py` | AES: ida e volta, tamanhos, aleatoriedade e erros |
| `teste_pessoa2.py` | RSA-OAEP e assinatura: todas as combinações, assinaturas inválidas e erros |
| `teste_pessoa3.py` | envelope completo: as 8 combinações de codificação e hashes, formato do JSON, adulteração, chaves trocadas e 11 situações de erro |

Os módulos também têm autotestes rápidos, que usam as chaves de `chaves/`: `python rsa_assinatura.py`, `python aes_cifragem.py` e `python envelope_digital.py`.

---

## 8. Trocando envelopes com outros grupos

1. Troquem as **chaves públicas**, nunca as privadas.
2. **Para enviar:** crie o envelope com a chave pública de destinatário **deles** e a **sua** chave privada de remetente, e envie o `envelope.json`.
3. **Para receber:** abra o envelope deles com a **sua** chave privada de destinatário e a chave pública de remetente **deles**.
4. Testem as combinações de Base64/Hex e de SHA-256/SHA-512.

Se der erro, a mensagem do programa indica qual parte do protocolo divergiu: assinatura, chave de sessão, formato do JSON ou codificação.
