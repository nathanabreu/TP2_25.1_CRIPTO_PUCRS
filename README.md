# TP2_25.1_CRIPTO_PUCRS
trabalho 2 da cadeira de criptografia na PUCRS

## Setup

Primeiro instale as dependências listadas em `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Executando

O programa principal está em `tp2_1_criptografia.py`. Para executá-lo, utilize:

```bash
python tp2_1_criptografia.py
```

Será solicitado um diretório para salvar ou carregar as chaves.

## Menu de opções

O script exibe o seguinte menu:

```
1 - Gerar chaves RSA do aluno (Parte 1)
2 - Compartilhar chave AES com o professor (Parte 2)
3 - Executar as duas etapas em sequência
4 - Decifrar mensagem do professor
5 - Decifrar mensagem AES
```

- **Opção 1** gera as chaves RSA e a chave simétrica `Sa`.
- **Opção 2** usa as chaves geradas para compartilhar `Sa` com o professor.
- **Opção 3** executa as etapas 1 e 2 em sequência.
- **Opção 4** descriptografa a mensagem RSA enviada pelo professor.
- **Opção 5** descriptografa mensagens criptografadas com AES usando `Sa`.
