# TP2 - Sistema de Chaves RSA e Compartilhamento AES

## 📋 Descrição do Projeto

Este é um projeto de criptografia que implementa um sistema completo de geração de chaves RSA, compartilhamento de chaves AES e descriptografia de mensagens. O projeto foi desenvolvido para o trabalho prático 2 da disciplina de Criptografia.

## 🏗️ Estrutura do Projeto

```
TP2_25.1_CRIPTO_PUCRS-main/
├── tp2_1_criptografia.py    # Arquivo principal com todas as funcionalidades
├── requirements.txt         # Dependências do projeto
├── README.md               # Documentação do projeto
├── resource/               # Diretório de recursos
└── agents.md               # Este arquivo - instruções para agentes
```

## 🔧 Funcionalidades Implementadas

### 1. Geração de Chaves RSA (`gerar_chaves`)
- Gera primos Pa e Qa de 1024 bits
- Calcula Na = Pa * Qa
- Encontra Ea coprimo com L = (Pa-1) * (Qa-1)
- Calcula Da = Ea^(-1) mod L
- **Gera chave simétrica Sa** (16 bytes aleatórios)
- Salva chaves em formato hexadecimal

### 2. Compartilhamento de Chave AES (`compartilhar_chave`)
- Carrega chaves RSA do aluno
- Usa chave pública fixa do professor
- Carrega Sa do arquivo de chave privada
- Criptografa Sa com chave pública do professor: X = Sa^Ep mod Np
- Assina X com chave privada do aluno: SIGx = X^Da mod Na
- Salva X, SIGx, Ea, Na (sem Sa)

### 3. Descriptografia RSA (`descriptografar_mensagem_professor`)
- Carrega chave privada RSA do aluno
- Descriptografa mensagens RSA do professor
- Quebra em blocos e descriptografa cada bloco
- Remove padding e combina resultados
- Tenta diferentes encodings

### 4. Descriptografia AES (`descriptografar_mensagem_aes`)
- Carrega chave Sa do arquivo de chave privada
- Remove prefixo "0x" se presente
- Descriptografa mensagens AES-CBC
- Remove padding PKCS7
- Decodifica para texto UTF-8

## 📁 Arquivos Gerados

### `chave_publica_hex.txt`
```
Ea = 0x...
Na = 0x...
```

### `chave_privada_hex.txt`
```
Da = 0x...
Pa = 0x...
Qa = 0x...
Sa = 0x...  # Chave simétrica AES
```

### `chave_simetrica_hex.txt`
```
X = 0x...      # Sa criptografado com chave do professor
SIGx = 0x...   # Assinatura digital
Ea = 0x...     # Chave pública do aluno
Na = 0x...     # Módulo do aluno
```

## 🔑 Chaves Fixas do Professor

```python
Ep_hex = "EEC2681EDAFB5FBF4249302A43764824B28F1D007C5D75955ECCD5CF630243F9"
Np_hex = "EB7ED592C4C4F9C5CF0D8DFA8921FA91DA89FAB0D31E74CE0451C54998B5CD6BED2F02D7BC5B5F1CF65023A4BD9C2A7B550BC89B8056B38F0AEC9302FDAFEDE506DFA860E74770EAF450AD3F76C4FE07CD6505CF877C62A48F2FE3A238E735A168DB70C220B75D74A3B783570130E2F96C9BE30FC23E2153E9B1B7C2D8DC77B5"
```

## 🚀 Como Usar

### Menu Principal
```
1 - Gerar chaves RSA do aluno (Parte 1)
2 - Compartilhar chave AES com o professor (Parte 2)
3 - Executar as duas etapas em sequência
4 - Decifrar mensagem do professor
5 - Decifrar mensagem AES
```

### Fluxo de Trabalho
1. **Execute opção 1** para gerar chaves RSA e Sa
2. **Execute opção 2** para compartilhar Sa com o professor
3. **Use opção 4** para descriptografar mensagens RSA do professor
4. **Use opção 5** para descriptografar mensagens AES

## 🔍 Pontos Importantes

### Chave Simétrica Sa
- **Gerada uma única vez** na função `gerar_chaves()`
- **Salva no arquivo** `chave_privada_hex.txt`
- **Carregada automaticamente** nas funções de descriptografia
- **16 bytes** (128 bits) de tamanho

### Formato Hexadecimal
- Todas as chaves são salvas em formato hexadecimal
- Prefixo "0x" é removido automaticamente
- Espaços e quebras de linha são limpos

### Padding
- **RSA**: Padding é removido com `lstrip(b'\x00')`
- **AES**: Padding PKCS7 é removido automaticamente ou manualmente

## 🛠️ Dependências

```python
from Crypto.Util.number import getPrime, inverse, GCD, isPrime, bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
from Crypto.Util.Padding import unpad
```

## 📝 Notas para Desenvolvimento

### Modificações Recentes
- Chave Sa agora é salva em `chave_privada_hex.txt` (não em `chave_simetrica_hex.txt`)
- Função `descriptografar_mensagem_aes()` remove prefixo "0x" automaticamente
- Melhor tratamento de erros e feedback informativo

### Padrões de Código
- Uso de emojis para melhor visualização
- Mensagens de erro detalhadas
- Validação de entrada robusta
- Tratamento de diferentes encodings

### Segurança
- Chaves privadas são salvas localmente
- Chave Sa é mantida segura no arquivo de chave privada
- Validação de tamanhos e formatos

## 🎯 Objetivos do Projeto

1. **Implementar criptografia RSA** completa
2. **Compartilhar chaves simétricas** de forma segura
3. **Descriptografar mensagens** RSA e AES
4. **Demonstrar fluxo completo** de criptografia híbrida

## 🔧 Comandos Úteis

```bash
# Instalar dependências
pip install -r requirements.txt

# Executar o programa
python tp2_1_criptografia.py

# Testar com diretório específico
# Digite: C:\temp\chaves
```

## 📞 Suporte

Para dúvidas sobre o projeto:
- Verifique os comentários no código
- Execute as funções em ordem (1 → 2 → 4/5)
- Use a opção 3 para executar tudo de uma vez
- Verifique se os arquivos foram gerados corretamente 