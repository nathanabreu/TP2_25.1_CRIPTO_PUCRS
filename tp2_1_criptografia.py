import os
from Crypto.Util.number import (
    getPrime,
    inverse,
    GCD,
    isPrime,
    bytes_to_long,
    long_to_bytes, # Importa a função long_to_bytes
)
from Crypto.Cipher import AES # Embora não seja usado na descriptografia RSA, mantido por contexto
from Crypto.Random import get_random_bytes, random

def gerar_chaves(output_dir):
    """
    Gera as chaves RSA (pública e privada) do aluno e as salva em arquivos.
    As chaves são geradas com 1024 bits e salvas em formato hexadecimal.
    """
    print("🔧 Gerando chaves RSA do aluno...")

    # Gerar dois números primos grandes para Pa e Qa
    Pa = getPrime(1024)
    Qa = getPrime(1024)
    # Calcular o módulo N (Na = Pa * Qa)
    Na = Pa * Qa
    # Calcular a função totiente de Euler (L = (Pa - 1) * (Qa - 1))
    L = (Pa - 1) * (Qa - 1)

    tentativas = 0
    # Gerar o expoente público Ea, que deve ser coprimo com L
    while True:
        Ea = random.randint(2, L - 1)
        tentativas += 1
        if isPrime(Ea) and GCD(Ea, L) == 1:
            break

    # Calcular o expoente privado Da (inverso modular de Ea mod L)
    Da = inverse(Ea, L)

    # Converter os valores das chaves para strings hexadecimais
    Ea_hex = hex(Ea)
    Na_hex = hex(Na)
    Da_hex = hex(Da)
    Pa_hex = hex(Pa)
    Qa_hex = hex(Qa)

    # Criar o diretório de saída se ele não existir
    os.makedirs(output_dir, exist_ok=True)

    # === Salvar chave pública em hexadecimal
    with open(os.path.join(output_dir, "chave_publica_hex.txt"), "w") as f:
        f.write(f"Ea = {Ea_hex}\n")
        f.write(f"Na = {Na_hex}\n")

    # === Salvar chave privada em hexadecimal
    with open(os.path.join(output_dir, "chave_privada_hex.txt"), "w") as f:
        f.write(f"Da = {Da_hex}\n")
        f.write(f"Pa = {Pa_hex}\n")
        f.write(f"Qa = {Qa_hex}\n")

    print(f"✅ Chaves salvas em formato HEX no diretório: {output_dir}")

def compartilhar_chave(output_dir):
    """
    Simula o compartilhamento de uma chave AES com o professor usando RSA.
    Gera um número aleatório Sa, o criptografa com a chave pública do professor
    e assina digitalmente com a chave privada do aluno.
    """
    print("📦 Gerando compartilhamento de chave AES...")

    # === Carregar chaves RSA do aluno em hexadecimal
    with open(os.path.join(output_dir, "chave_publica_hex.txt")) as f:
        pub_lines = f.readlines()
        Ea = int(pub_lines[0].split("=")[1].strip(), 16)
        Na = int(pub_lines[1].split("=")[1].strip(), 16)

    with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
        priv_lines = f.readlines()
        Da = int(priv_lines[0].split("=")[1].strip(), 16)

    # Chave pública fixa do professor (fornecida no problema)
    Ep_hex = "EEC2681EDAFB5FBF4249302A43764824B28F1D007C5D75955ECCD5CF630243F9"
    Np_hex = (
        "EB7ED592C4C4F9C5CF0D8DFA8921FA91DA89FAB0D31E74CE0451C54998B5CD6B"
        "ED2F02D7BC5B5F1CF65023A4BD9C2A7B550BC89B8056B38F0AEC9302FDAFEDE5"
        "06DFA860E74770EAF450AD3F76C4FE07CD6505CF877C62A48F2FE3A238E735A1"
        "68DB70C220B75D74A3B783570130E2F96C9BE30FC23E2153E9B1B7C2D8DC77B5"
    )
    Ep = int(Ep_hex, 16)
    Np = int(Np_hex, 16)

    # Gerar número aleatório Sa (simulando a chave simétrica)
    print("🔑 Gerando número aleatório Sa (chave simétrica)...")
    Sa_bytes = get_random_bytes(16) # 16 bytes para uma chave AES-128
    Sa = bytes_to_long(Sa_bytes)
    
    # Criptografar Sa com a chave pública do professor (X = Sa^Ep mod Np)
    X = pow(Sa, Ep, Np)
    # Assinar digitalmente X com a chave privada do aluno (SIGx = X^Da mod Na)
    SIGx = pow(X, Da, Na)

    # Salvar os componentes do compartilhamento em um arquivo
    with open(os.path.join(output_dir, "chave_simetrica_hex.txt"), "w") as f:
        f.write(f"X = {hex(X)}\n")
        f.write(f"SIGx = {hex(SIGx)}\n")
        f.write(f"Ea = {hex(Ea)}\n")
        f.write(f"Na = {hex(Na)}\n")

    print(f"✅ Compartilhamento salvo em: {os.path.join(output_dir, 'chave_simetrica_hex.txt')}")

def descriptografar_mensagem_professor():
    """
    Descriptografa uma mensagem cifrada em RSA fornecida pelo professor.
    A mensagem é dividida em blocos, cada bloco é descriptografado usando
    a chave privada do aluno, e então os bytes são convertidos para texto.
    """
    print("🔓 Descriptografando mensagem do professor...")
    
    try:
        # Carregar chave privada do aluno (Da, Pa, Qa)
        with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
            priv_lines = f.readlines()
            Da = int(priv_lines[0].split("=")[1].strip(), 16)
            Pa = int(priv_lines[1].split("=")[1].strip(), 16)
            Qa = int(priv_lines[2].split("=")[1].strip(), 16)
        # Recalcular Na a partir de Pa e Qa
        Na = Pa * Qa
        
        print("✅ Chave privada carregada")
        # Informar o tamanho de Na em bytes para referência
        print(f"   Tamanho de Na: {Na.bit_length()} bits ({Na.bit_length() // 8} bytes)")
        
        # Solicitar a mensagem cifrada do professor em formato hexadecimal
        print("\n📝 Cole a mensagem cifrada do professor (RSACipheredMsg_hex):")
        mensagem_hex = input().strip()
        
        # Limpar a entrada: remover o prefixo '0x' se presente, espaços em branco e quebras de linha
        if mensagem_hex.startswith("0x"):
            mensagem_hex = mensagem_hex[2:]
        mensagem_hex = mensagem_hex.replace(" ", "").replace("\n", "").replace("\r", "")
        
        # Converter a string hexadecimal da mensagem para bytes (conversão "raw")
        mensagem_bytes_raw = bytes.fromhex(mensagem_hex)

        print(f"📏 Tamanho da mensagem cifrada (raw): {len(mensagem_bytes_raw)} bytes")
        
        # Calcular o tamanho esperado de cada bloco cifrado, que é o tamanho de Na em bytes.
        # RSA criptografa números M < N. O ciphertext C também é < N.
        # Portanto, o ciphertext terá no máximo o mesmo número de bytes que N.
        tamanho_bloco_rsa_bytes = (Na.bit_length() + 7) // 8
        print(f"🔢 Tamanho esperado de cada bloco RSA (baseado em Na): {tamanho_bloco_rsa_bytes} bytes")

        # === LÓGICA ADICIONAL PARA LIDAR COM POSSÍVEL BYTE ZERO INICIAL ===
        # Se o comprimento total da mensagem em bytes for 1 byte a mais do que um múltiplo do tamanho do bloco,
        # E o primeiro byte for 0x00, é muito provável que seja um zero inicial "extra" que deve ser ignorado.
        # Isso é comum em representações hexadecimais de números RSA que não preenchem todos os 2048 bits.
        if len(mensagem_bytes_raw) > 0 and \
           len(mensagem_bytes_raw) % tamanho_bloco_rsa_bytes == 1 and \
           mensagem_bytes_raw[0] == 0x00:
            print("⚠️  Detectado um byte '0x00' inicial extra que será ignorado para o particionamento em blocos.")
            # Remove o byte 0x00 inicial
            mensagem_bytes = mensagem_bytes_raw[1:]
        else:
            # Caso contrário, usa os bytes raw como estão
            mensagem_bytes = mensagem_bytes_raw
        # === FIM DA LÓGICA ADICIONAL ===

        # Validar se o comprimento da mensagem agora é um múltiplo do tamanho do bloco
        if len(mensagem_bytes) % tamanho_bloco_rsa_bytes != 0:
            print(f"❌ Erro: O tamanho da mensagem cifrada ({len(mensagem_bytes)} bytes) não é um múltiplo do tamanho esperado do bloco RSA ({tamanho_bloco_rsa_bytes} bytes) após o tratamento inicial.")
            print("Certifique-se de que a mensagem foi copiada corretamente e consiste em blocos RSA completos.")
            return

        print(f"📏 Tamanho da mensagem cifrada (ajustado para blocos): {len(mensagem_bytes)} bytes")
        
        # Quebrar a mensagem cifrada em blocos do tamanho do módulo Na
        blocos_cifrados_int = []
        for i in range(0, len(mensagem_bytes), tamanho_bloco_rsa_bytes):
            bloco_bytes = mensagem_bytes[i:i + tamanho_bloco_rsa_bytes]
            if bloco_bytes: # Deve ser sempre verdadeiro se o comprimento for um múltiplo
                # Converter cada bloco de bytes cifrados para um inteiro
                bloco_cifrado_int = int.from_bytes(bloco_bytes, byteorder='big')
                blocos_cifrados_int.append(bloco_cifrado_int)
        
        print(f"📦 Total de blocos cifrados identificados: {len(blocos_cifrados_int)}")
        
        # Lista para armazenar os bytes descriptografados de cada bloco (sem padding inicial)
        blocos_descriptografados_bytes_lista = [] 
        
        # Descriptografar cada bloco
        for i, bloco_cifrado_int in enumerate(blocos_cifrados_int):
            print(f"\n🔓 Descriptografando bloco {i+1}/{len(blocos_cifrados_int)}...")
            
            # Verificar se o bloco cifrado é válido (deve ser menor que Na)
            if bloco_cifrado_int >= Na:
                print(f"❌ Erro: Bloco cifrado {i+1} é maior ou igual a Na. "
                      "Isso indica que a mensagem está corrompida ou foi criptografada incorretamente para esta chave.")
                # Continua para o próximo bloco, mas registra o erro
                blocos_descriptografados_bytes_lista.append(b'[ERRO_BLOCO_INVALIDO]') 
                continue
            
            # Descriptografar o bloco: mensagem_clara_int = bloco_cifrado_int^Da mod Na
            bloco_descriptografado_int = pow(bloco_cifrado_int, Da, Na)
            
            # Converter o inteiro descriptografado de volta para bytes.
            # long_to_bytes converte um inteiro em uma string de bytes.
            # É importante garantir que os bytes resultantes correspondam ao que era esperado após o padding RSA.
            # O comprimento da mensagem descriptografada (antes de remover o padding)
            # deve ser o mesmo que o tamanho do módulo N em bytes.
            bytes_descriptografados_com_padding = long_to_bytes(bloco_descriptografado_int, tamanho_bloco_rsa_bytes)
            
            print(f"   Tamanho dos bytes descriptografados (com padding): {len(bytes_descriptografados_com_padding)} bytes")
            print(f"   Hexadecimal (com padding): {bytes_descriptografados_com_padding.hex()}")

            # Remover bytes nulos iniciais (padding).
            # Em RSA básico, frequentemente o plaintext é preenchido com zeros à esquerda
            # para atingir o tamanho do bloco. `lstrip(b'\x00')` remove esses zeros.
            bytes_descriptografados_sem_padding = bytes_descriptografados_com_padding.lstrip(b'\x00')
            
            print(f"   Tamanho dos bytes descriptografados (sem padding): {len(bytes_descriptografados_sem_padding)} bytes")
            print(f"   Hexadecimal (sem padding): {bytes_descriptografados_sem_padding.hex()}")
            
            # Adicionar os bytes descriptografados (sem padding) à lista
            blocos_descriptografados_bytes_lista.append(bytes_descriptografados_sem_padding)
        
        # === Tentar decodificar a mensagem completa ===
        print("\n🔗 Tentando combinar e decodificar todos os blocos como uma mensagem única...")
        
        # Unir todos os bytes descriptografados (já sem o padding inicial de cada bloco)
        bytes_completos_descriptografados = b''.join(blocos_descriptografados_bytes_lista)
        
        print(f"📏 Tamanho total da mensagem em bytes (descriptografada e sem padding inicial): {len(bytes_completos_descriptografados)} bytes")

        texto_decodificado_completo = None
        # Tentar decodificar com diferentes codificações
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']:
            try:
                texto_teste = bytes_completos_descriptografados.decode(encoding)
                # Verifica se o texto resultante é imprimível ou contém apenas caracteres ASCII comuns
                if texto_teste.isprintable() or all(ord(c) < 128 for c in texto_teste):
                    texto_decodificado_completo = texto_teste
                    print(f"\n✅ Mensagem descriptografada com sucesso ({encoding}):")
                    print(f"📄 {texto_decodificado_completo}")
                    break # Se encontrou uma codificação válida, para o loop
            except UnicodeDecodeError:
                continue # Tenta a próxima codificação
        
        if texto_decodificado_completo is None:
            # Se nenhuma codificação resultou em texto legível
            print(f"\n⚠️  Não foi possível decodificar a mensagem completa como texto legível.")
            print(f"\n🔢 Hexadecimal dos bytes descriptografados (sem padding inicial, para debug): {bytes_completos_descriptografados.hex()}")
            print("\nIsso pode indicar que a mensagem não era texto ou que a codificação usada na criptografia original é diferente.")


    except FileNotFoundError:
        print("❌ Erro: Arquivo de chave privada não encontrado. Por favor, execute a opção '1 - Gerar chaves RSA do aluno' primeiro para criar as chaves.")
    except Exception as e:
        print(f"❌ Ocorreu um erro inesperado durante a descriptografia: {e}")

# === EXECUÇÃO PRINCIPAL DO SCRIPT ===
if __name__ == "__main__":
    print("=== TP2 - Sistema de Chaves RSA e Compartilhamento AES ===")
    output_dir = input("📁 Digite o diretório onde os arquivos serão salvos/carregados: ").strip()

    print("\nO que você deseja fazer?")
    print("1 - Gerar chaves RSA do aluno (Parte 1)")
    print("2 - Compartilhar chave AES com o professor (Parte 2)")
    print("3 - Executar as duas etapas em sequência")
    print("4 - Decifrar mensagem do professor")
    opcao = input("Digite sua escolha (1/2/3/4): ").strip()

    if opcao == "1":
        gerar_chaves(output_dir)
    elif opcao == "2":
        compartilhar_chave(output_dir)
    elif opcao == "3":
        gerar_chaves(output_dir)
        compartilhar_chave(output_dir)
    elif opcao == "4":
        descriptografar_mensagem_professor()
    else:
        print("❌ Opção inválida.")
