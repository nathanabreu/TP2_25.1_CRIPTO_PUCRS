import os
from Crypto.Util.number import (
    getPrime,
    inverse,
    GCD,
    isPrime,
    bytes_to_long,
    long_to_bytes, # Importa a função long_to_bytes
)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
from Crypto.Util.Padding import unpad

def gerar_chaves(output_dir):
    # Gerar primos Pa e Qa
    Pa = getPrime(1024)    
    Qa = getPrime(1024)
    Na = Pa * Qa
    L = (Pa - 1) * (Qa - 1)

    # Encontrar Ea coprimo com L
    tentativas = 0
    while True:
        Ea = random.randint(2, L - 1)
        if isPrime(Ea) and L % Ea != 0:
            break
        tentativas += 1
        if isPrime(Ea) and GCD(Ea, L) == 1:
            break

    # Calcular Da (chave privada)
    Da = inverse(Ea, L)

    # Gerar chave simétrica Sa
    Sa_bytes = get_random_bytes(16)
    Sa = bytes_to_long(Sa_bytes)

    # Converter para hex
    Ea_hex = hex(Ea)
    Na_hex = hex(Na)
    Da_hex = hex(Da)
    Pa_hex = hex(Pa)
    Qa_hex = hex(Qa)
    Sa_hex = hex(Sa)

    # Criar o diretório de saída se ele não existir
    os.makedirs(output_dir, exist_ok=True)

    # Salvar chave pública
    with open(os.path.join(output_dir, "chave_publica_hex.txt"), "w") as f:
        f.write(f"Ea = {Ea_hex}\n")
        f.write(f"Na = {Na_hex}\n")

    # Salvar chave privada
    with open(os.path.join(output_dir, "chave_privada_hex.txt"), "w") as f:
        f.write(f"Da = {Da_hex}\n")
        f.write(f"Pa = {Pa_hex}\n")
        f.write(f"Qa = {Qa_hex}\n")
        f.write(f"Sa = {Sa_hex}\n")

    print(f" Chaves salvas em formato HEX no diretório: {output_dir}")

def compartilhar_chave(output_dir):
    # Carregar chaves do aluno
    with open(os.path.join(output_dir, "chave_publica_hex.txt")) as f:
        pub_lines = f.readlines()
        Ea = int(pub_lines[0].split("=")[1].strip(), 16)
        Na = int(pub_lines[1].split("=")[1].strip(), 16)

    with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
        priv_lines = f.readlines()
        Da = int(priv_lines[0].split("=")[1].strip(), 16)
        Sa = int(priv_lines[3].split("=")[1].strip(), 16)

    # Chave pública fixa do professor
    Ep_hex = "EEC2681EDAFB5FBF4249302A43764824B28F1D007C5D75955ECCD5CF630243F9"
    Np_hex = (
        "EB7ED592C4C4F9C5CF0D8DFA8921FA91DA89FAB0D31E74CE0451C54998B5CD6B"
        "ED2F02D7BC5B5F1CF65023A4BD9C2A7B550BC89B8056B38F0AEC9302FDAFEDE5"
        "06DFA860E74770EAF450AD3F76C4FE07CD6505CF877C62A48F2FE3A238E735A1"
        "68DB70C220B75D74A3B783570130E2F96C9BE30FC23E2153E9B1B7C2D8DC77B5"
    )
    Ep = int(Ep_hex, 16)
    Np = int(Np_hex, 16)

    print("🔑 Carregando chave simétrica Sa do arquivo de chave privada...")
    
    # Criptografar com chave pública do professor
    X = pow(Sa, Ep, Np)
    # Assinar digitalmente X com a chave privada do aluno (SIGx = X^Da mod Na)
    SIGx = pow(X, Da, Na)

    # Salvar resultado
    with open(os.path.join(output_dir, "chave_simetrica_hex.txt"), "w") as f:
        f.write(f"X = {hex(X)}\n")
        f.write(f"SIGx = {hex(SIGx)}\n")
        f.write(f"Ea = {hex(Ea)}\n")
        f.write(f"Na = {hex(Na)}\n")

    print(f"✅ Compartilhamento salvo em: {os.path.join(output_dir, 'chave_simetrica_hex.txt')}")

def descriptografar_mensagem_rsa(output_dir):
    """Descriptografa mensagem RSA do professor"""
    print("Descriptografando mensagem do professor...")
    
    try:
        # carrega minha chave privada
        with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
            linhas = f.readlines()
            Da = int(linhas[0].split("=")[1].strip(), 16)  # minha chave privada
            Pa = int(linhas[1].split("=")[1].strip(), 16)  # primo P
            Qa = int(linhas[2].split("=")[1].strip(), 16)  # primo Q
        
        Na = Pa * Qa  # calcula N = P * Q
        print("Chave privada carregada!")
        
        # pega a mensagem cifrada do professor
        print("Cole a mensagem cifrada do professor:")
        msg_hex = input().strip()
        
        # limpa a mensagem (remove 0x e espaços)
        if msg_hex.startswith("0x"):
            msg_hex = msg_hex[2:]
        msg_hex = msg_hex.replace(" ", "").replace("\n", "")
        
        # converte hex para bytes
        msg_bytes = bytes.fromhex(msg_hex)
        print(f"Mensagem tem {len(msg_bytes)} bytes")
        
        # calcula tamanho do bloco RSA (baseado no tamanho de N)
        tamanho_bloco = (Na.bit_length() + 7) // 8
        print(f"Cada bloco RSA tem {tamanho_bloco} bytes")
        
        # remove byte zero extra se tiver
        if len(msg_bytes) > 0 and len(msg_bytes) % tamanho_bloco == 1 and msg_bytes[0] == 0x00:
            msg_bytes = msg_bytes[1:]
        
        # verifica se o tamanho está certo
        if len(msg_bytes) % tamanho_bloco != 0:
            print("Erro: tamanho da mensagem não é múltiplo do bloco RSA")
            return
        
        # quebra a mensagem em blocos
        blocos = []
        for i in range(0, len(msg_bytes), tamanho_bloco):
            bloco_bytes = msg_bytes[i:i + tamanho_bloco]
            if bloco_bytes:
                bloco_int = int.from_bytes(bloco_bytes, byteorder='big')
                blocos.append(bloco_int)
        
        print(f"Total de {len(blocos)} blocos para descriptografar")
        
        # descriptografa cada bloco
        resultado_final = b''
        
        for i, bloco_cifrado in enumerate(blocos):
            print(f"Descriptografando bloco {i+1}...")
            
            # verifica se o bloco é válido
            if bloco_cifrado >= Na:
                print(f"Erro no bloco {i+1}: muito grande")
                continue
            
            # descriptografa: m = c^d mod n
            bloco_descriptografado = pow(bloco_cifrado, Da, Na)
            
            # converte para bytes
            bytes_com_padding = long_to_bytes(bloco_descriptografado, tamanho_bloco)
            
            # remove padding (zeros à esquerda)
            bytes_sem_padding = bytes_com_padding.lstrip(b'\x00')
            
            resultado_final += bytes_sem_padding
        
        print(f"Mensagem descriptografada tem {len(resultado_final)} bytes")
        
        # tenta decodificar como texto
        try:
            texto = resultado_final.decode('utf-8')
            print("Mensagem do professor:")
            print(texto)
        except:
            # se não der UTF-8, tenta outros encodings
            for encoding in ['latin-1', 'ascii']:
                try:
                    texto = resultado_final.decode(encoding)
                    print(f"Mensagem ({encoding}):")
                    print(texto)
                    break
                except:
                    continue
            else:
                print("Não consegui decodificar como texto")
                print(f"Hex: {resultado_final.hex()}")

    except FileNotFoundError:
        print("Arquivo de chave privada não encontrado. Execute opção 1 primeiro.")
    except Exception as e:
        print(f"Erro: {e}")


# Menu principal
if __name__ == "__main__":
    print("=== TP2 - Sistema de Chaves RSA e Compartilhamento AES ===")
    output_dir = input("📁 Digite o diretório onde os arquivos serão salvos/carregados: ").strip()

    print("\nO que você deseja fazer?")
    print("1 - Gerar chaves RSA do aluno (Parte 1)")
    print("2 - Compartilhar chave AES com o professor (Parte 2)")
    print("3 - Executar as duas etapas em sequência")
    print("4 - Decifrar mensagem rsa")
    opcao = input("Digite sua escolha (1/2/3/4): ").strip()

    if opcao == "1":
        gerar_chaves(output_dir)
    elif opcao == "2":
        compartilhar_chave(output_dir)
    elif opcao == "3":
        gerar_chaves(output_dir)
        compartilhar_chave(output_dir)
    elif opcao == "4":
        descriptografar_mensagem_rsa(output_dir)
    else:
        print("❌ Opção inválida.")
