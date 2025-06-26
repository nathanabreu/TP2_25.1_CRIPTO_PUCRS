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
    """Gera as chaves RSA do aluno"""
    print("🔧 Gerando chaves RSA do aluno...")

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
    print("🔑 Gerando número aleatório Sa (chave simétrica)...")
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
    """Compartilha chave AES com o professor usando RSA"""
    print("Gerando compartilhamento de chave AES...")

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

def descriptografar_mensagem_professor():
    """Descriptografa mensagem RSA do professor"""
    print("🔓 Descriptografando mensagem do professor...")
    
    try:
        # Carregar chave privada
        with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
            priv_lines = f.readlines()
            Da = int(priv_lines[0].split("=")[1].strip(), 16)
            Pa = int(priv_lines[1].split("=")[1].strip(), 16)
            Qa = int(priv_lines[2].split("=")[1].strip(), 16)
        Na = Pa * Qa
        
        print("✅ Chave privada carregada")
        print(f"   Tamanho de Na: {Na.bit_length()} bits ({Na.bit_length() // 8} bytes)")
        
        # Pegar mensagem do professor
        print("\n📝 Cole a mensagem cifrada do professor (RSACipheredMsg_hex):")
        mensagem_hex = input().strip()
        
        # Limpar entrada
        if mensagem_hex.startswith("0x"):
            mensagem_hex = mensagem_hex[2:]
        mensagem_hex = mensagem_hex.replace(" ", "").replace("\n", "").replace("\r", "")
        
        # Converter para bytes
        mensagem_bytes_raw = bytes.fromhex(mensagem_hex)
        print(f"📏 Tamanho da mensagem cifrada (raw): {len(mensagem_bytes_raw)} bytes")
        
        # Calcular tamanho do bloco RSA
        tamanho_bloco_rsa_bytes = (Na.bit_length() + 7) // 8
        print(f"🔢 Tamanho esperado de cada bloco RSA: {tamanho_bloco_rsa_bytes} bytes")

        # Tratar possível byte zero inicial extra
        if len(mensagem_bytes_raw) > 0 and \
           len(mensagem_bytes_raw) % tamanho_bloco_rsa_bytes == 1 and \
           mensagem_bytes_raw[0] == 0x00:
            mensagem_bytes = mensagem_bytes_raw[1:]
        else:
            mensagem_bytes = mensagem_bytes_raw

        # Validar tamanho
        if len(mensagem_bytes) % tamanho_bloco_rsa_bytes != 0:
            print(f"❌ Erro: Tamanho da mensagem não é múltiplo do bloco RSA")
            return

        print(f"📏 Tamanho da mensagem (ajustado): {len(mensagem_bytes)} bytes")
        
        # Quebrar em blocos
        blocos_cifrados_int = []
        for i in range(0, len(mensagem_bytes), tamanho_bloco_rsa_bytes):
            bloco_bytes = mensagem_bytes[i:i + tamanho_bloco_rsa_bytes]
            if bloco_bytes:
                bloco_cifrado_int = int.from_bytes(bloco_bytes, byteorder='big')
                blocos_cifrados_int.append(bloco_cifrado_int)
        
        print(f"📦 Total de blocos: {len(blocos_cifrados_int)}")
        
        # Descriptografar cada bloco
        blocos_descriptografados_bytes_lista = []
        
        for i, bloco_cifrado_int in enumerate(blocos_cifrados_int):
            print(f"\n🔓 Descriptografando bloco {i+1}/{len(blocos_cifrados_int)}...")
            
            # Validar bloco
            if bloco_cifrado_int >= Na:
                print(f"❌ Erro: Bloco {i+1} maior que Na")
                blocos_descriptografados_bytes_lista.append(b'[ERRO_BLOCO_INVALIDO]')
                continue
            
            # Descriptografar
            bloco_descriptografado_int = pow(bloco_cifrado_int, Da, Na)
            
            # Converter para bytes
            bytes_descriptografados_com_padding = long_to_bytes(bloco_descriptografado_int, tamanho_bloco_rsa_bytes)
            
            print(f"   Tamanho (com padding): {len(bytes_descriptografados_com_padding)} bytes")
            print(f"   Hex (com padding): {bytes_descriptografados_com_padding.hex()}")

            # Remover padding
            bytes_descriptografados_sem_padding = bytes_descriptografados_com_padding.lstrip(b'\x00')
            
            print(f"   Tamanho (sem padding): {len(bytes_descriptografados_sem_padding)} bytes")
            print(f"   Hex (sem padding): {bytes_descriptografados_sem_padding.hex()}")
            
            blocos_descriptografados_bytes_lista.append(bytes_descriptografados_sem_padding)
        
        # Combinar e decodificar
        print("\n🔗 Combinando e decodificando blocos...")
        
        bytes_completos_descriptografados = b''.join(blocos_descriptografados_bytes_lista)
        print(f"📏 Tamanho total: {len(bytes_completos_descriptografados)} bytes")

        # Tentar diferentes encodings
        texto_decodificado_completo = None
        for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'ascii']:
            try:
                texto_teste = bytes_completos_descriptografados.decode(encoding)
                if texto_teste.isprintable() or all(ord(c) < 128 for c in texto_teste):
                    texto_decodificado_completo = texto_teste
                    print(f"\n✅ Mensagem descriptografada ({encoding}):")
                    print(f"📄 {texto_decodificado_completo}")
                    break
            except UnicodeDecodeError:
                continue
        
        if texto_decodificado_completo is None:
            print(f"\n⚠️  Não foi possível decodificar como texto legível")
            print(f"🔢 Hex para debug: {bytes_completos_descriptografados.hex()}")

    except FileNotFoundError:
        print("❌ Arquivo de chave privada não encontrado. Execute opção 1 primeiro.")
    except Exception as e:
        print(f"❌ Erro: {e}")

def descriptografar_mensagem_aes():
    """Descriptografa mensagem AES usando a chave Sa"""
    print("🔓 Descriptografando mensagem AES...")
    
    try:
        # Carregar chave simétrica Sa do arquivo de chave privada
        with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
            priv_lines = f.readlines()
            Sa_hex = priv_lines[3].split("=")[1].strip()
            
            # Remover prefixo 0x se presente
            if Sa_hex.startswith("0x"):
                Sa_hex = Sa_hex[2:]
            
            Sa = int(Sa_hex, 16)
        
        # Converter Sa de volta para bytes
        Sa_bytes = long_to_bytes(Sa, 16)
        print("✅ Chave simétrica Sa carregada")
        print(f"🔑 Sa (hex): {Sa_hex}")
        
        # Pegar mensagem cifrada AES
        print("\n📝 Cole a mensagem cifrada AES (AESCipheredMsg_hex):")
        mensagem_hex = input().strip()

        # Limpar possíveis prefixos ("AESCipheredMsg=" ou "0x")
        if "=" in mensagem_hex:
            mensagem_hex = mensagem_hex.split("=", 1)[1]
        if mensagem_hex.startswith("0x"):
            mensagem_hex = mensagem_hex[2:]
        mensagem_hex = mensagem_hex.replace(" ", "").replace("\n", "").replace("\r", "")
        
        # Converter para bytes
        mensagem_bytes = bytes.fromhex(mensagem_hex)
        print(f"📏 Tamanho da mensagem cifrada: {len(mensagem_bytes)} bytes")
        
        # Extrair IV (primeiros 16 bytes) e dados cifrados
        if len(mensagem_bytes) < 16:
            print("❌ Erro: Mensagem muito curta para conter IV")
            return
            
        iv = mensagem_bytes[:16]
        dados_cifrados = mensagem_bytes[16:]
        
        print(f"🔢 IV: {iv.hex()}")
        print(f"📦 Dados cifrados: {len(dados_cifrados)} bytes")
        
        # Criar cipher AES
        cipher = AES.new(Sa_bytes, AES.MODE_CBC, iv)
        
        # Descriptografar
        try:
            dados_descriptografados = cipher.decrypt(dados_cifrados)

            # Remover padding PKCS7 (se aplicável)
            try:
                dados_descriptografados = unpad(dados_descriptografados, 16)
            except ValueError:
                # Caso não haja padding válido, continuar com os bytes brutos
                pass

            # Tentar decodificar como texto
            try:
                texto_decodificado = dados_descriptografados.decode('utf-8')
                print(f"\n✅ Mensagem descriptografada:")
                print(f"📄 {texto_decodificado}")
            except UnicodeDecodeError:
                print(f"\n⚠️  Não foi possível decodificar como UTF-8")
                print(f"🔢 Hex: {dados_descriptografados.hex()}")

        except Exception as e:
            print(f"❌ Erro na descriptografia AES: {e}")
            
    except FileNotFoundError:
        print("❌ Arquivo de chave privada não encontrado. Execute opção 1 primeiro.")
    except Exception as e:
        print(f"❌ Erro: {e}")


# Menu principal
if __name__ == "__main__":
    print("=== TP2 - Sistema de Chaves RSA e Compartilhamento AES ===")
    output_dir = input("📁 Digite o diretório onde os arquivos serão salvos/carregados: ").strip()

    print("\nO que você deseja fazer?")
    print("1 - Gerar chaves RSA do aluno (Parte 1)")
    print("2 - Compartilhar chave AES com o professor (Parte 2)")
    print("3 - Executar as duas etapas em sequência")
    print("4 - Decifrar mensagem do professor")
    print("5 - Decifrar mensagem AES")
    opcao = input("Digite sua escolha (1/2/3/4/5): ").strip()

    if opcao == "1":
        gerar_chaves(output_dir)
    elif opcao == "2":
        compartilhar_chave(output_dir)
    elif opcao == "3":
        gerar_chaves(output_dir)
        compartilhar_chave(output_dir)
    elif opcao == "4":
        descriptografar_mensagem_professor()
    elif opcao == "5":
        descriptografar_mensagem_aes()
    else:
        print("❌ Opção inválida.")
