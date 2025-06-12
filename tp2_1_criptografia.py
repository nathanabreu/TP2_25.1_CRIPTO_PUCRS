import os
from Crypto.Util.number import getPrime, inverse, GCD, isPrime, bytes_to_long
from Crypto.Random import get_random_bytes, random

def gerar_chaves(output_dir):
    print("🔧 Gerando chaves RSA do aluno...")

    Pa = getPrime(1024)
    Qa = getPrime(1024)
    Na = Pa * Qa
    L = (Pa - 1) * (Qa - 1)

    tentativas = 0
    while True:
        Ea = random.randint(2, L - 1)
        tentativas += 1
        if isPrime(Ea) and GCD(Ea, L) == 1:
            break

    Da = inverse(Ea, L)

    # Converter para hexadecimal
    Ea_hex = hex(Ea)
    Na_hex = hex(Na)
    Da_hex = hex(Da)
    Pa_hex = hex(Pa)
    Qa_hex = hex(Qa)

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
    print("📦 Gerando compartilhamento de chave AES...")

    # === Carregar chaves em hexadecimal
    with open(os.path.join(output_dir, "chave_publica_hex.txt")) as f:
        pub_lines = f.readlines()
        Ea = int(pub_lines[0].split("=")[1].strip(), 16)
        Na = int(pub_lines[1].split("=")[1].strip(), 16)

    with open(os.path.join(output_dir, "chave_privada_hex.txt")) as f:
        priv_lines = f.readlines()
        Da = int(priv_lines[0].split("=")[1].strip(), 16)

    # Chave pública do professor (fixa)
    Ep_hex = "EEC2681EDAFB5FBF4249302A43764824B28F1D007C5D75955ECCD5CF630243F9"
    Np_hex = (
        "EB7ED592C4C4F9C5CF0D8DFA8921FA91DA89FAB0D31E74CE0451C54998B5CD6B"
        "ED2F02D7BC5B5F1CF65023A4BD9C2A7B550BC89B8056B38F0AEC9302FDAFEDE5"
        "06DFA860E74770EAF450AD3F76C4FE07CD6505CF877C62A48F2FE3A238E735A1"
        "68DB70C220B75D74A3B783570130E2F96C9BE30FC23E2153E9B1B7C2D8DC77B5"
    )
    Ep = int(Ep_hex, 16)
    Np = int(Np_hex, 16)

    # Gerar chave simétrica

    # Gerar número aleatório Sa
    print("🔑 Gerando número aleatório Sa...")
    Sa_bytes = get_random_bytes(16)
    Sa = bytes_to_long(Sa_bytes)
    
    X = pow(Sa, Ep, Np)
    SIGx = pow(X, Da, Na)

    with open(os.path.join(output_dir, "chave_simetrica_hex.txt"), "w") as f:
        f.write(f"X = {hex(X)}\n")
        f.write(f"SIGx = {hex(SIGx)}\n")
        f.write(f"Ea = {hex(Ea)}\n")
        f.write(f"Na = {hex(Na)}\n")

    print(f"✅ Compartilhamento salvo em: {os.path.join(output_dir, 'chave_simetrica_hex.txt')}")

# === EXECUÇÃO ===
if __name__ == "__main__":
    print("=== TP2 - Sistema de Chaves RSA e Compartilhamento AES ===")
    output_dir = input("📁 Digite o diretório onde os arquivos serão salvos/carregados: ").strip()

    print("\nO que você deseja fazer?")
    print("1 - Gerar chaves RSA do aluno (Parte 1)")
    print("2 - Compartilhar chave AES com o professor (Parte 2)")
    print("3 - Executar as duas etapas em sequência")
    opcao = input("Digite sua escolha (1/2/3): ").strip()

    if opcao == "1":
        gerar_chaves(output_dir)
    elif opcao == "2":
        compartilhar_chave(output_dir)
    elif opcao == "3":
        gerar_chaves(output_dir)
        compartilhar_chave(output_dir)
    else:
        print("❌ Opção inválida.")
