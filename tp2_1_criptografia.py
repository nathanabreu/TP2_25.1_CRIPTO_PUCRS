import os
from Crypto.Util.number import (
    getPrime,
    inverse,
    GCD,
    isPrime,
    bytes_to_long,
    long_to_bytes,
)
from Crypto.Cipher import AES
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

def decifrar_mensagem_professor():
    """Decifra a mensagem enviada pelo professor usando RSA e AES."""

    print("\n🔍 Decifrando mensagem enviada pelo professor...")

    # --- chaves RSA fornecidas pelo professor ---
    Da_hex = (
        "d1c8cb37ced842bf9b561a58065c92e4687a85eccf21f16846c00af92b613f41"
        "e354c135046e7756094570f3a9ad5908dfe3b94b8d8a43a1fa03acdc667e20fa"
        "69e9f3983a2f10d95eb45ba819b04e44108538fffc0faeadf95418d07265eeb4"
        "1e307598e103da84e186e0b48ac8281c36ff6829678b1755c83590a98d4261f6"
        "d6844d99a6bcf8456a0f2896cfa544f0f81cae6c96ae27834d79de0ad74260a7"
        "39714c4db3dafef93bd0b02fc517163e896c1a10f9ad202a7bdc2ce4ecabdf86"
        "d725a559af425c74424a12bd5e0fb7709ad53472bb2888af5c4112fa1cd0bcff"
        "3ae36946d34a23141e691560a1cc2d6c6105e637199669883fc344f6c0bdd24f"
    )
    Pa_hex = (
        "ed844f60146d14bc6db1567e6391a17745add3c53d1d27a8ae9edeb9cd1e55d2"
        "256ca7c91eb3e42fdf94c7d431312d9c55a3a2c1c1f496cca953e6267b9ba4c8"
        "373ecde48f2b633175643025cd498560ccd495718a63b331ba171e49d435d42b"
        "34cb960fd53e315718d1fd1aa9dd9024b60ef138cc6a35e1dae9f8c405f80a3f"
    )
    Qa_hex = (
        "eeef5eb70320f81c22e584eec005977eb539886414750d75619c77cc1230ff0b"
        "4bc578bec6c5971ddb8071676fb4542a3780d4ec420adcd2919853e284cd3c94"
        "407cb1a897159298ae118bcf891a582137a837c06edc746640f40ad6a9775c22"
        "0bd2b17507115189a070232e02549141e59cd5097f6e7594e66fd8dc94dbd949"
    )

    RSACipheredMsg_hex = (
        "00C282F6854678CE27B16F6F69808FDC1D5936AD79208E800120AEFC23F0D5C4"
        "D75EE82B9CE906B982E4C8D8860216F9054CC915C97DB62DA571405582551080A"
        "85F0BA20D03E804A2EB17808EEDF1CB3C4F9B6090A36C6D3FF9430F4157438481"
        "5A371DD52DDCB3C19057F64ABA289B5B19379CF766D07C77D3C411CD3DC3C0E16"
        "86D2023C46540A0B9C3C70DEC70464141B26AE042C164802A50FEC77DBAE4BCEA"
        "F1310D2731E9274B3E03A1245B5C0880DEF9006DA131037DA0CFDE03E6E24117E"
        "31C0BBD52395F758E9A3E427F52452E508A9A6A93A98FBBD3AE3CB71F5E379304"
        "3143FED30B3FC3E001ECC602A3FA3EE59AEFF66946ADBC1D999A3A9CACFF"
    )
    AESCipheredMsg_hex = "25C42A154A74B72A7D644A02711D0EC9196C85EF6E85D64A1116BC291F114755"

    Da = int(Da_hex, 16)
    Pa = int(Pa_hex, 16)
    Qa = int(Qa_hex, 16)
    Na = Pa * Qa

    rsa_ct = int(RSACipheredMsg_hex, 16)
    rsa_pt_int = pow(rsa_ct, Da, Na)
    rsa_pt_bytes = long_to_bytes(rsa_pt_int)
    rsa_message = rsa_pt_bytes.decode("utf-8", "ignore")

    aes_key_hex = input("Informe a chave AES (Sa) em hexadecimal: ").strip()
    aes_key = bytes.fromhex(aes_key_hex)
    aes_cipher = AES.new(aes_key, AES.MODE_ECB)
    aes_pt = aes_cipher.decrypt(bytes.fromhex(AESCipheredMsg_hex))

    padding_len = aes_pt[-1]
    if padding_len > 0 and all(b == padding_len for b in aes_pt[-padding_len:]):
        aes_pt = aes_pt[:-padding_len]

    aes_message = aes_pt.decode("utf-8", "ignore")

    print("Texto via RSA :", rsa_message)
    print("Texto via AES :", aes_message)

    if rsa_message == aes_message:
        print("\u2714 Mensagens RSA e AES coincidem!")
    else:
        print("\u274c Mensagens diferentes.")

# === EXECUÇÃO ===
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
        decifrar_mensagem_professor()
    else:
        print("❌ Opção inválida.")
