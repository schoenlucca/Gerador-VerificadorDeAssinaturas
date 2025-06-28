from Verificador import calcula_chaves
from hashlib import sha256,sha3_256
import os
import base64

def bytes_para_int(mensagem:bytes)->int:
    return int.from_bytes(mensagem, byteorder='big')

def int_para_bytes(mensagem:int)->bytes:
    return mensagem.to_bytes((mensagem.bit_length() + 7) // 8, byteorder='big')

def xor_bytes(a:bytes, b:bytes)->bytes:
    # Realiza XOR em bytes
    return bytes(x^y for x,y in zip(a,b))

def hash_g(data: bytes) -> bytes:
    # Função G (expande o número aleatório).
    return sha3_256(data).digest()

def hash_h(data: bytes) -> bytes:
    # Função H (mascarara o numero aleatorio).
    return sha3_256(data).digest()

def obter_bytes_sha3(mensagem:str)->bytes:
    return sha3_256(mensagem.encode('utf-8')).digest()

def criptografia_OAEP(mensagem_bytes:bytes, n:int) -> bytes:
    # seed de 256 bits
    seed = os.urandom(32)    

    # p1 = M xor G(r) 
    # Dividir em grupos de 32 bytes pra nao perder dados no XOR   
    chunks = []
    for i in range(0,len(mensagem_bytes),32):
        chunk = mensagem_bytes[i:i+32]
        hash_g_aux = hash_g(seed)
        aux_p1 = xor_bytes(chunk,hash_g_aux)
        chunks.append(aux_p1)
    p1 = b"".join(chunks)

    # p2 = r xor H(p1)
    hash_h_aux = hash_h(p1)
    p2 = xor_bytes(seed,hash_h_aux)

    # p1 || p2
    return p1 + p2 

def descriptografia_OAEP(mensagem_cifrada:bytes) -> bytes:
    # Recupera p1 e p2 da mensagem criptografada em bytes
    p1 = mensagem_cifrada[:-32]
    p2 = mensagem_cifrada[-32:]

    # r = p2 xor H(p1)
    aux_h_hash = hash_h(p1)
    r = xor_bytes(p2, aux_h_hash)

    # M = p1 xor G(r)
    chunks = []
    for i in range(0,len(p1),32):
        chunk = p1[i:i+32]
        aux_g_hash = hash_g(r)
        mensagem_aux = xor_bytes(chunk,aux_g_hash)
        chunks.append(mensagem_aux)

    mensagem = b"".join(chunks)
    return mensagem

def gerar_assinatura_digital(mensagem:str, chave_privada:tuple)->tuple:
    # Chave privada para criptografia
    n,d = chave_privada 
    hash_msg = obter_bytes_sha3(mensagem)
    hash_int = bytes_para_int(hash_msg) % n
    assinatura = pow(hash_int,d,n)

    # Formatação em BASE64
    assinatura_bytes = int_para_bytes(assinatura)
    
    pacote = f"{mensagem}::{assinatura_bytes.hex()}".encode('utf-8')
    
    return base64.b64encode(pacote).decode('utf-8')

def verificar_assinatura_digital(assinatura_recebida_64:str, chave_publica:tuple)-> tuple:
    # Chave publica para descriptografia
    n, e = chave_publica
    # decodificação BASE64
    try:
        decoded = base64.b64decode(assinatura_recebida_64).decode('utf-8')
        mensagem, assinatura_hex = decoded.split("::")
        assinatura_bytes = bytes.fromhex(assinatura_hex)
    except:
        return (None, False)
    
    # descriptografia da assinatura
    assinatura = bytes_para_int(assinatura_bytes)
    hash_decifrado = pow(assinatura, e, n)
    
    # verificação 
    hash_msg = obter_bytes_sha3(mensagem)
    hash_int = bytes_para_int(hash_msg) % n
    
    return (mensagem, hash_decifrado == hash_int)

def divide_blocos(mensagem: str, n: int) -> list:
    tamanho_bloco = int((n.bit_length() // 8) - 32 - 2)  

    # Aplicar a OAEP para cada bloco
    mensagem_bytes = mensagem.encode('utf-8')
    blocos = []
    for i in range(0,len(mensagem_bytes),tamanho_bloco):
        bloco = mensagem_bytes[i:i+tamanho_bloco]
        bloco_oaep = criptografia_OAEP(bloco,n)
        blocos.append(bloco_oaep)
    return blocos

def criptografa_mensagem(mensagem: str, chave_publica: tuple) -> list[int]:
    # Criptografia com RSA
    n, e = chave_publica
    blocos = divide_blocos(mensagem, n)
    mensagem_criptografada = []
    
    for bloco in blocos: 
        m = bytes_para_int(bloco)
        c = pow(m, e, n)
        mensagem_criptografada.append(c)

    return mensagem_criptografada

def descriptografa_mensagem(mensagem_criptografada: list, chave_privada: tuple) -> str:
    # Descriptografia com RSA
    n, d = chave_privada
    mensagem_bytes = bytearray()
    for c in mensagem_criptografada:
        m = pow(c, d, n)
        # Descriptografar os blocos OAEP
        bloco = int_para_bytes(m)
        bloco_descriptografado = descriptografia_OAEP(bloco)

        mensagem_bytes.extend(bloco_descriptografado)

    mensagem_descriptografada = mensagem_bytes.decode('utf-8',errors='replace')
    return mensagem_descriptografada

def enviar_pacote(mensagem:str,chave_privada:tuple,chave_publica:tuple)-> tuple:
    # HMAC = (assinatura,mensagem_criptografada)

    print(f"Mensagem enviada: {mensagem}\n")
    mensagem_critptografada = criptografa_mensagem(mensagem,chave_publica)
    print(f"Mensagem criptografada: {mensagem_critptografada}\n")

    assinatura = gerar_assinatura_digital(mensagem,chave_privada)
    print(f"Assinatura gerada: {assinatura}\n")

    pacote = (assinatura,mensagem_critptografada)
    return pacote

def receber_pacote(pacote:tuple,chave_privada_receptor:tuple, chave_publica_emissor:tuple)-> bool:
    assinatura_b64, mensagem_criptografada = pacote
    mensagem_original = descriptografa_mensagem(mensagem_criptografada,chave_privada_receptor)
    print(f"Mensagem original descriptografada: {mensagem_original}\n")

    mensagem_assinada, valido = verificar_assinatura_digital(assinatura_b64, chave_publica_emissor)
    if not valido:
        raise ValueError("Assinatura inválida! Pacote pode ter sido alterado")
    if mensagem_original != mensagem_assinada:
        raise ValueError("Mensagem descriptografada não coincide com a assinada")
    
    print(f"Mensagem recebida: {mensagem_assinada}\n")
    print(f"Assinatura valida: {valido}\n")

    return mensagem_original

chave_publica_A, chave_privada_A = calcula_chaves()  # Emissor
chave_publica_B, chave_privada_B = calcula_chaves()  # Receptor
mensagem = "Alice e Bob são personagens comumente usados nas explicações técnicas em criptografia. Estes nomes são utilizados por conveniência, por exemplo, a frase 'Alice envia para Bob uma mensagem cifrada com a chave pública de Bob' é mais fácil de ser seguida do que 'Parte A envia a Parte B uma mensagem cifrada com a chave pública da Parte B.' Por estarem em ordem alfabética, os nome Alice e Bob tornaram-se comuns nesses campos, ajudando a explicar tópicos técnicos de uma forma mais compreensível"

# Emissor 
pacote = enviar_pacote(mensagem, chave_privada_A, chave_publica_B)
print(f"Enviando o pacote...")

# Receptor 
try:
    msg_recebida = receber_pacote(pacote, chave_privada_B, chave_publica_A)
except ValueError as e:
    print("Erro:", e)