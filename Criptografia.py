from Verificador import calcula_chaves
from hashlib import sha256,sha3_256
import os

def xor_bytes(a:bytes, b:bytes)->bytes:
    return bytes(x^y for x,y in zip(a,b))

def hash_g(data: bytes) -> bytes:
    #Função G (expande o número aleatório).
    return sha256(data).digest()

def hash_h(data: bytes) -> bytes:
    #Função H (hash para mascarar o numero aleatorio).
    return sha256(data).digest()

def criptografia_OAEP(mensagem_bytes:bytes, n:int) -> bytes:
    # Random de 256 bits
    r = os.urandom(32)    

    # p1 = M xor G(r) 
    # Dividir em grupos de 32 bytes pra nao perder dados no XOR   
    chunks = []
    for i in range(0,len(mensagem_bytes),32):
        chunk = mensagem_bytes[i:i+32]
        aux_p1 = xor_bytes(chunk,hash_g(r))
        chunks.append(aux_p1)
    p1 = b"".join(chunks)

    # p2 = r xor H(p1)
    p2 = xor_bytes(r,hash_h(p1))

    # p1 || p2
    return p1 + p2 

def descriptografia_OAEP(mensagem_cifrada:bytes) -> bytes:
    p1 = mensagem_cifrada[:-32]
    p2 = mensagem_cifrada[-32:]

    # r = p2 xor H(p1)
    r = xor_bytes(p2, hash_h(p1))

    # M = p1 xor G(r)
    chunks = []
    for i in range(0,len(p1),32):
        chunk = p1[i:i+32]
        mensagem_aux = xor_bytes(chunk,hash_g(r))
        chunks.append(mensagem_aux)

    mensagem = b"".join(chunks)
    return mensagem

def gerar_assinatura_digital(mensagem:str,chave_privada:tuple)->tuple:
    n,d = chave_privada 
    hash_msg = sha3_256(mensagem.encode('utf-8')).digest()
    hash_int = int.from_bytes(hash_msg, byteorder='big') % n
    assinatura = pow(hash_int,d,n)
    return (mensagem,assinatura)

def verificar_assinatura_digital(assinatura_recebida:tuple, chave_publica:tuple)-> bool:
    # Chave publica para descriptografia
    n,e = chave_publica
    assinatura = assinatura_recebida[1]
    mensagem = assinatura_recebida[0]
    assinatura_comparada = pow(assinatura,e,n)

    hash_msg = sha3_256(mensagem.encode('utf-8')).digest()
    hash_int = int.from_bytes(hash_msg,byteorder='big') % n
    return assinatura_comparada == hash_int

def divide_blocos(mensagem: str, n: int) -> list[bytes]:
    # Tamanho que cada bloco deve ter
    tamanho_bloco = int((n.bit_length() // 8) - 32 - 2)  

    mensagem_bytes = mensagem.encode('utf-8')
    blocos = []
    for i in range(0,len(mensagem_bytes),tamanho_bloco):
        bloco = mensagem_bytes[i:i+tamanho_bloco]
        bloco_oaep = criptografia_OAEP(bloco,n)
        blocos.append(bloco_oaep)
    return blocos

def criptografa_mensagem(mensagem: str, chave_publica: tuple) -> list[int]:
    n, e = chave_publica
    blocos = divide_blocos(mensagem, n)
    mensagem_criptografada = []
    
    for bloco in blocos: 
        m = int.from_bytes(bloco, byteorder='big')
        c = pow(m, e, n)
        mensagem_criptografada.append(c)
    return mensagem_criptografada

def descriptografa_mensagem(mensagem_criptografada: list, chave_privada: tuple) -> str:
    n, d = chave_privada
    mensagem_bytes = bytearray()
    for c in mensagem_criptografada:
        m = pow(c, d, n)
        bloco = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
        bloco_descriptografado = descriptografia_OAEP(bloco)

        mensagem_bytes.extend(bloco_descriptografado)
    
    return mensagem_bytes.decode('utf-8',errors='replace')

def enviar_pacote(mensagem:str,chave_privada:tuple,chave_publica:tuple)->tuple:
    # HMAC = (assinatura,mensagem_criptografada)
    mensagem_critptografada = criptografa_mensagem(mensagem,chave_publica)
    assinatura = gerar_assinatura_digital(mensagem,chave_privada)
    return (assinatura,mensagem_critptografada)

def receber_pacote(pacote:tuple,chave_privada_receptor:tuple, chave_publica_emissor:tuple)->bool:
    assinatura = pacote[0]
    mensagem_criptografada = pacote[1]
    mensagem_original = descriptografa_mensagem(mensagem_criptografada,chave_privada_receptor)
    if not verificar_assinatura_digital(assinatura,chave_publica_emissor):
        print("Pacote pode ter sido modificado ou contaminado")
        return False
    return mensagem_original == assinatura[0]

chave_publica_A, chave_privada_A = calcula_chaves()  # Emissor
chave_publica_B, chave_privada_B = calcula_chaves()  # Receptor
mensagem = "Brasil pais do futbol"

# Emissor 
pacote = enviar_pacote(mensagem, chave_privada_A, chave_publica_B)

# Receptor 
try:
    msg_recebida = receber_pacote(pacote, chave_privada_B, chave_publica_A)
    print("Mensagem válida recebida:", msg_recebida)
except ValueError as e:
    print("Erro:", e)